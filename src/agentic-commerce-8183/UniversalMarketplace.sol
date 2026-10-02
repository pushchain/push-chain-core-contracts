// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {IPRC20} from "../Interfaces/IPRC20.sol";
import {IUniversalMarketplace} from "./interfaces/IUniversalMarketplace.sol";
import {UniversalMarketplaceErrors} from "./libraries/Errors.sol";
import {
    AgentCard,
    CEADeployment,
    CardView,
    JobInputs,
    StartJobParams,
    IntentRequest,
    InitParams,
    SessionContext,
    BuildContext
} from "./libraries/Types.sol";
import {IAgenticCommerce} from "./interfaces/IAgenticCommerce.sol";
import {IUniversalMarketplaceTerms} from "./interfaces/IUniversalMarketplaceTerms.sol";
import {JobSpecBuilder} from "./libraries/JobSpecBuilder.sol";
import {IAGWFactory} from "./interfaces/external/IAGWFactory.sol";
import {IAGW, OwnerIntent, OWNER_LANE_FLAG, Session} from "./interfaces/external/IAGW.sol";

/// @title UniversalMarketplace
/// @notice Agent cards, and `startJob`: one relayed call that, on one owner-signed OwnerIntent, deploys the
///         user's AGW if needed, grants it the card's rules, and creates the ERC-8183 job with the AGW as client.
/// @dev - Moves no funds. Wallet funding, the owner's approvals and 8183 `setBudget` / `fund` happen elsewhere.
///      - Never owns anything: it presents the owner's intent to the factory and wallet, which verify the
///        signature themselves and accept it only from the intent's `executor` (this contract).
///      - Rules ⊆ card: the owner signs a session they cannot read, so this contract proves it is the card's.
///        Card ⊆ job: the job's criteria are BUILT here (JobSpecBuilder) from the card's stored template, never
///        supplied. The template itself is not judged: whether the evaluator can run it is the provider's
///        responsibility, reviewed through the verified tag.
///      - The card's content lives on-chain. The rules side is checked by `TERMS`, a stateless helper split out
///        for EIP-170.
///      - Deployed behind `TransparentUpgradeableProxy`. Storage is append-only from this layout.
contract UniversalMarketplace is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    IUniversalMarketplace
{
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    /// @notice The owner lane `startJob` executes `createJob` on (owner lane, key 0).
    uint192 public constant STARTJOB_LANE = OWNER_LANE_FLAG;
    /// @notice ERC-7579 single call, default exec type: all four mode components are zero.
    bytes32 public constant MODE_SINGLE = bytes32(0);

    uint32 internal constant MIN_DURATION = 1 hours;
    bytes7 internal constant EVM_PREFIX = "eip155:";

    // ───────── storage: append-only ─────────

    IAGWFactory public AGW_FACTORY;
    IAgenticCommerce public KERNEL;
    address public hook;
    /// @notice The 8183 evaluator of every job started here.
    address public evaluator;
    /// @notice keccak256("eip155:" ‖ decimal(block.chainid)): Push itself, which no card or read may name.
    bytes32 public pushChainHash;
    IUniversalMarketplaceTerms public TERMS;
    uint256 public cardCount;
    mapping(uint256 => AgentCard) internal _cards;
    mapping(uint256 => bytes) internal _rulesTerms;
    mapping(uint256 => bytes) internal _evaluations;
    /// @notice 1 at registration, +1 per modification. Bound into the job's criteria (`origin`).
    mapping(uint256 => uint256) public cardVersion;
    /// @notice Verified by the admin at the CURRENT version. Cleared by every modification.
    mapping(uint256 => bool) public isCardVerified;
    /// @notice Disabled by the admin. Permanent: the provider cannot reactivate the card.
    mapping(uint256 => bool) public isCardAdminDisabled;
    mapping(bytes32 => CEADeployment) public ceaDeployment;
    /// @notice `startJob` paused for cards on this chain. Pause before rotating its CEA implementation.
    mapping(bytes32 => bool) public isUniversalPaused;
    /// @notice AGW → the last job started here for it.
    mapping(address => uint256) public lastJobOf;
    mapping(uint256 => uint256) public cardOfJob;
    mapping(uint256 => address) public agwOfJob;
    mapping(uint256 => bytes32) public rulesOfJob;
    uint256[30] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the proxy.
    /// @param p The addresses; every one non-zero, and `p.hook` whitelisted on the kernel.
    function initialize(InitParams calldata p) external initializer {
        if (p.agwFactory == address(0) || p.kernel == address(0) || p.terms == address(0) || p.admin == address(0)) {
            revert UniversalMarketplaceErrors.ZeroAddress();
        }
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        AGW_FACTORY = IAGWFactory(p.agwFactory);
        KERNEL = IAgenticCommerce(p.kernel);
        TERMS = IUniversalMarketplaceTerms(p.terms);
        pushChainHash = keccak256(abi.encodePacked("eip155:", Strings.toString(block.chainid)));
        _setHook(p.hook);
        _setEvaluator(p.evaluator);
        _grantRole(DEFAULT_ADMIN_ROLE, p.admin);
        _grantRole(ADMIN_ROLE, p.admin);
    }

    // ═════════════════════════════════ admin ═════════════════════════════════

    /// @inheritdoc IUniversalMarketplace
    /// @dev Jobs keep the hook they were created with; new jobs get this one.
    function setHook(address hook_) external onlyRole(ADMIN_ROLE) {
        _setHook(hook_);
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev Not checked against providers: `startJob` refuses a card whose provider is the evaluator.
    function setEvaluator(address evaluator_) external onlyRole(ADMIN_ROLE) {
        _setEvaluator(evaluator_);
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev - The derived CEA is the beneficiary pin of every rules grant on `chainHash`, and the CEA the job's
    ///        criteria read. The SDK derives it from the destination CEAFactory; `startJob` refuses a mismatch.
    ///      - Rotation runbook: `setUniversalPaused(chain, true)` → rotate on the destination → this → unpause.
    function setCEADeployment(bytes32 chainHash, address ceaFactory, address ceaProxyImpl)
        external
        onlyRole(ADMIN_ROLE)
    {
        if (ceaFactory == address(0) || ceaProxyImpl == address(0)) {
            revert UniversalMarketplaceErrors.ZeroAddress();
        }
        ceaDeployment[chainHash] = CEADeployment({ceaFactory: ceaFactory, ceaProxyImpl: ceaProxyImpl});
        emit CEADeploymentSet(chainHash, ceaFactory, ceaProxyImpl);
    }

    /// @inheritdoc IUniversalMarketplace
    function setUniversalPaused(bytes32 chainHash, bool paused_) external onlyRole(ADMIN_ROLE) {
        isUniversalPaused[chainHash] = paused_;
        emit UniversalChainPaused(chainHash, paused_);
    }

    /// @inheritdoc IUniversalMarketplace
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /// @inheritdoc IUniversalMarketplace
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev The per-card kill switch. Permanent, so a compromised provider cannot switch it back on.
    function adminDisableCard(uint256 cardId) external onlyRole(ADMIN_ROLE) {
        _requireCard(cardId);
        isCardAdminDisabled[cardId] = true;
        _cards[cardId].active = false;
        _clearVerified(cardId);
        emit CardDisabledByAdmin(cardId);
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev - A tag, not a gate: `startJob` treats verified and unverified cards alike.
    ///      - `version` is the one the admin reviewed: a modification in between makes this revert.
    ///      - Refused for an admin-disabled card; allowed for one its provider switched off.
    function verifyAgentCard(uint256 cardId, uint256 version) external onlyRole(ADMIN_ROLE) {
        _requireCard(cardId);
        if (isCardAdminDisabled[cardId]) revert UniversalMarketplaceErrors.CardAdminDisabled(cardId);
        uint256 current = cardVersion[cardId];
        if (version != current) revert UniversalMarketplaceErrors.CardVersionMismatch(version, current);
        isCardVerified[cardId] = true;
        emit CardVerified(cardId, version);
    }

    /// @inheritdoc IUniversalMarketplace
    function revokeAgentCardVerification(uint256 cardId) external onlyRole(ADMIN_ROLE) {
        _requireCard(cardId);
        _clearVerified(cardId);
    }

    // ═════════════════════════════════ cards ═════════════════════════════════

    /// @inheritdoc IUniversalMarketplace
    function registerCard(AgentCard calldata c, bytes calldata rulesTerms, bytes calldata evaluation)
        external
        whenNotPaused
        returns (uint256 cardId)
    {
        _validateCard(c, rulesTerms);

        cardId = ++cardCount;
        _cards[cardId] = c;
        AgentCard storage stored = _cards[cardId];
        stored.provider = msg.sender;
        stored.active = true;
        _rulesTerms[cardId] = rulesTerms;
        _evaluations[cardId] = evaluation;
        cardVersion[cardId] = 1;

        emit CardRegistered(
            cardId,
            msg.sender,
            c.jobType,
            c.chainNamespace,
            keccak256(rulesTerms),
            keccak256(evaluation),
            c.metadataHash,
            c.fee
        );
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev - Provider only; refused for an admin-disabled card and while paused.
    ///      - `chainNamespace` identifies the card: another chain is another card. `provider` and `active` stay.
    ///      - The version is part of every job's criteria (`origin`), so an intent signed against the old
    ///        version fails `startJob`. Jobs already started are untouched.
    function modifyAgentCard(uint256 cardId, AgentCard calldata c, bytes calldata rulesTerms, bytes calldata evaluation)
        external
        whenNotPaused
    {
        AgentCard storage stored = _cards[cardId];
        if (stored.provider == address(0) || msg.sender != stored.provider) {
            revert UniversalMarketplaceErrors.CallerIsNotProvider();
        }
        if (isCardAdminDisabled[cardId]) revert UniversalMarketplaceErrors.CardAdminDisabled(cardId);
        if (keccak256(bytes(c.chainNamespace)) != keccak256(bytes(stored.chainNamespace))) {
            revert UniversalMarketplaceErrors.CardIdentityImmutable();
        }
        _validateCard(c, rulesTerms);

        stored.jobType = c.jobType;
        stored.metadataURI = c.metadataURI;
        stored.metadataHash = c.metadataHash;
        stored.fee = c.fee;
        stored.principalMin = c.principalMin;
        stored.principalMax = c.principalMax;
        stored.minDuration = c.minDuration;
        stored.maxDuration = c.maxDuration;
        stored.minExecuteWindow = c.minExecuteWindow;
        stored.settleWindow = c.settleWindow;
        _rulesTerms[cardId] = rulesTerms;
        _evaluations[cardId] = evaluation;

        uint256 version = ++cardVersion[cardId];
        _clearVerified(cardId);

        emit CardModified(cardId, version, keccak256(rulesTerms), keccak256(evaluation), c.metadataHash, c.fee);
    }

    /// @inheritdoc IUniversalMarketplace
    function setCardActive(uint256 cardId, bool active) external {
        AgentCard storage c = _cards[cardId];
        if (c.provider == address(0) || msg.sender != c.provider) {
            revert UniversalMarketplaceErrors.CallerIsNotProvider();
        }
        if (active && isCardAdminDisabled[cardId]) revert UniversalMarketplaceErrors.CardAdminDisabled(cardId);
        c.active = active;
        emit CardStatusChanged(cardId, active);
    }

    /// @inheritdoc IUniversalMarketplace
    function getCard(uint256 cardId) external view returns (CardView memory v) {
        v.card = _cards[cardId];
        v.rulesTerms = _rulesTerms[cardId];
        v.evaluation = _evaluations[cardId];
        v.version = cardVersion[cardId];
        v.verified = isCardVerified[cardId];
        v.adminDisabled = isCardAdminDisabled[cardId];
    }

    // ═════════════════════════════════ startJob ═════════════════════════════════

    /// @inheritdoc IUniversalMarketplace
    /// @dev Normative order (PRD 09 §3.2), every check before the first state change:
    ///      1-6 card, version, ranges, evaluator · 7 wallet · 8 free · 9-10 build the job · 11 bind the intent ·
    ///      12 rules ⊆ card · ── 13 deploy or check owner · 14 grant · 15 create, verified · 16 record.
    function startJob(StartJobParams calldata p)
        external
        whenNotPaused
        nonReentrant
        returns (uint256 jobId, address agw, bytes32 rulesId)
    {
        AgentCard storage c = _cards[p.cardId];
        bytes32 chainHash = _checkCardAndJob(c, p);
        bool deployed;
        (agw, deployed) = _resolveWallet(p);
        if (!isAGWFree(agw)) revert UniversalMarketplaceErrors.AGWBusy(agw, lastJobOf[agw]);
        (bytes32 mode, bytes memory execCalldata) = _buildCreateJob(p.cardId, agw, p.job);
        _bindIntent(p, mode, execCalldata);
        _verifyRules(c, p, agw, chainHash);

        _deployOrCheckOwner(p, agw, deployed);
        rulesId = IAGW(agw).grantRulesWithSig(p.session, p.intent, p.sig);
        jobId = _createJob(c, agw, mode, execCalldata, p.intent, p.sig);

        lastJobOf[agw] = jobId;
        cardOfJob[jobId] = p.cardId;
        agwOfJob[jobId] = agw;
        rulesOfJob[jobId] = rulesId;
        emit JobStarted(p.cardId, p.intent.owner, agw, jobId, rulesId, p.job.principal, p.cardVersion);
    }

    // ═════════════════════════════════ views ═════════════════════════════════

    /// @inheritdoc IUniversalMarketplace
    /// @dev Busy while the last job started here is Funded, Submitted, or Open and not yet expired.
    function isAGWFree(address agw) public view returns (bool) {
        uint256 id = lastJobOf[agw];
        if (id == 0) return true;
        IAgenticCommerce.Job memory j = KERNEL.getJob(id);
        if (j.status == IAgenticCommerce.JobStatus.Funded || j.status == IAgenticCommerce.JobStatus.Submitted) {
            return false;
        }
        if (j.status == IAgenticCommerce.JobStatus.Open) return block.timestamp >= j.expiredAt;
        return true;
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev Mirrors `CEAFactory._computeCEAInternal`: an OZ minimal proxy of `ceaProxyImpl`, salt
    ///      `keccak256(abi.encode(pushAccount))`, deployer = the CEA factory. Stale after a destination
    ///      implementation rotation until `setCEADeployment`: pause the chain first.
    function expectedCEAOf(address agw, bytes32 chainHash) public view returns (address) {
        CEADeployment memory d = ceaDeployment[chainHash];
        if (d.ceaFactory == address(0)) revert UniversalMarketplaceErrors.ChainNotSupported(chainHash);
        return Clones.predictDeterministicAddress(d.ceaProxyImpl, keccak256(abi.encode(agw)), d.ceaFactory);
    }

    /// @inheritdoc IUniversalMarketplace
    function buildCreateJobCalldata(uint256 cardId, address owner, uint96 index, JobInputs calldata job)
        external
        view
        returns (bytes32 mode, bytes memory executionCalldata)
    {
        _requireCard(cardId);
        (address agw,) = AGW_FACTORY.predictWallet(owner, index);
        return _buildCreateJob(cardId, agw, job);
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev The SDK signs exactly what this returns. Nonces are 0 for a wallet not yet deployed.
    function previewIntent(IntentRequest calldata r, Session calldata s) external view returns (OwnerIntent memory i) {
        _requireCard(r.cardId);
        (address wallet, bool deployed) = AGW_FACTORY.predictWallet(r.owner, r.index);
        (bytes32 mode, bytes memory cd) = _buildCreateJob(r.cardId, wallet, r.job);
        i.owner = r.owner;
        i.wallet = wallet;
        i.executor = address(this);
        i.index = r.index;
        i.sessionHash = keccak256(abi.encode(s));
        i.mode = mode;
        i.execCalldataHash = keccak256(cd);
        i.nonceKey = STARTJOB_LANE;
        i.nonceSeq = deployed ? IAGW(wallet).getNonce(STARTJOB_LANE) : 0;
        i.grantNonce = deployed ? IAGW(wallet).grantNonce() : 0;
        i.deadline = r.deadline;
        i.signerChainId = r.signerChainId;
    }

    // ═════════════════════════════════ internal: config and cards ═════════════════════════════════

    function _setHook(address hook_) internal {
        if (hook_ == address(0)) revert UniversalMarketplaceErrors.ZeroAddress();
        if (!KERNEL.whitelistedHooks(hook_)) revert UniversalMarketplaceErrors.HookNotWhitelisted();
        hook = hook_;
        emit HookUpdated(hook_);
    }

    function _setEvaluator(address evaluator_) internal {
        if (evaluator_ == address(0)) revert UniversalMarketplaceErrors.ZeroAddress();
        evaluator = evaluator_;
        emit EvaluatorUpdated(evaluator_);
    }

    /// @dev `CardInactive` for a card that was never registered.
    function _requireCard(uint256 cardId) internal view {
        if (_cards[cardId].provider == address(0)) revert UniversalMarketplaceErrors.CardInactive();
    }

    /// @dev Clears the verified tag, emitting only when there was one to clear.
    function _clearVerified(uint256 cardId) internal {
        if (!isCardVerified[cardId]) return;
        isCardVerified[cardId] = false;
        emit CardVerificationRevoked(cardId);
    }

    /// @dev Registration and modification checks, in PRD 09 §5.1.5 order. The caller is the provider. The criteria
    ///      template is stored as given.
    function _validateCard(AgentCard calldata c, bytes calldata rulesTerms) internal view {
        if (c.jobType == bytes32(0)) revert UniversalMarketplaceErrors.InvalidCard("job type zero");
        if (bytes(c.metadataURI).length == 0) revert UniversalMarketplaceErrors.InvalidCard("metadata uri empty");
        if (c.metadataHash == bytes32(0)) revert UniversalMarketplaceErrors.InvalidCard("metadata hash zero");
        bytes calldata ns = bytes(c.chainNamespace);
        if (ns.length <= EVM_PREFIX.length || bytes7(ns[:7]) != EVM_PREFIX) {
            revert UniversalMarketplaceErrors.InvalidCard("chain namespace");
        }
        bytes32 chainHash = keccak256(ns);
        if (chainHash == pushChainHash || ceaDeployment[chainHash].ceaFactory == address(0)) {
            revert UniversalMarketplaceErrors.ChainNotSupported(chainHash);
        }
        _validateWindows(c);
        _requireAssetOnChain(TERMS.validateRulesTerms(rulesTerms), chainHash);
    }

    /// @dev Items 7-11: the provider is not the evaluator, and the principal and time windows are coherent.
    function _validateWindows(AgentCard calldata c) internal view {
        if (msg.sender == evaluator) revert UniversalMarketplaceErrors.InvalidCard("provider is evaluator");
        if (c.principalMax == 0 || c.principalMin > c.principalMax) {
            revert UniversalMarketplaceErrors.InvalidCard("principal range");
        }
        if (c.minDuration < MIN_DURATION || c.minDuration > c.maxDuration) {
            revert UniversalMarketplaceErrors.InvalidCard("duration range");
        }
        if (c.settleWindow == 0) revert UniversalMarketplaceErrors.InvalidCard("settle window");
        if (uint256(c.minExecuteWindow) + c.settleWindow > c.maxDuration) {
            revert UniversalMarketplaceErrors.InvalidCard("execute window");
        }
    }

    /// @dev The rules asset is a PRC20 of the card's chain. A raw staticcall, not try/catch: a non-string
    ///      answer must fail as "asset", and a try clause cannot catch its own return-data decoding.
    ///      A codeless asset answers empty, so it fails the length check.
    function _requireAssetOnChain(address asset, bytes32 chainHash) internal view {
        (bool ok, bytes memory ret) = asset.staticcall(abi.encodeCall(IPRC20.SOURCE_CHAIN_NAMESPACE, ()));
        if (!ok || ret.length < 64) revert UniversalMarketplaceErrors.InvalidCard("asset");
        (uint256 offset, uint256 len) = abi.decode(ret, (uint256, uint256));
        if (offset != 32 || len > ret.length - 64) revert UniversalMarketplaceErrors.InvalidCard("asset");
        if (keccak256(abi.decode(ret, (bytes))) != chainHash) {
            revert UniversalMarketplaceErrors.InvalidCard("asset chain");
        }
    }

    // ═════════════════════════════════ internal: startJob ═════════════════════════════════

    /// @dev Steps 1-6. Returns the card's chain hash.
    function _checkCardAndJob(AgentCard storage c, StartJobParams calldata p)
        internal
        view
        returns (bytes32 chainHash)
    {
        if (!c.active) revert UniversalMarketplaceErrors.CardInactive();
        chainHash = keccak256(bytes(c.chainNamespace));
        if (isUniversalPaused[chainHash]) revert UniversalMarketplaceErrors.ChainPaused(chainHash);
        uint256 current = cardVersion[p.cardId];
        if (p.cardVersion != current) revert UniversalMarketplaceErrors.CardVersionMismatch(p.cardVersion, current);
        _checkJobWindows(c, p.job);
        if (c.provider == evaluator) revert UniversalMarketplaceErrors.ProviderIsEvaluator();
    }

    /// @dev Steps 3-5: principal, expiry and executeBy inside the card's windows.
    function _checkJobWindows(AgentCard storage c, JobInputs calldata job) internal view {
        if (job.principal < c.principalMin || job.principal > c.principalMax) {
            revert UniversalMarketplaceErrors.PrincipalOutOfRange();
        }
        uint256 expiredAt = job.expiredAt;
        if (expiredAt < block.timestamp + c.minDuration || expiredAt > block.timestamp + c.maxDuration) {
            revert UniversalMarketplaceErrors.ExpiryOutOfRange();
        }
        uint256 executeBy = job.executeBy;
        if (executeBy < block.timestamp + c.minExecuteWindow || executeBy + c.settleWindow > expiredAt) {
            revert UniversalMarketplaceErrors.ExecuteByOutOfRange();
        }
    }

    /// @dev Step 7: the intent names the wallet derived from its owner and index, and this executor.
    function _resolveWallet(StartJobParams calldata p) internal view returns (address agw, bool deployed) {
        (agw, deployed) = AGW_FACTORY.predictWallet(p.intent.owner, p.intent.index);
        if (p.intent.wallet != agw) revert UniversalMarketplaceErrors.IntentWalletMismatch(agw, p.intent.wallet);
        if (p.intent.executor != address(this)) {
            revert UniversalMarketplaceErrors.ExecutorMismatch(p.intent.executor, address(this));
        }
    }

    /// @dev Steps 9-10: the job's criteria, built from the card's template, inside `createJob` as an ERC-7579
    ///      single execution. Everything the owner signs per job (principal, times, params, card version and
    ///      the wallet, through its CEA) is in this calldata, so the intent's calldata hash binds all of it.
    function _buildCreateJob(uint256 cardId, address agw, JobInputs calldata job)
        internal
        view
        returns (bytes32 mode, bytes memory executionCalldata)
    {
        AgentCard storage c = _cards[cardId];
        bytes memory description = JobSpecBuilder.build(
            _evaluations[cardId],
            BuildContext({
                agw: agw,
                principal: job.principal,
                executeBy: job.executeBy,
                settleWindow: c.settleWindow,
                params: job.params,
                origin: keccak256(abi.encode(address(this), cardId, cardVersion[cardId], job.principal))
            })
        );
        bytes memory call = abi.encodeCall(
            IAgenticCommerce.createJob, (c.provider, evaluator, uint256(job.expiredAt), string(description), hook)
        );
        mode = MODE_SINGLE;
        executionCalldata = abi.encodePacked(address(KERNEL), uint256(0), call);
    }

    /// @dev Step 11: the intent's exec fields name exactly this createJob, on the startJob lane, and its
    ///      session hash is this session. The wallet re-checks both; this names the error before state moves.
    function _bindIntent(StartJobParams calldata p, bytes32 mode, bytes memory execCalldata) internal pure {
        bytes32 cdHash = keccak256(execCalldata);
        if (p.intent.mode != mode || p.intent.execCalldataHash != cdHash || p.intent.nonceKey != STARTJOB_LANE) {
            revert UniversalMarketplaceErrors.IntentExecMismatch(cdHash);
        }
        bytes32 sessionHash = keccak256(abi.encode(p.session));
        if (p.intent.sessionHash != sessionHash) revert UniversalMarketplaceErrors.IntentSessionMismatch(sessionHash);
    }

    /// @dev Step 12: the signed session is the card's rules, for the card's agent, bound to this job and CEA.
    function _verifyRules(AgentCard storage c, StartJobParams calldata p, address agw, bytes32 chainHash)
        internal
        view
    {
        TERMS.verifySession(
            _rulesTerms[p.cardId],
            p.session,
            SessionContext({
                agent: c.provider,
                chainHash: chainHash,
                principal: p.job.principal,
                expiredAt: p.job.expiredAt,
                expectedCEA: expectedCEAOf(agw, chainHash)
            })
        );
    }

    /// @dev Step 13: deploy the predicted wallet, or check the factory's owner of the existing one.
    function _deployOrCheckOwner(StartJobParams calldata p, address agw, bool deployed) internal {
        if (!deployed) {
            address d = AGW_FACTORY.deployWalletWithSig(p.intent, p.sig, p.label);
            if (d != agw) revert UniversalMarketplaceErrors.AGWMismatch(agw, d);
            return;
        }
        address owner = AGW_FACTORY.ownerOf(agw);
        if (owner != p.intent.owner) revert UniversalMarketplaceErrors.WalletOwnerMismatch(p.intent.owner, owner);
    }

    /// @dev Step 15: the AGW creates the job; exactly one job appeared, with this AGW as client and the card's
    ///      provider, this hook and this evaluator.
    function _createJob(
        AgentCard storage c,
        address agw,
        bytes32 mode,
        bytes memory execCalldata,
        OwnerIntent calldata intent,
        bytes calldata sig
    ) internal returns (uint256 jobId) {
        uint256 before = KERNEL.jobCounter();
        IAGW(agw).executeWithSig(mode, execCalldata, intent, sig);
        jobId = KERNEL.jobCounter();
        if (jobId != before + 1) revert UniversalMarketplaceErrors.UnexpectedJobCount(before, jobId);
        IAgenticCommerce.Job memory j = KERNEL.getJob(jobId);
        if (j.client != agw || j.provider != c.provider || j.hook != hook || j.evaluator != evaluator) {
            revert UniversalMarketplaceErrors.JobMismatch();
        }
    }
}
