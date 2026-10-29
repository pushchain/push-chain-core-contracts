// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {OwnerIntent, OWNER_LANE_FLAG} from "@push-agw/libraries/Types.sol";
import {Execution} from "@push-agw/libraries/ExecutionLib.sol";
import {IPRC20} from "../Interfaces/IPRC20.sol";
import {IUniversalMarketplace} from "./interfaces/IUniversalMarketplace.sol";
import {UniversalMarketplaceErrors} from "./libraries/Errors.sol";
import {
    AgentCard,
    AgentCardView,
    CEADeployment,
    JobInputs,
    OpenJobParams,
    IntentRequest,
    InitParams,
    SessionContext,
    BuildContext,
    MAX_RULES
} from "./libraries/Types.sol";
import {IAgenticCommerce} from "./interfaces/IAgenticCommerce.sol";
import {IUniversalMarketplaceRules} from "./interfaces/IUniversalMarketplaceRules.sol";
import {JobSpecBuilder} from "./libraries/JobSpecBuilder.sol";
import {IAGWFactory} from "./interfaces/external/IAGWFactory.sol";
import {IAGW, Session} from "./interfaces/external/IAGW.sol";
import {ISmartSession} from "./interfaces/external/ISmartSession.sol";

/// @title UniversalMarketplace
/// @notice Agent cards, and `openJob`: one relayed call that, on one owner-signed OwnerIntent, deploys the
///         user's AGW if needed, grants it the card's rules (one rules set per destination chain), and creates the
///         ERC-8183 job with the AGW as client.
/// @dev - Moves no funds. Wallet funding and 8183 `setBudget` / `fund` happen elsewhere.
///      - Never owns anything: it presents the owner's intent to the factory and wallet, which verify the
///        signature themselves and accept it only from the intent's `executor` (this contract).
///      - Rules = card: the owner signs a session they cannot read, so this contract proves it is the card's, with
///        the card's markers filled for this job. Card ⊆ job: the job's criteria are BUILT here (JobSpecBuilder) from
///        the card's stored `jobSpecTemplate`, never supplied. The template itself is not judged: whether the
///        evaluator can run it is the provider's responsibility, reviewed through the verified tag.
///      - The card's content lives on-chain. The rules side is checked by `RULES`, a stateless helper split out
///        for EIP-170.
///      - One card per provider.
///      - Grants and `createJob` run as ONE owner-signed `executeWithSig` batch: the wallet self-calls `grantRules`
///        per rule (owner authority, `onlyOwnerOrSelf`), then calls the kernel. One signature for any rule count.
///      - Deployed behind `TransparentUpgradeableProxy`. Storage is append-only from this layout.
contract UniversalMarketplace is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    IUniversalMarketplace
{
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    /// @notice The owner lane `openJob` executes `createJob` on (owner lane, key 0).
    uint192 public constant OPENJOB_LANE = OWNER_LANE_FLAG;
    /// @notice ERC-7579 single call, default exec type: all four mode components are zero.
    bytes32 public constant MODE_SINGLE = bytes32(0);
    /// @notice ERC-7579 batch, default exec type (AGW `ModeLib.encodeSimpleBatch()`): the mode `openJob` signs.
    bytes32 public constant MODE_BATCH = bytes32(bytes1(0x01));

    uint32 internal constant MIN_DURATION = 1 hours;

    // ───────── storage: append-only ─────────

    IAGWFactory public AGW_FACTORY;
    IAgenticCommerce public KERNEL;
    address public hook;
    /// @notice The 8183 evaluator of every job opened here.
    address public evaluator;
    /// @notice keccak256("eip155:" ‖ decimal(block.chainid)): Push itself, which no card may name.
    bytes32 public PUSH_CHAIN_HASH;
    IUniversalMarketplaceRules public RULES;
    uint256 public agentCardCount;
    mapping(uint256 => AgentCard) internal _cards;
    mapping(uint256 => bytes) internal _agentCardRules;
    mapping(uint256 => bytes) internal _jobSpecTemplates;
    /// @notice 1 at registration, +1 per update. Bound into the job's criteria (`origin`).
    mapping(uint256 => uint256) public agentCardVersion;
    /// @notice Verified by the admin at the CURRENT version. Cleared by every update.
    mapping(uint256 => bool) public isAgentCardVerified;
    /// @notice Disabled by the admin. Permanent: the provider cannot reactivate the card.
    mapping(uint256 => bool) public isAgentCardDisabled;
    mapping(bytes32 => CEADeployment) public ceaDeployment;
    /// @dev AGW → the last job opened here for it. Read through `activeJobOf`.
    mapping(address => uint256) internal _lastJobOf;
    mapping(uint256 => uint256) public cardOfJob;
    mapping(uint256 => address) public agwOfJob;
    mapping(uint256 => bytes32[]) internal _rulesOfJob;
    /// @notice Provider → their card id; 0 for none. Never cleared, so a disabled provider cannot register again.
    mapping(address => uint256) public agentCardOf;
    mapping(uint256 => uint256) public cardVersionOfJob;
    mapping(address => uint256) internal _agentRating;
    /// @notice The live cap on rules per card, 1..MAX_RULES. Applies at register and update.
    uint8 public maxRulesPerCard;
    /// @dev Card → each rule's `keccak256(chainNamespace)`, in rule order. Written at register and update.
    mapping(uint256 => bytes32[]) internal _cardChainHashes;
    uint256[27] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the proxy.
    /// @param p The addresses; every one non-zero, and `p.hook` whitelisted on the kernel.
    function initialize(InitParams calldata p) external initializer {
        if (p.agwFactory == address(0) || p.kernel == address(0) || p.rules == address(0) || p.admin == address(0)) {
            revert UniversalMarketplaceErrors.ZeroAddress();
        }
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        AGW_FACTORY = IAGWFactory(p.agwFactory);
        KERNEL = IAgenticCommerce(p.kernel);
        RULES = IUniversalMarketplaceRules(p.rules);
        PUSH_CHAIN_HASH = keccak256(abi.encodePacked("eip155:", Strings.toString(block.chainid)));
        _setHook(p.hook);
        _setEvaluator(p.evaluator);
        _setMaxRulesPerCard(1);
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
    /// @dev Not checked against providers: `openJob` refuses a card whose provider is the evaluator.
    function setEvaluator(address evaluator_) external onlyRole(ADMIN_ROLE) {
        _setEvaluator(evaluator_);
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev - The derived CEA is the `MARKER_WALLET` value and expected CEA of every rules grant on `chainHash`, and
    ///        the CEA the job's criteria read. The SDK derives it from the destination CEAFactory; `openJob` refuses
    ///        a mismatch.
    ///      - Both zero clears the chain: registration, update, `computeCEA` and `openJob` then revert
    ///        `ChainNotSupported`. Exactly one zero reverts `ZeroAddress`.
    ///      - Rotation runbook: `pause()` → rotate on the destination → this → `unpause()`.
    function setCEADeployment(bytes32 chainHash, address ceaFactory, address ceaProxyImpl)
        external
        onlyRole(ADMIN_ROLE)
    {
        if (ceaFactory == address(0) && ceaProxyImpl == address(0)) {
            delete ceaDeployment[chainHash];
        } else if (ceaFactory == address(0) || ceaProxyImpl == address(0)) {
            revert UniversalMarketplaceErrors.ZeroAddress();
        } else {
            ceaDeployment[chainHash] = CEADeployment({ceaFactory: ceaFactory, ceaProxyImpl: ceaProxyImpl});
        }
        emit CEADeploymentSet(chainHash, ceaFactory, ceaProxyImpl);
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev Raise only once the job hook binds every rules set of a job at `fund` (until then, 1). Cards already
    ///      registered keep their rules.
    function setMaxRulesPerCard(uint8 n) external onlyRole(ADMIN_ROLE) {
        _setMaxRulesPerCard(n);
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev Placeholder until VerifiedRatings is wired (page 2 M12).
    function setAgentRating(address agent, uint256 rating) external onlyRole(ADMIN_ROLE) {
        _agentRating[agent] = rating;
        emit AgentRatingSet(agent, rating);
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
    /// @dev The per-card kill switch. Permanent, so a compromised provider cannot switch it back on. Keeps
    ///      `agentCardOf[provider]`: one card per provider, so a disabled provider cannot register again.
    function disableAgentCard(uint256 cardId) external onlyRole(ADMIN_ROLE) {
        _requireCard(cardId);
        isAgentCardDisabled[cardId] = true;
        _cards[cardId].active = false;
        _clearVerified(cardId);
        emit AgentCardDisabled(cardId);
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev - A tag, not a gate: `openJob` treats verified and unverified cards alike.
    ///      - `cardVersion` is the one the admin reviewed: an update in between makes this revert.
    ///      - Refused for a disabled card; allowed for one its provider switched off.
    function verifyAgentCard(uint256 cardId, uint256 cardVersion) external onlyRole(ADMIN_ROLE) {
        _requireCard(cardId);
        if (isAgentCardDisabled[cardId]) revert UniversalMarketplaceErrors.AgentCardDisabled(cardId);
        uint256 current = agentCardVersion[cardId];
        if (cardVersion != current) revert UniversalMarketplaceErrors.AgentCardVersionMismatch(cardVersion, current);
        isAgentCardVerified[cardId] = true;
        emit AgentCardVerified(cardId, cardVersion);
    }

    /// @inheritdoc IUniversalMarketplace
    function revokeAgentCardVerification(uint256 cardId) external onlyRole(ADMIN_ROLE) {
        _requireCard(cardId);
        _clearVerified(cardId);
    }

    // ═════════════════════════════════ cards ═════════════════════════════════

    /// @inheritdoc IUniversalMarketplace
    function registerAgentCard(AgentCard calldata c, bytes calldata rules, bytes calldata jobSpecTemplate)
        external
        whenNotPaused
        returns (uint256 cardId)
    {
        if (agentCardOf[msg.sender] != 0) revert UniversalMarketplaceErrors.AgentCardAlreadyRegistered(msg.sender);
        bytes32[] memory chainHashes = _validateCard(c, rules);

        cardId = ++agentCardCount;
        _cards[cardId] = c;
        AgentCard storage stored = _cards[cardId];
        stored.provider = msg.sender;
        stored.active = true;
        _agentCardRules[cardId] = rules;
        _cardChainHashes[cardId] = chainHashes;
        _jobSpecTemplates[cardId] = jobSpecTemplate;
        agentCardVersion[cardId] = 1;
        agentCardOf[msg.sender] = cardId;

        emit AgentCardRegistered(
            cardId,
            msg.sender,
            c.jobType,
            keccak256(rules),
            keccak256(jobSpecTemplate),
            c.metadataHash,
            c.providerFee
        );
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev - Provider only; refused for a disabled card and while paused.
    ///      - The rules (and so the chains) may change; `provider` and `active` stay.
    ///      - The version is part of every job's criteria (`origin`), so an intent signed against the old
    ///        version fails `openJob`. Jobs already opened are untouched.
    function updateAgentCard(uint256 cardId, AgentCard calldata c, bytes calldata rules, bytes calldata jobSpecTemplate)
        external
        whenNotPaused
    {
        AgentCard storage stored = _cards[cardId];
        if (stored.provider == address(0) || msg.sender != stored.provider) {
            revert UniversalMarketplaceErrors.CallerIsNotProvider();
        }
        if (isAgentCardDisabled[cardId]) revert UniversalMarketplaceErrors.AgentCardDisabled(cardId);
        bytes32[] memory chainHashes = _validateCard(c, rules);

        stored.jobType = c.jobType;
        stored.metadataURI = c.metadataURI;
        stored.metadataHash = c.metadataHash;
        stored.providerFee = c.providerFee;
        stored.paymentToken = c.paymentToken;
        stored.minDuration = c.minDuration;
        stored.maxDuration = c.maxDuration;
        _agentCardRules[cardId] = rules;
        _cardChainHashes[cardId] = chainHashes;
        _jobSpecTemplates[cardId] = jobSpecTemplate;

        uint256 newVersion = ++agentCardVersion[cardId];
        _clearVerified(cardId);

        emit AgentCardUpdated(
            cardId, newVersion, keccak256(rules), keccak256(jobSpecTemplate), c.metadataHash, c.providerFee
        );
    }

    /// @inheritdoc IUniversalMarketplace
    function setAgentCardActive(uint256 cardId, bool active) external {
        AgentCard storage c = _cards[cardId];
        if (c.provider == address(0) || msg.sender != c.provider) {
            revert UniversalMarketplaceErrors.CallerIsNotProvider();
        }
        if (active && isAgentCardDisabled[cardId]) revert UniversalMarketplaceErrors.AgentCardDisabled(cardId);
        c.active = active;
        emit AgentCardStatusChanged(cardId, active);
    }

    /// @inheritdoc IUniversalMarketplace
    function getAgentCard(uint256 cardId) external view returns (AgentCardView memory v) {
        v.card = _cards[cardId];
        v.rules = _agentCardRules[cardId];
        v.jobSpecTemplate = _jobSpecTemplates[cardId];
        v.version = agentCardVersion[cardId];
        v.verified = isAgentCardVerified[cardId];
        v.disabled = isAgentCardDisabled[cardId];
    }

    // ═════════════════════════════════ openJob ═════════════════════════════════

    /// @inheritdoc IUniversalMarketplace
    /// @dev Normative order, every check before the first state change:
    ///      1-4 card, version, principal, expiry, evaluator · 5 wallet · 6 no active job · 7 build the batch ·
    ///      8 bind the intent · 9 rules = card · ── 10 deploy or check owner · 11 run the batch (grants, then
    ///      createJob), verify the job · 12 rules ids, each enabled · 13 record.
    ///      Binding before rules = card names a tampered input as unsigned (`IntentExecMismatch`), not as a rules
    ///      mismatch: every signed input is inside the batch.
    function openJob(OpenJobParams calldata p)
        external
        whenNotPaused
        nonReentrant
        returns (uint256 jobId, address agw, bytes32[] memory rulesIds)
    {
        AgentCard storage c = _cards[p.cardId];
        _checkCardAndJob(c, p);
        bool deployed;
        (agw, deployed) = _resolveWallet(p);
        uint256 active = activeJobOf(agw);
        if (active != 0) revert UniversalMarketplaceErrors.WalletHasActiveJob(agw, active);
        bytes memory execCalldata = _buildBatch(p.cardId, agw, p.job, p.sessions);
        _bindIntent(p.intent, execCalldata);
        _checkRules(c, p, agw);
        uint256 grantNonce = deployed ? IAGW(agw).grantNonce() : 0;

        _deployOrCheckOwner(p, agw, deployed);
        jobId = _createJob(c, agw, execCalldata, p.intent, p.sig);
        rulesIds = _grantedRulesIds(agw, p.sessions, grantNonce);

        _lastJobOf[agw] = jobId;
        cardOfJob[jobId] = p.cardId;
        agwOfJob[jobId] = agw;
        _rulesOfJob[jobId] = rulesIds;
        cardVersionOfJob[jobId] = p.cardVersion;
        emit JobOpened(p.cardId, p.intent.owner, agw, jobId, rulesIds, p.job.principal, p.cardVersion);
    }

    // ═════════════════════════════════ views ═════════════════════════════════

    /// @inheritdoc IUniversalMarketplace
    /// @dev Active while the last job opened here is Funded, Submitted, or Open and not yet expired.
    function activeJobOf(address agw) public view returns (uint256) {
        uint256 id = _lastJobOf[agw];
        if (id == 0) return 0;
        IAgenticCommerce.Job memory j = KERNEL.getJob(id);
        if (j.status == IAgenticCommerce.JobStatus.Funded || j.status == IAgenticCommerce.JobStatus.Submitted) {
            return id;
        }
        if (j.status == IAgenticCommerce.JobStatus.Open && block.timestamp < j.expiredAt) return id;
        return 0;
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev Mirrors `CEAFactory._computeCEAInternal`: an OZ minimal proxy of `ceaProxyImpl`, salt
    ///      `keccak256(abi.encode(pushAccount))`, deployer = the CEA factory. Stale after a destination
    ///      implementation rotation until `setCEADeployment`: pause first.
    function computeCEA(address agw, bytes32 chainHash) public view returns (address) {
        CEADeployment memory d = ceaDeployment[chainHash];
        if (d.ceaFactory == address(0)) revert UniversalMarketplaceErrors.ChainNotSupported(chainHash);
        return Clones.predictDeterministicAddress(d.ceaProxyImpl, keccak256(abi.encode(agw)), d.ceaFactory);
    }

    /// @inheritdoc IUniversalMarketplace
    function rulesOfJob(uint256 jobId) external view returns (bytes32[] memory) {
        return _rulesOfJob[jobId];
    }

    /// @inheritdoc IUniversalMarketplace
    function getAgentRating(address agent) external view returns (uint256) {
        return _agentRating[agent];
    }

    /// @inheritdoc IUniversalMarketplace
    function version() external pure returns (string memory) {
        return "2.1.0";
    }

    /// @inheritdoc IUniversalMarketplace
    function buildCreateJobCalldata(
        uint256 cardId,
        address owner,
        uint96 index,
        JobInputs calldata job,
        Session[] calldata sessions
    ) external view returns (bytes32 mode, bytes memory executionCalldata) {
        _requireCard(cardId);
        (address agw,) = AGW_FACTORY.predictWallet(owner, index);
        return (MODE_BATCH, _buildBatch(cardId, agw, job, sessions));
    }

    /// @inheritdoc IUniversalMarketplace
    /// @dev The SDK signs exactly what this returns. `sessionHash` is 0: the rules are granted inside the batch,
    ///      not through the grant door. Nonces are 0 for a wallet not yet deployed.
    function previewIntent(IntentRequest calldata r, Session[] calldata sessions)
        external
        view
        returns (OwnerIntent memory i)
    {
        _requireCard(r.cardId);
        (address wallet, bool deployed) = AGW_FACTORY.predictWallet(r.owner, r.index);
        i.owner = r.owner;
        i.wallet = wallet;
        i.executor = address(this);
        i.index = r.index;
        i.mode = MODE_BATCH;
        i.execCalldataHash = keccak256(_buildBatch(r.cardId, wallet, r.job, sessions));
        i.nonceKey = OPENJOB_LANE;
        i.nonceSeq = deployed ? IAGW(wallet).getNonce(OPENJOB_LANE) : 0;
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

    function _setMaxRulesPerCard(uint8 n) internal {
        if (n == 0 || n > MAX_RULES) revert UniversalMarketplaceErrors.InvalidMaxRules(n);
        maxRulesPerCard = n;
        emit MaxRulesPerCardUpdated(n);
    }

    /// @dev `AgentCardInactive` for a card that was never registered.
    function _requireCard(uint256 cardId) internal view {
        if (_cards[cardId].provider == address(0)) revert UniversalMarketplaceErrors.AgentCardInactive();
    }

    /// @dev Clears the verified tag, emitting only when there was one to clear.
    function _clearVerified(uint256 cardId) internal {
        if (!isAgentCardVerified[cardId]) return;
        isAgentCardVerified[cardId] = false;
        emit AgentCardVerificationRevoked(cardId);
    }

    /// @dev Registration and update checks, in order. The caller is the provider. The `jobSpecTemplate` is stored
    ///      as given. Returns each rule's chain hash, in rule order.
    function _validateCard(AgentCard calldata c, bytes calldata rules) internal view returns (bytes32[] memory) {
        if (c.jobType == bytes32(0)) revert UniversalMarketplaceErrors.InvalidAgentCard("job type zero");
        if (bytes(c.metadataURI).length == 0) revert UniversalMarketplaceErrors.InvalidAgentCard("metadata uri empty");
        if (c.metadataHash == bytes32(0)) revert UniversalMarketplaceErrors.InvalidAgentCard("metadata hash zero");
        // Until the kernel's K-12, every job is paid in the kernel's token; a card may not advertise another.
        if (c.paymentToken != address(KERNEL.paymentToken())) {
            revert UniversalMarketplaceErrors.InvalidAgentCard("payment token");
        }
        if (msg.sender == evaluator) revert UniversalMarketplaceErrors.InvalidAgentCard("provider is evaluator");
        if (c.minDuration < MIN_DURATION || c.minDuration > c.maxDuration) {
            revert UniversalMarketplaceErrors.InvalidAgentCard("duration range");
        }
        (bytes32[] memory chainHashes, address[] memory tokens, bytes32[] memory tokenChains) =
            RULES.validateAgentCardRules(rules, maxRulesPerCard);
        for (uint256 i; i < chainHashes.length; ++i) {
            bytes32 h = chainHashes[i];
            if (h == PUSH_CHAIN_HASH || ceaDeployment[h].ceaFactory == address(0)) {
                revert UniversalMarketplaceErrors.ChainNotSupported(h);
            }
        }
        for (uint256 k; k < tokens.length; ++k) {
            _requireAssetOnChain(tokens[k], tokenChains[k]);
        }
        return chainHashes;
    }

    /// @dev The asset is a PRC20 of its rule's chain. A raw staticcall, not try/catch: a non-string answer must
    ///      fail as "asset", and a try clause cannot catch its own return-data decoding. A codeless asset answers
    ///      empty, so it fails the length check.
    function _requireAssetOnChain(address asset, bytes32 chainHash) internal view {
        (bool ok, bytes memory ret) = asset.staticcall(abi.encodeCall(IPRC20.SOURCE_CHAIN_NAMESPACE, ()));
        if (!ok || ret.length < 64) revert UniversalMarketplaceErrors.InvalidAgentCard("asset");
        (uint256 offset, uint256 len) = abi.decode(ret, (uint256, uint256));
        if (offset != 32 || len > ret.length - 64) revert UniversalMarketplaceErrors.InvalidAgentCard("asset");
        if (keccak256(abi.decode(ret, (bytes))) != chainHash) {
            revert UniversalMarketplaceErrors.InvalidAgentCard("asset chain");
        }
    }

    // ═════════════════════════════════ internal: openJob ═════════════════════════════════

    /// @dev Steps 1-4: active card at the signed version, a non-zero principal, the expiry inside the card's
    ///      duration bounds, and a provider that is not the evaluator.
    function _checkCardAndJob(AgentCard storage c, OpenJobParams calldata p) internal view {
        if (!c.active) revert UniversalMarketplaceErrors.AgentCardInactive();
        uint256 current = agentCardVersion[p.cardId];
        if (p.cardVersion != current) {
            revert UniversalMarketplaceErrors.AgentCardVersionMismatch(p.cardVersion, current);
        }
        if (p.job.principal == 0) revert UniversalMarketplaceErrors.ZeroPrincipal();
        uint256 expiredAt = p.job.expiredAt;
        if (expiredAt < block.timestamp + c.minDuration || expiredAt > block.timestamp + c.maxDuration) {
            revert UniversalMarketplaceErrors.ExpiryOutOfRange();
        }
        if (c.provider == evaluator) revert UniversalMarketplaceErrors.ProviderIsEvaluator();
    }

    /// @dev Step 5: the intent names the wallet derived from its owner and index, and this executor.
    function _resolveWallet(OpenJobParams calldata p) internal view returns (address agw, bool deployed) {
        (agw, deployed) = AGW_FACTORY.predictWallet(p.intent.owner, p.intent.index);
        if (p.intent.wallet != agw) revert UniversalMarketplaceErrors.IntentWalletMismatch(agw, p.intent.wallet);
        if (p.intent.executor != address(this)) {
            revert UniversalMarketplaceErrors.ExecutorMismatch(p.intent.executor, address(this));
        }
    }

    /// @dev Step 9: each signed session is its card rule with the markers filled for this job, for the card's
    ///      agent, bound to this job and to the AGW's CEA on that rule's chain.
    function _checkRules(AgentCard storage c, OpenJobParams calldata p, address agw) internal view {
        bytes32[] storage chains = _cardChainHashes[p.cardId];
        address[] memory ceas = new address[](chains.length);
        for (uint256 i; i < ceas.length; ++i) {
            ceas[i] = computeCEA(agw, chains[i]);
        }
        RULES.checkRulesMatchCard(
            _agentCardRules[p.cardId],
            p.sessions,
            SessionContext({agent: c.provider, principal: p.job.principal, expiredAt: p.job.expiredAt, expectedCEAs: ceas})
        );
    }

    /// @dev Step 7: the ERC-7579 batch the AGW runs: `grantRules(sessions[i])` on itself for every rule, then
    ///      `createJob` on the kernel with the criteria built from the card's template. Everything the owner signs
    ///      per job (sessions, principal, expiry, params, card version and the wallet, through its CEA) is in this
    ///      calldata, so the intent's calldata hash binds all of it.
    function _buildBatch(uint256 cardId, address agw, JobInputs calldata job, Session[] calldata sessions)
        internal
        view
        returns (bytes memory)
    {
        AgentCard storage c = _cards[cardId];
        bytes memory description = JobSpecBuilder.build(
            _jobSpecTemplates[cardId],
            BuildContext({
                agw: agw,
                principal: job.principal,
                params: job.params,
                origin: keccak256(abi.encode(address(this), cardId, agentCardVersion[cardId], job.principal))
            })
        );
        uint256 n = sessions.length;
        Execution[] memory execs = new Execution[](n + 1);
        for (uint256 i; i < n; ++i) {
            execs[i] = Execution({target: agw, value: 0, callData: abi.encodeCall(IAGW.grantRules, (sessions[i]))});
        }
        execs[n] = Execution({
            target: address(KERNEL),
            value: 0,
            callData: abi.encodeCall(
                IAgenticCommerce.createJob, (c.provider, evaluator, uint256(job.expiredAt), string(description), hook)
            )
        });
        return abi.encode(execs);
    }

    /// @dev Step 8: the intent's exec fields name exactly this batch, on the openJob lane, and it asks for no grant
    ///      through the grant door. The wallet re-checks the exec fields; this names the error before state moves.
    function _bindIntent(OwnerIntent calldata intent, bytes memory execCalldata) internal pure {
        bytes32 cdHash = keccak256(execCalldata);
        if (intent.mode != MODE_BATCH || intent.execCalldataHash != cdHash || intent.nonceKey != OPENJOB_LANE) {
            revert UniversalMarketplaceErrors.IntentExecMismatch(cdHash);
        }
        if (intent.sessionHash != bytes32(0)) revert UniversalMarketplaceErrors.IntentSessionMismatch(bytes32(0));
    }

    /// @dev Step 10: deploy the predicted wallet, or check the factory's owner of the existing one.
    function _deployOrCheckOwner(OpenJobParams calldata p, address agw, bool deployed) internal {
        if (!deployed) {
            address d = AGW_FACTORY.deployWalletWithSig(p.intent, p.sig, p.label);
            if (d != agw) revert UniversalMarketplaceErrors.AGWMismatch(agw, d);
            return;
        }
        address owner = AGW_FACTORY.ownerOf(agw);
        if (owner != p.intent.owner) revert UniversalMarketplaceErrors.WalletOwnerMismatch(p.intent.owner, owner);
    }

    /// @dev Step 11: the AGW runs the batch (grants, then `createJob`); exactly one job appeared, with this AGW as
    ///      client and the card's provider, this hook and this evaluator.
    function _createJob(
        AgentCard storage c,
        address agw,
        bytes memory execCalldata,
        OwnerIntent calldata intent,
        bytes calldata sig
    ) internal returns (uint256 jobId) {
        uint256 before = KERNEL.jobCounter();
        IAGW(agw).executeWithSig(MODE_BATCH, execCalldata, intent, sig);
        jobId = KERNEL.jobCounter();
        if (jobId != before + 1) revert UniversalMarketplaceErrors.UnexpectedJobCount(before, jobId);
        IAgenticCommerce.Job memory j = KERNEL.getJob(jobId);
        if (j.client != agw || j.provider != c.provider || j.hook != hook || j.evaluator != evaluator) {
            revert UniversalMarketplaceErrors.JobMismatch();
        }
    }

    /// @dev Step 12: the rules ids the batch granted, each enabled on the wallet's engine. The AGW overwrites a
    ///      session's salt with its grant nonce before enabling it (v6 `_grantRules`), and the engine's id is
    ///      `keccak256(abi.encode(validator, validatorInitData, salt))` (SmartSession `IdLib.toPermissionId`), so
    ///      grant `i` of this batch has salt `grantNonce + i`.
    function _grantedRulesIds(address agw, Session[] calldata sessions, uint256 grantNonce)
        internal
        view
        returns (bytes32[] memory ids)
    {
        ISmartSession engine = ISmartSession(IAGW(agw).SESSION_ENGINE());
        ids = new bytes32[](sessions.length);
        for (uint256 i; i < ids.length; ++i) {
            ids[i] = keccak256(
                abi.encode(
                    sessions[i].sessionValidator, sessions[i].sessionValidatorInitData, bytes32(grantNonce + i)
                )
            );
            if (!engine.isPermissionEnabled(ids[i], agw)) revert UniversalMarketplaceErrors.RulesNotGranted(i);
        }
    }
}
