// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {
    OwnerIntent,
    UniversalTerms,
    OWNER_INTENT_TYPEHASH,
    OWNER_INTENT_DOMAIN_TYPEHASH,
    OWNER_INTENT_DOMAIN_NAME_HASH,
    OWNER_INTENT_DOMAIN_VERSION_HASH,
    SEND_OUTBOUND_SELECTOR
} from "@push-agw/libraries/Types.sol";
import {TemplateParts} from "./helpers/TemplateParts.sol";
import {RulesFixtures, SessionSkeleton} from "./helpers/RulesFixtures.sol";
import {MockERC20_6} from "./mocks/MockERC20_6.sol";
import {AgenticCommerce} from "../../src/agentic-commerce-8183/AgenticCommerce.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {RulesBindingHook} from "../../src/agentic-commerce-8183/hooks/RulesBindingHook.sol";
import {UniversalMarketplace} from "../../src/agentic-commerce-8183/UniversalMarketplace.sol";
import {UniversalMarketplaceRules} from "../../src/agentic-commerce-8183/UniversalMarketplaceRules.sol";
import {UniversalMarketplaceErrors} from "../../src/agentic-commerce-8183/libraries/Errors.sol";
import {IAGWFactory} from "../../src/agentic-commerce-8183/interfaces/external/IAGWFactory.sol";
import {ISmartSession} from "../../src/agentic-commerce-8183/interfaces/external/ISmartSession.sol";
import {Session} from "../../src/agentic-commerce-8183/interfaces/external/IAGW.sol";
import {
    Evaluation,
    Operation,
    LogicKind,
    AllowedMutability,
    JobSpec
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {
    AgentCard,
    CardRule,
    JobInputs,
    OpenJobParams,
    IntentRequest,
    InitParams,
    ReadTemplate,
    TargetSource,
    CheckTemplate,
    ParamBounds,
    JobSpecTemplate,
    MAX_RULES
} from "../../src/agentic-commerce-8183/libraries/Types.sol";

/// @notice The wallet's owner door (AGW `execute` is `onlyOwner`; the owner here is an EOA).
interface IAGWExecute {
    function execute(bytes32 mode, bytes calldata executionCalldata) external payable;
}

/// @title UniversalMarketplace — fork suite against the REAL AGW v6 on Donut (PRD 12 §6.9, sdk_iterations_v2).
/// @notice Proves, against the deployed factory, wallet, URP, engine and AgentValidator: a TWO-RULE card (Sepolia +
///         Base) granted and its job created on ONE owner signature (an owner-door batch whose self-calls grant
///         each rule), the rules ids the marketplace derives (salt = the wallet's grant nonce), the versioned
///         envelope, multi-asset caps, pins with filled markers per chain, the `Session` mirror (inside the signed
///         batch) and the imported `OwnerIntent` (via the owner's signature).
/// @dev - Skips unless PUSH_CHAIN_TESTNET_RPC_URL is set (forge also reads `.env`). Forks the latest block, logged.
///      - The marketplace, its rules helper, a kernel and the hook are deployed on the fork; the AGW stack is live.
contract UniversalMarketplaceForkTest is Test, TemplateParts, RulesFixtures {
    address internal constant FACTORY = 0xFBBEB6a365178fAaA81A9789a5f64b300c37e5bc;
    address internal constant ENGINE = 0xf63DC0628fe1B25049FE3E3a3585Ef051CB98c1d;
    address internal constant URP = 0xBA32e7A1500cb34311a31127bcD40CA52C8CFd36;
    address internal constant AGENT_VALIDATOR = 0xBf08d8335c1cE41a577DB70666816027814737dD;
    address internal constant GATEWAY_PC = 0x00000000000000000000000000000000000000C1;
    address internal constant USDC_ETH = 0x7A58048036206bB898008b5bBDA85697DB1e5d66; // PRC20 USDC.eth (Sepolia)
    address internal constant PETH = 0x2971824Db68229D087931155C2b8bB820B275809; // PRC20 pETH (Sepolia)
    address internal constant PETH_BASE = 0xc7007af2B24D4eb963fc9633B0c66e1d2D90Fc21; // PRC20 pETH (Base Sepolia)

    string internal constant SEPOLIA_ID = "11155111";
    uint256 internal constant PRINCIPAL = 500e6;
    uint256 internal constant BUDGET = 5e6;

    MockERC20_6 internal token;
    AgenticCommerce internal kernel;
    RulesBindingHook internal hook;
    UniversalMarketplace internal mkt;

    address internal admin = makeAddr("forkAdmin");
    address internal provider = makeAddr("forkProvider");
    address internal evaluator = makeAddr("evaluator");
    address internal relayer = makeAddr("forkRelayer");
    address internal owner;
    uint256 internal ownerKey;

    // made-up, non-zero Sepolia addresses: the destination calls are never executed here
    address internal usdcSepolia = makeAddr("USDC.sepolia");
    address internal pool = makeAddr("aavePool.sepolia");
    address internal aUSDC = makeAddr("aUSDC.sepolia");
    address internal poolBase = makeAddr("aavePool.base");

    function _deploy() internal {
        (owner, ownerKey) = makeAddrAndKey("forkOwner");
        token = new MockERC20_6("Push USDC", "pUSDC");
        kernel = AgenticCommerce(
            address(
                new TransparentUpgradeableProxy(
                    address(new AgenticCommerce()),
                    makeAddr("kernelProxyAdminOwner"),
                    abi.encodeCall(AgenticCommerce.initialize, (address(token), makeAddr("treasury"), admin))
                )
            )
        );
        hook = RulesBindingHook(
            address(
                new TransparentUpgradeableProxy(
                    address(new RulesBindingHook()),
                    makeAddr("hookAdmin"),
                    abi.encodeCall(RulesBindingHook.initialize, (address(kernel), FACTORY, ENGINE))
                )
            )
        );
        vm.prank(admin);
        kernel.setHookWhitelist(address(hook), true);

        InitParams memory ip = InitParams({
            agwFactory: FACTORY,
            kernel: address(kernel),
            hook: address(hook),
            evaluator: evaluator,
            rules: address(new UniversalMarketplaceRules()),
            admin: admin
        });
        mkt = UniversalMarketplace(
            address(
                new TransparentUpgradeableProxy(
                    address(new UniversalMarketplace()),
                    makeAddr("mktAdmin"),
                    abi.encodeCall(UniversalMarketplace.initialize, (ip))
                )
            )
        );
        vm.startPrank(admin);
        mkt.setCEADeployment(SEPOLIA_HASH, makeAddr("ceaFactory"), makeAddr("ceaProxyImpl"));
        mkt.setCEADeployment(BASE_HASH, makeAddr("ceaFactory.base"), makeAddr("ceaProxyImpl.base"));
        mkt.setMaxRulesPerCard(MAX_RULES);
        vm.stopPrank();
    }

    function _card() internal view returns (AgentCard memory c) {
        c.jobType = keccak256("LENDING_DEPOSIT");
        c.metadataURI = "ipfs://card";
        c.metadataHash = keccak256("card.json");
        c.providerFee = BUDGET;
        c.paymentToken = address(token);
        c.minDuration = 3 hours;
        c.maxDuration = 30 days;
    }

    /// @dev Sepolia (the principal, USDC.eth, plus pETH) and Base (pETH.base, literal caps).
    function _rules() internal view returns (CardRule[] memory) {
        return _rulesOf(_cardRulesTwoAssets(USDC_ETH, usdcSepolia, pool, PETH), _sideRule(BASE, PETH_BASE, poolBase));
    }

    function _lendingTemplate() internal view returns (JobSpecTemplate memory t) {
        t.reads = new ReadTemplate[](2);
        t.reads[0] = _balanceOfCEA(SEPOLIA_ID, aUSDC);
        t.reads[1] = _read(
            SEPOLIA_ID, pool, GET_RESERVE_DATA, abi.encode(usdcSepolia), _noFills(), _reserveDataOut(), _f2(0, 2)
        );
        t.checks = new CheckTemplate[](2);
        t.checks[0] = _chk(0, Evaluation.COMPARE, Operation.GREATER_OR_EQUAL, TargetSource.PRINCIPAL_BPS, 9999);
        t.checks[1] = _chk(1, Evaluation.COMPARE, Operation.GREATER_OR_EQUAL, TargetSource.FIXED, 0.04e27);
        t.logic = _rootOf(LogicKind.ALL, _kids(0, 1));
        t.params = new ParamBounds[](0);
    }

    /// @dev The real v6 values: the wallet refuses anything else (`MalformedSessionShape` / `RulesTypeMismatch`).
    function _skeletonV6() internal pure returns (SessionSkeleton memory) {
        return SessionSkeleton({
            validator: AGENT_VALIDATOR, actionTarget: GATEWAY_PC, actionSelector: SEND_OUTBOUND_SELECTOR, policy: URP
        });
    }

    function _inputs() internal view returns (JobInputs memory j) {
        j.principal = PRINCIPAL;
        j.expiredAt = uint48(block.timestamp + 7 days);
        j.params = new int256[](0);
    }

    /// @dev One session per card rule, each with its own chain's CEA, as the SDK builds them.
    function _sessionsFor(address agw, JobInputs memory job) internal view returns (Session[] memory ss) {
        CardRule[] memory rs = _rules();
        ss = new Session[](rs.length);
        for (uint256 i; i < rs.length; ++i) {
            address cea = mkt.computeCEA(agw, keccak256(bytes(rs[i].chainNamespace)));
            UniversalTerms memory t = _fillTerms(rs[i], job.principal, job.expiredAt, cea);
            ss[i] = _wrapSession(_envelope(t, rs[i].chainNamespace), provider, _skeletonV6());
        }
    }

    /// @dev The id the AGW gives grant number `nonce` of `s` (it overwrites the salt with its grant nonce).
    function _rulesIdOf(Session memory s, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(s.sessionValidator, s.sessionValidatorInitData, bytes32(nonce)));
    }

    function _sign(OwnerIntent memory intent) internal view returns (bytes memory) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                OWNER_INTENT_DOMAIN_TYPEHASH,
                OWNER_INTENT_DOMAIN_NAME_HASH,
                OWNER_INTENT_DOMAIN_VERSION_HASH,
                intent.signerChainId,
                FACTORY,
                bytes32(block.chainid)
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, keccak256(abi.encode(OWNER_INTENT_TYPEHASH, intent)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev An owner-signed openJob for wallet `index`, built the way the SDK does: session, previewIntent, sign.
    function _signed(uint256 cardId, uint96 index, Session[] memory s, JobInputs memory job)
        internal
        view
        returns (OpenJobParams memory p)
    {
        p.cardId = cardId;
        p.cardVersion = mkt.agentCardVersion(cardId);
        p.job = job;
        p.sessions = s;
        p.intent = mkt.previewIntent(
            IntentRequest({
                cardId: cardId,
                owner: owner,
                index: index,
                job: job,
                deadline: uint48(block.timestamp + 1 hours),
                signerChainId: block.chainid
            }),
            s
        );
        p.sig = _sign(p.intent);
        p.label = "fork";
    }

    function _ownerExecute(address agw, address target, bytes memory data) internal {
        vm.prank(owner);
        IAGWExecute(agw).execute(bytes32(0), abi.encodePacked(target, uint256(0), data));
    }

    function test_fork_openJob_realAGWv6() public {
        string memory url = vm.envOr("PUSH_CHAIN_TESTNET_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        emit log_named_uint("fork block", block.number);
        _deploy();

        bytes memory rules = abi.encode(_rules());
        bytes memory template = abi.encode(_lendingTemplate());
        AgentCard memory card = _card();
        vm.prank(provider);
        uint256 cardId = mkt.registerAgentCard(card, rules, template);

        // ── 1. openJob on a fresh wallet: two rules, one signature ──
        uint96 index = uint96(IAGWFactory(FACTORY).walletCount(owner));
        (address agw, bool deployed) = IAGWFactory(FACTORY).predictWallet(owner, index);
        assertFalse(deployed);
        JobInputs memory job = _inputs();
        OpenJobParams memory p = _signed(cardId, index, _sessionsFor(agw, job), job);
        assertEq(p.intent.sessionHash, bytes32(0), "no grant-door session");
        vm.prank(relayer);
        (uint256 jobId, address opened, bytes32[] memory rulesIds) = mkt.openJob(p);

        assertEq(opened, agw);
        assertTrue(IAGWFactory(FACTORY).isWallet(agw), "deployed by the real factory");
        assertEq(rulesIds.length, 2);
        for (uint256 i; i < 2; ++i) {
            assertEq(rulesIds[i], _rulesIdOf(p.sessions[i], i), "salt = the wallet's grant nonce");
            assertTrue(ISmartSession(ENGINE).isPermissionEnabled(rulesIds[i], agw), "rules live in the real engine");
        }
        IAgenticCommerce.Job memory j = kernel.getJob(jobId);
        assertEq(j.client, agw);
        assertEq(j.provider, provider);
        assertEq(j.hook, address(hook));
        assertEq(j.evaluator, evaluator);
        JobSpec memory spec = abi.decode(bytes(j.description), (JobSpec));
        assertEq(abi.encode(spec), bytes(j.description), "the evaluator's JobSpec, nothing more (no timing)");
        assertEq(abi.encode(spec.logic), abi.encode(_lendingTemplate().logic), "lending logic");
        assertEq(uint8(spec.allowedMutability), uint8(AllowedMutability.NONE));
        assertEq(spec.origin, keccak256(abi.encode(address(mkt), cardId, uint256(1), PRINCIPAL)), "origin");

        // ── 2. fund through the hook, from the owner's own door, binding the first rules set ──
        vm.prank(provider);
        kernel.setBudget(jobId, BUDGET, "");
        token.mint(agw, BUDGET);
        _ownerExecute(agw, address(token), abi.encodeCall(IERC20.approve, (address(kernel), BUDGET)));
        _ownerExecute(
            agw, address(kernel), abi.encodeCall(IAgenticCommerce.fund, (jobId, BUDGET, abi.encode(rulesIds[0])))
        );
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Funded));
        assertEq(hook.rulesOfJob(jobId), rulesIds[0]);
        assertEq(hook.agwOfJob(jobId), agw);

        // ── 3. a second openJob while Funded ──
        JobInputs memory job2 = _inputs();
        OpenJobParams memory busy = _signed(cardId, index, _sessionsFor(agw, job2), job2);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.WalletHasActiveJob.selector, agw, jobId));
        mkt.openJob(busy);

        // ── 4. the existing-wallet path, once the job is Rejected ──
        vm.prank(evaluator);
        kernel.reject(jobId, bytes32(0), "");
        assertEq(mkt.activeJobOf(agw), 0);
        OpenJobParams memory again = _signed(cardId, index, _sessionsFor(agw, job2), job2);
        assertEq(again.intent.grantNonce, 2, "the live grant nonce: two grants so far");
        assertEq(again.intent.nonceSeq, 1, "the live lane");
        vm.prank(relayer);
        (uint256 jobId2, address same, bytes32[] memory rulesIds2) = mkt.openJob(again);
        assertEq(same, agw);
        assertEq(jobId2, jobId + 1);
        for (uint256 i; i < 2; ++i) {
            assertEq(rulesIds2[i], _rulesIdOf(again.sessions[i], 2 + i));
            assertTrue(ISmartSession(ENGINE).isPermissionEnabled(rulesIds2[i], agw));
            assertTrue(rulesIds2[i] != rulesIds[i], "a new rules set");
        }

        // ── 5. a pre-v6 envelope is named by the marketplace; the AGW is never called ──
        uint96 fresh = uint96(IAGWFactory(FACTORY).walletCount(owner));
        (address agw2,) = IAGWFactory(FACTORY).predictWallet(owner, fresh);
        Session[] memory ss = _sessionsFor(agw2, job2);
        UniversalTerms memory t = _fillTerms(_rules()[0], PRINCIPAL, job2.expiredAt, mkt.computeCEA(agw2, SEPOLIA_HASH));
        ss[0] = _wrapSession(abi.encode(SEPOLIA, abi.encode(t)), provider, _skeletonV6());
        OpenJobParams memory old = _signed(cardId, fresh, ss, job2);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.EnvelopeVersionMismatch.selector, 0, 64));
        mkt.openJob(old);
        assertFalse(IAGWFactory(FACTORY).isWallet(agw2), "nothing deployed");
    }
}
