// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {
    TransparentUpgradeableProxy,
    ITransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {KernelBase} from "./KernelBase.t.sol";
import {TemplateParts} from "./helpers/TemplateParts.sol";
import {MockAGWFactory} from "./mocks/MockAGWFactory.sol";
import {MockAGW} from "./mocks/MockAGW.sol";
import {MockSmartSession} from "./mocks/MockSmartSession.sol";
import {MockPRC20Source} from "./mocks/MockPRC20Source.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {MandateBindingHook} from "../../src/agentic-commerce-8183/hooks/MandateBindingHook.sol";
import {UniversalMarketplace} from "../../src/agentic-commerce-8183/UniversalMarketplace.sol";
import {UniversalMarketplaceTerms} from "../../src/agentic-commerce-8183/UniversalMarketplaceTerms.sol";
import {
    IUniversalMarketplace,
    IUniversalMarketplaceErrors
} from "../../src/agentic-commerce-8183/interfaces/IUniversalMarketplace.sol";
import {
    JobSpecBuilder,
    ReadTemplate,
    TargetSource,
    CheckTemplate,
    ParamBounds,
    EvaluationTemplate,
    BuildContext
} from "../../src/agentic-commerce-8183/libraries/JobSpecBuilder.sol";
import {EvalType, Op, NodeKind, Node, JobSpec} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {
    OwnerIntent,
    OWNER_LANE_FLAG,
    Session,
    ActionData,
    PolicyData,
    ERC7739Data,
    ERC7739Context,
    AllowedCall,
    UniversalTerms
} from "../../src/agentic-commerce-8183/interfaces/external/IAGW.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";

/// @notice TEST ONLY: runs JobSpecBuilder as the marketplace does, with CEAs from the real marketplace, so a test can
///         compute the description a job must carry.
contract MarketJobSpecBuilder {
    IUniversalMarketplace internal immutable MARKET;

    constructor(IUniversalMarketplace market) {
        MARKET = market;
    }

    function build(bytes memory evaluation, BuildContext memory ctx) external view returns (bytes memory) {
        return JobSpecBuilder.build(evaluation, ctx);
    }

    function expectedCEAOf(address agw, bytes32 chainHash) external view returns (address) {
        return MARKET.expectedCEAOf(agw, chainHash);
    }
}

/// @title MarketplaceFixtures — shared setup and builders for the marketplace unit and invariant suites.
/// @notice Real kernel, real MandateBindingHook (the interim hook, PRD 09 P8), real Terms helper and JobSpecBuilder
///         library, real CEAFactory. The AGW factory and wallet are mocks that enforce the rules the marketplace relies
///         on and verify no signature; the AGW repo's E2E suite runs the real wallet stack.
abstract contract MarketplaceFixtures is KernelBase, TemplateParts {
    UniversalMarketplace internal mkt;
    UniversalMarketplaceTerms internal terms;
    MarketJobSpecBuilder internal expectedBuilder;
    MandateBindingHook internal hook;
    MockAGWFactory internal factory;
    MockSmartSession internal engine;
    CEAFactory internal ceaFactory;
    MockPRC20Source internal pUSDC; // the rules asset: pUSDC.sepolia, 6 decimals
    MockPRC20Source internal pETH; // a second rules asset, 18 decimals: asset independence

    address internal user = makeAddr("userUEA");
    address internal relayer = makeAddr("relayer");
    address internal mktAdmin = makeAddr("mktAdmin");
    address internal universalEvaluator = makeAddr("universalEvaluator");
    address internal ceaProxyImpl = makeAddr("ceaProxyImpl");
    address internal pool = makeAddr("aavePool.sepolia");
    address internal aUSDC = makeAddr("aUSDC.sepolia");
    address internal usdc = makeAddr("USDC.sepolia");
    address internal weth = makeAddr("WETH.sepolia");
    address internal gateway = makeAddr("universalGatewayPC");
    address internal urp = makeAddr("urp");
    address internal validator = makeAddr("sessionValidator");

    string internal constant SEPOLIA = "eip155:11155111";
    string internal constant SEPOLIA_ID = "11155111";
    bytes32 internal constant SEPOLIA_HASH = keccak256("eip155:11155111");
    bytes4 internal constant SEND_OUTBOUND =
        bytes4(keccak256("sendUniversalTxOutbound((bytes,address,uint256,uint256,uint256,uint256,bytes,address))"));
    bytes4 internal constant SUPPLY = bytes4(keccak256("supply(address,uint256,address,uint16)"));
    bytes4 internal constant WITHDRAW = bytes4(keccak256("withdraw(address,uint256,address)"));
    bytes4 internal constant ERC20_APPROVE = 0x095ea7b3;

    uint256 internal constant PRINCIPAL = 500e6;
    uint256 internal constant FEE = 2e6;

    function setUp() public virtual override {
        super.setUp();
        factory = new MockAGWFactory();
        engine = new MockSmartSession();
        MandateBindingHook hookImpl = new MandateBindingHook();
        hook = MandateBindingHook(
            address(
                new TransparentUpgradeableProxy(
                    address(hookImpl),
                    makeAddr("hookAdmin"),
                    abi.encodeCall(MandateBindingHook.initialize, (address(kernel), address(factory), address(engine)))
                )
            )
        );
        vm.prank(admin);
        kernel.setHookWhitelist(address(hook), true);

        terms = new UniversalMarketplaceTerms();
        mkt = UniversalMarketplace(
            address(
                new TransparentUpgradeableProxy(
                    address(new UniversalMarketplace()),
                    mktAdmin,
                    abi.encodeCall(UniversalMarketplace.initialize, (_initParams()))
                )
            )
        );

        CEAFactory ceaImpl = new CEAFactory();
        ceaFactory = CEAFactory(
            address(
                new TransparentUpgradeableProxy(
                    address(ceaImpl),
                    makeAddr("ceaAdmin"),
                    abi.encodeCall(
                        CEAFactory.initialize,
                        (admin, admin, makeAddr("vault"), ceaProxyImpl, makeAddr("ceaImpl"), makeAddr("gateway"))
                    )
                )
            )
        );
        vm.prank(admin);
        mkt.setCEADeployment(SEPOLIA_HASH, address(ceaFactory), ceaProxyImpl);
        expectedBuilder = new MarketJobSpecBuilder(IUniversalMarketplace(address(mkt)));

        pUSDC = new MockPRC20Source("pUSDC.sepolia", SEPOLIA, 6);
        pETH = new MockPRC20Source("pETH.sepolia", SEPOLIA, 18);
        pUSDC.mint(user, 1e15);
        token.mint(user, 1e15);
        vm.deal(user, 100 ether);
    }

    function _initParams() internal view returns (IUniversalMarketplace.InitParams memory) {
        return IUniversalMarketplace.InitParams({
            agwFactory: address(factory),
            kernel: address(kernel),
            hook: address(hook),
            evaluator: universalEvaluator,
            terms: address(terms),
            admin: admin
        });
    }

    // ═════════════════════════════ cards ═════════════════════════════

    /// @dev The lending card of PRD 09 Appendix C, on Sepolia. `minDuration` is 3 h so that a job at the shortest
    ///      expiry still fits `minExecuteWindow + settleWindow` (10 min + 2 h).
    function _card() internal pure returns (IUniversalMarketplace.AgentCard memory c) {
        c.jobType = keccak256("LENDING_DEPOSIT");
        c.metadataURI = "ipfs://card";
        c.metadataHash = keccak256("card.json");
        c.chainNamespace = SEPOLIA;
        c.fee = FEE;
        c.principalMin = 100e6;
        c.principalMax = 1_000e6;
        c.minDuration = 3 hours;
        c.maxDuration = 30 days;
        c.minExecuteWindow = 10 minutes;
        c.settleWindow = 2 hours;
    }

    /// @dev One `supply` call with the beneficiary (onBehalfOf) at 68, one owner approval USDC → Pool for principal.
    function _rules() internal view returns (IUniversalMarketplace.RulesCardTerms memory r) {
        r.asset = address(pUSDC);
        r.maxPCPerCall = 1 ether;
        r.allowedCalls = new AllowedCall[](1);
        r.allowedCalls[0] =
            AllowedCall({target: pool, selector: SUPPLY, beneficiaryOffset: 68, hasBeneficiary: true, maxValue: 0});
        r.approvals = new IUniversalMarketplace.Approval[](1);
        r.approvals[0] = IUniversalMarketplace.Approval({token: usdc, spender: pool, capIsPrincipal: true, cap: 0});
    }

    /// @dev The V2 doc's lending criteria on Sepolia: aUSDC.balanceOf(CEA) ≥ 99.99% of principal AND rate ≥ 4%.
    function _lendingTemplate() internal view returns (EvaluationTemplate memory t) {
        t.reads = new ReadTemplate[](2);
        t.reads[0] = _balanceOfCEA(SEPOLIA_ID, aUSDC);
        t.reads[1] =
            _read(SEPOLIA_ID, pool, GET_RESERVE_DATA, abi.encode(usdc), _noFills(), _reserveDataOut(), _f2(0, 2));
        t.checks = new CheckTemplate[](2);
        t.checks[0] = _chk(0, EvalType.CMP, Op.GTE, TargetSource.PRINCIPAL_BPS, 9999);
        t.checks[1] = _chk(1, EvalType.CMP, Op.GTE, TargetSource.FIXED, 0.04e27);
        t.nodes = new Node[](3);
        t.nodes[0] = _parent(NodeKind.ALL, _kids(1, 2), 0);
        t.nodes[1] = _checkNode(0);
        t.nodes[2] = _checkNode(1);
        t.params = new ParamBounds[](0);
    }

    /// @dev The V2 doc's swap criteria on Sepolia: the CEA's WETH grows by at least `minOut`, the job's param 0.
    function _swapTemplate() internal view returns (EvaluationTemplate memory t) {
        t.reads = new ReadTemplate[](1);
        t.reads[0] = _balanceOfCEA(SEPOLIA_ID, weth);
        t.reads[0].minConfirmations = 3;
        t.checks = new CheckTemplate[](1);
        t.checks[0] = _chk(0, EvalType.NUM, Op.GTE, TargetSource.PARAM, 0);
        t.nodes = new Node[](1);
        t.nodes[0] = _checkNode(0);
        t.params = new ParamBounds[](1);
        t.params[0] = ParamBounds({min: 1, max: 1e30});
    }

    function _register(
        IUniversalMarketplace.AgentCard memory c,
        IUniversalMarketplace.RulesCardTerms memory r,
        EvaluationTemplate memory t
    ) internal returns (uint256 id) {
        bytes memory rules = abi.encode(r);
        bytes memory evaluation = abi.encode(t);
        vm.prank(provider);
        id = mkt.registerCard(c, rules, evaluation);
    }

    function _registerLending() internal returns (uint256) {
        return _register(_card(), _rules(), _lendingTemplate());
    }

    function _registerSwap() internal returns (uint256) {
        IUniversalMarketplace.AgentCard memory c = _card();
        c.jobType = keccak256("SWAP");
        return _register(c, _rules(), _swapTemplate());
    }

    // ═════════════════════════════ jobs ═════════════════════════════

    /// @dev Expires in 7 days; execute within 1 hour; no params.
    function _inputs(uint256 principal) internal view returns (IUniversalMarketplace.JobInputs memory j) {
        j.principal = principal;
        j.expiredAt = uint48(block.timestamp + 7 days);
        j.executeBy = uint48(block.timestamp + 1 hours);
        j.params = new int256[](0);
    }

    function _swapInputs(int256 minOut) internal view returns (IUniversalMarketplace.JobInputs memory j) {
        j = _inputs(PRINCIPAL);
        j.params = new int256[](1);
        j.params[0] = minOut;
    }

    /// @dev The UNIVERSAL rules an honest SDK signs for `r` and this job.
    function _termsFor(
        IUniversalMarketplace.RulesCardTerms memory r,
        address agw,
        IUniversalMarketplace.JobInputs memory job
    ) internal view returns (UniversalTerms memory t) {
        t.validUntil = job.expiredAt;
        t.expectedCEA = ceaFactory.computeCEA(agw);
        t.asset = r.asset;
        t.maxAmountPerCall = job.principal;
        t.maxAmountTotal = job.principal;
        t.maxPCPerCall = r.maxPCPerCall;
        t.allowedCalls = r.allowedCalls;
    }

    /// @dev A session for the card's agent (`abi.encode(provider)`, AGW D3) holding one gateway action.
    function _session(UniversalTerms memory t) internal view returns (Session memory s) {
        s.sessionValidator = validator;
        s.sessionValidatorInitData = abi.encode(provider);
        s.erc7739Policies =
            ERC7739Data({allowedERC7739Content: new ERC7739Context[](0), erc1271Policies: new PolicyData[](0)});
        s.actions = new ActionData[](1);
        s.actions[0] = _action(SEPOLIA, abi.encode(t));
    }

    function _action(string memory chain, bytes memory body) internal view returns (ActionData memory) {
        PolicyData[] memory p = new PolicyData[](1);
        p[0] = PolicyData({policy: urp, initData: abi.encode(chain, body)});
        return ActionData({actionTargetSelector: SEND_OUTBOUND, actionTarget: gateway, actionPolicies: p});
    }

    function _params(uint256 cardId, uint96 index, IUniversalMarketplace.JobInputs memory job, Session memory s)
        internal
        view
        returns (IUniversalMarketplace.StartJobParams memory p)
    {
        p.cardId = cardId;
        p.cardVersion = mkt.cardVersion(cardId);
        p.job = job;
        p.session = s;
        p.intent = mkt.previewIntent(
            IUniversalMarketplace.IntentRequest({
                cardId: cardId,
                owner: user,
                index: index,
                job: job,
                deadline: uint48(block.timestamp + 1 hours),
                signerChainId: 1
            }),
            s
        );
        p.sig = hex"01";
        p.label = "job";
    }

    /// @dev An honest, signed startJob for wallet `index` of the user.
    function _readyAt(
        uint256 cardId,
        uint96 index,
        IUniversalMarketplace.RulesCardTerms memory r,
        IUniversalMarketplace.JobInputs memory job
    ) internal view returns (IUniversalMarketplace.StartJobParams memory) {
        (address agw,) = factory.predictWallet(user, index);
        return _params(cardId, index, job, _session(_termsFor(r, agw, job)));
    }

    /// @dev An honest, signed startJob on the user's next (fresh) wallet.
    function _ready(uint256 cardId) internal view returns (IUniversalMarketplace.StartJobParams memory) {
        return _readyAt(cardId, uint96(factory.walletCount(user)), _rules(), _inputs(PRINCIPAL));
    }

    function _start(IUniversalMarketplace.StartJobParams memory p) internal returns (uint256 jobId, address agw) {
        vm.prank(relayer);
        (jobId, agw,) = mkt.startJob(p);
    }

    function _expectStart(IUniversalMarketplace.StartJobParams memory p, bytes memory err) internal {
        vm.prank(relayer);
        vm.expectRevert(err);
        mkt.startJob(p);
    }

    /// @dev The 8183 continuation outside the marketplace: the provider prices, the AGW funds with its rulesId.
    function _budgetAndFund(uint256 jobId, address agw, uint256 amount) internal {
        vm.prank(provider);
        kernel.setBudget(jobId, amount, "");
        _fund(jobId, agw, amount);
    }

    function _fund(uint256 jobId, address agw, uint256 amount) internal {
        engine.setPermission(MockAGW(payable(agw)).RULES_ID(), agw, true);
        token.mint(agw, amount);
        vm.startPrank(agw);
        token.approve(address(kernel), amount);
        kernel.fund(jobId, amount, abi.encode(mkt.rulesOfJob(jobId)));
        vm.stopPrank();
    }

    /// @dev The JobSpec bytes the card's template must give for this job.
    function _expectedDescription(
        EvaluationTemplate memory t,
        uint256 cardId,
        uint256 version,
        address agw,
        IUniversalMarketplace.JobInputs memory job
    ) internal view returns (bytes memory) {
        return expectedBuilder.build(
            abi.encode(t),
            BuildContext({
                agw: agw,
                principal: job.principal,
                executeBy: job.executeBy,
                settleWindow: _card().settleWindow,
                params: job.params,
                origin: keccak256(abi.encode(address(mkt), cardId, version, job.principal))
            })
        );
    }

    function _calldataHash(uint256 cardId, uint96 index, IUniversalMarketplace.JobInputs memory job)
        internal
        view
        returns (bytes32)
    {
        (, bytes memory cd) = mkt.buildCreateJobCalldata(cardId, user, index, job);
        return keccak256(cd);
    }

    /// @dev Pure on purpose: an external read here would consume a pending `vm.prank`.
    function _adminRevert(address who) internal pure returns (bytes memory) {
        return
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, who, keccak256("ADMIN_ROLE")
            );
    }
}

/// @title UniversalMarketplace — unit suite (PRD 09 §7.1).
contract UniversalMarketplaceTest is MarketplaceFixtures {
    // ═════════════════════════════ MR · registration ═════════════════════════════

    function test_MR01_registerCard_storesEverythingAndEmits() public {
        IUniversalMarketplace.AgentCard memory c = _card();
        bytes memory r = abi.encode(_rules());
        bytes memory e = abi.encode(_lendingTemplate());
        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.CardRegistered(
            1, provider, c.jobType, SEPOLIA, keccak256(r), keccak256(e), c.metadataHash, FEE
        );
        vm.prank(provider);
        uint256 id = mkt.registerCard(c, r, e);

        assertEq(id, 1);
        assertEq(mkt.cardCount(), 1);
        IUniversalMarketplace.CardView memory v = mkt.getCard(id);
        assertEq(v.card.provider, provider);
        assertEq(v.card.jobType, c.jobType);
        assertEq(v.card.metadataURI, c.metadataURI);
        assertEq(v.card.metadataHash, c.metadataHash);
        assertEq(v.card.chainNamespace, SEPOLIA);
        assertEq(v.card.fee, FEE);
        assertEq(v.card.principalMin, c.principalMin);
        assertEq(v.card.principalMax, c.principalMax);
        assertEq(v.card.minDuration, c.minDuration);
        assertEq(v.card.maxDuration, c.maxDuration);
        assertEq(v.card.minExecuteWindow, c.minExecuteWindow);
        assertEq(v.card.settleWindow, c.settleWindow);
        assertTrue(v.card.active);
        assertEq(v.rulesTerms, r, "rules stored byte-equal");
        assertEq(v.evaluation, e, "template stored byte-equal");
        assertEq(v.version, 1);
        assertFalse(v.verified);
        assertFalse(v.adminDisabled);
        assertEq(mkt.cardVersion(id), 1);
    }

    function test_MR02_providerAndActiveAreContractWritten() public {
        IUniversalMarketplace.AgentCard memory c = _card();
        c.provider = stranger;
        c.active = false;
        uint256 id = _register(c, _rules(), _lendingTemplate());
        assertEq(mkt.getCard(id).card.provider, provider);
        assertTrue(mkt.getCard(id).card.active);
    }

    function _expectInvalidCard(IUniversalMarketplace.AgentCard memory c, string memory reason) internal {
        bytes memory r = abi.encode(_rules());
        bytes memory e = abi.encode(_lendingTemplate());
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.InvalidCard.selector, reason));
        mkt.registerCard(c, r, e);
    }

    function test_MR03_eachInvalidCardField_reverts() public {
        IUniversalMarketplace.AgentCard memory c = _card();
        c.jobType = bytes32(0);
        _expectInvalidCard(c, "job type zero");
        c = _card();
        c.metadataURI = "";
        _expectInvalidCard(c, "metadata uri empty");
        c = _card();
        c.metadataHash = bytes32(0);
        _expectInvalidCard(c, "metadata hash zero");

        string[5] memory badChains =
            ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "eip155:", "eip155", "EIP155:11155111", ""];
        for (uint256 i; i < badChains.length; ++i) {
            c = _card();
            c.chainNamespace = badChains[i];
            _expectInvalidCard(c, "chain namespace");
        }

        vm.prank(admin);
        mkt.setEvaluator(provider);
        _expectInvalidCard(_card(), "provider is evaluator");
        vm.prank(admin);
        mkt.setEvaluator(universalEvaluator);

        c = _card();
        c.principalMin = 0;
        c.principalMax = 0;
        _expectInvalidCard(c, "principal range");
        c = _card();
        c.principalMin = 2;
        c.principalMax = 1;
        _expectInvalidCard(c, "principal range");
        c = _card();
        c.minDuration = 1 hours - 1;
        _expectInvalidCard(c, "duration range");
        c = _card();
        c.minDuration = 2 days;
        c.maxDuration = 1 days;
        _expectInvalidCard(c, "duration range");
        c = _card();
        c.settleWindow = 0;
        _expectInvalidCard(c, "settle window");
        c = _card();
        c.minExecuteWindow = 30 days - 2 hours + 1;
        _expectInvalidCard(c, "execute window");

        // every boundary passes: principal min == max, min duration 1 h, min == max duration, window == max
        c = _card();
        c.principalMin = 7;
        c.principalMax = 7;
        c.minDuration = 1 hours;
        c.minExecuteWindow = 30 days - 2 hours;
        _register(c, _rules(), _lendingTemplate());
        c = _card();
        c.minDuration = 30 days;
        _register(c, _rules(), _lendingTemplate());
    }

    function test_MR04_pushChain_refused() public {
        string memory push = string.concat("eip155:", Strings.toString(block.chainid));
        bytes32 pushHash = keccak256(bytes(push));
        assertEq(mkt.pushChainHash(), pushHash);
        vm.prank(admin);
        mkt.setCEADeployment(pushHash, address(ceaFactory), ceaProxyImpl); // refused even with a deployment
        IUniversalMarketplace.AgentCard memory c = _card();
        c.chainNamespace = push;
        bytes memory r = abi.encode(_rules());
        bytes memory e = abi.encode(_lendingTemplate());
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.ChainNotSupported.selector, pushHash));
        mkt.registerCard(c, r, e);
    }

    function test_MR05_unsupportedEvmChain_refused() public {
        IUniversalMarketplace.AgentCard memory c = _card();
        c.chainNamespace = "eip155:137";
        bytes memory r = abi.encode(_rules());
        bytes memory e = abi.encode(_lendingTemplate());
        vm.prank(provider);
        vm.expectRevert(
            abi.encodeWithSelector(IUniversalMarketplaceErrors.ChainNotSupported.selector, keccak256("eip155:137"))
        );
        mkt.registerCard(c, r, e);
    }

    function _expectInvalidRules(IUniversalMarketplace.RulesCardTerms memory r, string memory reason) internal {
        bytes memory rules = abi.encode(r);
        bytes memory e = abi.encode(_lendingTemplate());
        IUniversalMarketplace.AgentCard memory c = _card();
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.InvalidCard.selector, reason));
        mkt.registerCard(c, rules, e);
    }

    function test_MR06_assetTeeth() public {
        IUniversalMarketplace.RulesCardTerms memory r = _rules();
        r.asset = makeAddr("codelessAsset");
        _expectInvalidRules(r, "asset");

        MockPRC20Source.Answer[4] memory malformed = [
            MockPRC20Source.Answer.Reverts,
            MockPRC20Source.Answer.Short,
            MockPRC20Source.Answer.BadOffset,
            MockPRC20Source.Answer.Overlong
        ];
        for (uint256 i; i < malformed.length; ++i) {
            pUSDC.setAnswer(malformed[i]);
            _expectInvalidRules(_rules(), "asset");
        }
        pUSDC.setAnswer(MockPRC20Source.Answer.Namespace);
        pUSDC.setNamespace("eip155:1");
        _expectInvalidRules(_rules(), "asset chain");

        pUSDC.setNamespace(SEPOLIA);
        _registerLending();
    }

    function test_MR07_rulesTermsErrorsSurface() public {
        IUniversalMarketplace.RulesCardTerms memory r = _rules();
        r.allowedCalls[0].selector = ERC20_APPROVE;
        _expectInvalidRules(r, "erc20 approval");
    }

    /// @dev The criteria template is stored as given: registration never judges it. A template that writes a fill
    ///      outside its args registers, and fails only when a job is built from it.
    function test_MR08_criteriaNotJudgedAtRegistration() public {
        EvaluationTemplate memory t = _lendingTemplate();
        ReadTemplate[] memory reads = new ReadTemplate[](3);
        reads[0] = t.reads[0];
        reads[1] = t.reads[1];
        reads[2] = _balanceOfCEA(SEPOLIA_ID, weth); // read by no check
        t.reads = reads;
        t.reads[0].fills[0].word = 1; // args are one word long
        uint256 id = _register(_card(), _rules(), t);
        assertEq(mkt.getCard(id).evaluation, abi.encode(t), "stored byte-equal");

        IUniversalMarketplace.JobInputs memory job = _inputs(PRINCIPAL);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.FillOutOfBounds.selector, 0, 0));
        mkt.buildCreateJobCalldata(id, user, 0, job); // the same build startJob runs at step 9
    }

    function test_MR09_assetIndependent() public {
        assertTrue(address(pETH) != address(kernel.paymentToken()), "pETH is not the kernel's payment token");
        IUniversalMarketplace.RulesCardTerms memory r = _rules();
        r.asset = address(pETH);
        uint256 id = _register(_card(), r, _lendingTemplate());
        IUniversalMarketplace.StartJobParams memory p = _readyAt(id, 0, r, _inputs(PRINCIPAL));
        (uint256 jobId, address agw) = _start(p);
        assertEq(kernel.getJob(jobId).client, agw);
        assertEq(abi.decode(mkt.getCard(id).rulesTerms, (IUniversalMarketplace.RulesCardTerms)).asset, address(pETH));
    }

    function test_MR10_paused() public {
        vm.prank(admin);
        mkt.pause();
        bytes memory r = abi.encode(_rules());
        bytes memory e = abi.encode(_lendingTemplate());
        IUniversalMarketplace.AgentCard memory c = _card();
        vm.prank(provider);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        mkt.registerCard(c, r, e);
    }

    // ═════════════════════════════ ML · card lifecycle ═════════════════════════════

    function test_ML01_setCardActive() public {
        uint256 id = _registerLending();
        vm.prank(stranger);
        vm.expectRevert(IUniversalMarketplaceErrors.NotProvider.selector);
        mkt.setCardActive(id, false);
        vm.prank(provider);
        vm.expectRevert(IUniversalMarketplaceErrors.NotProvider.selector);
        mkt.setCardActive(999, false);

        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.CardStatusChanged(id, false);
        vm.prank(provider);
        mkt.setCardActive(id, false);
        assertFalse(mkt.getCard(id).card.active);
        vm.prank(provider);
        mkt.setCardActive(id, true);
        assertTrue(mkt.getCard(id).card.active);

        vm.prank(admin);
        mkt.adminDisableCard(id);
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.CardAdminDisabled.selector, id));
        mkt.setCardActive(id, true);
        vm.prank(provider);
        mkt.setCardActive(id, false); // switching off stays allowed
    }

    function test_ML02_adminDisableCard() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        vm.prank(admin);
        mkt.verifyAgentCard(id, 1);

        vm.prank(stranger);
        vm.expectRevert(_adminRevert(stranger));
        mkt.adminDisableCard(id);

        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.CardVerificationRevoked(id);
        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.CardDisabledByAdmin(id);
        vm.prank(admin);
        mkt.adminDisableCard(id);

        IUniversalMarketplace.CardView memory v = mkt.getCard(id);
        assertTrue(v.adminDisabled);
        assertFalse(v.card.active);
        assertFalse(v.verified);
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.CardInactive.selector));

        vm.prank(admin);
        vm.expectRevert(IUniversalMarketplaceErrors.CardInactive.selector);
        mkt.adminDisableCard(999);
    }

    function test_ML03_verifyAgentCard() public {
        uint256 id = _registerLending();
        vm.prank(stranger);
        vm.expectRevert(_adminRevert(stranger));
        mkt.verifyAgentCard(id, 1);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.CardVersionMismatch.selector, 2, 1));
        mkt.verifyAgentCard(id, 2);
        vm.prank(admin);
        vm.expectRevert(IUniversalMarketplaceErrors.CardInactive.selector);
        mkt.verifyAgentCard(999, 1);

        vm.prank(provider);
        mkt.setCardActive(id, false); // a card its provider switched off can still be verified
        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.CardVerified(id, 1);
        vm.prank(admin);
        mkt.verifyAgentCard(id, 1);
        assertTrue(mkt.cardVerified(id));
        assertTrue(mkt.getCard(id).verified);

        uint256 disabled = _registerLending();
        vm.startPrank(admin);
        mkt.adminDisableCard(disabled);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.CardAdminDisabled.selector, disabled));
        mkt.verifyAgentCard(disabled, 1);
        vm.stopPrank();
    }

    function test_ML04_verify_racedByModification() public {
        uint256 id = _registerLending();
        _modify(id, _card(), _rules(), _lendingTemplate());
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.CardVersionMismatch.selector, 1, 2));
        mkt.verifyAgentCard(id, 1);
        vm.prank(admin);
        mkt.verifyAgentCard(id, 2);
        assertTrue(mkt.cardVerified(id));
    }

    function test_ML05_revokeVerification() public {
        uint256 id = _registerLending();
        vm.prank(admin);
        mkt.verifyAgentCard(id, 1);
        vm.prank(stranger);
        vm.expectRevert(_adminRevert(stranger));
        mkt.revokeAgentCardVerification(id);

        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.CardVerificationRevoked(id);
        vm.prank(admin);
        mkt.revokeAgentCardVerification(id);
        assertFalse(mkt.cardVerified(id));

        vm.recordLogs();
        vm.prank(admin);
        mkt.revokeAgentCardVerification(id);
        assertEq(vm.getRecordedLogs().length, 0, "revoking an unverified card logs nothing");

        vm.prank(admin);
        vm.expectRevert(IUniversalMarketplaceErrors.CardInactive.selector);
        mkt.revokeAgentCardVerification(999);
    }

    function _modify(
        uint256 id,
        IUniversalMarketplace.AgentCard memory c,
        IUniversalMarketplace.RulesCardTerms memory r,
        EvaluationTemplate memory t
    ) internal {
        bytes memory rules = abi.encode(r);
        bytes memory evaluation = abi.encode(t);
        vm.prank(provider);
        mkt.modifyAgentCard(id, c, rules, evaluation);
    }

    /// @dev Every mutable field changed, two calls, two approvals, and the swap criteria.
    function _modified()
        internal
        view
        returns (
            IUniversalMarketplace.AgentCard memory c,
            IUniversalMarketplace.RulesCardTerms memory r,
            EvaluationTemplate memory t
        )
    {
        c = _card();
        c.jobType = keccak256("SWAP");
        c.metadataURI = "ipfs://card-v2";
        c.metadataHash = keccak256("card-v2.json");
        c.fee = FEE * 3;
        c.principalMin = 200e6;
        c.principalMax = 2_000e6;
        c.minDuration = 4 hours;
        c.maxDuration = 10 days;
        c.minExecuteWindow = 20 minutes;
        c.settleWindow = 3 hours;
        r = _rules();
        r.maxPCPerCall = 2 ether;
        AllowedCall[] memory calls = new AllowedCall[](2);
        calls[0] = r.allowedCalls[0];
        calls[1] =
            AllowedCall({target: pool, selector: WITHDRAW, beneficiaryOffset: 68, hasBeneficiary: true, maxValue: 0});
        r.allowedCalls = calls;
        IUniversalMarketplace.Approval[] memory approvals = new IUniversalMarketplace.Approval[](2);
        approvals[0] = r.approvals[0];
        approvals[1] = IUniversalMarketplace.Approval({token: aUSDC, spender: pool, capIsPrincipal: false, cap: 1e12});
        r.approvals = approvals;
        t = _swapTemplate();
    }

    function test_ML06_modify_updatesEveryMutableField() public {
        uint256 id = _registerLending();
        vm.prank(provider);
        mkt.setCardActive(id, false);
        (
            IUniversalMarketplace.AgentCard memory c,
            IUniversalMarketplace.RulesCardTerms memory r,
            EvaluationTemplate memory t
        ) = _modified();
        c.provider = stranger; // ignored
        c.active = true; // ignored: the provider's switch stays off
        bytes memory rules = abi.encode(r);
        bytes memory evaluation = abi.encode(t);

        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.CardModified(id, 2, keccak256(rules), keccak256(evaluation), c.metadataHash, c.fee);
        vm.prank(provider);
        mkt.modifyAgentCard(id, c, rules, evaluation);

        IUniversalMarketplace.CardView memory v = mkt.getCard(id);
        assertEq(v.card.provider, provider, "provider kept");
        assertEq(v.card.chainNamespace, SEPOLIA, "chain kept");
        assertFalse(v.card.active, "active kept");
        assertEq(v.card.jobType, c.jobType);
        assertEq(v.card.metadataURI, c.metadataURI);
        assertEq(v.card.metadataHash, c.metadataHash);
        assertEq(v.card.fee, c.fee);
        assertEq(v.card.principalMin, c.principalMin);
        assertEq(v.card.principalMax, c.principalMax);
        assertEq(v.card.minDuration, c.minDuration);
        assertEq(v.card.maxDuration, c.maxDuration);
        assertEq(v.card.minExecuteWindow, c.minExecuteWindow);
        assertEq(v.card.settleWindow, c.settleWindow);
        assertEq(v.rulesTerms, rules);
        assertEq(v.evaluation, evaluation);
        assertEq(v.version, 2);
        assertEq(mkt.cardCount(), 1, "no new card");

        // and an active card stays active when the input says inactive
        vm.prank(provider);
        mkt.setCardActive(id, true);
        c.active = false;
        _modify(id, c, r, t);
        assertTrue(mkt.getCard(id).card.active);
        assertEq(mkt.cardVersion(id), 3);
    }

    function test_ML07_modify_clearsVerification() public {
        uint256 id = _registerLending();
        vm.prank(admin);
        mkt.verifyAgentCard(id, 1);
        IUniversalMarketplace.AgentCard memory c = _card();
        bytes memory r = abi.encode(_rules());
        bytes memory e = abi.encode(_lendingTemplate());
        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.CardVerificationRevoked(id);
        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.CardModified(id, 2, keccak256(r), keccak256(e), c.metadataHash, c.fee);
        vm.prank(provider);
        mkt.modifyAgentCard(id, c, r, e);
        assertFalse(mkt.cardVerified(id));
    }

    function test_ML08_modify_access() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.AgentCard memory c = _card();
        bytes memory r = abi.encode(_rules());
        bytes memory e = abi.encode(_lendingTemplate());

        vm.prank(stranger);
        vm.expectRevert(IUniversalMarketplaceErrors.NotProvider.selector);
        mkt.modifyAgentCard(id, c, r, e);
        vm.prank(provider);
        vm.expectRevert(IUniversalMarketplaceErrors.NotProvider.selector);
        mkt.modifyAgentCard(999, c, r, e);

        vm.prank(admin);
        mkt.pause();
        vm.prank(provider);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        mkt.modifyAgentCard(id, c, r, e);
        vm.prank(admin);
        mkt.unpause();

        vm.prank(admin);
        mkt.adminDisableCard(id);
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.CardAdminDisabled.selector, id));
        mkt.modifyAgentCard(id, c, r, e);
    }

    function test_ML09_modify_chainImmutable() public {
        uint256 id = _registerLending();
        bytes32 baseSepolia = keccak256("eip155:84532");
        vm.prank(admin);
        mkt.setCEADeployment(baseSepolia, address(ceaFactory), ceaProxyImpl);
        IUniversalMarketplace.AgentCard memory c = _card();
        c.chainNamespace = "eip155:84532";
        bytes memory r = abi.encode(_rules());
        bytes memory e = abi.encode(_lendingTemplate());
        vm.prank(provider);
        vm.expectRevert(IUniversalMarketplaceErrors.CardIdentityImmutable.selector);
        mkt.modifyAgentCard(id, c, r, e);
    }

    function test_ML10_modify_validatesLikeRegistration() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.AgentCard memory c = _card();
        c.settleWindow = 0;
        _expectInvalidModify(id, c, abi.encode(_rules()), abi.encode(_lendingTemplate()), "settle window");

        IUniversalMarketplace.RulesCardTerms memory r = _rules();
        r.allowedCalls[0].selector = ERC20_APPROVE;
        _expectInvalidModify(id, _card(), abi.encode(r), abi.encode(_lendingTemplate()), "erc20 approval");

        assertEq(mkt.cardVersion(id), 1, "no failed modification bumped the version");
    }

    function _expectInvalidModify(
        uint256 id,
        IUniversalMarketplace.AgentCard memory c,
        bytes memory r,
        bytes memory e,
        string memory reason
    ) internal {
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.InvalidCard.selector, reason));
        mkt.modifyAgentCard(id, c, r, e);
    }

    function test_ML11_modify_invalidatesOldIntents() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        _modify(id, _card(), _rules(), _lendingTemplate()); // same content, version 2

        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.CardVersionMismatch.selector, 1, 2));
        p.cardVersion = 2;
        _expectStart(
            p,
            abi.encodeWithSelector(IUniversalMarketplaceErrors.IntentExecMismatch.selector, _calldataHash(id, 0, p.job))
        );
        assertEq(factory.walletCount(user), 0, "nothing deployed");
    }

    function test_ML12_modify_leavesStartedJobsUntouched() public {
        uint256 id = _registerLending();
        (uint256 jobId, address agw) = _start(_ready(id));
        IAgenticCommerce.Job memory before = kernel.getJob(jobId);

        (
            IUniversalMarketplace.AgentCard memory c,
            IUniversalMarketplace.RulesCardTerms memory r,
            EvaluationTemplate memory t
        ) = _modified();
        _modify(id, c, r, t);

        IAgenticCommerce.Job memory afterJob = kernel.getJob(jobId);
        assertEq(afterJob.provider, before.provider);
        assertEq(afterJob.evaluator, before.evaluator);
        assertEq(afterJob.description, before.description);
        assertEq(afterJob.hook, before.hook);
        assertEq(mkt.cardOfJob(jobId), id);
        assertEq(mkt.agwOfJob(jobId), agw);
        assertEq(mkt.lastJobOf(agw), jobId);
        assertEq(mkt.rulesOfJob(jobId), MockAGW(payable(agw)).RULES_ID());
    }

    function test_ML13_startJob_afterModify_usesNewContent() public {
        uint256 id = _registerLending();
        EvaluationTemplate memory t = _lendingTemplate();
        t.checks[1].value = 0.05e27;
        IUniversalMarketplace.RulesCardTerms memory r = _rules();
        r.maxPCPerCall = 2 ether;
        _modify(id, _card(), r, t);

        IUniversalMarketplace.StartJobParams memory p = _readyAt(id, 0, r, _inputs(PRINCIPAL));
        (uint256 jobId, address agw) = _start(p);
        bytes memory description = bytes(kernel.getJob(jobId).description);
        assertEq(description, _expectedDescription(t, id, 2, agw, p.job));
        JobSpec memory spec = abi.decode(description, (JobSpec));
        assertEq(spec.checks[1].target, 0.05e27, "the new criteria");
        assertEq(spec.origin, keccak256(abi.encode(address(mkt), id, uint256(2), PRINCIPAL)), "origin carries v2");
    }

    // ═════════════════════════════ MS · startJob ═════════════════════════════

    function test_MS01_freshWallet_happyPath() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        address agw = p.intent.wallet;
        uint256 expectedJobId = kernel.jobCounter() + 1;

        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.JobStarted(id, user, agw, expectedJobId, keccak256("mock-rules"), PRINCIPAL, 1);
        vm.prank(relayer);
        (uint256 jobId, address got, bytes32 rulesId) = mkt.startJob(p);

        assertEq(jobId, expectedJobId);
        assertEq(got, agw, "deployed at the predicted address");
        assertEq(factory.ownerOf(agw), user);
        MockAGW w = MockAGW(payable(agw));
        assertEq(rulesId, w.RULES_ID());
        assertEq(w.lastSessionHash(), keccak256(abi.encode(p.session)));
        assertEq(w.lastGrantIntentHash(), keccak256(abi.encode(p.intent)), "grant got the signed intent");
        assertEq(w.lastExecIntentHash(), keccak256(abi.encode(p.intent)), "exec got the same intent");
        assertEq(w.lastGrantCaller(), address(mkt));
        assertEq(w.lastExecCalldataHash(), _calldataHash(id, 0, p.job));

        IAgenticCommerce.Job memory j = kernel.getJob(jobId);
        assertEq(j.client, agw);
        assertEq(j.provider, provider);
        assertEq(j.evaluator, universalEvaluator);
        assertEq(j.hook, address(hook));
        assertEq(j.expiredAt, p.job.expiredAt);
        assertEq(j.budget, 0);
        assertEq(uint8(j.status), uint8(IAgenticCommerce.JobStatus.Open));
        assertEq(bytes(j.description), _expectedDescription(_lendingTemplate(), id, 1, agw, p.job));

        assertEq(mkt.lastJobOf(agw), jobId);
        assertEq(mkt.cardOfJob(jobId), id);
        assertEq(mkt.agwOfJob(jobId), agw);
        assertEq(mkt.rulesOfJob(jobId), rulesId);
    }

    function test_MS02_movesNoFunds() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        address agw = p.intent.wallet;
        address[3] memory who = [user, agw, address(mkt)];
        uint256[3] memory tokenBefore;
        uint256[3] memory assetBefore;
        uint256[3] memory ethBefore;
        for (uint256 i; i < 3; ++i) {
            tokenBefore[i] = token.balanceOf(who[i]);
            assetBefore[i] = pUSDC.balanceOf(who[i]);
            ethBefore[i] = who[i].balance;
        }
        assertEq(token.allowance(user, address(mkt)), 0, "no allowance");
        assertEq(pUSDC.allowance(user, address(mkt)), 0, "no allowance");
        assertEq(agw.balance, 0, "no PC in the AGW");

        _start(p);

        for (uint256 i; i < 3; ++i) {
            assertEq(token.balanceOf(who[i]), tokenBefore[i], "payment token moved");
            assertEq(pUSDC.balanceOf(who[i]), assetBefore[i], "rules asset moved");
            assertEq(who[i].balance, ethBefore[i], "PC moved");
        }
        assertEq(token.balanceOf(address(mkt)), 0);
        assertEq(address(mkt).balance, 0);
    }

    function test_MS03_existingWallet_skipsDeploy() public {
        uint256 id = _registerLending();
        (uint256 job1, address agw) = _start(_ready(id));
        vm.prank(provider);
        kernel.reject(job1, bytes32(0), "");

        IUniversalMarketplace.StartJobParams memory p = _readyAt(id, 0, _rules(), _inputs(PRINCIPAL));
        assertEq(p.intent.grantNonce, 1, "preview reads the live grant nonce");
        assertEq(p.intent.nonceSeq, 1, "preview reads the live lane");
        (uint256 job2, address again) = _start(p);
        assertEq(again, agw);
        assertEq(factory.walletCount(user), 1, "no second wallet");
        assertEq(job2, job1 + 1);
        assertEq(MockAGW(payable(agw)).grantNonce(), 2, "rules granted again");
        assertEq(mkt.lastJobOf(agw), job2);
    }

    function test_MS04_existingWallet_wrongOwner() public {
        uint256 id = _registerLending();
        (uint256 job1, address agw) = _start(_ready(id));
        vm.prank(provider);
        kernel.reject(job1, bytes32(0), "");
        IUniversalMarketplace.StartJobParams memory p = _readyAt(id, 0, _rules(), _inputs(PRINCIPAL));
        // the factory's registry disagrees with the derivation (MockAGWFactory.ownerOf is slot 2)
        vm.store(address(factory), keccak256(abi.encode(agw, uint256(2))), bytes32(uint256(uint160(stranger))));
        _expectStart(
            p, abi.encodeWithSelector(IUniversalMarketplaceErrors.WalletOwnerMismatch.selector, user, stranger)
        );
    }

    function test_MS04b_factoryDeploysElsewhere_agwMismatch() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        factory.setMisdeploy(true);
        bytes32 salt = keccak256(abi.encode(keccak256(abi.encode(user, uint96(0)))));
        address elsewhere = vm.computeCreate2Address(
            salt, keccak256(abi.encodePacked(type(MockAGW).creationCode, abi.encode(user))), address(factory)
        );
        _expectStart(
            p, abi.encodeWithSelector(IUniversalMarketplaceErrors.AGWMismatch.selector, p.intent.wallet, elsewhere)
        );
    }

    function test_MS05_cardInactive_unknown_chainPaused() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);

        vm.prank(provider);
        mkt.setCardActive(id, false);
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.CardInactive.selector));
        vm.prank(provider);
        mkt.setCardActive(id, true);

        p.cardId = 999;
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.CardInactive.selector));
        p.cardId = id;

        vm.prank(admin);
        mkt.setUniversalPaused(SEPOLIA_HASH, true);
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.ChainPaused.selector, SEPOLIA_HASH));
        vm.prank(admin);
        mkt.setUniversalPaused(SEPOLIA_HASH, false);
        _start(p);
    }

    function test_MS06_cardVersionMismatch() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        p.cardVersion = 2;
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.CardVersionMismatch.selector, 2, 1));
        p.cardVersion = 0;
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.CardVersionMismatch.selector, 0, 1));
    }

    function test_MS07_principalOutOfRange() public {
        uint256 id = _registerLending();
        uint256[2] memory bad = [uint256(100e6 - 1), 1_000e6 + 1];
        for (uint256 i; i < 2; ++i) {
            IUniversalMarketplace.StartJobParams memory p =
                _readyAt(id, uint96(factory.walletCount(user)), _rules(), _inputs(bad[i]));
            _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.PrincipalOutOfRange.selector));
        }
        _start(_readyAt(id, 0, _rules(), _inputs(100e6)));
        _start(_readyAt(id, 1, _rules(), _inputs(1_000e6)));
    }

    function _withTimes(uint256 expiredAt, uint256 executeBy)
        internal
        view
        returns (IUniversalMarketplace.JobInputs memory j)
    {
        j = _inputs(PRINCIPAL);
        // forge-lint: disable-next-line(unsafe-typecast)
        j.expiredAt = uint48(expiredAt); // a timestamp within 31 days of now
        // forge-lint: disable-next-line(unsafe-typecast)
        j.executeBy = uint48(executeBy); // a timestamp within 31 days of now
    }

    function test_MS08_expiryOutOfRange() public {
        uint256 id = _registerLending();
        uint256 t = block.timestamp;
        IUniversalMarketplace.JobInputs memory tooSoon = _withTimes(t + 3 hours - 1, t + 10 minutes);
        IUniversalMarketplace.JobInputs memory tooLate = _withTimes(t + 30 days + 1, t + 10 minutes);
        _expectStart(
            _readyAt(id, 0, _rules(), tooSoon),
            abi.encodeWithSelector(IUniversalMarketplaceErrors.ExpiryOutOfRange.selector)
        );
        _expectStart(
            _readyAt(id, 0, _rules(), tooLate),
            abi.encodeWithSelector(IUniversalMarketplaceErrors.ExpiryOutOfRange.selector)
        );
        _start(_readyAt(id, 0, _rules(), _withTimes(t + 3 hours, t + 10 minutes)));
        _start(_readyAt(id, 1, _rules(), _withTimes(t + 30 days, t + 10 minutes)));
    }

    function test_MS09_executeByOutOfRange() public {
        uint256 id = _registerLending();
        uint256 t = block.timestamp;
        uint256 expiry = t + 7 days;
        _expectStart(
            _readyAt(id, 0, _rules(), _withTimes(expiry, t + 10 minutes - 1)),
            abi.encodeWithSelector(IUniversalMarketplaceErrors.ExecuteByOutOfRange.selector)
        );
        _expectStart(
            _readyAt(id, 0, _rules(), _withTimes(expiry, expiry - 2 hours + 1)),
            abi.encodeWithSelector(IUniversalMarketplaceErrors.ExecuteByOutOfRange.selector)
        );
        _start(_readyAt(id, 0, _rules(), _withTimes(expiry, t + 10 minutes)));
        _start(_readyAt(id, 1, _rules(), _withTimes(expiry, expiry - 2 hours)));
    }

    function test_MS10_params() public {
        uint256 id = _registerSwap();

        IUniversalMarketplace.StartJobParams memory p = _readyAt(id, 0, _rules(), _swapInputs(0.5e18));
        p.job.params = new int256[](0);
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.ParamCountMismatch.selector, 1, 0));
        p = _readyAt(id, 0, _rules(), _swapInputs(0.5e18));
        p.job.params = new int256[](2);
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.ParamCountMismatch.selector, 1, 2));

        p = _readyAt(id, 0, _rules(), _swapInputs(0.5e18));
        p.job.params[0] = 0;
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.ParamOutOfRange.selector, 0, int256(0)));
        p = _readyAt(id, 0, _rules(), _swapInputs(0.5e18));
        p.job.params[0] = 1e30 + 1;
        _expectStart(
            p, abi.encodeWithSelector(IUniversalMarketplaceErrors.ParamOutOfRange.selector, 0, int256(1e30 + 1))
        );

        (uint256 jobA,) = _start(_readyAt(id, 0, _rules(), _swapInputs(1)));
        (uint256 jobB,) = _start(_readyAt(id, 1, _rules(), _swapInputs(1e30)));
        assertEq(abi.decode(bytes(kernel.getJob(jobA).description), (JobSpec)).checks[0].target, 1);
        assertEq(abi.decode(bytes(kernel.getJob(jobB).description), (JobSpec)).checks[0].target, 1e30);
    }

    function test_MS11_intentWalletAndExecutor() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        address agw = p.intent.wallet;
        p.intent.wallet = stranger;
        _expectStart(
            p, abi.encodeWithSelector(IUniversalMarketplaceErrors.IntentWalletMismatch.selector, agw, stranger)
        );
        p = _ready(id);
        p.intent.executor = stranger;
        _expectStart(
            p, abi.encodeWithSelector(IUniversalMarketplaceErrors.ExecutorMismatch.selector, stranger, address(mkt))
        );
    }

    function _expectExecMismatch(IUniversalMarketplace.StartJobParams memory p, uint96 index) internal {
        _expectStart(
            p,
            abi.encodeWithSelector(
                IUniversalMarketplaceErrors.IntentExecMismatch.selector, _calldataHash(p.cardId, index, p.job)
            )
        );
    }

    function test_MS12_intentExecMismatch_everyBoundInput() public {
        uint256 id = _registerSwap();
        IUniversalMarketplace.JobInputs memory job = _swapInputs(0.5e18);

        IUniversalMarketplace.StartJobParams memory p = _readyAt(id, 0, _rules(), job);
        p.job.principal = PRINCIPAL + 1;
        _expectExecMismatch(p, 0);

        p = _readyAt(id, 0, _rules(), _swapInputs(0.5e18));
        p.job.executeBy += 1;
        _expectExecMismatch(p, 0);

        p = _readyAt(id, 0, _rules(), _swapInputs(0.5e18));
        p.job.expiredAt += 1;
        _expectExecMismatch(p, 0);

        p = _readyAt(id, 0, _rules(), _swapInputs(0.5e18));
        p.job.params[0] += 1;
        _expectExecMismatch(p, 0);

        // another wallet of the same owner: its CEA is in the criteria
        p = _readyAt(id, 0, _rules(), _swapInputs(0.5e18));
        p.intent.index = 1;
        (p.intent.wallet,) = factory.predictWallet(user, 1);
        _expectExecMismatch(p, 1);

        p = _readyAt(id, 0, _rules(), _swapInputs(0.5e18));
        p.intent.mode = bytes32(uint256(1));
        _expectExecMismatch(p, 0);

        p = _readyAt(id, 0, _rules(), _swapInputs(0.5e18));
        p.intent.nonceKey = 0;
        _expectExecMismatch(p, 0);

        p = _readyAt(id, 0, _rules(), _swapInputs(0.5e18));
        p.intent.execCalldataHash = keccak256("another call");
        _expectExecMismatch(p, 0);
    }

    function test_MS13_intentSessionMismatch_noStateOnFailure() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        p.session.salt = bytes32(uint256(1));
        uint256 jobsBefore = kernel.jobCounter();
        _expectStart(
            p,
            abi.encodeWithSelector(
                IUniversalMarketplaceErrors.IntentSessionMismatch.selector, keccak256(abi.encode(p.session))
            )
        );
        assertEq(factory.walletCount(user), 0, "no wallet");
        assertEq(kernel.jobCounter(), jobsBefore, "no job");
        assertEq(mkt.lastJobOf(p.intent.wallet), 0);
    }

    function _expectBusy(uint256 id, address agw, uint256 jobId) internal {
        assertFalse(mkt.isAGWFree(agw));
        _expectStart(
            _readyAt(id, 0, _rules(), _inputs(PRINCIPAL)),
            abi.encodeWithSelector(IUniversalMarketplaceErrors.AGWBusy.selector, agw, jobId)
        );
    }

    function test_MS14_oneLiveJob() public {
        uint256 id = _registerLending();

        // Open → busy; expired Open → free
        (uint256 job1, address agw) = _start(_ready(id));
        _expectBusy(id, agw, job1);
        vm.warp(kernel.getJob(job1).expiredAt);
        assertTrue(mkt.isAGWFree(agw), "free after an expired Open job");

        // Open → Rejected → free
        (uint256 job2,) = _start(_readyAt(id, 0, _rules(), _inputs(PRINCIPAL)));
        vm.prank(provider);
        kernel.reject(job2, bytes32(0), "");
        assertTrue(mkt.isAGWFree(agw), "free after Rejected");

        // Funded → busy; Submitted → busy; Completed → free
        (uint256 job3,) = _start(_readyAt(id, 0, _rules(), _inputs(PRINCIPAL)));
        _budgetAndFund(job3, agw, FEE);
        assertEq(uint8(_status(job3)), uint8(IAgenticCommerce.JobStatus.Funded));
        _expectBusy(id, agw, job3);
        vm.prank(provider);
        kernel.submit(job3, keccak256("deliverable"), "");
        _expectBusy(id, agw, job3);
        vm.prank(universalEvaluator);
        kernel.complete(job3, bytes32(0), "");
        assertTrue(mkt.isAGWFree(agw), "free after Completed");
        _start(_readyAt(id, 0, _rules(), _inputs(PRINCIPAL)));
    }

    function test_MS15_jobVerification() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        vm.prank(user);
        factory.deployWalletWithSig(p.intent, "", "");
        MockAGW(payable(p.intent.wallet)).setMode(MockAGW.Mode.TwoJobs);
        uint256 n = kernel.jobCounter();
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.UnexpectedJobCount.selector, n, n + 2));

        MockAGW(payable(p.intent.wallet)).setMode(MockAGW.Mode.ForeignClient);
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.JobMismatch.selector));

        MockAGW(payable(p.intent.wallet)).setMode(MockAGW.Mode.OtherEvaluator);
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.JobMismatch.selector));
    }

    function test_MS16_providerIsEvaluator_afterSetEvaluator() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        vm.prank(admin);
        mkt.setEvaluator(provider);
        _expectStart(p, abi.encodeWithSelector(IUniversalMarketplaceErrors.ProviderIsEvaluator.selector));
    }

    function test_MS17_8183Continuation_feeEnforcedAtFund() public {
        uint256 id = _registerLending();
        (uint256 jobId, address agw) = _start(_ready(id));
        uint256 fee = mkt.getCard(id).card.fee;

        // a provider who prices above the card cannot be funded: the owner's expectedBudget is the card fee
        vm.prank(provider);
        kernel.setBudget(jobId, fee + 1, "");
        engine.setPermission(MockAGW(payable(agw)).RULES_ID(), agw, true);
        token.mint(agw, fee + 1);
        bytes memory optParams = abi.encode(mkt.rulesOfJob(jobId));
        vm.startPrank(agw);
        token.approve(address(kernel), fee + 1);
        vm.expectRevert(IAgenticCommerce.BudgetMismatch.selector);
        kernel.fund(jobId, fee, optParams);
        vm.stopPrank();

        uint256 escrowBefore = kernel.totalEscrowed();
        _budgetAndFund(jobId, agw, fee);
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Funded));
        assertEq(kernel.totalEscrowed() - escrowBefore, fee, "the kernel escrows the card fee");
        assertEq(kernel.getJob(jobId).budget, fee);
    }

    /// @dev Ceilings = measured + 10%, rounded up to 10k (PRD 09 §8.5). Measured 2026-10-02 with the mock wallet
    ///      and factory: registerCard 2,231,229 · startJob fresh 3,172,694 · startJob existing 1,891,132.
    uint256 internal constant REGISTER_GAS_CEILING = 2_460_000;
    uint256 internal constant START_FRESH_GAS_CEILING = 3_490_000;
    uint256 internal constant START_EXISTING_GAS_CEILING = 2_090_000;

    function test_MS18_gasCeilings() public {
        IUniversalMarketplace.AgentCard memory c = _card();
        bytes memory r = abi.encode(_rules());
        bytes memory e = abi.encode(_lendingTemplate());
        vm.prank(provider);
        uint256 g = gasleft();
        uint256 id = mkt.registerCard(c, r, e);
        assertLe(g - gasleft(), REGISTER_GAS_CEILING, "registerCard (lending card)");

        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        vm.prank(relayer);
        g = gasleft();
        (uint256 jobId,,) = mkt.startJob(p);
        assertLe(g - gasleft(), START_FRESH_GAS_CEILING, "startJob (fresh wallet)");

        vm.prank(provider);
        kernel.reject(jobId, bytes32(0), "");
        p = _readyAt(id, 0, _rules(), _inputs(PRINCIPAL));
        vm.prank(relayer);
        g = gasleft();
        mkt.startJob(p);
        assertLe(g - gasleft(), START_EXISTING_GAS_CEILING, "startJob (existing wallet)");
    }

    // ═════════════════════════════ MB · rules ⊆ card, through the marketplace ═════════════════════════════

    function _sessionCase(function(Session memory) internal view mutate, bytes memory err) internal {
        uint256 id = _registerLending();
        IUniversalMarketplace.JobInputs memory job = _inputs(PRINCIPAL);
        (address agw,) = factory.predictWallet(user, 0);
        Session memory s = _session(_termsFor(_rules(), agw, job));
        mutate(s);
        _expectStart(_params(id, 0, job, s), err);
    }

    function _termsCase(function(UniversalTerms memory) internal view mutate, bytes memory err) internal {
        uint256 id = _registerLending();
        IUniversalMarketplace.JobInputs memory job = _inputs(PRINCIPAL);
        (address agw,) = factory.predictWallet(user, 0);
        UniversalTerms memory t = _termsFor(_rules(), agw, job);
        mutate(t);
        _expectStart(_params(id, 0, job, _session(t)), err);
    }

    function _otherAgent(Session memory s) internal view {
        s.sessionValidatorInitData = abi.encode(stranger);
    }

    function _wideInitData(Session memory s) internal view {
        s.sessionValidatorInitData = abi.encode(provider, provider);
    }

    function _noActions(Session memory s) internal pure {
        s.actions = new ActionData[](0);
    }

    function _twoActions(Session memory s) internal pure {
        ActionData[] memory a = new ActionData[](2);
        a[0] = s.actions[0];
        a[1] = s.actions[0];
        s.actions = a;
    }

    function _twoPolicies(Session memory s) internal pure {
        PolicyData[] memory p = new PolicyData[](2);
        p[0] = s.actions[0].actionPolicies[0];
        p[1] = s.actions[0].actionPolicies[0];
        s.actions[0].actionPolicies = p;
    }

    function _otherChain(Session memory s) internal pure {
        (, bytes memory body) = abi.decode(s.actions[0].actionPolicies[0].initData, (string, bytes));
        s.actions[0].actionPolicies[0].initData = abi.encode("eip155:1", body);
    }

    function test_MB01_agentMismatch() public {
        _sessionCase(_otherAgent, abi.encodeWithSelector(IUniversalMarketplaceErrors.AgentMismatch.selector));
        _sessionCase(_wideInitData, abi.encodeWithSelector(IUniversalMarketplaceErrors.AgentMismatch.selector));
    }

    function test_MB02_shape() public {
        _sessionCase(_noActions, abi.encodeWithSelector(IUniversalMarketplaceErrors.ActionCount.selector));
        _sessionCase(_twoActions, abi.encodeWithSelector(IUniversalMarketplaceErrors.ActionCount.selector));
        _sessionCase(_twoPolicies, abi.encodeWithSelector(IUniversalMarketplaceErrors.PolicyShape.selector, 0));
        _sessionCase(_otherChain, abi.encodeWithSelector(IUniversalMarketplaceErrors.ChainMismatch.selector, 0));
    }

    function _otherAsset(UniversalTerms memory t) internal view {
        t.asset = address(pETH);
    }

    function _pcCapUp(UniversalTerms memory t) internal pure {
        t.maxPCPerCall += 1;
    }

    function _extraCall(UniversalTerms memory t) internal view {
        AllowedCall[] memory calls = new AllowedCall[](2);
        calls[0] = t.allowedCalls[0];
        calls[1] =
            AllowedCall({target: pool, selector: WITHDRAW, beneficiaryOffset: 68, hasBeneficiary: true, maxValue: 0});
        t.allowedCalls = calls;
    }

    function _missingCall(UniversalTerms memory t) internal pure {
        t.allowedCalls = new AllowedCall[](0);
    }

    function _valueChanged(UniversalTerms memory t) internal pure {
        t.allowedCalls[0].maxValue = 1;
    }

    function _totalNotPrincipal(UniversalTerms memory t) internal pure {
        t.maxAmountTotal -= 1;
    }

    function _perCallOverPrincipal(UniversalTerms memory t) internal pure {
        t.maxAmountPerCall += 1;
    }

    function _validUntilMoved(UniversalTerms memory t) internal pure {
        t.validUntil += 1;
    }

    function _attackerCEA(UniversalTerms memory t) internal pure {
        t.expectedCEA = address(0xBAD);
    }

    function test_MB03_terms() public {
        _termsCase(_otherAsset, abi.encodeWithSelector(IUniversalMarketplaceErrors.AssetMismatch.selector));
        _termsCase(_pcCapUp, abi.encodeWithSelector(IUniversalMarketplaceErrors.PCCapMismatch.selector));
        _termsCase(_extraCall, abi.encodeWithSelector(IUniversalMarketplaceErrors.ActionsMismatch.selector));
        _termsCase(_missingCall, abi.encodeWithSelector(IUniversalMarketplaceErrors.ActionsMismatch.selector));
        _termsCase(_valueChanged, abi.encodeWithSelector(IUniversalMarketplaceErrors.ActionsMismatch.selector));
        _termsCase(_totalNotPrincipal, abi.encodeWithSelector(IUniversalMarketplaceErrors.CapMismatch.selector));
        _termsCase(_perCallOverPrincipal, abi.encodeWithSelector(IUniversalMarketplaceErrors.CapMismatch.selector));
        _termsCase(_validUntilMoved, abi.encodeWithSelector(IUniversalMarketplaceErrors.ExpiryMismatch.selector));
        (address agw,) = factory.predictWallet(user, 0);
        _termsCase(
            _attackerCEA,
            abi.encodeWithSelector(
                IUniversalMarketplaceErrors.ExpectedCEAMismatch.selector, ceaFactory.computeCEA(agw), address(0xBAD)
            )
        );

        // reordered: a two-call card, the session lists the calls the other way round
        (, IUniversalMarketplace.RulesCardTerms memory two,) = _modified();
        uint256 id = _register(_card(), two, _lendingTemplate());
        IUniversalMarketplace.JobInputs memory job = _inputs(PRINCIPAL);
        UniversalTerms memory t = _termsFor(two, agw, job);
        (t.allowedCalls[0], t.allowedCalls[1]) = (t.allowedCalls[1], t.allowedCalls[0]);
        _expectStart(
            _params(id, 0, job, _session(t)),
            abi.encodeWithSelector(IUniversalMarketplaceErrors.ActionsMismatch.selector)
        );
    }

    function test_MB04_perCallBelowPrincipal_passes() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.JobInputs memory job = _inputs(PRINCIPAL);
        (address agw,) = factory.predictWallet(user, 0);
        UniversalTerms memory t = _termsFor(_rules(), agw, job);
        t.maxAmountPerCall = PRINCIPAL / 4;
        _start(_params(id, 0, job, _session(t)));
    }

    function test_MB05_approvalsNotInSession() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.JobInputs memory job = _inputs(PRINCIPAL);
        (address agw,) = factory.predictWallet(user, 0);
        UniversalTerms memory t = _termsFor(_rules(), agw, job);
        AllowedCall[] memory calls = new AllowedCall[](2);
        calls[0] = t.allowedCalls[0];
        calls[1] = AllowedCall({
            target: usdc, selector: ERC20_APPROVE, beneficiaryOffset: 4, hasBeneficiary: true, maxValue: 0
        }); // the card's approval, granted to the agent
        t.allowedCalls = calls;
        _expectStart(
            _params(id, 0, job, _session(t)),
            abi.encodeWithSelector(IUniversalMarketplaceErrors.ActionsMismatch.selector)
        );
    }

    // ═════════════════════════════ MV · views, admin, upgrade ═════════════════════════════

    function test_MV01_getCard_fullView() public {
        uint256 id = _registerLending();
        vm.prank(admin);
        mkt.verifyAgentCard(id, 1);
        IUniversalMarketplace.CardView memory v = mkt.getCard(id);
        IUniversalMarketplace.AgentCard memory expected = _card();
        expected.provider = provider;
        expected.active = true;
        assertEq(abi.encode(v.card), abi.encode(expected), "card");
        assertEq(v.rulesTerms, abi.encode(_rules()));
        assertEq(v.evaluation, abi.encode(_lendingTemplate()));
        assertEq(v.version, 1);
        assertTrue(v.verified);
        assertFalse(v.adminDisabled);

        IUniversalMarketplace.CardView memory none = mkt.getCard(999);
        IUniversalMarketplace.CardView memory zero;
        assertEq(abi.encode(none), abi.encode(zero), "an unknown card reads all zero");
    }

    function test_MV02_expectedCEAOf() public {
        address agw = makeAddr("anyAGW");
        assertEq(mkt.expectedCEAOf(agw, SEPOLIA_HASH), ceaFactory.computeCEA(agw));
        (address cea,) = ceaFactory.getCEAForPushAccount(agw);
        assertEq(mkt.expectedCEAOf(agw, SEPOLIA_HASH), cea);
        vm.expectRevert(
            abi.encodeWithSelector(IUniversalMarketplaceErrors.ChainNotSupported.selector, bytes32(uint256(1)))
        );
        mkt.expectedCEAOf(agw, bytes32(uint256(1)));
    }

    /// @dev After a destination implementation rotation, the stale config is refused until updated.
    function test_MV03_ceaRotation_staleCaught() public {
        uint256 id = _registerLending();
        address newImpl = makeAddr("ceaProxyImplV2");
        vm.prank(admin);
        ceaFactory.setCEAProxyImplementation(newImpl);
        IUniversalMarketplace.StartJobParams memory p = _ready(id); // an honest SDK signs the NEW CEA
        address agw = p.intent.wallet;
        _expectStart(
            p,
            abi.encodeWithSelector(
                IUniversalMarketplaceErrors.ExpectedCEAMismatch.selector,
                mkt.expectedCEAOf(agw, SEPOLIA_HASH),
                ceaFactory.computeCEA(agw)
            )
        );
        vm.prank(admin);
        mkt.setCEADeployment(SEPOLIA_HASH, address(ceaFactory), newImpl);
        _start(_ready(id)); // re-signed: the criteria's CEA moved too
    }

    function test_MV04_buildCreateJobCalldata() public {
        uint256 id = _registerSwap();
        IUniversalMarketplace.JobInputs memory job = _swapInputs(0.5e18);
        (bytes32 mode, bytes memory cd) = mkt.buildCreateJobCalldata(id, user, 0, job);
        (address agw,) = factory.predictWallet(user, 0);
        assertEq(mode, bytes32(0));
        bytes memory call = abi.encodeCall(
            IAgenticCommerce.createJob,
            (
                provider,
                universalEvaluator,
                uint256(job.expiredAt),
                string(_expectedDescription(_swapTemplate(), id, 1, agw, job)),
                address(hook)
            )
        );
        assertEq(cd, abi.encodePacked(address(kernel), uint256(0), call));

        bytes32 base = keccak256(cd);
        IUniversalMarketplace.JobInputs memory j = _swapInputs(0.5e18);
        j.principal += 1;
        assertTrue(_calldataHash(id, 0, j) != base, "principal");
        j = _swapInputs(0.5e18);
        j.executeBy += 1;
        assertTrue(_calldataHash(id, 0, j) != base, "executeBy");
        j = _swapInputs(0.5e18);
        j.expiredAt += 1;
        assertTrue(_calldataHash(id, 0, j) != base, "expiredAt");
        assertTrue(_calldataHash(id, 0, _swapInputs(0.5e18 + 1)) != base, "params");
        assertTrue(_calldataHash(id, 1, job) != base, "index");
        (, bytes memory otherOwner) = mkt.buildCreateJobCalldata(id, stranger, 0, job);
        assertTrue(keccak256(otherOwner) != base, "owner");
        _modify(id, _card(), _rules(), _swapTemplate());
        assertTrue(_calldataHash(id, 0, job) != base, "card version");

        // what startJob executes is exactly this view's answer
        IUniversalMarketplace.StartJobParams memory p = _readyAt(id, 0, _rules(), job);
        (, address started) = _start(p);
        assertEq(MockAGW(payable(started)).lastExecCalldataHash(), _calldataHash(id, 0, job));

        vm.expectRevert(IUniversalMarketplaceErrors.CardInactive.selector);
        mkt.buildCreateJobCalldata(999, user, 0, job);
    }

    function test_MV05_previewIntent_roundTrips() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        OwnerIntent memory i = p.intent;
        (address agw,) = factory.predictWallet(user, 0);
        assertEq(i.owner, user);
        assertEq(i.wallet, agw);
        assertEq(i.executor, address(mkt));
        assertEq(i.index, 0);
        assertEq(i.sessionHash, keccak256(abi.encode(p.session)));
        assertEq(i.mode, bytes32(0));
        assertEq(i.execCalldataHash, _calldataHash(id, 0, p.job));
        assertEq(i.nonceKey, OWNER_LANE_FLAG);
        assertEq(i.nonceSeq, 0, "fresh wallet");
        assertEq(i.grantNonce, 0, "fresh wallet");
        assertEq(i.deadline, uint48(block.timestamp + 1 hours));
        assertEq(i.signerChainId, 1);
        (uint256 jobId,) = _start(p);

        vm.prank(provider);
        kernel.reject(jobId, bytes32(0), "");
        OwnerIntent memory again = _readyAt(id, 0, _rules(), _inputs(PRINCIPAL)).intent;
        assertEq(again.nonceSeq, 1, "deployed: the live lane");
        assertEq(again.grantNonce, 1, "deployed: the live grant nonce");

        Session memory s;
        vm.expectRevert(IUniversalMarketplaceErrors.CardInactive.selector);
        mkt.previewIntent(
            IUniversalMarketplace.IntentRequest({
                cardId: 999, owner: user, index: 0, job: _inputs(PRINCIPAL), deadline: 0, signerChainId: 1
            }),
            s
        );
    }

    function test_MV06_adminSetters() public {
        vm.prank(stranger);
        vm.expectRevert(_adminRevert(stranger));
        mkt.setHook(address(hook));
        vm.prank(admin);
        vm.expectRevert(IUniversalMarketplaceErrors.ZeroAddress.selector);
        mkt.setHook(address(0));
        vm.prank(admin);
        vm.expectRevert(IUniversalMarketplaceErrors.HookNotWhitelisted.selector);
        mkt.setHook(stranger);
        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.HookUpdated(address(hook));
        vm.prank(admin);
        mkt.setHook(address(hook));

        vm.prank(stranger);
        vm.expectRevert(_adminRevert(stranger));
        mkt.setEvaluator(stranger);
        vm.prank(admin);
        vm.expectRevert(IUniversalMarketplaceErrors.ZeroAddress.selector);
        mkt.setEvaluator(address(0));
        address next = makeAddr("evaluatorV2");
        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.EvaluatorUpdated(next);
        vm.prank(admin);
        mkt.setEvaluator(next);
        assertEq(mkt.evaluator(), next);

        vm.prank(stranger);
        vm.expectRevert(_adminRevert(stranger));
        mkt.setCEADeployment(SEPOLIA_HASH, address(ceaFactory), ceaProxyImpl);
        vm.startPrank(admin);
        vm.expectRevert(IUniversalMarketplaceErrors.ZeroAddress.selector);
        mkt.setCEADeployment(SEPOLIA_HASH, address(0), ceaProxyImpl);
        vm.expectRevert(IUniversalMarketplaceErrors.ZeroAddress.selector);
        mkt.setCEADeployment(SEPOLIA_HASH, address(ceaFactory), address(0));
        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.CEADeploymentSet(SEPOLIA_HASH, address(ceaFactory), ceaProxyImpl);
        mkt.setCEADeployment(SEPOLIA_HASH, address(ceaFactory), ceaProxyImpl);
        vm.stopPrank();

        vm.prank(stranger);
        vm.expectRevert(_adminRevert(stranger));
        mkt.setUniversalPaused(SEPOLIA_HASH, true);
        vm.expectEmit(address(mkt));
        emit IUniversalMarketplace.UniversalChainPaused(SEPOLIA_HASH, true);
        vm.prank(admin);
        mkt.setUniversalPaused(SEPOLIA_HASH, true);
        assertTrue(mkt.universalPaused(SEPOLIA_HASH));
    }

    function test_MV07_pause() public {
        uint256 id = _registerLending();
        IUniversalMarketplace.StartJobParams memory p = _ready(id);
        vm.prank(stranger);
        vm.expectRevert(_adminRevert(stranger));
        mkt.pause();
        vm.prank(admin);
        mkt.pause();

        _expectStart(p, abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector));
        IUniversalMarketplace.AgentCard memory c = _card();
        bytes memory r = abi.encode(_rules());
        bytes memory e = abi.encode(_lendingTemplate());
        vm.prank(provider);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        mkt.registerCard(c, r, e);
        vm.prank(provider);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        mkt.modifyAgentCard(id, c, r, e);

        vm.prank(stranger);
        vm.expectRevert(_adminRevert(stranger));
        mkt.unpause();
        vm.prank(admin);
        mkt.unpause();
        _start(p);
    }

    function _expectInitRevert(IUniversalMarketplace.InitParams memory ip, bytes4 err) internal {
        address impl = address(new UniversalMarketplace());
        vm.expectRevert(err);
        new TransparentUpgradeableProxy(impl, mktAdmin, abi.encodeCall(UniversalMarketplace.initialize, (ip)));
    }

    function test_MV08_initialize() public {
        bytes4 zero = IUniversalMarketplaceErrors.ZeroAddress.selector;
        IUniversalMarketplace.InitParams memory ip = _initParams();
        ip.agwFactory = address(0);
        _expectInitRevert(ip, zero);
        ip = _initParams();
        ip.kernel = address(0);
        _expectInitRevert(ip, zero);
        ip = _initParams();
        ip.hook = address(0);
        _expectInitRevert(ip, zero);
        ip = _initParams();
        ip.evaluator = address(0);
        _expectInitRevert(ip, zero);
        ip = _initParams();
        ip.terms = address(0);
        _expectInitRevert(ip, zero);
        ip = _initParams();
        ip.admin = address(0);
        _expectInitRevert(ip, zero);
        ip = _initParams();
        ip.hook = stranger;
        _expectInitRevert(ip, IUniversalMarketplaceErrors.HookNotWhitelisted.selector);

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        mkt.initialize(_initParams());
        UniversalMarketplace impl = new UniversalMarketplace();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(_initParams());

        assertEq(address(mkt.agwFactory()), address(factory));
        assertEq(address(mkt.kernel()), address(kernel));
        assertEq(mkt.hook(), address(hook));
        assertEq(mkt.evaluator(), universalEvaluator);
        assertEq(address(mkt.terms()), address(terms));
        assertTrue(mkt.hasRole(mkt.ADMIN_ROLE(), admin));
        assertTrue(mkt.hasRole(mkt.DEFAULT_ADMIN_ROLE(), admin));
    }

    /// ⚠️ NEVER-DELETE. Every slot of the reset layout (PRD 09 P6) is pinned by position after an exercise that
    ///    writes every variable, so an insertion, reorder or forgotten gap decrement fails here instead of on the
    ///    first upgrade. Append-only: extend this test, never loosen it.
    function test_MV09_storageLayout_bySlot() public {
        uint256 id = _registerLending();
        uint256 id2 = _registerLending();
        (uint256 jobId, address agw) = _start(_ready(id));
        _modify(id, _card(), _rules(), _lendingTemplate()); // version 2
        vm.startPrank(admin);
        mkt.verifyAgentCard(id, 2);
        mkt.setUniversalPaused(SEPOLIA_HASH, true);
        mkt.adminDisableCard(id2);
        vm.stopPrank();

        address m = address(mkt);
        assertEq(_word(m, 0), uint256(uint160(address(factory))), "0 agwFactory");
        assertEq(_word(m, 1), uint256(uint160(address(kernel))), "1 kernel");
        assertEq(_word(m, 2), uint256(uint160(address(hook))), "2 hook");
        assertEq(_word(m, 3), uint256(uint160(universalEvaluator)), "3 evaluator");
        assertEq(vm.load(m, bytes32(uint256(4))), mkt.pushChainHash(), "4 pushChainHash");
        assertEq(_word(m, 5), uint256(uint160(address(terms))), "5 terms");
        assertEq(_word(m, 6), 2, "6 cardCount");

        // mappings: the entry lives at keccak256(key ‖ slot); a long `bytes` stores 2·length + 1
        assertEq(_entry(m, id, 7), uint256(uint160(provider)), "7 _cards[id].provider");
        assertEq(_entry(m, id, 8), abi.encode(_rules()).length * 2 + 1, "8 _rulesTerms");
        assertEq(_entry(m, id, 9), abi.encode(_lendingTemplate()).length * 2 + 1, "9 _evaluations");
        assertEq(_entry(m, id, 10), 2, "10 cardVersion");
        assertEq(_entry(m, id2, 10), 1, "10 cardVersion (unmodified)");
        assertEq(_entry(m, id, 11), 1, "11 cardVerified");
        assertEq(_entry(m, id2, 12), 1, "12 adminDisabled");
        assertEq(
            uint256(vm.load(m, keccak256(abi.encode(SEPOLIA_HASH, uint256(13))))),
            uint256(uint160(address(ceaFactory))),
            "13 ceaDeployment.ceaFactory"
        );
        assertEq(uint256(vm.load(m, keccak256(abi.encode(SEPOLIA_HASH, uint256(14))))), 1, "14 universalPaused");
        assertEq(uint256(vm.load(m, keccak256(abi.encode(agw, uint256(15))))), jobId, "15 lastJobOf");
        assertEq(_entry(m, jobId, 16), id, "16 cardOfJob");
        assertEq(_entry(m, jobId, 17), uint256(uint160(agw)), "17 agwOfJob");
        assertEq(
            vm.load(m, keccak256(abi.encode(jobId, uint256(18)))), MockAGW(payable(agw)).RULES_ID(), "18 rulesOfJob"
        );
        for (uint256 slot = 7; slot <= 18; ++slot) {
            assertEq(_word(m, slot), 0, "a mapping's base slot is never written");
        }
        for (uint256 slot = 19; slot <= 49; ++slot) {
            assertEq(_word(m, slot), 0, "gap (19-48) or slot 49 written");
        }
    }

    function _word(address m, uint256 slot) internal view returns (uint256) {
        return uint256(vm.load(m, bytes32(slot)));
    }

    function _entry(address m, uint256 key, uint256 slot) internal view returns (uint256) {
        return uint256(vm.load(m, keccak256(abi.encode(key, slot))));
    }

    function test_MV10_upgrade_preservesState() public {
        uint256 id = _registerLending();
        (uint256 jobId, address agw) = _start(_ready(id));
        _modify(id, _card(), _rules(), _lendingTemplate());
        bytes memory viewBefore = abi.encode(mkt.getCard(id));

        UniversalMarketplace next = new UniversalMarketplace();
        vm.prank(mktAdmin);
        ProxyAdmin(_proxyAdmin(address(mkt)))
            .upgradeAndCall(ITransparentUpgradeableProxy(address(mkt)), address(next), "");
        assertEq(address(uint160(uint256(vm.load(address(mkt), ERC1967Utils.IMPLEMENTATION_SLOT)))), address(next));

        assertEq(abi.encode(mkt.getCard(id)), viewBefore, "card, blobs, version and tags intact");
        assertEq(mkt.cardCount(), 1);
        assertEq(mkt.lastJobOf(agw), jobId);
        assertEq(mkt.cardOfJob(jobId), id);
        assertEq(mkt.agwOfJob(jobId), agw);
        assertEq(mkt.rulesOfJob(jobId), MockAGW(payable(agw)).RULES_ID());
        assertEq(mkt.evaluator(), universalEvaluator);
        _start(_ready(id)); // and it still starts jobs
    }
}
