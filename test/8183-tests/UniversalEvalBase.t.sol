// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {KernelBase} from "./KernelBase.t.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {UniversalEvaluatorLogic} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluatorLogic.sol";
import {UniversalCallback} from "../../src/UniversalCallback.sol";
import {PendingRead, RequestStatus, ReadSpec} from "../../src/libraries/ReadTypes.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {
    JobSpec,
    Read,
    Check,
    Node,
    EvalType,
    Op,
    NodeKind,
    Mutability,
    T_TUPLE,
    T_UINT
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {ReadConfig} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {MockAGWFactory} from "./mocks/MockAGWFactory.sol";
import {MockSmartSession} from "./mocks/MockSmartSession.sol";
import {MockCheckpointAGW} from "./mocks/MockCheckpointAGW.sol";
import {MockReadCore} from "./mocks/MockReadCore.sol";
import {MockVaultPC} from "../mocks/MockVaultPC.sol";

/// @notice Shared fixture: the real kernel and the real Read State contract, the UniversalHook and the
///         UniversalEvaluator behind Transparent proxies, a wallet with the AGW's checkpoint counter, and helpers
///         that drive a job from creation to verdict. The snapshot is taken inside `fund`; the "after" reads are
///         sent by `submit`.
/// @dev - `_deliver` plays the node: it refuses a request whose callback budget does not cover
///        `callbackGasLimit × base fee` (`x/ucallback/keeper/evm.go`, `CanAffordCallback`), then calls
///        `fulfillExternalCallback` as the Read State module.
///      - Addresses for tokens and the CEA are labels, not real deployments.
abstract contract UniversalEvalBase is KernelBase {
    UniversalCallback internal readState;
    MockReadCore internal core;
    MockVaultPC internal vaultPC;
    MockAGWFactory internal factory;
    MockSmartSession internal engine;
    UniversalHook internal hook;
    UniversalEvaluator internal ue;
    UniversalEvaluatorLogic internal logic;
    MockCheckpointAGW internal agw;

    address internal owner = makeAddr("owner");
    address internal feeRecipient = makeAddr("feeRecipient");
    address internal readAdmin = makeAddr("readAdmin");
    address internal proxyAdminOwner = makeAddr("proxyAdminOwner");
    address internal weth = makeAddr("WETH");
    address internal ausdc = makeAddr("aUSDC");
    address internal cea = makeAddr("CEA");
    address internal morphoVault = makeAddr("morphoVault");

    address internal constant READ_MODULE = 0x07a0258D367A4A4cd9d6E4b7eEE8E7eF491CC519;
    bytes32 internal constant RULES = keccak256("rules");

    string internal constant NS = "eip155";
    string internal constant BASE = "8453";
    string internal constant BASE_KEY = "eip155:8453";
    uint256 internal constant READ_FEE = 0.01 ether;
    uint256 internal constant BASE_FEE = 1 gwei;
    uint64 internal constant START_HEIGHT = 30_000_000;
    /// @dev One "after" read's price: protocol fee + 1M callback gas × base fee × 3.
    uint256 internal constant READ_COST = READ_FEE + 1_000_000 * BASE_FEE * 3;
    /// @dev One snapshot read's price: protocol fee + 300k callback gas × base fee × 3.
    uint256 internal constant SNAPSHOT_COST = READ_FEE + 300_000 * BASE_FEE * 3;

    function setUp() public virtual override {
        super.setUp();
        vm.fee(BASE_FEE);

        core = new MockReadCore();
        core.setReadBaseFee(NS, BASE, READ_FEE);
        core.setChainHeight(BASE_KEY, START_HEIGHT);
        vaultPC = new MockVaultPC();

        UniversalCallback readImpl = new UniversalCallback();
        readState = UniversalCallback(
            payable(address(
                    new ERC1967Proxy(
                        address(readImpl),
                        abi.encodeCall(UniversalCallback.initialize, (address(core), address(vaultPC), readAdmin))
                    )
                ))
        );

        factory = new MockAGWFactory();
        engine = new MockSmartSession();
        agw = new MockCheckpointAGW(owner);
        factory.setWallet(address(agw), true);
        engine.setPermission(RULES, address(agw), true);

        _deployPair();

        vm.prank(admin);
        kernel.setHookWhitelist(address(hook), true);

        token.mint(address(agw), 1e15);
        vm.prank(owner);
        agw.execute(address(token), 0, abi.encodeCall(IERC20.approve, (address(kernel), type(uint256).max)));

        vm.deal(address(agw), 100 ether);
        vm.deal(provider, 100 ether);
        vm.deal(stranger, 100 ether);
    }

    // ───────────── deployment ─────────────

    function _config() internal pure returns (ReadConfig memory) {
        return ReadConfig({
            readTtl: 300,
            callbackGasLimit: 1_000_000,
            snapshotCallbackGasLimit: 300_000,
            budgetMultiplier: 3,
            maxHeightAge: 1 hours,
            maxConfirmations: 64 // a test value: the specs here ask for 3 or 12
        });
    }

    /// @dev The hook and the evaluator each need the other's address. The evaluator is not upgradeable, so its
    ///      address is predicted from this contract's nonce, the hook proxy is initialised with it in its own
    ///      constructor, and the evaluator is then deployed at that address.
    function _deployPair() internal virtual {
        logic = new UniversalEvaluatorLogic();
        UniversalHook hookImpl = new UniversalHook();
        address predictedEvaluator = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);

        bytes memory hookInit = abi.encodeCall(
            UniversalHook.initialize, (address(kernel), address(factory), address(engine), predictedEvaluator)
        );
        hook = UniversalHook(address(new TransparentUpgradeableProxy(address(hookImpl), proxyAdminOwner, hookInit)));

        ue = new UniversalEvaluator(
            address(kernel), address(hook), address(readState), address(core), address(logic), feeRecipient, _config()
        );
        require(address(ue) == predictedEvaluator, "evaluator address prediction");
    }

    // ───────────── specs ─────────────

    function _u8(uint8 a) internal pure returns (uint8[] memory x) {
        x = new uint8[](1);
        x[0] = a;
    }

    function _u8(uint8 a, uint8 b) internal pure returns (uint8[] memory x) {
        x = new uint8[](2);
        x[0] = a;
        x[1] = b;
    }

    function _balanceRead(address target, address account) internal pure returns (Read memory) {
        return Read({
            chainNamespace: NS,
            chainId: BASE,
            minConfirmations: 3,
            target: target,
            selector: IERC20.balanceOf.selector,
            args: abi.encode(account),
            outputs: abi.encodePacked(T_TUPLE, uint8(1), T_UINT),
            field: _u8(0)
        });
    }

    function _checkNode(uint8 check) internal pure returns (Node memory) {
        return Node({kind: NodeKind.CHECK, check: check, children: new uint8[](0), k: 0});
    }

    /// @notice "The CEA receives at least 0.38 WETH": one read, one NUM check. Not replaceable.
    function _swapSpec() internal view returns (JobSpec memory s) {
        s.executeBy = uint64(block.timestamp + 1 hours);
        s.failFinalAt = uint64(block.timestamp + 2 hours);
        s.reads = new Read[](1);
        s.reads[0] = _balanceRead(weth, cea);
        s.checks = new Check[](1);
        s.checks[0] = Check({read: 0, evalType: EvalType.NUM, op: Op.GTE, target: 0.38e18});
        s.nodes = new Node[](1);
        s.nodes[0] = _checkNode(0);
        s.mutability = Mutability.NONE;
    }

    /// @notice "Deposited into Aave OR Morpho": two CMP reads under ANY. No snapshot.
    function _anySpec() internal view returns (JobSpec memory s) {
        s.executeBy = uint64(block.timestamp + 1 hours);
        s.failFinalAt = uint64(block.timestamp + 2 hours);
        s.reads = new Read[](2);
        s.reads[0] = _balanceRead(ausdc, cea);
        s.reads[1] = _balanceRead(morphoVault, cea);
        s.checks = new Check[](2);
        s.checks[0] = Check({read: 0, evalType: EvalType.CMP, op: Op.GTE, target: 99.99e6});
        s.checks[1] = Check({read: 1, evalType: EvalType.CMP, op: Op.GTE, target: 99.99e6});
        s.nodes = new Node[](3);
        s.nodes[0] = Node({kind: NodeKind.ANY, check: 0, children: _u8(1, 2), k: 0});
        s.nodes[1] = _checkNode(0);
        s.nodes[2] = _checkNode(1);
        s.mutability = Mutability.NONE;
    }

    // ───────────── lifecycle helpers ─────────────

    function _createSpec(JobSpec memory s) internal returns (uint256 jobId) {
        return _createDescription(string(abi.encode(s)));
    }

    /// @notice Creates the job and has the provider price it (no spec replacement).
    function _createDescription(string memory description) internal returns (uint256 jobId) {
        vm.prank(owner);
        agw.execute(
            address(kernel),
            0,
            abi.encodeCall(kernel.createJob, (provider, address(ue), _expiry(), description, address(hook)))
        );
        jobId = kernel.jobCounter();
        vm.prank(provider);
        kernel.setBudget(jobId, BUDGET, "");
    }

    function _prefund(uint256 jobId, uint256 amount) internal {
        vm.prank(owner);
        agw.execute(address(ue), amount, abi.encodeCall(ue.prefund, (jobId)));
    }

    /// @notice What the client signs at `fund`: its rules set, the hash of the spec it agreed to, and no replacement.
    function _fundParams(uint256 jobId) internal view returns (bytes memory) {
        return abi.encode(RULES, keccak256(bytes(kernel.getJob(jobId).description)), bytes(""));
    }

    function _fundWith(uint256 jobId, bytes memory optParams) internal {
        vm.prank(owner);
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (jobId, BUDGET, optParams)));
    }

    /// @notice The funding batch: prepay the snapshot and one round of "after" reads, then fund.
    function _fund(uint256 jobId) internal {
        (uint256 snap, uint256 eval_) = ue.prefundCost(jobId);
        _prefund(jobId, snap + eval_);
        _fundWith(jobId, _fundParams(jobId));
    }

    /// @notice The provider submits; the evaluator fixes the end blocks and sends the reads.
    function _submit(uint256 jobId) internal {
        vm.prank(provider);
        kernel.submit(jobId, keccak256("done"), "");
    }

    /// @notice Plays the node for one request. Returns false where the node would not deliver.
    function _deliver(uint256 requestId, bytes memory result) internal returns (bool) {
        if (readState.statusOf(requestId) != RequestStatus.PENDING) return false;
        PendingRead memory p = readState.getPendingRead(requestId);
        if (p.callbackBudget < uint256(p.callbackGasLimit) * block.basefee) return false;
        vm.prank(READ_MODULE);
        readState.fulfillExternalCallback(requestId, result);
        return true;
    }

    function _answerSnapshot(uint256 jobId, uint256 read, uint256 value) internal {
        assertTrue(_deliver(ue.snapshotRequestOf(jobId, read), abi.encode(value)), "snapshot not delivered");
    }

    function _answer(uint256 jobId, uint256 read, bytes memory result) internal {
        assertTrue(_deliver(ue.requestOf(jobId, read), result), "answer not delivered");
    }

    /// @notice A swap job, funded and snapshotted at `before`; the chain moves on (the swap lands), then it is submitted.
    function _submittedSwap(uint256 before) internal returns (uint256 jobId) {
        jobId = _createSpec(_swapSpec());
        _fund(jobId);
        _answerSnapshot(jobId, 0, before);
        _advance();
        _submit(jobId);
    }

    /// @notice The chain moves on by 120 blocks, observed now: the provider's work lands after `fund`. Every real
    ///         `submit` needs this, since an end block must be above the height recorded at `fund`.
    function _advance() internal {
        core.setChainHeight(BASE_KEY, core.chainHeightByChainNamespace(BASE_KEY) + 120);
    }

    /// @dev Finds the ReadSpec of `requestId` in the recorded `ReadRequested` logs.
    function _readSpecFromLogs(uint256 requestId) internal returns (ReadSpec memory spec) {
        bytes32 topic = IUniversalCallback.ReadRequested.selector;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics.length > 1 && logs[i].topics[0] == topic && uint256(logs[i].topics[1]) == requestId) {
                (spec,,,,) = abi.decode(logs[i].data, (ReadSpec, uint64, uint256, uint256, uint256));
                return spec;
            }
        }
        revert("ReadRequested not found");
    }
}
