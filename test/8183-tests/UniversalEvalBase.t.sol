// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {KernelBase} from "./KernelBase.t.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {UniversalCallback} from "../../src/UniversalCallback.sol";
import {PendingRead, RequestStatus, ReadSpec} from "../../src/libraries/ReadTypes.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {
    JobSpec,
    Read,
    Check,
    Logic,
    Evaluation,
    Operation,
    LogicKind,
    AllowedMutability,
    ReadAt,
    T_TUPLE,
    T_UINT,
    T_ADDRESS
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {ReadConfig} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {MockAGWFactory} from "./mocks/MockAGWFactory.sol";
import {MockSmartSession} from "./mocks/MockSmartSession.sol";
import {MockCheckpointAGW} from "./mocks/MockCheckpointAGW.sol";
import {MockReadCore} from "./mocks/MockReadCore.sol";
import {MockVaultPC} from "../mocks/MockVaultPC.sol";

/// @notice Shared fixture: the real kernel and the real Read State contract, the UniversalHook and the
///         UniversalEvaluator behind Transparent proxies, a wallet with the AGW's checkpoint counter, and helpers
///         that drive a job from creation to verdict. PRE_EXECUTION reads are sent inside `fund`, POST_EXECUTION
///         reads by `submit`.
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
    UniversalEvaluator internal ueImpl;
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
    /// @dev The swap spec's PRE_EXECUTION read; its POST_EXECUTION read is 0.
    uint256 internal constant SWAP_PRE = 1;

    string internal constant NS = "eip155";
    string internal constant BASE = "8453";
    string internal constant BASE_KEY = "eip155:8453";
    uint256 internal constant READ_FEE = 0.01 ether;
    uint256 internal constant BASE_FEE = 1 gwei;
    uint64 internal constant START_HEIGHT = 30_000_000;
    /// @dev One evaluation read's price: protocol fee + 1M callback gas × base fee × 3.
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

    /// @dev An evaluator proxy over `ueImpl`, initialised with these settings.
    function _newEvaluator(
        address kernel_,
        address hook_,
        address readState_,
        address core_,
        address feeRecipient_,
        ReadConfig memory c
    ) internal returns (UniversalEvaluator) {
        bytes memory init =
            abi.encodeCall(UniversalEvaluator.initialize, (kernel_, hook_, readState_, core_, feeRecipient_, c));
        return UniversalEvaluator(address(new TransparentUpgradeableProxy(address(ueImpl), proxyAdminOwner, init)));
    }

    /// @dev The hook and the evaluator each need the other's address: the evaluator proxy's is predicted from this
    ///      contract's nonce, the hook proxy is initialised with it in its own constructor, then the evaluator proxy
    ///      is deployed at that address.
    function _deployPair() internal virtual {
        UniversalHook hookImpl = new UniversalHook();
        ueImpl = new UniversalEvaluator();
        address predictedEvaluator = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);

        bytes memory hookInit = abi.encodeCall(
            UniversalHook.initialize, (address(kernel), address(factory), address(engine), predictedEvaluator)
        );
        hook = UniversalHook(address(new TransparentUpgradeableProxy(address(hookImpl), proxyAdminOwner, hookInit)));

        ue = _newEvaluator(address(kernel), address(hook), address(readState), address(core), feeRecipient, _config());
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
            field: _u8(0),
            at: ReadAt.POST_EXECUTION
        });
    }

    /// @dev An empty check side.
    function _none() internal pure returns (uint8[] memory) {}

    function _pre(Read memory r) internal pure returns (Read memory) {
        r.at = ReadAt.PRE_EXECUTION;
        return r;
    }

    function _single(Read memory r) internal pure returns (Read[] memory x) {
        x = new Read[](1);
        x[0] = r;
    }

    /// @dev Moves a read to another chain, in place.
    function _on(Read memory r, string memory chainId) internal pure returns (Read memory) {
        r.chainId = chainId;
        return r;
    }

    /// @dev Aave v3 `getReserveData`-shaped return: one struct of 15 static fields.
    function _reserveOutputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            T_TUPLE,
            uint8(1),
            T_TUPLE,
            uint8(15),
            T_TUPLE,
            uint8(1),
            T_UINT,
            T_UINT,
            T_UINT,
            T_UINT,
            T_UINT,
            T_UINT,
            T_UINT,
            T_UINT,
            T_ADDRESS,
            T_ADDRESS,
            T_ADDRESS,
            T_ADDRESS,
            T_UINT,
            T_UINT,
            T_UINT
        );
    }

    function _reserveAnswer(uint256 rate) internal pure returns (bytes memory) {
        uint256[15] memory w;
        w[2] = rate;
        return abi.encode(w);
    }

    function _checkLogic(uint8 check) internal pure returns (Logic memory) {
        return Logic({kind: LogicKind.CHECK, check: check, children: new uint8[](0), k: 0});
    }

    /// @notice "The CEA receives at least 0.38 WETH": the balance after (read 0) minus before (read 1). Not replaceable.
    function _swapSpec() internal view returns (JobSpec memory s) {
        s.executeBy = uint64(block.timestamp + 1 hours);
        s.failFinalAt = uint64(block.timestamp + 2 hours);
        s.reads = new Read[](2);
        s.reads[0] = _balanceRead(weth, cea);
        s.reads[SWAP_PRE] = _pre(_balanceRead(weth, cea));
        s.checks = new Check[](1);
        s.checks[0] = Check({
            left: _u8(0),
            right: _u8(1),
            evaluation: Evaluation.NUMBER,
            operation: Operation.GREATER_OR_EQUAL,
            target: 0.38e18
        });
        s.logic = new Logic[](1);
        s.logic[0] = _checkLogic(0);
        s.allowedMutability = AllowedMutability.NONE;
    }

    /// @notice "Deposited into Aave OR Morpho": two COMPARE reads under ANY. No snapshot.
    function _anySpec() internal view returns (JobSpec memory s) {
        s.executeBy = uint64(block.timestamp + 1 hours);
        s.failFinalAt = uint64(block.timestamp + 2 hours);
        s.reads = new Read[](2);
        s.reads[0] = _balanceRead(ausdc, cea);
        s.reads[1] = _balanceRead(morphoVault, cea);
        s.checks = new Check[](2);
        s.checks[0] = Check({
            left: _u8(0),
            right: _none(),
            evaluation: Evaluation.COMPARE,
            operation: Operation.GREATER_OR_EQUAL,
            target: 99.99e6
        });
        s.checks[1] = Check({
            left: _u8(1),
            right: _none(),
            evaluation: Evaluation.COMPARE,
            operation: Operation.GREATER_OR_EQUAL,
            target: 99.99e6
        });
        s.logic = new Logic[](3);
        s.logic[0] = Logic({kind: LogicKind.ANY, check: 0, children: _u8(1, 2), k: 0});
        s.logic[1] = _checkLogic(0);
        s.logic[2] = _checkLogic(1);
        s.allowedMutability = AllowedMutability.NONE;
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

    /// @notice The funding batch: prepay the snapshot and one round of POST reads, then fund.
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
        assertTrue(_deliver(ue.requestOf(jobId, read), abi.encode(value)), "snapshot not delivered");
    }

    function _answer(uint256 jobId, uint256 read, bytes memory result) internal {
        assertTrue(_deliver(ue.requestOf(jobId, read), result), "answer not delivered");
    }

    /// @notice A swap job, funded and snapshotted at `before`; the chain moves on (the swap lands), then it is submitted.
    function _submittedSwap(uint256 before) internal returns (uint256 jobId) {
        jobId = _createSpec(_swapSpec());
        _fund(jobId);
        _answerSnapshot(jobId, SWAP_PRE, before);
        _advance();
        _submit(jobId);
    }

    /// @notice Tracks `chainId` next to Base: same start height and read fee.
    function _track(string memory chainId) internal {
        core.setReadBaseFee(NS, chainId, READ_FEE);
        core.setChainHeight(string.concat(NS, ":", chainId), START_HEIGHT);
    }

    /// @notice Moves `chainId`'s tracked height on by 120 blocks, observed now.
    function _move(string memory chainId) internal {
        string memory key = string.concat(NS, ":", chainId);
        core.setChainHeight(key, core.chainHeightByChainNamespace(key) + 120);
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
