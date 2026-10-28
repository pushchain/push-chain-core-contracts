// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {KernelBase} from "../KernelBase.t.sol";
import {UniversalCallback} from "../../../src/UniversalCallback.sol";
import {PendingRead, RequestStatus} from "../../../src/libraries/ReadTypes.sol";
import {UniversalTxRequest} from "../../../src/interfaces/IUniversalGateway.sol";
import {UniversalPayload, UniversalAccountId} from "../../../src/libraries/Types.sol";
import {IUEA} from "../../../src/interfaces/IUEA.sol";
import {UEA_EVM} from "../../../src/uea/UEA_EVM.sol";
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
    T_UINT
} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {ReadConfig} from "../../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {EvaluationGateway} from "../../../src/agentic-commerce-8183/remote/EvaluationGateway.sol";
import {RemoteEvaluator} from "../../../src/agentic-commerce-8183/remote/RemoteEvaluator.sol";
import {NoopHook} from "../../../src/agentic-commerce-8183/remote/NoopHook.sol";
import {InboundSender} from "../../../src/agentic-commerce-8183/remote/InboundSender.sol";
import {
    PushFees,
    LAYOUT_V,
    RemoteKeys,
    UniversalOutboundTxRequest
} from "../../../src/agentic-commerce-8183/remote/RemoteTypes.sol";
import {MockVaultPC} from "../../mocks/MockVaultPC.sol";
import {
    MockRemoteGateway,
    MockRemoteVault,
    MockCEAFactory,
    MockBalances,
    MockUEAFactory,
    MockRemoteCore,
    MockUGPC
} from "./RemoteMocks.sol";

/// @notice Both chains in one EVM: the remote side (Push's Phase 1 kernel as a layout-V kernel, the gateway) and Push
///         (the RemoteEvaluator, the real Read State contract). Helpers play the network:
///         - `_inbound` runs the gateway's last inbound as the node does: the executor module calls
///           `executeUniversalTx` on the sender's UEA, a real `UEA_EVM` (with its nonce rule), which calls `to` with
///           `value`;
///         - `_deliver` runs a Read State answer as the callback module, which is also `tx.origin` for the callback;
///         - `_outbound` runs the evaluator's last outbound as its CEA on the remote chain.
/// @dev The running example of the Phase 2 plan: Alice (client) hires Bob (provider) to put 600 USDC into Aave and 400
///      into a Morpho vault for her on Base Sepolia (chain 84532). Reads 0, 1 are after the work, 2, 3 before it.
abstract contract RemoteBase is KernelBase {
    // remote chain
    MockRemoteGateway internal ugw;
    MockCEAFactory internal ceaFactory;
    MockRemoteVault internal vault;
    NoopHook internal noop;
    EvaluationGateway internal gw;
    MockBalances internal ausdc;
    MockBalances internal morpho;
    // Push
    MockUEAFactory internal ueaFactory;
    MockRemoteCore internal core;
    MockVaultPC internal vaultPC;
    UniversalCallback internal readState;
    MockUGPC internal ugpc;
    RemoteEvaluator internal re;

    address internal feeRecipient = makeAddr("feeRecipient");
    address internal proxyAdminOwner = makeAddr("proxyAdminOwner");
    address internal readAdmin = makeAddr("readAdmin");
    address internal evaluatorCEA = makeAddr("evaluatorCEA");
    address internal gasToken = makeAddr("pETH.base");

    address internal constant READ_MODULE = 0x07a0258D367A4A4cd9d6E4b7eEE8E7eF491CC519;
    address internal constant UE_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    string internal constant NS = "eip155";
    string internal constant CHAIN = "84532";
    string internal constant CHAIN_KEY = "eip155:84532";
    string internal constant ARB = "421614";
    string internal constant ARB_KEY = "eip155:421614";

    // the bytes a caller of `sendReads` / `sendVerdict` supplies, kept as the test sends and answers
    bytes internal lastSpec;
    bytes[] internal lastPre;
    bytes[] internal lastVerify; // the values the gateway read inside `verify`
    mapping(bytes32 => mapping(uint256 => bytes)) internal delivered;
    // a sender on the remote chain => its UEA on Push
    mapping(address => address) internal ueaOf;
    // the InboundSender creation code hash, as this build compiles it (the gateway's `senderCodeHash()`)
    bytes32 internal senderCodeHash = keccak256(type(InboundSender).creationCode);
    uint256 internal constant READ_GAS = 200_000;
    uint256 internal constant SETTLE_WINDOW = 15 minutes;
    uint64 internal constant SETTLE_GAS = 700_000;
    uint256 internal constant READ_FEE = 0.01 ether;
    uint256 internal constant BASE_FEE = 1 gwei;
    uint256 internal constant OUTBOUND_FEE = 0.05 ether;
    /// @dev One POST read's price: protocol fee + 1M callback gas × base fee × 3.
    uint256 internal constant READ_COST = READ_FEE + 1_000_000 * BASE_FEE * 3;
    uint256 internal constant PC_FOR_JOB = 1 ether;
    uint256 internal constant INBOUND_GAS = 0.001 ether;

    function setUp() public virtual override {
        vm.chainId(84532);
        super.setUp();
        vm.fee(BASE_FEE);
        vm.roll(1_000);

        // Push
        ueaFactory = new MockUEAFactory();
        core = new MockRemoteCore();
        core.setReadBaseFee(NS, CHAIN, READ_FEE);
        core.setReadBaseFee(NS, ARB, READ_FEE);
        core.setGasToken(CHAIN_KEY, gasToken);
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
        ugpc = new MockUGPC();
        ugpc.setFee(OUTBOUND_FEE);

        // remote chain
        ugw = new MockRemoteGateway();
        ceaFactory = new MockCEAFactory();
        vault = new MockRemoteVault(address(ceaFactory));
        ugw.setVault(address(vault));
        noop = new NoopHook();
        ausdc = new MockBalances();
        morpho = new MockBalances();

        _deployPair();

        ceaFactory.set(evaluatorCEA, address(re));

        vm.prank(admin);
        kernel.setHookWhitelist(address(noop), true);
        vm.deal(provider, 100 ether);
        vm.deal(client, 100 ether);
        vm.deal(stranger, 100 ether);
    }

    // ───────────── deployment ─────────────

    function _readConfig() internal pure returns (ReadConfig memory) {
        return ReadConfig({
            readTtl: 300,
            callbackGasLimit: 1_000_000,
            snapshotCallbackGasLimit: 300_000,
            budgetMultiplier: 3,
            maxHeightAge: 1 hours,
            maxConfirmations: 64
        });
    }

    function _gatewayConfig(address remoteEvaluator, address[] memory kernels, uint8[] memory layouts, uint256 readGas)
        internal
        view
        returns (EvaluationGateway.Config memory)
    {
        return EvaluationGateway.Config({
            universalGateway: address(ugw),
            remoteEvaluator: remoteEvaluator,
            noopHook: address(noop),
            feeRecipient: feeRecipient,
            readGas: readGas,
            minSettleWindow: SETTLE_WINDOW,
            maxConfirmations: 64,
            kernels: kernels,
            layouts: layouts
        });
    }

    /// @dev Each needs the other's address: the gateway proxy's is predicted from this contract's nonce.
    function _deployPair() internal {
        RemoteEvaluator reImpl = new RemoteEvaluator();
        EvaluationGateway gwImpl = new EvaluationGateway();
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);

        RemoteEvaluator.Remote[] memory remotes = new RemoteEvaluator.Remote[](1);
        remotes[0] = RemoteEvaluator.Remote({
            chainId: CHAIN, gateway: predicted, settleGasLimit: SETTLE_GAS, senderCodeHash: gwImpl.senderCodeHash()
        });
        RemoteEvaluator.Config memory rc = RemoteEvaluator.Config({
            ueaFactory: address(ueaFactory),
            universalGatewayPC: address(ugpc),
            readState: address(readState),
            universalCore: address(core),
            read: _readConfig(),
            remotes: remotes
        });
        re = RemoteEvaluator(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(reImpl), proxyAdminOwner, abi.encodeCall(RemoteEvaluator.initialize, (rc))
                    )
                ))
        );

        address[] memory kernels = new address[](1);
        kernels[0] = address(kernel);
        uint8[] memory layouts = new uint8[](1);
        layouts[0] = LAYOUT_V;
        gw = EvaluationGateway(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(gwImpl),
                        proxyAdminOwner,
                        abi.encodeCall(
                            EvaluationGateway.initialize, (_gatewayConfig(address(re), kernels, layouts, READ_GAS))
                        )
                    )
                ))
        );
        require(address(gw) == predicted, "gateway address prediction");
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

    function _none() internal pure returns (uint8[] memory) {}

    function _balanceRead(address target, address account, ReadAt at) internal pure returns (Read memory) {
        return Read({
            chainNamespace: NS,
            chainId: CHAIN,
            minConfirmations: 3,
            target: target,
            selector: IERC20.balanceOf.selector,
            args: abi.encode(account),
            outputs: abi.encodePacked(T_TUPLE, uint8(1), T_UINT),
            field: _u8(0),
            at: at
        });
    }

    function _checkLogic(uint8 check) internal pure returns (Logic memory) {
        return Logic({kind: LogicKind.COMPARE, check: check, children: new uint8[](0), k: 0});
    }

    /// @notice The running example: aUSDC up by 600 and the Morpho position up by 400, both for Alice (`client`).
    function _exampleSpec() internal view returns (JobSpec memory s) {
        s.reads = new Read[](4);
        s.reads[0] = _balanceRead(address(ausdc), client, ReadAt.POST_EXECUTION);
        s.reads[1] = _balanceRead(address(morpho), client, ReadAt.POST_EXECUTION);
        s.reads[2] = _balanceRead(address(ausdc), client, ReadAt.PRE_EXECUTION);
        s.reads[3] = _balanceRead(address(morpho), client, ReadAt.PRE_EXECUTION);
        s.checks = new Check[](2);
        s.checks[0] = Check({
            left: _u8(0),
            right: _u8(2),
            evaluation: Evaluation.NUMBER,
            operation: Operation.GREATER_OR_EQUAL,
            target: 600e6
        });
        s.checks[1] = Check({
            left: _u8(1),
            right: _u8(3),
            evaluation: Evaluation.NUMBER,
            operation: Operation.GREATER_OR_EQUAL,
            target: 400e6
        });
        s.logic = new Logic[](3);
        s.logic[0] = Logic({kind: LogicKind.ALL, check: 0, children: _u8(1, 2), k: 0});
        s.logic[1] = _checkLogic(0);
        s.logic[2] = _checkLogic(1);
        s.allowedMutability = AllowedMutability.NONE;
    }

    // ───────────── the job's parties ─────────────

    function _fees() internal pure returns (PushFees memory) {
        return PushFees({pcForJob: PC_FOR_JOB, gasLimit: 5_000_000, maxFeePerGas: 10 gwei});
    }

    function _noFees() internal pure returns (PushFees memory f) {}

    function _create(JobSpec memory s, address hook_) internal returns (uint256 jobId) {
        vm.prank(client);
        jobId = kernel.createJob(provider, address(gw), _expiry(), string(abi.encode(s)), hook_);
        vm.prank(provider);
        kernel.setBudget(jobId, BUDGET, "");
    }

    function _fund(uint256 jobId) internal {
        vm.prank(client);
        kernel.fund(jobId, BUDGET, "");
    }

    /// @notice Alice takes the snapshot; returns the PRE answers from the event. `value` pays the snapshot inbound,
    ///         needed only when the criteria have PRE reads on other chains.
    function _snapshot(uint256 jobId) internal returns (bytes[] memory pre) {
        return _snapshotPaying(jobId, 0);
    }

    function _snapshotPaying(uint256 jobId, uint256 value) internal returns (bytes[] memory pre) {
        vm.recordLogs();
        vm.prank(client);
        gw.snapshot{value: value}(kernel_(), jobId, value == 0 ? _noFees() : _fees());
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == EvaluationGateway.Snapshotted.selector) {
                (,, pre) = abi.decode(logs[i].data, (bytes32, uint64, bytes[]));
                delete lastPre;
                for (uint256 k; k < pre.length; ++k) {
                    lastPre.push(pre[k]);
                }
                return pre;
            }
        }
        revert("no Snapshotted event");
    }

    function kernel_() internal view returns (address) {
        return address(kernel);
    }

    /// @notice Bob's work: 600 aUSDC and a 400 Morpho position for Alice.
    function _work(uint256 aave, uint256 morphoAmount) internal {
        ausdc.set(client, ausdc.balanceOf(client) + aave);
        morpho.set(client, morpho.balanceOf(client) + morphoAmount);
    }

    function _submit(uint256 jobId) internal {
        vm.prank(provider);
        kernel.submit(jobId, keccak256("deliverable"), "");
    }

    /// @notice Bob verifies one block later. Returns the values the gateway read inside `verify`.
    function _verify(uint256 jobId, JobSpec memory s, bytes[] memory pre) internal returns (bytes[] memory got) {
        vm.roll(block.number + 1);
        lastSpec = abi.encode(s);
        vm.recordLogs();
        vm.prank(provider);
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(s), pre, _fees());
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == EvaluationGateway.VerifySent.selector) {
                (,, got) = abi.decode(logs[i].data, (bytes32, uint64, bytes[]));
            }
        }
        delete lastVerify;
        for (uint256 i; i < got.length; ++i) {
            lastVerify.push(got[i]);
        }
    }

    /// @notice A job through `verify`, with Bob's work done: returns the job and the key Push files it under.
    function _verified(JobSpec memory s, uint256 aave, uint256 morphoAmount)
        internal
        returns (uint256 jobId, bytes32 key)
    {
        jobId = _create(s, address(0));
        _fund(jobId);
        bytes[] memory pre = _snapshot(jobId);
        vm.roll(block.number + 1);
        _work(aave, morphoAmount);
        _submit(jobId);
        _verify(jobId, s, pre);
        key = gw.snapshotKeyOf(kernel_(), jobId);
    }

    // ───────────── the network ─────────────

    /// @notice The last inbound's payload, as the node decodes it.
    function _lastPayload() internal view returns (UniversalPayload memory p, MockRemoteGateway.Sent memory s) {
        s = ugw.sent(ugw.count() - 1);
        p = abi.decode(s.req.payload, (UniversalPayload));
    }

    /// @notice The UEA Push runs `sender`'s inbounds from: a real `UEA_EVM`, deployed on first use as the node does.
    function _ueaFor(string memory chainId, address sender) internal returns (address uea) {
        uea = ueaOf[sender];
        if (uea != address(0)) return uea;
        UEA_EVM u = new UEA_EVM();
        u.initialize(
            UniversalAccountId({chainNamespace: NS, chainId: chainId, owner: abi.encodePacked(sender)}),
            address(ueaFactory)
        );
        uea = address(u);
        ueaFactory.setOrigin(uea, NS, chainId, abi.encodePacked(sender));
        ueaOf[sender] = uea;
    }

    /// @notice `who`'s UEA on Push for a remote chain. A job's refunds go to the UEA of whoever paid its latest inbound.
    function _ueaOf(string memory chainId, address who) internal view returns (address) {
        return
            ueaFactory.computeUEA(
                UniversalAccountId({chainNamespace: NS, chainId: chainId, owner: abi.encodePacked(who)})
            );
    }

    /// @notice The client pays the snapshot inbound.
    function _clientUEA(string memory chainId) internal view returns (address) {
        return _ueaOf(chainId, client);
    }

    /// @notice The provider pays the verify inbound.
    function _providerUEA(string memory chainId) internal view returns (address) {
        return _ueaOf(chainId, provider);
    }

    /// @notice The UEA of the gateway's sender for one of a job's inbounds (worked out here, with no call).
    function _senderUEA(uint256 jobId, uint32 slot) internal returns (address) {
        return _ueaFor(CHAIN, RemoteKeys.senderOf(address(gw), kernel_(), jobId, slot, senderCodeHash));
    }

    /// @notice Runs the gateway's last inbound on Push.
    function _inbound() internal returns (bool ok, bytes memory ret) {
        (UniversalPayload memory p, MockRemoteGateway.Sent memory s) = _lastPayload();
        return _runInbound(s.sender, p, p.value);
    }

    /// @notice Runs one inbound as the node does: the swap credits `swapped` PC to the sender's UEA, then the executor
    ///         module calls `executeUniversalTx` with the payload's gas limit.
    function _runInbound(address sender, UniversalPayload memory p, uint256 swapped)
        internal
        returns (bool ok, bytes memory ret)
    {
        address uea = _ueaFor(CHAIN, sender);
        vm.deal(uea, uea.balance + swapped);
        vm.prank(UE_MODULE, UE_MODULE);
        (ok, ret) = uea.call{gas: p.gasLimit}(abi.encodeCall(IUEA.executeUniversalTx, (p, "")));
    }

    function _inboundOk() internal {
        (bool ok, bytes memory ret) = _inbound();
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    /// @notice Push now tracks Base Sepolia up to `h`.
    function _track(uint256 h) internal {
        core.setChainHeight(CHAIN_KEY, h);
    }

    /// @notice Plays the node for one request. Returns false where the node would not deliver.
    function _deliver(uint256 requestId, bytes memory result) internal returns (bool) {
        if (readState.statusOf(requestId) != RequestStatus.PENDING) return false;
        PendingRead memory p = readState.getPendingRead(requestId);
        if (p.callbackBudget < uint256(p.callbackGasLimit) * block.basefee) return false;
        vm.prank(READ_MODULE, READ_MODULE);
        readState.fulfillExternalCallback(requestId, result);
        return true;
    }

    function _answer(bytes32 key, uint256 read, bytes memory result) internal {
        (, uint256 requestId,) = re.readOf(key, read);
        assertTrue(_deliver(requestId, result), "answer not delivered");
        delivered[key][read] = result;
    }

    /// @notice What a caller of `sendVerdict` gives for the job's answers: `ReadFulfilled` data, or the value the
    ///         gateway read inside `verify`; empty when missing.
    function _results(bytes32 key, uint256 n) internal view returns (bytes[] memory r) {
        r = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            r[i] = delivered[key][i];
            if (r[i].length == 0 && i < lastVerify.length) r[i] = lastVerify[i];
        }
    }

    /// @notice Works out and sends the verdict with the bytes the test kept.
    function _sendVerdict(bytes32 key) internal {
        re.sendVerdict(key, lastSpec, lastPre, _results(key, lastPre.length));
    }

    /// @notice Answers both POST reads with the balances as they stand now.
    function _answerPost(bytes32 key) internal {
        _answer(key, 0, abi.encode(ausdc.balanceOf(client)));
        _answer(key, 1, abi.encode(morpho.balanceOf(client)));
    }

    /// @notice Runs the evaluator's last outbound on the remote chain: its CEA calls the recipient with the payload.
    function _outbound() internal returns (bool ok) {
        MockUGPC.Out memory o = ugpc.out(ugpc.count() - 1);
        address to = address(bytes20(o.req.recipient));
        vm.prank(evaluatorCEA);
        (ok,) = to.call(o.req.payload);
    }
}
