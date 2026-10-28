// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IUEA} from "../../../src/interfaces/IUEA.sol";
import {IUEAFactory} from "../../../src/interfaces/IUEAFactory.sol";
import {IUniversalCallback} from "../../../src/interfaces/IUniversalCallback.sol";
import {UniversalAccountId, UniversalPayload, VerificationType} from "../../../src/libraries/Types.sol";
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
import {ReadConfig, Verdict, IReadStateViews} from "../../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {PendingRead} from "../../../src/libraries/ReadTypes.sol";
import {RemoteEvaluator} from "../../../src/agentic-commerce-8183/remote/RemoteEvaluator.sol";
import {InboundSender} from "../../../src/agentic-commerce-8183/remote/InboundSender.sol";
import {
    IRemoteEvaluator,
    IEvaluationGateway,
    RemoteKeys,
    SNAPSHOT_SLOT,
    VERIFY_SLOT
} from "../../../src/agentic-commerce-8183/remote/RemoteTypes.sol";

interface ICoreViews {
    function chainHeightByChainNamespace(string memory chainNamespace) external view returns (uint256);
    function gasTokenPRC20ByChainNamespace(string memory chainNamespace) external view returns (address);
    function gasPriceByChainNamespace(string memory chainNamespace) external view returns (uint256);
    function setChainMeta(string memory chainNamespace, uint256 price, uint256 chainHeight) external;
}

/// @notice The Push side on a fork of Push Donut, with every contract it touches the deployed one:
///         - the UEA factory deploys the UEA of the gateway's InboundSender for each inbound (`UEA_EVM`), and the
///           executor module runs the payload through `executeUniversalTx`, as the node does;
///         - the real UniversalCallback takes the read requests (height rule, fees, limits) and its callback module
///           delivers the answers, with `tx.origin` the module, as in `DerivedEVMCallWithData`;
///         - the real UniversalCore tracks the heights reads are pinned at (moved with its own `setChainMeta`, from the
///           executor module, as the node moves it);
///         - the real UniversalGatewayPC and UniversalCore take the verdict outbound: fee quote, PC swap into the gas
///           token, the surplus refunded to the evaluator in the same call.
/// @dev Network-dependent: skipped when the RPC can't be reached. `PUSH_DONUT_RPC_URL` overrides the endpoint. The
///      remote side is not on this chain: the gateway is a plain address, and its senders' addresses are worked out as
///      the gateway would deploy them.
contract RemoteEvaluatorDonutForkTest is Test {
    address constant UEA_FACTORY = 0x00000000000000000000000000000000000000eA;
    address constant UNIVERSAL_CORE = 0x00000000000000000000000000000000000000C0;
    address constant UGPC = 0x00000000000000000000000000000000000000C1;
    address constant READ_STATE = 0x00000000000000000000000000000000000000c2;
    address constant UE_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    string constant CHAIN = "84532"; // Base Sepolia, the gateway's chain
    string constant ARB = "421614"; // Arbitrum Sepolia, tracked by Donut
    address constant KERNEL = address(0xBEEF);

    address internal baseGateway = makeAddr("EvaluationGateway on Base Sepolia");
    address internal client = makeAddr("alice on Base Sepolia"); // pays the snapshot inbound
    address internal provider = makeAddr("bob on Base Sepolia"); // pays the verify inbound
    bytes32 internal senderCodeHash = keccak256(type(InboundSender).creationCode);
    RemoteEvaluator internal re;

    function setUp() public {
        string memory url = vm.envOr("PUSH_DONUT_RPC_URL", string("https://evm.donut.rpc.push.org/"));
        try vm.createSelectFork(url) returns (uint256) {}
        catch {
            vm.skip(true);
            return;
        }
        RemoteEvaluator.Remote[] memory remotes = new RemoteEvaluator.Remote[](1);
        remotes[0] = RemoteEvaluator.Remote({
            chainId: CHAIN, gateway: baseGateway, settleGasLimit: 700_000, senderCodeHash: senderCodeHash
        });
        RemoteEvaluator impl = new RemoteEvaluator();
        re = RemoteEvaluator(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(impl),
                        makeAddr("proxyAdminOwner"),
                        abi.encodeCall(
                            RemoteEvaluator.initialize,
                            (RemoteEvaluator.Config({
                                    ueaFactory: UEA_FACTORY,
                                    universalGatewayPC: UGPC,
                                    readState: READ_STATE,
                                    universalCore: UNIVERSAL_CORE,
                                    read: ReadConfig({
                                        readTtl: 300,
                                        callbackGasLimit: 1_000_000,
                                        snapshotCallbackGasLimit: 300_000,
                                        budgetMultiplier: 3,
                                        maxHeightAge: 1 hours,
                                        maxConfirmations: 64
                                    }),
                                    remotes: remotes
                                }))
                        )
                    )
                ))
        );
    }

    // ───────────── helpers ─────────────

    function _read(string memory chainId, ReadAt at) internal pure returns (Read memory) {
        uint8[] memory field = new uint8[](1);
        return Read({
            chainNamespace: "eip155",
            chainId: chainId,
            minConfirmations: 3,
            target: address(0xA1),
            selector: IERC20.balanceOf.selector,
            args: abi.encode(address(0xA11CE)),
            outputs: abi.encodePacked(T_TUPLE, uint8(1), T_UINT),
            field: field,
            at: at
        });
    }

    /// @dev Read 0 after the work, read 1 before it, on `chainId`; one check: read 0 - read 1 >= 600.
    function _spec(string memory chainId) internal pure returns (JobSpec memory s) {
        s.reads = new Read[](2);
        s.reads[0] = _read(chainId, ReadAt.POST_EXECUTION);
        s.reads[1] = _read(chainId, ReadAt.PRE_EXECUTION);
        uint8[] memory l = new uint8[](1);
        uint8[] memory r = new uint8[](1);
        l[0] = 0;
        r[0] = 1;
        s.checks = new Check[](1);
        s.checks[0] = Check({
            left: l, right: r, evaluation: Evaluation.NUMBER, operation: Operation.GREATER_OR_EQUAL, target: 600e6
        });
        s.logic = new Logic[](1);
        s.logic[0] = Logic({kind: LogicKind.COMPARE, check: 0, children: new uint8[](0), k: 0});
        s.allowedMutability = AllowedMutability.NONE;
    }

    /// @notice The real UEA of the gateway's sender for `slot`, deployed through the factory on first use.
    function _senderUEA(uint256 jobId, uint32 slot) internal returns (address uea) {
        address sender = RemoteKeys.senderOf(baseGateway, KERNEL, jobId, slot, senderCodeHash);
        UniversalAccountId memory id =
            UniversalAccountId({chainNamespace: "eip155", chainId: CHAIN, owner: abi.encodePacked(sender)});
        uea = IUEAFactory(UEA_FACTORY).computeUEA(id);
        if (uea.code.length == 0) uea = IUEAFactory(UEA_FACTORY).deployUEA(id);
        (UniversalAccountId memory origin, bool isUEA) = IUEAFactory(UEA_FACTORY).getOriginForUEA(uea);
        assertTrue(isUEA);
        assertEq(address(bytes20(origin.owner)), sender);
    }

    /// @notice Runs one inbound from the gateway's sender for `slot`, through that sender's real UEA.
    function _inbound(uint256 jobId, uint32 slot, bytes memory data) internal returns (uint256 gasUsed) {
        address uea = _senderUEA(jobId, slot);
        UniversalPayload memory p = _payload(data);
        vm.deal(uea, 2 ether); // what the node's auto-swap would have credited
        vm.prank(UE_MODULE, UE_MODULE);
        uint256 g = gasleft();
        IUEA(uea).executeUniversalTx(p, "");
        gasUsed = g - gasleft();
    }

    /// @notice Runs one inbound that fails on Push; returns its revert data (the UEA passes it through).
    function _inboundFails(uint256 jobId, uint32 slot, bytes memory data) internal returns (bytes memory err) {
        address uea = _senderUEA(jobId, slot);
        UniversalPayload memory p = _payload(data);
        vm.deal(uea, 2 ether);
        vm.prank(UE_MODULE, UE_MODULE);
        try IUEA(uea).executeUniversalTx(p, "") {
            revert("the inbound ran");
        } catch (bytes memory e) {
            err = e;
        }
        assertEq(IUEA(uea).nonce(), 0, "a failed payload leaves its UEA's nonce at 0");
    }

    function _payload(bytes memory data) internal view returns (UniversalPayload memory) {
        return UniversalPayload({
            to: address(re),
            value: 1 ether,
            data: data,
            gasLimit: 5_000_000,
            maxFeePerGas: 10 gwei,
            maxPriorityFeePerGas: 0,
            nonce: 0,
            deadline: 0,
            vType: VerificationType.universalTxVerification
        });
    }

    function _deliver(bytes32 key, uint256 read, bytes memory answer) internal {
        (, uint256 requestId,) = re.readOf(key, read);
        assertEq(uint8(IUniversalCallback(READ_STATE).statusOf(requestId)), 1, "PENDING at the real Read State");
        address module = re.CALLBACK_MODULE();
        vm.prank(module, module);
        IUniversalCallback(READ_STATE).fulfillExternalCallback(requestId, answer);
    }

    /// @notice Sends the verdict through the real UniversalGatewayPC and checks the outbound it emitted.
    function _sendVerdictAndCheck(bytes32 key, bytes memory spec, bytes[] memory pre, bytes[] memory results) internal {
        (,,,,,,, uint256 before) = re.jobOf(key);
        vm.recordLogs();
        uint256 g = gasleft();
        re.sendVerdict(key, spec, pre, results);
        console2.log("sendVerdict gas (judge + real outbound, swap, refund):", g - gasleft());
        (,,, bool sent, Verdict v,,, uint256 after_) = re.jobOf(key);
        assertEq(uint8(v), uint8(Verdict.PASS));
        assertTrue(sent);
        console2.log("PC spent on the outbound:", before - after_);
        assertGt(after_, 0, "the surplus came back to the job in the same call");
        assertLt(after_, before, "the outbound cost something");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool seen;
        address gasToken = ICoreViews(UNIVERSAL_CORE).gasTokenPRC20ByChainNamespace("eip155:84532");
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != UGPC || logs[i].topics.length < 4) continue;
            // UniversalTxOutbound(bytes32 indexed subTxId, address indexed sender, string, address indexed token, ...)
            if (address(uint160(uint256(logs[i].topics[2]))) != address(re)) continue;
            assertEq(address(uint160(uint256(logs[i].topics[3]))), gasToken, "the destination's gas token");
            (
                string memory ns,
                bytes memory recipient,
                uint256 amount,,,
                uint256 gasLimit,
                bytes memory payload,,
                address revertRecipient,,
            ) = abi.decode(
                logs[i].data,
                (string, bytes, uint256, address, uint256, uint256, bytes, uint256, address, uint8, uint256)
            );
            assertEq(ns, "eip155:84532");
            assertEq(recipient, abi.encodePacked(baseGateway));
            assertEq(amount, 0);
            assertEq(gasLimit, 700_000);
            assertEq(revertRecipient, _ueaOn(provider), "unused outbound gas: to whoever paid the verify inbound");
            assertEq(bytes4(payload), IEvaluationGateway.settle.selector);
            seen = true;
        }
        assertTrue(seen, "UniversalTxOutbound emitted by the real UniversalGatewayPC");
    }

    // ───────────── tests ─────────────

    /// @notice A job whose reads are all on the gateway's chain: one verify inbound, one POST read, the verdict out.
    function test_donut_sameChain() public {
        assertEq(re.CALLBACK_MODULE(), 0x07a0258D367A4A4cd9d6E4b7eEE8E7eF491CC519, "the deployed callback module");
        uint64 tracked = uint64(ICoreViews(UNIVERSAL_CORE).chainHeightByChainNamespace("eip155:84532"));
        assertGt(tracked, 100, "Push tracks Base Sepolia");
        uint64 s = tracked - 20;
        uint64 e = tracked - 10;
        bytes[] memory pre = new bytes[](2);
        pre[1] = abi.encode(uint256(100e6)); // the gateway read it at S
        bytes memory spec = abi.encode(_spec(CHAIN));

        uint256 used = _inbound(
            7,
            VERIFY_SLOT,
            abi.encodeCall(IRemoteEvaluator.onRemoteJob, (KERNEL, 7, provider, spec, pre, s, e, new bytes[](2)))
        );
        console2.log("verify inbound through UEA_EVM -> onRemoteJob gas:", used);

        bytes32 key = RemoteKeys.snapshotKey(CHAIN, KERNEL, 7, keccak256(spec), keccak256(abi.encode(pre)), s);
        (uint64 sb, uint64 eb,,,,,,) = re.jobOf(key);
        assertEq(sb, s);
        assertEq(eb, e);
        (uint64 h0,,) = re.readOf(key, 0);
        assertEq(h0, e, "the POST read at E");

        bytes[] memory results = new bytes[](2);
        results[0] = abi.encode(uint256(700e6));
        _deliver(key, 0, results[0]);
        _sendVerdictAndCheck(key, spec, pre, results); // 700 - 100 >= 600
    }

    /// @notice A job that reads Arbitrum Sepolia before and after the work:
    ///         1. the snapshot inbound pins the PRE read at Push's tracked Arbitrum height, and Read State answers it;
    ///         2. a verify inbound that runs before Push's Arbitrum height has moved past the snapshot's reverts, as
    ///            Phase 1's `submit` would, and leaves its sender's nonce at 0;
    ///         3. Push's Arbitrum height moves (the node's `setChainMeta`); the provider sends the verify again, and that
    ///            inbound fixes the POST read's block and sends it;
    ///         4. Read State answers it, and the verdict goes out to Base Sepolia.
    function test_donut_crossChain_arbitrum() public {
        uint64 arb = uint64(ICoreViews(UNIVERSAL_CORE).chainHeightByChainNamespace("eip155:421614"));
        assertGt(arb, 100, "Push tracks Arbitrum Sepolia");
        uint64 base = uint64(ICoreViews(UNIVERSAL_CORE).chainHeightByChainNamespace("eip155:84532"));
        uint64 s = base - 20;
        uint64 e = base - 10;
        bytes[] memory pre = new bytes[](2); // both reads are elsewhere: nothing read by the gateway
        bytes memory spec = abi.encode(_spec(ARB));
        bytes32 key = RemoteKeys.snapshotKey(CHAIN, KERNEL, 8, keccak256(spec), keccak256(abi.encode(pre)), s);

        // 1. the snapshot
        uint256 used = _inbound(
            8,
            SNAPSHOT_SLOT,
            abi.encodeCall(IRemoteEvaluator.onRemoteJob, (KERNEL, 8, client, spec, pre, s, 0, new bytes[](0)))
        );
        console2.log("snapshot inbound (1 Arbitrum PRE read pinned and sent) gas:", used);
        (uint64 h1,,) = re.readOf(key, 1);
        assertEq(h1, arb, "pinned at the tracked Arbitrum height");
        // the deployed Read State's PendingRead has the layout `sendReads` reads its expiry from
        (, uint256 r1,) = re.readOf(key, 1);
        PendingRead memory pr = IReadStateViews(READ_STATE).getPendingRead(r1);
        assertEq(pr.callbackTarget, address(re), "callback target");
        assertEq(pr.callbackSelector, RemoteEvaluator.onUniversalData.selector, "callback selector");
        assertEq(pr.revertRecipient, _ueaOn(client), "the snapshot's payer");
        assertGt(pr.expiryHeight, block.number, "expiry height in the future");
        assertLe(pr.expiryHeight, block.number + 1_000, "expiry height within the TTL");
        bytes[] memory results = new bytes[](2);
        results[1] = abi.encode(uint256(100e6));
        _deliver(key, 1, results[1]);

        // 2. the verify, before Push's Arbitrum height has moved past the snapshot's: the inbound reverts
        bytes memory verifyCall =
            abi.encodeCall(IRemoteEvaluator.onRemoteJob, (KERNEL, 8, provider, spec, pre, s, e, new bytes[](2)));
        bytes memory err = _inboundFails(8, VERIFY_SLOT, verifyCall);
        assertEq(err, abi.encodeWithSignature("HeightNotAfterSnapshot(uint256,uint64,uint64)", 0, arb, arb));
        (, uint64 eb,,,,,,) = re.jobOf(key);
        assertEq(eb, 0, "nothing recorded");

        // 3. Push's Arbitrum height moves on; the verify again, through the same sender
        uint256 price = ICoreViews(UNIVERSAL_CORE).gasPriceByChainNamespace("eip155:421614");
        vm.prank(UE_MODULE);
        ICoreViews(UNIVERSAL_CORE).setChainMeta("eip155:421614", price, arb + 5);
        _inbound(8, VERIFY_SLOT, verifyCall);
        (uint64 h0, uint256 r0,) = re.readOf(key, 0);
        assertEq(h0, arb + 5, "fixed in the verify inbound");
        assertGt(r0, 0, "and sent from it");

        // 4. the answer and the verdict: 800 - 100 >= 600
        results[0] = abi.encode(uint256(800e6));
        _deliver(key, 0, results[0]);
        _sendVerdictAndCheck(key, spec, pre, results);
    }

    function _ueaOn(address who) internal view returns (address) {
        return IUEAFactory(UEA_FACTORY)
            .computeUEA(UniversalAccountId({chainNamespace: "eip155", chainId: CHAIN, owner: abi.encodePacked(who)}));
    }

    /// @notice Reads inside `verify`: the verify inbound carries the gateway's answers, Push judges inside it and the
    ///         verdict outbound is created by the real UniversalGatewayPC in that same inbound execution. No Read State
    ///         request; nothing to do on Push afterwards.
    function test_donut_fastPath_verdictFromTheInbound() public {
        uint64 tracked = uint64(ICoreViews(UNIVERSAL_CORE).chainHeightByChainNamespace("eip155:84532"));
        uint64 s = tracked - 20;
        uint64 e = tracked - 10;
        JobSpec memory js = _spec(CHAIN);
        js.reads[0].at = ReadAt.POST_AT_VERIFY;
        bytes memory spec = abi.encode(js);
        bytes[] memory pre = new bytes[](2);
        pre[1] = abi.encode(uint256(100e6)); // the gateway read it at S
        bytes[] memory atVerify = new bytes[](2);
        atVerify[0] = abi.encode(uint256(700e6)); // the gateway read it inside `verify`

        vm.recordLogs();
        uint256 used = _inbound(
            9,
            VERIFY_SLOT,
            abi.encodeCall(IRemoteEvaluator.onRemoteJob, (KERNEL, 9, provider, spec, pre, s, e, atVerify))
        );
        console2.log("verify inbound, judged and sent inside it (UEA_EVM + judge + real outbound):", used);
        bytes32 key = RemoteKeys.snapshotKey(CHAIN, KERNEL, 9, keccak256(spec), keccak256(abi.encode(pre)), s);
        (,,, bool sent, Verdict v,,,) = re.jobOf(key);
        assertEq(uint8(v), uint8(Verdict.PASS), "700 - 100 >= 600");
        assertTrue(sent, "the verdict left from the inbound");
        (, uint256 requestId,) = re.readOf(key, 0);
        assertEq(requestId, 0, "no Read State request");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool seen;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == UGPC && logs[i].topics.length >= 4) {
                if (address(uint160(uint256(logs[i].topics[2]))) == address(re)) seen = true;
            }
        }
        assertTrue(seen, "UniversalTxOutbound from the real UniversalGatewayPC, during the inbound");
    }
}
