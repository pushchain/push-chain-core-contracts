// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {RemoteBase} from "./RemoteBase.t.sol";
import {IAgenticCommerce} from "../../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {UniversalPayload, VerificationType} from "../../../src/libraries/Types.sol";
import {
    JobSpec,
    Read,
    Check,
    Logic,
    Evaluation,
    Operation,
    LogicKind,
    ReadAt
} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {Verdict} from "../../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {EvaluationGateway} from "../../../src/agentic-commerce-8183/remote/EvaluationGateway.sol";
import {
    IRemoteEvaluator,
    RemoteEvaluatorErrors,
    VERDICT_PASS,
    VERDICT_FAIL,
    VERIFY_SLOT
} from "../../../src/agentic-commerce-8183/remote/RemoteTypes.sol";
import {MockRemoteGateway, MockUGPC} from "./RemoteMocks.sol";
import {IUEA} from "../../../src/interfaces/IUEA.sol";
import {UEAErrors} from "../../../src/libraries/Errors.sol";

/// @notice The running example end to end: remote kernel → gateway → Push → Read State → verdict → remote kernel.
///         Milestone A reads only the kernel's chain; Milestone B adds a read on Arbitrum Sepolia.
contract RemoteFlowTest is RemoteBase {
    function _verdictOf(bytes32 key) internal view returns (Verdict v) {
        (,,,, v,,,) = re.jobOf(key);
    }

    function _prepaidOf(bytes32 key) internal view returns (uint256 p) {
        (,,,,,,, p) = re.jobOf(key);
    }

    // ───────────── Milestone A: reads on the kernel's chain ─────────────

    function test_pass_endToEnd() public {
        JobSpec memory s = _exampleSpec();
        ausdc.set(client, 5e6); // Alice already holds some; only the increase counts
        (uint256 jobId, bytes32 key) = _verified(s, 600e6, 400e6);
        uint64 e = gw.recordOf(kernel_(), jobId).verifyBlock;

        // the inbound, as the gateway sent it
        (UniversalPayload memory p, MockRemoteGateway.Sent memory sent) = _lastPayload();
        assertEq(sent.sender, gw.senderOf(kernel_(), jobId, VERIFY_SLOT), "inbound sender: the job's verify sender");
        assertEq(p.nonce, 0);
        assertEq(sent.value, INBOUND_GAS, "gas forwarded");
        assertEq(sent.req.recipient, address(0));
        assertEq(sent.req.token, address(0));
        assertEq(sent.req.amount, 0);
        assertEq(sent.req.revertRecipient, provider, "a failed swap returns the gas to the caller");
        assertEq(p.to, address(re));
        assertEq(p.value, PC_FOR_JOB);
        assertEq(uint8(p.vType), uint8(VerificationType.universalTxVerification));
        assertEq(bytes4(p.data), IRemoteEvaluator.onRemoteJob.selector);

        // Push tracks E already: the reads go out inside the inbound
        _track(e);
        _inboundOk();
        (uint64 h0, uint256 r0,) = re.readOf(key, 0);
        assertEq(h0, e, "POST read on the kernel's chain at E");
        assertGt(r0, 0, "sent inside the inbound");
        assertEq(_prepaidOf(key), PC_FOR_JOB - 2 * READ_COST);

        // the validators answer at E; the callbacks only store hashes
        _answerPost(key);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.NONE), "nothing judged in a callback");
        assertEq(ugpc.count(), 0, "a callback never sends");

        // anyone works out and sends the verdict
        vm.prank(stranger);
        _sendVerdict(key);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.PASS));
        assertEq(ugpc.count(), 1);
        MockUGPC.Out memory o = ugpc.out(0);
        assertEq(o.req.recipient, abi.encodePacked(address(gw)));
        assertEq(o.req.token, gasToken);
        assertEq(o.req.amount, 0);
        assertEq(o.req.gasLimit, SETTLE_GAS);
        assertEq(o.req.revertRecipient, _providerUEA(CHAIN), "unused outbound gas: to whoever paid the verify inbound");
        assertEq(_prepaidOf(key), PC_FOR_JOB - 2 * READ_COST - OUTBOUND_FEE, "surplus back to the job");

        // the CEA settles on the remote chain
        uint256 before = token.balanceOf(provider);
        assertTrue(_outbound());
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Completed));
        assertEq(token.balanceOf(provider), before + BUDGET, "provider paid");
        EvaluationGateway.Record memory r = gw.recordOf(kernel_(), jobId);
        assertEq(r.verdict, VERDICT_PASS);
        assertTrue(r.applied);
    }

    function test_fail_refundsClient() public {
        JobSpec memory s = _exampleSpec();
        (uint256 jobId, bytes32 key) = _verified(s, 600e6, 300e6); // only 300 into Morpho
        _track(block.number);
        _inboundOk();
        uint256 before = token.balanceOf(client);
        _answerPost(key);
        _sendVerdict(key);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.FAIL));
        assertTrue(_outbound());
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Rejected));
        assertEq(token.balanceOf(client), before + BUDGET, "client refunded");
        assertEq(gw.recordOf(kernel_(), jobId).verdict, VERDICT_FAIL);
    }

    function test_readsWaitForTrackedHeight_thenSendReads() public {
        JobSpec memory s = _exampleSpec();
        (uint256 jobId, bytes32 key) = _verified(s, 600e6, 400e6);
        uint64 e = gw.recordOf(kernel_(), jobId).verifyBlock;
        _track(e - 1); // Push's height trails the chain
        _inboundOk();
        (, uint256 r0,) = re.readOf(key, 0);
        assertEq(r0, 0, "Read State refuses a block above the tracked height");

        vm.expectRevert(); // still too new
        re.sendReads(key, lastSpec);

        _track(e);
        vm.prank(stranger);
        re.sendReads(key, lastSpec);
        (, r0,) = re.readOf(key, 0);
        assertGt(r0, 0);
        _answerPost(key);
        _sendVerdict(key);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.PASS));
    }

    function test_snapshotAnswersAreTheRawCallBytes() public {
        JobSpec memory s = _exampleSpec();
        ausdc.set(client, 7e6);
        morpho.set(client, 9e6);
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        bytes[] memory pre = _snapshot(jobId);
        assertEq(pre.length, 4);
        assertEq(pre[0].length, 0, "POST slots stay empty");
        assertEq(pre[1].length, 0);
        assertEq(pre[2], abi.encode(uint256(7e6)), "what eth_call returns");
        assertEq(pre[3], abi.encode(uint256(9e6)));
        assertEq(ugw.count(), 0, "no inbound for a snapshot with every read on this chain");
    }

    // ───────────── Milestone B: a read on another chain ─────────────

    /// @notice The running example plus "Bob also bridges 200 USDC to Alice on Arbitrum Sepolia": read 4 is her USDC
    ///         there after the work, read 5 before.
    address internal constant ARB_USDC = address(uint160(uint256(keccak256("USDC on Arbitrum Sepolia"))));

    function _crossSpec() internal view returns (JobSpec memory s) {
        JobSpec memory base = _exampleSpec();
        s.reads = new Read[](6);
        for (uint256 i; i < 4; ++i) {
            s.reads[i] = base.reads[i];
        }
        s.reads[4] = _balanceRead(ARB_USDC, client, ReadAt.POST_EXECUTION);
        s.reads[4].chainId = ARB;
        s.reads[5] = _balanceRead(ARB_USDC, client, ReadAt.PRE_EXECUTION);
        s.reads[5].chainId = ARB;
        s.checks = new Check[](3);
        s.checks[0] = base.checks[0];
        s.checks[1] = base.checks[1];
        s.checks[2] = Check({
            left: _u8(4),
            right: _u8(5),
            evaluation: Evaluation.NUMBER,
            operation: Operation.GREATER_OR_EQUAL,
            target: 200e6
        });
        s.logic = new Logic[](4);
        uint8[] memory children = new uint8[](3);
        children[0] = 1;
        children[1] = 2;
        children[2] = 3;
        s.logic[0] = Logic({kind: LogicKind.ALL, check: 0, children: children, k: 0});
        s.logic[1] = _checkLogic(0);
        s.logic[2] = _checkLogic(1);
        s.logic[3] = _checkLogic(2);
        s.allowedMutability = base.allowedMutability;
    }

    function test_crossChain_endToEnd() public {
        JobSpec memory s = _crossSpec();
        core.setChainHeight(ARB_KEY, 1_000);
        uint256 jobId = _create(s, address(0));
        _fund(jobId);

        // Alice's snapshot: reads 2, 3 here; read 5 (Arbitrum) through the snapshot inbound
        bytes[] memory pre = _snapshotPaying(jobId, INBOUND_GAS);
        assertEq(pre[5].length, 0, "not read on this chain");
        (UniversalPayload memory p,) = _lastPayload();
        (,,,,,, uint64 eb,) =
            abi.decode(_args(p.data), (address, uint256, address, bytes, bytes[], uint64, uint64, bytes[]));
        assertEq(eb, 0, "the snapshot inbound carries no E");
        lastSpec = abi.encode(s);
        _inboundOk();
        bytes32 key = gw.snapshotKeyOf(kernel_(), jobId);
        (uint64 h5, uint256 r5,) = re.readOf(key, 5);
        assertEq(h5, 1_000, "PRE read on Arbitrum pinned at Push's tracked height");
        assertGt(r5, 0, "sent inside the snapshot inbound");
        _answer(key, 5, abi.encode(uint256(50e6)));

        // Bob works after the pin: on Base, and 200 USDC to Alice on Arbitrum. He verifies before Push's tracked
        // Arbitrum height has moved past the snapshot's, so the verify inbound reverts, as Phase 1's `submit` would:
        // every POST block is fixed in that inbound or not at all.
        vm.roll(block.number + 1);
        _work(600e6, 400e6);
        _submit(jobId);
        bytes[] memory got = _verify(jobId, s, pre);
        _track(block.number);
        (bool ok, bytes memory ret) = _inbound();
        assertFalse(ok);
        assertEq(
            ret,
            abi.encodeWithSelector(
                RemoteEvaluatorErrors.HeightNotAfterSnapshot.selector, uint256(4), uint64(1_000), uint64(1_000)
            )
        );

        // once Push's Arbitrum height has moved on, Bob sends the verify again; that inbound fixes read 4
        core.setChainHeight(ARB_KEY, 1_007);
        vm.prank(provider);
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, lastSpec, pre, got, _fees());
        _inboundOk();
        (uint64 h4, uint256 r4,) = re.readOf(key, 4);
        assertEq(h4, 1_007, "fixed in the verify inbound, above the snapshot's");
        assertGt(r4, 0, "sent with the reads on Base");
        (, uint256 r0,) = re.readOf(key, 0);
        assertGt(r0, 0, "the reads on Base went out at E");

        _answerPost(key);
        _answer(key, 4, abi.encode(uint256(250e6)));
        _sendVerdict(key);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.PASS), "600, 400 and 250 - 50 >= 200");
        assertTrue(_outbound());
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    function test_crossChain_verifyBeforeSnapshotLands_thenResend() public {
        JobSpec memory s = _crossSpec();
        core.setChainHeight(ARB_KEY, 1_000);
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        bytes[] memory pre = _snapshotPaying(jobId, INBOUND_GAS); // its inbound is not run yet
        vm.roll(block.number + 1);
        _submit(jobId);
        _verify(jobId, s, pre);
        (bool ok, bytes memory ret) = _inbound(); // the verify inbound lands first
        assertFalse(ok);
        bytes32 key = gw.snapshotKeyOf(kernel_(), jobId);
        assertEq(ret, abi.encodeWithSelector(RemoteEvaluatorErrors.SnapshotNotRegistered.selector, key));

        address verifyUEA = _senderUEA(jobId, VERIFY_SLOT);
        assertEq(IUEA(verifyUEA).nonce(), 0, "the failed payload left its UEA's nonce at 0");

        // the snapshot inbound lands late, from its own sender's UEA; once Push's Arbitrum height has moved past the
        // snapshot's, Bob sends the verify again
        EvaluationGateway.Record memory r = gw.recordOf(kernel_(), jobId);
        assertGt(r.verifyBlock, 0);
        (UniversalPayload memory first, MockRemoteGateway.Sent memory snap) = _payloadAt(ugw.count() - 2);
        (ok,) = _runInbound(snap.sender, first, first.value);
        assertTrue(ok, "the snapshot lands");
        core.setChainHeight(ARB_KEY, 1_005);
        vm.prank(provider);
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), pre, new bytes[](6), _fees());
        _inboundOk(); // nonce 0 again: the copy runs
        assertEq(IUEA(verifyUEA).nonce(), 1);
        (, uint64 e,,,,,,) = re.jobOf(key);
        assertEq(e, r.verifyBlock, "the verify landed after its snapshot");

        // a further copy fails on Push at the UEA's nonce rule, and changes nothing
        vm.prank(provider);
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), pre, new bytes[](6), _fees());
        (ok, ret) = _inbound();
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(UEAErrors.NonceMismatch.selector, uint256(1), uint256(0)));
    }

    function test_untrackedChain_failsAtOnce_clientRefunded() public {
        JobSpec memory s = _crossSpec(); // Arbitrum Sepolia, which this Push does not track here
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        _snapshotPaying(jobId, INBOUND_GAS);
        uint256 before = token.balanceOf(client);
        _inboundOk();
        bytes32 key = gw.snapshotKeyOf(kernel_(), jobId);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.FAIL));
        assertEq(ugpc.count(), 1, "the FAIL went out inside the inbound");
        assertTrue(_outbound());
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Rejected));
        assertEq(token.balanceOf(client), before + BUDGET, "refunded before any work");
    }

    function _payloadAt(uint256 i) internal view returns (UniversalPayload memory p, MockRemoteGateway.Sent memory s) {
        s = ugw.sent(i);
        p = abi.decode(s.req.payload, (UniversalPayload));
    }

    function _args(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length - 4);
        for (uint256 i; i < out.length; ++i) {
            out[i] = data[i + 4];
        }
    }
}
