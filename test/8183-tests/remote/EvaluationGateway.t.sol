// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {RemoteBase} from "./RemoteBase.t.sol";
import {AgenticCommerce} from "../../../src/agentic-commerce-8183/AgenticCommerce.sol";
import {IAgenticCommerce} from "../../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {UniversalPayload} from "../../../src/libraries/Types.sol";
import {JobSpec, Read, ReadAt} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {JobSpecErrors} from "../../../src/agentic-commerce-8183/libraries/Errors.sol";
import {EvaluationGateway} from "../../../src/agentic-commerce-8183/remote/EvaluationGateway.sol";
import {NoopHook} from "../../../src/agentic-commerce-8183/remote/NoopHook.sol";
import {InboundSender} from "../../../src/agentic-commerce-8183/remote/InboundSender.sol";
import {IUniversalGateway, UniversalTxRequest} from "../../../src/interfaces/IUniversalGateway.sol";
import {MockRemoteGateway} from "./RemoteMocks.sol";
import {
    RemoteKeys,
    IRemoteEvaluator,
    IKernelLayoutR,
    RemoteJob,
    PushFees,
    LAYOUT_V,
    LAYOUT_R,
    VERDICT_NONE,
    VERDICT_PASS,
    SNAPSHOT_SLOT,
    VERIFY_SLOT,
    EvaluationGatewayErrors
} from "../../../src/agentic-commerce-8183/remote/RemoteTypes.sol";
import {RevertingTarget, BombTarget, GasHungryTarget, MockKernelR} from "./RemoteMocks.sol";

contract EvaluationGatewayTest is RemoteBase {
    // ───────────── initialize ─────────────

    function test_initialize_fixesSettings() public view {
        assertEq(address(gw.UGW()), address(ugw));
        assertEq(gw.REMOTE_EVALUATOR(), address(re));
        assertEq(gw.NOOP_HOOK(), address(noop));
        assertEq(gw.FEE_RECIPIENT(), feeRecipient);
        assertEq(gw.READ_GAS(), READ_GAS);
        assertEq(gw.MIN_SETTLE_WINDOW(), SETTLE_WINDOW);
        assertEq(gw.layoutOf(kernel_()), LAYOUT_V);
    }

    function test_initialize_onlyOnce() public {
        address[] memory k = new address[](1);
        k[0] = kernel_();
        uint8[] memory l = new uint8[](1);
        l[0] = LAYOUT_V;
        vm.expectRevert();
        gw.initialize(_gatewayConfig(address(re), k, l, READ_GAS));
    }

    function test_initialize_refusesBadLayoutAndCodelessKernel() public {
        EvaluationGateway impl = new EvaluationGateway();
        address[] memory k = new address[](1);
        uint8[] memory l = new uint8[](1);
        k[0] = kernel_();
        l[0] = 3;
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.BadLayout.selector, kernel_(), uint8(3)));
        new TransparentUpgradeableProxy(
            address(impl),
            proxyAdminOwner,
            abi.encodeCall(EvaluationGateway.initialize, (_gatewayConfig(address(re), k, l, READ_GAS)))
        );
        k[0] = makeAddr("eoa");
        l[0] = LAYOUT_V;
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.BadLayout.selector, k[0], LAYOUT_V));
        new TransparentUpgradeableProxy(
            address(impl),
            proxyAdminOwner,
            abi.encodeCall(EvaluationGateway.initialize, (_gatewayConfig(address(re), k, l, READ_GAS)))
        );
    }

    // ───────────── snapshot ─────────────

    function test_snapshot_recordsHashesAndBlock() public {
        JobSpec memory s = _exampleSpec();
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        bytes[] memory pre = _snapshot(jobId);
        EvaluationGateway.Record memory r = gw.recordOf(kernel_(), jobId);
        assertEq(r.specHash, keccak256(abi.encode(s)));
        assertEq(r.preHash, keccak256(abi.encode(pre)));
        assertEq(r.snapshotBlock, block.number);
        assertEq(r.verifyBlock, 0);
        assertEq(gw.captureKeyOf(kernel_(), jobId), bytes32(0), "no key before verify");
    }

    function test_snapshot_onlyClient() public {
        uint256 jobId = _create(_exampleSpec(), address(0));
        _fund(jobId);
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NotClient.selector, provider));
        gw.snapshot(kernel_(), jobId, _noFees());
    }

    function test_snapshot_onlyOnce() public {
        uint256 jobId = _create(_exampleSpec(), address(0));
        _fund(jobId);
        _snapshot(jobId);
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.AlreadySnapshotted.selector, kernel_(), jobId));
        gw.snapshot(kernel_(), jobId, _noFees());
    }

    function test_snapshot_onlyFunded() public {
        uint256 jobId = _create(_exampleSpec(), address(0));
        vm.prank(client);
        vm.expectRevert(
            abi.encodeWithSelector(EvaluationGatewayErrors.WrongStatus.selector, kernel_(), jobId, uint8(0))
        );
        gw.snapshot(kernel_(), jobId, _noFees());
    }

    function test_snapshot_refusesValue() public {
        uint256 jobId = _create(_exampleSpec(), address(0));
        _fund(jobId);
        vm.prank(client);
        vm.expectRevert(EvaluationGatewayErrors.NoInboundNeeded.selector);
        gw.snapshot{value: 1}(kernel_(), jobId, _noFees());
    }

    function test_snapshot_refusesClientHook_acceptsNoopHook() public {
        NoopHook other = new NoopHook(); // a hook that is not NOOP_HOOK, standing in for a client's own
        vm.prank(admin);
        kernel.setHookWhitelist(address(other), true);
        uint256 jobId = _create(_exampleSpec(), address(other));
        _fund(jobId);
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.HookNotAllowed.selector, address(other)));
        gw.snapshot(kernel_(), jobId, _noFees());

        uint256 ok = _create(_exampleSpec(), address(noop));
        _fund(ok);
        _snapshot(ok);
    }

    function test_snapshot_refusesUnlistedKernel() public {
        AgenticCommerce impl = new AgenticCommerce();
        address other = _deployKernelProxy(address(impl), address(token), treasury, admin);
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.UnsupportedKernel.selector, other));
        gw.snapshot(other, 1, _noFees());
    }

    function test_snapshot_refusesJobWithAnotherEvaluator() public {
        vm.prank(client);
        uint256 jobId = kernel.createJob(provider, evaluator, _expiry(), string(abi.encode(_exampleSpec())), address(0));
        vm.prank(provider);
        kernel.setBudget(jobId, BUDGET, "");
        _fund(jobId);
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NotOurJob.selector, kernel_(), jobId));
        gw.snapshot(kernel_(), jobId, _noFees());
    }

    function test_snapshot_refusesUnknownJob() public {
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.UnknownJob.selector, kernel_(), uint256(77)));
        gw.snapshot(kernel_(), 77, _noFees());
    }

    /// @notice A PRE read on another chain is not read here: the snapshot sends it to Push, paid by the client.
    function test_snapshot_preReadOnOtherChain_sendsTheSnapshotInbound() public {
        JobSpec memory s = _exampleSpec();
        s.reads[3].chainId = ARB;
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        vm.prank(client);
        vm.expectRevert(EvaluationGatewayErrors.NoGasSent.selector);
        gw.snapshot(kernel_(), jobId, _fees());

        vm.prank(client);
        gw.snapshot{value: INBOUND_GAS}(kernel_(), jobId, _fees());
        (UniversalPayload memory p,) = _lastPayload();
        (,, address c,, bytes[] memory pre, uint64 sb, uint64 eb, bytes[] memory vr) =
            abi.decode(_args(p.data), (address, uint256, address, bytes, bytes[], uint64, uint64, bytes[]));
        assertEq(c, client, "the client, for refunds on Push");
        assertEq(bytes4(p.data), IRemoteEvaluator.onRemoteJob.selector);
        assertEq(sb, gw.recordOf(kernel_(), jobId).snapshotBlock);
        assertEq(eb, 0, "a snapshot inbound");
        assertEq(vr.length, 0);
        assertEq(pre[3].length, 0, "the Arbitrum read is left to Push");
        assertEq(pre[2], abi.encode(uint256(0)), "the Base read is taken here");
    }

    /// @notice POST reads on other chains need no snapshot inbound.
    function test_snapshot_postReadOnOtherChain_noInbound() public {
        JobSpec memory s = _exampleSpec();
        s.reads[1].chainId = ARB;
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        _snapshot(jobId);
        assertEq(ugw.count(), 0);
    }

    function test_snapshot_refusesGarbageDescription() public {
        vm.prank(client);
        uint256 jobId = kernel.createJob(provider, address(gw), _expiry(), "plain text brief", address(0));
        vm.prank(provider);
        kernel.setBudget(jobId, BUDGET, "");
        _fund(jobId);
        vm.prank(client);
        vm.expectRevert();
        gw.snapshot(kernel_(), jobId, _noFees());
    }

    // ───────────── local reads ─────────────

    function _preOn(address target) internal returns (bytes memory) {
        JobSpec memory s = _exampleSpec();
        s.reads[2].target = target;
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        return _snapshot(jobId)[2];
    }

    function test_localRead_revertIsEmpty() public {
        assertEq(_preOn(address(new RevertingTarget())).length, 0);
    }

    function test_localRead_oversizedAnswerIsEmpty() public {
        assertEq(_preOn(address(new BombTarget())).length, 0);
    }

    function test_localRead_outOfGasIsEmpty() public {
        assertEq(_preOn(address(new GasHungryTarget())).length, 0);
    }

    /// @notice A caller can't starve a read into "unreadable": too little gas reverts the whole snapshot.
    function test_localRead_starvingRevertsTheSnapshot() public {
        uint256 jobId = _create(_exampleSpec(), address(0));
        _fund(jobId);
        vm.prank(client);
        vm.expectPartialRevert(EvaluationGatewayErrors.ReadGasTooLow.selector);
        gw.snapshot{gas: 230_000}(kernel_(), jobId, _noFees());
    }

    // ───────────── verify ─────────────

    function _snapshotted() internal returns (uint256 jobId, JobSpec memory s, bytes[] memory pre) {
        s = _exampleSpec();
        jobId = _create(s, address(0));
        _fund(jobId);
        pre = _snapshot(jobId);
        vm.roll(block.number + 1);
    }

    function test_verify_onlyProvider() public {
        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _snapshotted();
        _submit(jobId);
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NotProvider.selector, client));
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(s), pre, _fees());
    }

    function test_verify_onlySubmitted() public {
        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _snapshotted();
        vm.prank(provider);
        vm.expectRevert(
            abi.encodeWithSelector(EvaluationGatewayErrors.WrongStatus.selector, kernel_(), jobId, uint8(1))
        );
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(s), pre, _fees());
    }

    function test_verify_needsSnapshot() public {
        JobSpec memory s = _exampleSpec();
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        _submit(jobId);
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NoSnapshot.selector, kernel_(), jobId));
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(s), new bytes[](4), _fees());
    }

    function test_verify_notInSnapshotBlock() public {
        JobSpec memory s = _exampleSpec();
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        bytes[] memory pre = _snapshot(jobId);
        _submit(jobId);
        vm.prank(provider);
        vm.expectRevert(EvaluationGatewayErrors.SameBlockAsSnapshot.selector);
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(s), pre, _fees());
    }

    function test_verify_refusesNearExpiry() public {
        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _snapshotted();
        _submit(jobId);
        vm.warp(kernel.getJob(jobId).expiredAt - SETTLE_WINDOW + 1);
        vm.prank(provider);
        vm.expectPartialRevert(EvaluationGatewayErrors.TooCloseToExpiry.selector);
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(s), pre, _fees());
    }

    function test_verify_refusesOtherBytes() public {
        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _snapshotted();
        _submit(jobId);
        JobSpec memory t = _exampleSpec();
        t.checks[0].target = 1; // easier criteria
        vm.prank(provider);
        vm.expectRevert(EvaluationGatewayErrors.SpecMismatch.selector);
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(t), pre, _fees());

        pre[2] = abi.encode(uint256(1)); // another "before" (the real one is 0)
        vm.prank(provider);
        vm.expectRevert(EvaluationGatewayErrors.PreResultsMismatch.selector);
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(s), pre, _fees());
    }

    function test_verify_onlyOnce() public {
        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _snapshotted();
        _submit(jobId);
        _verify(jobId, s, pre);
        vm.roll(block.number + 1);
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.AlreadyVerified.selector, kernel_(), jobId));
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(s), pre, _fees());
    }

    function test_verify_refusesMinHeightsNoGasAndBadFees() public {
        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _snapshotted();
        _submit(jobId);
        vm.startPrank(provider);
        vm.expectRevert(EvaluationGatewayErrors.NoGasSent.selector);
        gw.verify(kernel_(), jobId, abi.encode(s), pre, _fees());
        PushFees memory f = _fees();
        f.maxFeePerGas = 0;
        vm.expectRevert(EvaluationGatewayErrors.BadPushFees.selector);
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(s), pre, f);
        vm.stopPrank();
    }

    function test_verify_payloadCarriesTheCapture() public {
        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _snapshotted();
        _submit(jobId);
        _verify(jobId, s, pre);
        EvaluationGateway.Record memory r = gw.recordOf(kernel_(), jobId);
        (UniversalPayload memory p,) = _lastPayload();
        (address k, uint256 id,, bytes memory spec, bytes[] memory pre2, uint64 sb, uint64 eb, bytes[] memory vr) =
            abi.decode(_args(p.data), (address, uint256, address, bytes, bytes[], uint64, uint64, bytes[]));
        assertEq(k, kernel_());
        assertEq(id, jobId);
        assertEq(spec, abi.encode(s));
        assertEq(keccak256(abi.encode(pre2)), keccak256(abi.encode(pre)));
        assertEq(sb, r.snapshotBlock);
        assertEq(eb, r.verifyBlock);
        assertGt(eb, sb);
        assertEq(vr.length, 4, "one entry per read");
        assertEq(p.gasLimit, _fees().gasLimit);
        assertEq(p.maxFeePerGas, _fees().maxFeePerGas);
    }

    function _args(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length - 4);
        for (uint256 i; i < out.length; ++i) {
            out[i] = data[i + 4];
        }
    }

    /// @dev `onRemoteJob` calldata: the payer is the third argument, the word at bytes 4 + 64.
    function _payerOf(bytes memory data) internal pure returns (address a) {
        assembly {
            a := mload(add(data, 100))
        }
    }

    // ───────────── resend ─────────────

    /// @notice Only the provider resends the verify inbound, as only he calls `verify`: Push fixes the job's POST blocks
    ///         when that message runs, so nobody else may choose the moment (Phase 1: only he calls `submit`).
    function test_resend_byTheParty_sameBytes_sameSender() public {
        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _snapshotted();
        _submit(jobId);
        _verify(jobId, s, pre);
        (UniversalPayload memory first, MockRemoteGateway.Sent memory a) = _lastPayload();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NotProvider.selector, stranger));
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), pre, new bytes[](4), _fees());
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NotProvider.selector, client));
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), pre, new bytes[](4), _fees());
        vm.prank(provider);
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), pre, new bytes[](4), _fees());
        (UniversalPayload memory second, MockRemoteGateway.Sent memory b) = _lastPayload();
        assertEq(second.data, first.data, "the same message");
        assertEq(_payerOf(second.data), provider, "paid by the provider");
        assertEq(second.nonce, 0);
        assertEq(b.sender, a.sender, "same sender, so the same UEA on Push");
        assertEq(b.sender, gw.senderOf(kernel_(), jobId, VERIFY_SLOT));
        assertEq(b.req.revertRecipient, provider, "a failed swap refunds whoever paid");
    }

    function test_resend_needsSnapshot() public {
        uint256 jobId = _create(_exampleSpec(), address(0));
        _fund(jobId);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NoSnapshot.selector, kernel_(), jobId));
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, "", new bytes[](0), new bytes[](0), _fees());
    }

    /// @notice A job whose criteria have a PRE read on Arbitrum: its snapshot sends an inbound.
    function _crossSnapshotted() internal returns (uint256 jobId, JobSpec memory s, bytes[] memory pre) {
        s = _exampleSpec();
        s.reads[3].chainId = ARB;
        jobId = _create(s, address(0));
        _fund(jobId);
        pre = _snapshotPaying(jobId, INBOUND_GAS);
        vm.roll(block.number + 1);
    }

    /// @notice The client sends the snapshot inbound again, before and after `verify` (a verify that reached Push first
    ///         waits for it), always with E = 0, through the snapshot's sender. Only she may: it fixes the PRE blocks
    ///         on other chains (Phase 1: only she calls `fund`).
    function test_resend_snapshotInbound() public {
        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _crossSnapshotted();
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NotVerified.selector, kernel_(), jobId));
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), pre, new bytes[](4), _fees());
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NotClient.selector, stranger));
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, SNAPSHOT_SLOT, abi.encode(s), pre, new bytes[](0), _fees());
        vm.startPrank(client);
        vm.expectRevert(EvaluationGatewayErrors.VerifyResultsMismatch.selector);
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, SNAPSHOT_SLOT, abi.encode(s), pre, new bytes[](4), _fees());
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.BadSlot.selector, uint32(2)));
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, 2, abi.encode(s), pre, new bytes[](0), _fees());
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, SNAPSHOT_SLOT, abi.encode(s), pre, new bytes[](0), _fees());
        vm.stopPrank();
        (UniversalPayload memory p, MockRemoteGateway.Sent memory sent) = _lastPayload();
        (,,,,,, uint64 eb,) =
            abi.decode(_args(p.data), (address, uint256, address, bytes, bytes[], uint64, uint64, bytes[]));
        assertEq(eb, 0);
        assertEq(sent.sender, gw.senderOf(kernel_(), jobId, SNAPSHOT_SLOT));

        _submit(jobId);
        _verify(jobId, s, pre);
        vm.prank(client);
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, SNAPSHOT_SLOT, abi.encode(s), pre, new bytes[](0), _fees());
        (p, sent) = _lastPayload();
        (,,,,,, eb,) = abi.decode(_args(p.data), (address, uint256, address, bytes, bytes[], uint64, uint64, bytes[]));
        assertEq(eb, 0, "still the snapshot payload after verify");
        assertEq(sent.sender, gw.senderOf(kernel_(), jobId, SNAPSHOT_SLOT));
    }

    /// @notice A job that sent no snapshot inbound has none to send again.
    function test_resend_noSnapshotInbound() public {
        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _snapshotted();
        vm.prank(client);
        vm.expectRevert(EvaluationGatewayErrors.NoInboundNeeded.selector);
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, SNAPSHOT_SLOT, abi.encode(s), pre, new bytes[](0), _fees());
    }

    /// @notice Every inbound leaves from its own InboundSender, deployed by the gateway at its CREATE2 address on first
    ///         use; each payload carries nonce 0. Nobody else can send through a sender.
    function test_inbounds_eachFromItsOwnSender() public {
        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _crossSnapshotted();
        (, MockRemoteGateway.Sent memory a) = _lastPayload();
        _submit(jobId);
        _verify(jobId, s, pre);
        (UniversalPayload memory p, MockRemoteGateway.Sent memory b) = _lastPayload();
        address snapshotSender = gw.senderOf(kernel_(), jobId, SNAPSHOT_SLOT);
        address verifySender = gw.senderOf(kernel_(), jobId, VERIFY_SLOT);
        assertEq(a.sender, snapshotSender);
        assertEq(b.sender, verifySender);
        assertTrue(snapshotSender != verifySender);
        assertGt(snapshotSender.code.length, 0);
        assertGt(verifySender.code.length, 0);
        assertEq(p.nonce, 0);
        assertEq(gw.senderCodeHash(), keccak256(type(InboundSender).creationCode));
        assertEq(
            gw.senderOf(kernel_(), jobId + 1, VERIFY_SLOT).code.length, 0, "another job's sender is not deployed yet"
        );

        UniversalTxRequest memory req;
        bytes memory call = abi.encodeCall(IUniversalGateway.sendUniversalTx, (req));
        vm.deal(stranger, 1 ether);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(InboundSender.NotGateway.selector, stranger));
        InboundSender(verifySender).send{value: 1}(address(ugw), call);
    }

    // ───────────── settle ─────────────

    function test_settle_onlyEvaluatorCEA() public {
        (uint256 jobId,) = _verified(_exampleSpec(), 600e6, 400e6);
        bytes32 key = gw.captureKeyOf(kernel_(), jobId);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NotEvaluatorCEA.selector, stranger));
        gw.settle(kernel_(), jobId, key, true, bytes32(0));
    }

    function test_settle_ignoresAnotherCapture() public {
        (uint256 jobId,) = _verified(_exampleSpec(), 600e6, 400e6);
        vm.prank(evaluatorCEA);
        gw.settle(kernel_(), jobId, keccak256("a replaced transaction"), true, bytes32(0));
        assertEq(gw.recordOf(kernel_(), jobId).verdict, VERDICT_NONE);
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Submitted));
    }

    function test_settle_secondCopyIgnored() public {
        (uint256 jobId,) = _verified(_exampleSpec(), 600e6, 400e6);
        bytes32 key = gw.captureKeyOf(kernel_(), jobId);
        vm.startPrank(evaluatorCEA);
        gw.settle(kernel_(), jobId, key, true, bytes32("r"));
        gw.settle(kernel_(), jobId, key, false, bytes32("r2")); // a copy with another verdict changes nothing
        vm.stopPrank();
        assertEq(gw.recordOf(kernel_(), jobId).verdict, VERDICT_PASS);
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    function test_settle_pausedKernel_thenApplyVerdict() public {
        (uint256 jobId,) = _verified(_exampleSpec(), 600e6, 400e6);
        bytes32 key = gw.captureKeyOf(kernel_(), jobId);
        vm.prank(admin);
        kernel.pause();
        vm.prank(evaluatorCEA);
        gw.settle(kernel_(), jobId, key, true, bytes32("r")); // does not revert
        EvaluationGateway.Record memory r = gw.recordOf(kernel_(), jobId);
        assertEq(r.verdict, VERDICT_PASS);
        assertFalse(r.applied);
        vm.expectRevert(); // the kernel's own revert
        gw.applyVerdict(kernel_(), jobId);
        vm.prank(admin);
        kernel.unpause();
        vm.prank(stranger);
        gw.applyVerdict(kernel_(), jobId);
        assertTrue(gw.recordOf(kernel_(), jobId).applied);
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Completed));
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NothingToApply.selector, kernel_(), jobId));
        gw.applyVerdict(kernel_(), jobId);
    }

    function test_settle_afterExpiryRefund_isNoOp() public {
        (uint256 jobId,) = _verified(_exampleSpec(), 600e6, 400e6);
        bytes32 key = gw.captureKeyOf(kernel_(), jobId);
        vm.warp(kernel.getJob(jobId).expiredAt + 2 hours);
        kernel.claimRefund(jobId);
        vm.prank(evaluatorCEA);
        gw.settle(kernel_(), jobId, key, true, bytes32("r"));
        assertFalse(gw.recordOf(kernel_(), jobId).applied);
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Expired));
    }

    // ───────────── rejectInvalid ─────────────

    function test_rejectInvalid_refundsAtOnce() public {
        JobSpec memory s = _exampleSpec();
        s.reads[0].chainNamespace = "solana"; // only EVM reads can be encoded
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        uint256 before = token.balanceOf(client);
        vm.prank(stranger);
        gw.rejectInvalid(kernel_(), jobId);
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Rejected));
        assertEq(token.balanceOf(client), before + BUDGET);
    }

    function test_rejectInvalid_refusesValidJob() public {
        uint256 jobId = _create(_exampleSpec(), address(0));
        _fund(jobId);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.SpecIsValid.selector, kernel_(), jobId));
        gw.rejectInvalid(kernel_(), jobId);
    }

    /// @notice Starving the criteria check of gas must not make a valid job look invalid.
    function test_rejectInvalid_outOfGasCheckIsRefused() public {
        uint256 jobId = _create(_exampleSpec(), address(0));
        _fund(jobId);
        bool rejected;
        bool guardFired;
        for (uint256 g = 60_000; g < 400_000; g += 5_000) {
            vm.prank(stranger);
            (bool ok, bytes memory ret) =
                address(gw).call{gas: g}(abi.encodeCall(EvaluationGateway.rejectInvalid, (kernel_(), jobId)));
            if (ok) rejected = true;
            if (ret.length >= 4 && bytes4(ret) == EvaluationGatewayErrors.CheckRanOutOfGas.selector) guardFired = true;
        }
        assertFalse(rejected, "a valid job was rejected");
        assertTrue(guardFired, "the out-of-gas guard was reached");
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Funded));
    }

    function test_rejectInvalid_disallowedHook() public {
        NoopHook other = new NoopHook();
        vm.prank(admin);
        kernel.setHookWhitelist(address(other), true);
        uint256 jobId = _create(_exampleSpec(), address(other));
        _fund(jobId);
        gw.rejectInvalid(kernel_(), jobId);
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Rejected));
    }

    // ───────────── fees ─────────────

    function test_sweep_evaluatorFee() public {
        vm.prank(admin);
        kernel.setEvaluatorFee(500); // 5%, as Virtuals' kernel pays
        (uint256 jobId,) = _verified(_exampleSpec(), 600e6, 400e6);
        bytes32 key = gw.captureKeyOf(kernel_(), jobId);
        vm.prank(evaluatorCEA);
        gw.settle(kernel_(), jobId, key, true, bytes32("r"));
        assertEq(token.balanceOf(address(gw)), BUDGET * 500 / 10_000);
        gw.sweep(address(token));
        assertEq(token.balanceOf(feeRecipient), BUDGET * 500 / 10_000);
        assertEq(token.balanceOf(address(gw)), 0);
    }

    // ───────────── layout R (APEX) ─────────────

    function test_layoutR_readsApexShapedKernel() public {
        MockKernelR apex = new MockKernelR();
        address[] memory k = new address[](2);
        k[0] = kernel_();
        k[1] = address(apex);
        uint8[] memory l = new uint8[](2);
        l[0] = LAYOUT_V;
        l[1] = LAYOUT_R;
        EvaluationGateway impl = new EvaluationGateway();
        EvaluationGateway g2 = EvaluationGateway(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(impl),
                        proxyAdminOwner,
                        abi.encodeCall(EvaluationGateway.initialize, (_gatewayConfig(address(re), k, l, READ_GAS)))
                    )
                ))
        );
        JobSpec memory s = _exampleSpec();
        apex.setJob(
            1,
            IKernelLayoutR.JobR({
                id: 1,
                client: client,
                provider: provider,
                evaluator: address(g2),
                description: string(abi.encode(s)),
                budget: BUDGET,
                expiredAt: block.timestamp + 1 days,
                status: 1,
                hook: address(noop),
                submittedAt: 0,
                deliverable: bytes32(0)
            })
        );
        RemoteJob memory j = g2.jobOf(address(apex), 1);
        assertEq(j.client, client);
        assertEq(j.provider, provider);
        assertEq(j.evaluator, address(g2));
        assertEq(j.hook, address(noop));
        assertEq(j.status, 1);
        assertEq(j.expiredAt, block.timestamp + 1 days);
        vm.prank(client);
        g2.snapshot(address(apex), 1, _noFees());
        assertEq(g2.recordOf(address(apex), 1).snapshotBlock, block.number);
    }

    /// @notice As in Phase 1, a `complete` that runs out of gas costs the settle outbound nothing: the verdict is
    ///         recorded before the kernel call, which keeps 1/64 of the gas, so `settle` still succeeds and anyone
    ///         applies the verdict later.
    function test_settle_completeOutOfGas_verdictKept_applyLater() public {
        MockKernelR apex = new MockKernelR();
        EvaluationGateway.Config memory c = _cfg();
        c.kernels[0] = address(apex);
        c.layouts[0] = LAYOUT_R;
        EvaluationGateway g2 = EvaluationGateway(payable(this.deployGateway(c)));
        JobSpec memory s = _exampleSpec();
        apex.setJob(
            1,
            IKernelLayoutR.JobR({
                id: 1,
                client: client,
                provider: provider,
                evaluator: address(g2),
                description: string(abi.encode(s)),
                budget: BUDGET,
                expiredAt: block.timestamp + 1 days,
                status: 1,
                hook: address(noop),
                submittedAt: 0,
                deliverable: bytes32(0)
            })
        );
        vm.recordLogs();
        vm.prank(client);
        g2.snapshot(address(apex), 1, _noFees());
        bytes[] memory pre;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == EvaluationGateway.Snapshotted.selector) {
                (,, pre) = abi.decode(logs[i].data, (bytes32, uint64, bytes[]));
            }
        }
        apex.setStatus(1, 2); // submitted
        vm.roll(block.number + 1);
        vm.prank(provider);
        g2.verify{value: INBOUND_GAS}(address(apex), 1, abi.encode(s), pre, _fees());
        bytes32 key = g2.captureKeyOf(address(apex), 1);

        apex.setHeavy(true);
        vm.prank(evaluatorCEA);
        g2.settle{gas: SETTLE_GAS}(address(apex), 1, key, true, bytes32("r")); // does not revert
        EvaluationGateway.Record memory r = g2.recordOf(address(apex), 1);
        assertEq(r.verdict, VERDICT_PASS, "recorded before the kernel call");
        assertFalse(r.applied);
        assertEq(apex.completed(), 0);

        apex.setHeavy(false);
        vm.prank(stranger);
        g2.applyVerdict(address(apex), 1);
        assertTrue(g2.recordOf(address(apex), 1).applied);
        assertEq(apex.completed(), 1);
    }

    // ───────────── NoopHook ─────────────

    function test_noopHook_answersTheHookInterface() public view {
        assertTrue(noop.supportsInterface(0x01ffc9a7)); // ERC-165
        bytes4 hookId = NoopHook.beforeAction.selector ^ NoopHook.afterAction.selector;
        assertTrue(noop.supportsInterface(hookId), "IACPHook / IERC8183Hook");
        assertFalse(noop.supportsInterface(0xffffffff));
    }

    // ───────────── more branches ─────────────

    function _cfg() internal view returns (EvaluationGateway.Config memory c) {
        address[] memory k = new address[](1);
        k[0] = kernel_();
        uint8[] memory l = new uint8[](1);
        l[0] = LAYOUT_V;
        c = _gatewayConfig(address(re), k, l, READ_GAS);
    }

    function deployGateway(EvaluationGateway.Config memory c) external returns (address) {
        EvaluationGateway impl = new EvaluationGateway();
        return address(
            new TransparentUpgradeableProxy(
                address(impl), proxyAdminOwner, abi.encodeCall(EvaluationGateway.initialize, (c))
            )
        );
    }

    function test_initialize_refusesZeroValues_mismatch_duplicates() public {
        EvaluationGateway.Config memory c = _cfg();
        c.universalGateway = address(0);
        vm.expectRevert(EvaluationGatewayErrors.ZeroValue.selector);
        this.deployGateway(c);
        c = _cfg();
        c.readGas = 0;
        vm.expectRevert(EvaluationGatewayErrors.ZeroValue.selector);
        this.deployGateway(c);
        c = _cfg();
        c.kernels = new address[](0);
        c.layouts = new uint8[](0);
        vm.expectRevert(EvaluationGatewayErrors.ZeroValue.selector);
        this.deployGateway(c);
        c = _cfg();
        c.layouts = new uint8[](2);
        vm.expectRevert(EvaluationGatewayErrors.LayoutsMismatch.selector);
        this.deployGateway(c);
        c = _cfg();
        c.kernels = new address[](2);
        c.kernels[0] = kernel_();
        c.kernels[1] = kernel_();
        c.layouts = new uint8[](2);
        c.layouts[0] = LAYOUT_V;
        c.layouts[1] = LAYOUT_V;
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.BadLayout.selector, kernel_(), LAYOUT_V));
        this.deployGateway(c);
    }

    function test_snapshot_refusesOverlongDescription() public {
        vm.prank(client);
        uint256 jobId = kernel.createJob(provider, address(gw), _expiry(), string(new bytes(32_769)), address(0));
        vm.prank(provider);
        kernel.setBudget(jobId, BUDGET, "");
        _fund(jobId);
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.SpecTooLong.selector, uint256(32_769)));
        gw.snapshot(kernel_(), jobId, _noFees());
    }

    function test_verify_refusesJobWithAnotherEvaluator_andZeroGasLimit() public {
        vm.prank(client);
        uint256 other = kernel.createJob(provider, evaluator, _expiry(), string(abi.encode(_exampleSpec())), address(0));
        vm.prank(provider);
        kernel.setBudget(other, BUDGET, "");
        _fund(other);
        _submit(other);
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NotOurJob.selector, kernel_(), other));
        gw.verify{value: INBOUND_GAS}(kernel_(), other, "", new bytes[](0), _fees());

        (uint256 jobId, JobSpec memory s, bytes[] memory pre) = _snapshotted();
        _submit(jobId);
        PushFees memory f = _fees();
        f.gasLimit = 0;
        vm.prank(provider);
        vm.expectRevert(EvaluationGatewayErrors.BadPushFees.selector);
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(s), pre, f);
    }

    function test_resend_refusals() public {
        (uint256 jobId,) = _verified(_exampleSpec(), 600e6, 400e6);
        bytes32 key = gw.captureKeyOf(kernel_(), jobId);
        JobSpec memory s = _exampleSpec();
        bytes[] memory pre = new bytes[](4);
        pre[2] = abi.encode(uint256(0));
        pre[3] = abi.encode(uint256(0));
        vm.startPrank(provider);
        vm.expectRevert(EvaluationGatewayErrors.VerifyResultsMismatch.selector); // not what `verify` was given
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), pre, new bytes[](1), _fees());
        bytes[] memory wrong = new bytes[](4);
        vm.expectRevert(EvaluationGatewayErrors.PreResultsMismatch.selector);
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), wrong, new bytes[](4), _fees());
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), pre, new bytes[](4), _fees());
        vm.stopPrank();
        vm.prank(evaluatorCEA);
        gw.settle(kernel_(), jobId, key, true, bytes32("r"));
        vm.prank(provider);
        vm.expectRevert(
            abi.encodeWithSelector(EvaluationGatewayErrors.VerdictAlreadyRecorded.selector, kernel_(), jobId)
        );
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), pre, new bytes[](4), _fees());
    }

    function test_rejectInvalid_refusals() public {
        vm.prank(client);
        uint256 other = kernel.createJob(provider, evaluator, _expiry(), "x", address(0));
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NotOurJob.selector, kernel_(), other));
        gw.rejectInvalid(kernel_(), other);

        JobSpec memory s = _exampleSpec();
        s.reads[0].chainNamespace = "solana";
        uint256 open = _create(s, address(0)); // invalid, but still Open: the client can reject it itself
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.WrongStatus.selector, kernel_(), open, uint8(0)));
        gw.rejectInvalid(kernel_(), open);
    }

    function test_rejectInvalid_afterCompletion_refused() public {
        (uint256 jobId,) = _verified(_exampleSpec(), 600e6, 400e6);
        bytes32 key = gw.captureKeyOf(kernel_(), jobId);
        vm.prank(evaluatorCEA);
        gw.settle(kernel_(), jobId, key, true, bytes32("r"));
        vm.expectRevert(
            abi.encodeWithSelector(EvaluationGatewayErrors.WrongStatus.selector, kernel_(), jobId, uint8(3))
        );
        gw.rejectInvalid(kernel_(), jobId);
    }

    function test_sweep_native_andNothing() public {
        vm.recordLogs();
        gw.sweep(address(0)); // nothing to send: no event
        assertEq(vm.getRecordedLogs().length, 0);
        vm.deal(address(gw), 2 ether);
        gw.sweep(address(0));
        assertEq(feeRecipient.balance, 2 ether);
        assertEq(address(gw).balance, 0);
    }

    /// @notice Before `verify` only a FAIL is taken (criteria reading a chain Push does not track), never a PASS.
    function test_settle_beforeVerify_onlyFail() public {
        (uint256 jobId,,) = _snapshotted();
        bytes32 preVerify = keccak256(abi.encode(gw.snapshotKeyOf(kernel_(), jobId), uint64(0), bytes32(0)));
        assertEq(gw.captureKeyOf(kernel_(), jobId), bytes32(0));
        vm.prank(evaluatorCEA);
        gw.settle(kernel_(), jobId, preVerify, true, bytes32("r"));
        assertEq(gw.recordOf(kernel_(), jobId).verdict, VERDICT_NONE, "a PASS before verify is ignored");
        vm.prank(evaluatorCEA);
        gw.settle(kernel_(), jobId, preVerify, false, bytes32("r"));
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Rejected));
    }

    function test_applyVerdict_withoutVerdict() public {
        (uint256 jobId,) = _verified(_exampleSpec(), 600e6, 400e6);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.NothingToApply.selector, kernel_(), jobId));
        gw.applyVerdict(kernel_(), jobId);
    }

    function test_layoutR_expiryAboveUint64_isCapped() public {
        MockKernelR apex = new MockKernelR();
        EvaluationGateway.Config memory c = _cfg();
        c.kernels[0] = address(apex);
        c.layouts[0] = LAYOUT_R;
        EvaluationGateway g2 = EvaluationGateway(payable(this.deployGateway(c)));
        IKernelLayoutR.JobR memory j;
        j.id = 1;
        j.client = client;
        j.evaluator = address(g2);
        j.expiredAt = uint256(type(uint64).max) + 5;
        apex.setJob(1, j);
        assertEq(g2.jobOf(address(apex), 1).expiredAt, type(uint64).max);
    }

    // ───────────── reads inside `verify` ─────────────

    /// @notice `verify` reads each `POST_AT_VERIFY` read here, inside the provider's call, and sends the answers to
    ///         Push; the capture key binds them, so a verdict on other values is never applied.
    function test_verify_readsAtVerifyValues_andBindsThem() public {
        JobSpec memory s = _exampleSpec();
        s.reads[0].at = ReadAt.POST_AT_VERIFY;
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        bytes[] memory pre = _snapshot(jobId);
        vm.roll(block.number + 1);
        _work(600e6, 400e6);
        _submit(jobId);
        bytes[] memory got = _verify(jobId, s, pre);
        assertEq(got[0], abi.encode(uint256(600e6)), "Alice's aUSDC, read inside verify");
        assertEq(got[1].length, 0, "read 1 is left to Read State");

        (UniversalPayload memory p,) = _lastPayload();
        (,,,,,,, bytes[] memory vr) =
            abi.decode(_args(p.data), (address, uint256, address, bytes, bytes[], uint64, uint64, bytes[]));
        assertEq(keccak256(abi.encode(vr)), keccak256(abi.encode(got)), "the same answers go to Push");

        EvaluationGateway.Record memory r = gw.recordOf(kernel_(), jobId);
        assertEq(r.verifyHash, keccak256(abi.encode(got)));
        assertEq(
            gw.captureKeyOf(kernel_(), jobId),
            RemoteKeys.captureKey(gw.snapshotKeyOf(kernel_(), jobId), r.verifyBlock, keccak256(abi.encode(got)))
        );
        bytes32 otherValues = RemoteKeys.captureKey(gw.snapshotKeyOf(kernel_(), jobId), r.verifyBlock, bytes32(0));
        vm.prank(evaluatorCEA);
        gw.settle(kernel_(), jobId, otherValues, true, bytes32("r"));
        assertEq(gw.recordOf(kernel_(), jobId).verdict, VERDICT_NONE, "a verdict on other values is ignored");
    }

    /// @notice A `POST_AT_VERIFY` read must be on this chain: the gateway is what reads it. Such criteria are refused at
    ///         `snapshot` and can be rejected at once.
    function test_atVerifyReadElsewhere_refused() public {
        JobSpec memory s = _exampleSpec();
        s.reads[0].at = ReadAt.POST_AT_VERIFY;
        s.reads[0].chainId = ARB;
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        vm.prank(client);
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.ReadNotHere.selector, uint256(0)));
        gw.snapshot(kernel_(), jobId, _noFees());
        vm.expectRevert(abi.encodeWithSelector(EvaluationGatewayErrors.ReadNotHere.selector, uint256(0)));
        gw.checkSpec(abi.encode(s));
        gw.rejectInvalid(kernel_(), jobId);
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Rejected));
    }

    /// @notice Resending the verify inbound needs the values `verify` read, exactly.
    function test_resend_verifyInbound_needsTheVerifyValues() public {
        JobSpec memory s = _exampleSpec();
        s.reads[0].at = ReadAt.POST_AT_VERIFY;
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        bytes[] memory pre = _snapshot(jobId);
        vm.roll(block.number + 1);
        _work(600e6, 400e6);
        _submit(jobId);
        bytes[] memory got = _verify(jobId, s, pre);
        bytes[] memory forged = new bytes[](4);
        forged[0] = abi.encode(uint256(10_000e6));
        vm.startPrank(provider);
        vm.expectRevert(EvaluationGatewayErrors.VerifyResultsMismatch.selector);
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), pre, forged, _fees());
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), pre, got, _fees());
        vm.stopPrank();
    }
}
