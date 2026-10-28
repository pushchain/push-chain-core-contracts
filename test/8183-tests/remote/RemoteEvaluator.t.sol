// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {console2} from "forge-std/console2.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {RemoteBase} from "./RemoteBase.t.sol";
import {RequestStatus} from "../../../src/libraries/ReadTypes.sol";
import {UniversalPayload, UniversalAccountId} from "../../../src/libraries/Types.sol";
import {IUEA} from "../../../src/interfaces/IUEA.sol";
import {UEAErrors} from "../../../src/libraries/Errors.sol";
import {JobSpec, Check, ReadAt, LogicKind} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {JobSpecErrors, EvmReadErrors} from "../../../src/agentic-commerce-8183/libraries/Errors.sol";
import {Verdict, OwnerCheck} from "../../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {IAgenticCommerce} from "../../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {RemoteEvaluator} from "../../../src/agentic-commerce-8183/remote/RemoteEvaluator.sol";
import {EvaluationGateway} from "../../../src/agentic-commerce-8183/remote/EvaluationGateway.sol";
import {
    RemoteKeys,
    IEvaluationGateway,
    PushFees,
    SNAPSHOT_SLOT,
    VERIFY_SLOT,
    RemoteEvaluatorErrors
} from "../../../src/agentic-commerce-8183/remote/RemoteTypes.sol";
import {MockUGPC, MockRemoteGateway} from "./RemoteMocks.sol";

contract RemoteEvaluatorTest is RemoteBase {
    function setUp() public override {
        super.setUp();
        // job 1's sender UEAs exist before any test expects a revert from them
        _senderUEA(1, SNAPSHOT_SLOT);
        _senderUEA(1, VERIFY_SLOT);
    }

    // ───────────── helpers ─────────────

    function _verdictOf(bytes32 key) internal view returns (Verdict v) {
        (,,,, v,,,) = re.jobOf(key);
    }

    function _prepaidOf(bytes32 key) internal view returns (uint256 p) {
        (,,,,,,, p) = re.jobOf(key);
    }

    function _keyOf(string memory chainId, uint256 jobId, bytes memory spec, bytes[] memory pre, uint64 sb)
        internal
        view
        returns (bytes32)
    {
        return RemoteKeys.snapshotKey(chainId, kernel_(), jobId, keccak256(spec), keccak256(abi.encode(pre)), sb);
    }

    function _pre4() internal pure returns (bytes[] memory pre) {
        pre = new bytes[](4);
        pre[2] = abi.encode(uint256(0));
        pre[3] = abi.encode(uint256(0));
    }

    /// @dev Read 3 is on another chain, so the gateway gives no answer for it.
    function _pre3() internal pure returns (bytes[] memory pre) {
        pre = new bytes[](4);
        pre[2] = abi.encode(uint256(0));
    }

    /// @dev The running example with both POST reads taken by the gateway inside `verify`.
    function _atVerifySpec() internal view returns (JobSpec memory s) {
        s = _exampleSpec();
        s.reads[0].at = ReadAt.POST_AT_VERIFY;
        s.reads[1].at = ReadAt.POST_AT_VERIFY;
    }

    /// @dev Job 1's inbound, straight from the UEA of its gateway sender (the snapshot's when `eb` is 0, the verify's
    ///      otherwise), carrying `value` PC and no `POST_AT_VERIFY` answers.
    function _direct(uint256 value, bytes memory spec, bytes[] memory pre, uint64 sb, uint64 eb) internal {
        _directFrom(
            _senderUEA(1, eb == 0 ? SNAPSHOT_SLOT : VERIFY_SLOT), value, spec, pre, sb, eb, new bytes[](pre.length)
        );
    }

    function _directFrom(
        address caller,
        uint256 value,
        bytes memory spec,
        bytes[] memory pre,
        uint64 sb,
        uint64 eb,
        bytes[] memory verifyResults
    ) internal {
        vm.deal(caller, caller.balance + value);
        vm.prank(caller);
        re.onRemoteJob{value: value}(kernel_(), 1, client, spec, pre, sb, eb, verifyResults);
    }

    function _decided() internal returns (bytes32 key) {
        (, key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        _answerPost(key);
        _sendVerdict(key);
    }

    function _answerSave(bytes32 key, uint256 read, bytes memory result) internal {
        (, uint256 requestId,) = re.readOf(key, read);
        assertTrue(_deliver(requestId, result));
        delivered[key][read] = result;
    }

    function _stripSelector(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length - 4);
        for (uint256 i; i < out.length; ++i) {
            out[i] = data[i + 4];
        }
    }

    function _settleArgs(uint256 i) internal view returns (bytes32 captureKey, bool pass, bytes32 reason) {
        MockUGPC.Out memory o = ugpc.out(i);
        assertEq(bytes4(o.req.payload), IEvaluationGateway.settle.selector);
        (,, captureKey, pass, reason) =
            abi.decode(_stripSelector(o.req.payload), (address, uint256, bytes32, bool, bytes32));
    }

    // ───────────── initialize ─────────────

    function _config(RemoteEvaluator.Remote[] memory remotes) internal view returns (RemoteEvaluator.Config memory) {
        return RemoteEvaluator.Config({
            ueaFactory: address(ueaFactory),
            universalGatewayPC: address(ugpc),
            readState: address(readState),
            universalCore: address(core),
            read: _readConfig(),
            remotes: remotes
        });
    }

    function _one() internal view returns (RemoteEvaluator.Remote[] memory one) {
        one = new RemoteEvaluator.Remote[](1);
        one[0] = RemoteEvaluator.Remote({
            chainId: CHAIN, gateway: address(gw), settleGasLimit: SETTLE_GAS, senderCodeHash: senderCodeHash
        });
    }

    function deployProxy(RemoteEvaluator.Config memory c) external returns (RemoteEvaluator) {
        RemoteEvaluator impl = new RemoteEvaluator();
        return RemoteEvaluator(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(impl), proxyAdminOwner, abi.encodeCall(RemoteEvaluator.initialize, (c))
                    )
                ))
        );
    }

    function test_initialize_fixesSettings() public view {
        assertEq(re.CALLBACK_MODULE(), READ_MODULE, "read from Read State, not hardcoded");
        assertEq(re.gatewayOf(CHAIN), address(gw));
        assertEq(re.settleGasOf(CHAIN), SETTLE_GAS);
        assertEq(re.senderCodeHashOf(CHAIN), gw.senderCodeHash());
        assertEq(re.MAX_HEIGHT_AGE(), 1 hours);
        assertEq(re.SNAPSHOT_CALLBACK_GAS_LIMIT(), 300_000);
    }

    function test_initialize_refusals() public {
        RemoteEvaluator.Config memory c = _config(_one());
        c.ueaFactory = address(0);
        vm.expectRevert(RemoteEvaluatorErrors.ZeroValue.selector);
        this.deployProxy(c);
        vm.expectRevert(RemoteEvaluatorErrors.ZeroValue.selector);
        this.deployProxy(_config(new RemoteEvaluator.Remote[](0)));
        c = _config(_one());
        c.read.readTtl = 0;
        vm.expectRevert(RemoteEvaluatorErrors.ZeroValue.selector);
        this.deployProxy(c);
        c = _config(_one());
        c.read.callbackGasLimit = 1_000_001; // above Read State's cap
        vm.expectRevert(RemoteEvaluatorErrors.ZeroValue.selector);
        this.deployProxy(c);
        RemoteEvaluator.Remote[] memory bad = _one();
        bad[0].chainId = "";
        vm.expectRevert(RemoteEvaluatorErrors.ZeroValue.selector);
        this.deployProxy(_config(bad));
        bad = _one();
        bad[0].gateway = address(0);
        vm.expectRevert(RemoteEvaluatorErrors.ZeroValue.selector);
        this.deployProxy(_config(bad));
        bad = _one();
        bad[0].settleGasLimit = 0;
        vm.expectRevert(RemoteEvaluatorErrors.ZeroValue.selector);
        this.deployProxy(_config(bad));
        bad = _one();
        bad[0].senderCodeHash = bytes32(0);
        vm.expectRevert(RemoteEvaluatorErrors.ZeroValue.selector);
        this.deployProxy(_config(bad));
        RemoteEvaluator.Remote[] memory two = new RemoteEvaluator.Remote[](2);
        two[0] = _one()[0];
        two[1] = RemoteEvaluator.Remote({
            chainId: CHAIN, gateway: stranger, settleGasLimit: SETTLE_GAS, senderCodeHash: senderCodeHash
        });
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.DuplicateChain.selector, CHAIN));
        this.deployProxy(_config(two));
    }

    function test_initialize_onlyOnce_andImplementationLocked() public {
        RemoteEvaluator.Config memory c = _config(_one());
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        re.initialize(c);
        RemoteEvaluator impl = new RemoteEvaluator();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(c);
    }

    // ───────────── who may register, and with what ─────────────

    /// @notice Only the UEA of the gateway's sender for this job and this inbound.
    function test_onRemoteJob_onlyTheJobsSenderUEA() public {
        bytes memory spec = abi.encode(_exampleSpec());
        bytes[] memory pre = _pre4();
        bytes[] memory none = new bytes[](4);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NotGateway.selector, stranger));
        _directFrom(stranger, 0, spec, pre, 10, 11, none);

        address gatewaysOwn = _ueaFor(CHAIN, address(gw)); // the gateway's own UEA: not a sender
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NotGateway.selector, gatewaysOwn));
        _directFrom(gatewaysOwn, 0, spec, pre, 10, 11, none);

        address otherJob = _senderUEA(2, VERIFY_SLOT); // job 2's verify sender, sending for job 1
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NotGateway.selector, otherJob));
        _directFrom(otherJob, 0, spec, pre, 10, 11, none);

        address snapshotSender = _senderUEA(1, SNAPSHOT_SLOT); // job 1's snapshot sender, sending a verify
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NotGateway.selector, snapshotSender));
        _directFrom(snapshotSender, 0, spec, pre, 10, 11, none);

        address verifySender = gw.senderOf(kernel_(), 1, VERIFY_SLOT);
        address otherChain = _ueaFor("1", makeAddr("unused")); // the right sender address on a chain not registered
        ueaFactory.setOrigin(otherChain, NS, "1", abi.encodePacked(verifySender));
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NotGateway.selector, otherChain));
        _directFrom(otherChain, 0, spec, pre, 10, 11, none);

        address svm = makeAddr("svmUEA");
        ueaFactory.setOrigin(svm, "solana", CHAIN, abi.encodePacked(verifySender));
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NotGateway.selector, svm));
        _directFrom(svm, 0, spec, pre, 10, 11, none);

        _track(20);
        _directFrom(_senderUEA(1, VERIFY_SLOT), PC_FOR_JOB, spec, pre, 10, 11, none); // the right one
        (, uint64 e,,,,,,) = re.jobOf(_keyOf(CHAIN, 1, spec, pre, 10));
        assertEq(e, 11);
    }

    function test_onRemoteJob_refusesBadInput() public {
        bytes memory spec = abi.encode(_exampleSpec());
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.BadBlocks.selector, uint64(0), uint64(5)));
        _direct(0, spec, _pre4(), 0, 5);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.BadBlocks.selector, uint64(11), uint64(11)));
        _direct(0, spec, _pre4(), 11, 11);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.ResultsLength.selector, uint256(3), uint256(4)));
        _direct(0, spec, new bytes[](3), 10, 11);
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.SpecTooLong.selector, uint256(32_769)));
        _direct(0, new bytes(32_769), _pre4(), 10, 11);
        JobSpec memory s = _exampleSpec();
        s.checks = new Check[](0);
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckCount.selector, uint256(0)));
        _direct(0, abi.encode(s), _pre4(), 10, 11);
    }

    /// @notice An answer is taken from the gateway only for a read it reads: a PRE read on its chain at S, a
    ///         `POST_AT_VERIFY` read inside `verify`, and the latter only on its own chain.
    function test_onRemoteJob_suppliedAnswersOnlyWhereTheGatewayReads() public {
        bytes memory spec = abi.encode(_exampleSpec());
        bytes[] memory pre = _pre4();
        pre[0] = abi.encode(uint256(1)); // read 0 is a POST read
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.SuppliedWrongRead.selector, uint256(0)));
        _direct(0, spec, pre, 10, 11);

        address verifier = _senderUEA(1, VERIFY_SLOT);
        bytes[] memory vr = new bytes[](4);
        vr[1] = abi.encode(uint256(1)); // read 1 is read through Read State, not inside `verify`
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.SuppliedWrongRead.selector, uint256(1)));
        _directFrom(verifier, 0, spec, _pre4(), 10, 11, vr);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.ResultsLength.selector, uint256(3), uint256(4)));
        _directFrom(verifier, 0, spec, _pre4(), 10, 11, new bytes[](3));

        JobSpec memory s = _atVerifySpec();
        s.reads[1].chainId = ARB; // a `POST_AT_VERIFY` read the gateway can't read
        core.setChainHeight(ARB_KEY, 900);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.ReadNotOnGatewayChain.selector, uint256(1)));
        _direct(0, abi.encode(s), _pre4(), 10, 11);
    }

    /// @notice A copy of an inbound that already ran fails at its UEA's nonce. Called directly again (as a sender
    ///         could only if Push let it), even with another E, it only adds its PC.
    function test_copies_failAtTheUEA_andOnlyAddPC() public {
        (uint256 jobId, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        (, uint256 req0,) = re.readOf(key, 0);
        uint256 prepaid = _prepaidOf(key);
        (bool ok, bytes memory ret) = _inbound(); // the same inbound again
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(UEAErrors.NonceMismatch.selector, uint256(1), uint256(0)));
        EvaluationGateway.Record memory r = gw.recordOf(kernel_(), jobId);
        _direct(1 ether, lastSpec, lastPre, r.snapshotBlock, r.verifyBlock + 7);
        (, uint256 req0b,) = re.readOf(key, 0);
        (, uint64 e,,,,,,) = re.jobOf(key);
        assertEq(req0b, req0, "no new read");
        assertEq(e, r.verifyBlock, "E unchanged");
        assertEq(_prepaidOf(key), prepaid + 1 ether, "the PC stays with the job");
    }

    /// @notice A payload whose `value` exceeds what the swap gave the UEA fails, and leaves the UEA's nonce at 0; the
    ///         same bytes sent again through the same sender then run.
    function test_underfundedInbound_thenResend() public {
        JobSpec memory s = _exampleSpec();
        (uint256 jobId, bytes32 key) = _verified(s, 600e6, 400e6);
        _track(block.number);
        (UniversalPayload memory p, MockRemoteGateway.Sent memory sent) = _lastPayload();
        (bool ok,) = _runInbound(sent.sender, p, p.value - 1); // the swap gave one wei too little
        assertFalse(ok, "the UEA can't pay pcForJob");
        address uea = _senderUEA(jobId, VERIFY_SLOT);
        assertEq(IUEA(uea).nonce(), 0);
        (uint64 sb,,,,,,,) = re.jobOf(key);
        assertEq(sb, 0, "nothing registered");
        vm.prank(provider);
        gw.resend{value: INBOUND_GAS}(kernel_(), jobId, VERIFY_SLOT, abi.encode(s), lastPre, lastVerify, _fees());
        _inboundOk();
        assertEq(IUEA(uea).nonce(), 1);
        (sb,,,,,,,) = re.jobOf(key);
        assertGt(sb, 0);
    }

    // ───────────── reads ─────────────

    function test_sendReads_refusals() public {
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.UnknownJob.selector, bytes32(uint256(1))));
        re.sendReads(bytes32(uint256(1)), "");
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.SpecMismatch.selector, key));
        re.sendReads(key, hex"00");
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NothingToSend.selector, key)); // all in flight
        re.sendReads(key, lastSpec);
    }

    /// @notice A snapshot-only job (no verify yet) with every PRE read answered waits for the provider.
    function test_sendReads_awaitingVerify() public {
        JobSpec memory s = _exampleSpec();
        s.reads[1].chainId = ARB; // a POST read elsewhere; no PRE read elsewhere
        core.setChainHeight(ARB_KEY, 900);
        bytes32 key = _keyOf(CHAIN, 1, abi.encode(s), _pre4(), 10);
        _direct(PC_FOR_JOB, abi.encode(s), _pre4(), 10, 0);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.AwaitingVerify.selector, key));
        re.sendReads(key, abi.encode(s));
    }

    function test_expiredRead_isResentAtTheSameBlock() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        (uint64 h, uint256 old,) = re.readOf(key, 0);
        vm.roll(block.number + 400); // past READ_TTL (300 Push blocks)
        vm.prank(READ_MODULE);
        readState.expireExternalRead(old);
        re.sendReads(key, lastSpec);
        (uint64 h2, uint256 fresh,) = re.readOf(key, 0);
        assertTrue(fresh != old, "a new request");
        assertEq(h2, h, "the same block");
        assertEq(uint8(readState.statusOf(fresh)), uint8(RequestStatus.PENDING));
        assertFalse(_deliver(old, abi.encode(uint256(1))), "the old request can't be answered");
        _answerPost(key);
        _sendVerdict(key);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.PASS));
    }

    /// @notice Heights on other chains are recorded at the snapshot from a fresh tracked height; with a stale one the
    ///         inbound reverts, and the gateway sends it again.
    function test_snapshot_staleHeight_revertsTheInbound() public {
        JobSpec memory s = _exampleSpec();
        s.reads[3].chainId = ARB; // a PRE read on Arbitrum
        core.setChainHeight(ARB_KEY, 900);
        vm.warp(block.timestamp + 2 hours); // older than MAX_HEIGHT_AGE
        vm.expectPartialRevert(EvmReadErrors.HeightStale.selector);
        _direct(PC_FOR_JOB, abi.encode(s), _pre3(), 10, 0);
        core.setChainHeight(ARB_KEY, 950);
        _direct(PC_FOR_JOB, abi.encode(s), _pre3(), 10, 0);
        (uint64 h,,) = re.readOf(_keyOf(CHAIN, 1, abi.encode(s), _pre3(), 10), 3);
        assertEq(h, 950);
    }

    /// @notice As in Phase 1, a POST read on another chain is fixed once, in the verify inbound (Phase 1: at `submit`),
    ///         at Push's fresh tracked height, which must be above the one recorded at the snapshot; POST reads on one
    ///         chain share the height.
    function test_postPin_aboveTheSnapshotHeight_andShared() public {
        JobSpec memory s = _exampleSpec();
        s.reads[0].chainId = ARB; // POST elsewhere
        s.reads[1].chainId = ARB; // POST elsewhere
        s.reads[3].chainId = ARB; // PRE elsewhere
        core.setChainHeight(ARB_KEY, 700);
        bytes[] memory pre = _pre3();
        bytes32 key = _keyOf(CHAIN, 1, abi.encode(s), pre, 10);
        _direct(PC_FOR_JOB, abi.encode(s), pre, 10, 0);
        (uint64 h3,,) = re.readOf(key, 3);
        assertEq(h3, 700);
        _answerSave(key, 3, abi.encode(uint256(0)));
        // the verify while Arbitrum is still at 700: reverts, as Phase 1's `submit` does, so no block is fixed later
        vm.expectRevert(
            abi.encodeWithSelector(
                RemoteEvaluatorErrors.HeightNotAfterSnapshot.selector, uint256(0), uint64(700), uint64(700)
            )
        );
        _direct(0, abi.encode(s), pre, 10, 11);
        core.setChainHeight(ARB_KEY, 701);
        _direct(0, abi.encode(s), pre, 10, 11); // the verify again: fixes both POST reads in the inbound
        (uint64 h0,,) = re.readOf(key, 0);
        (uint64 h1,,) = re.readOf(key, 1);
        assertEq(h0, 701);
        assertEq(h1, 701, "one height per chain");
    }

    // ───────────── callbacks ─────────────

    function test_onUniversalData_onlyReadState() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.CallerIsNotReadState.selector, stranger));
        re.onUniversalData(1, "");
        vm.prank(address(readState));
        re.onUniversalData(12345, ""); // an unknown request is ignored
    }

    /// @notice A callback stores the answer's hash and nothing else.
    function test_callback_storesHashOnly() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        _answer(key, 0, abi.encode(uint256(600e6)));
        (,, bytes32 h) = re.readOf(key, 0);
        assertEq(h, keccak256(abi.encode(uint256(600e6))));
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.NONE));
        assertEq(ugpc.count(), 0);
    }

    /// @notice The unspent part of a callback budget goes back to whoever paid for the read: a POST read is paid by
    ///         the verify inbound, so the provider's UEA.
    function test_callbackBudget_refundsThePayer() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        (, uint256 req,) = re.readOf(key, 0);
        assertEq(readState.getPendingRead(req).revertRecipient, _providerUEA(CHAIN));
    }

    function test_supersededAnswer_ignored() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        (, uint256 old,) = re.readOf(key, 0);
        vm.roll(block.number + 400);
        vm.prank(READ_MODULE);
        readState.expireExternalRead(old);
        re.sendReads(key, lastSpec);
        vm.prank(address(readState)); // as if Read State delivered the old one
        re.onUniversalData(old, abi.encode(uint256(600e6)));
        (,, bytes32 h) = re.readOf(key, 0);
        assertEq(h, bytes32(0), "the old request's answer is not taken");
    }

    /// @notice Inside a Read State callback `tx.origin` is the callback module: nothing may be sent from there.
    function test_insideCallback_sendsNothing() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        _answerPost(key);
        bytes[] memory results = _results(key, 4);
        vm.prank(stranger, READ_MODULE);
        vm.expectRevert(RemoteEvaluatorErrors.InsideCallback.selector);
        re.sendVerdict(key, lastSpec, lastPre, results);
        vm.prank(stranger, READ_MODULE);
        vm.expectRevert(RemoteEvaluatorErrors.InsideCallback.selector);
        re.sendReads(key, lastSpec);
    }

    // ───────────── verdicts ─────────────

    function test_sendVerdict_notDecided_whileAnswersAreOut() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        _answer(key, 0, abi.encode(uint256(600e6))); // check 0 PASS; check 1 still waits
        bytes[] memory results = _results(key, 4);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NotDecided.selector, key));
        re.sendVerdict(key, lastSpec, lastPre, results);
    }

    function test_sendVerdict_failDecidedEarly_lateAnswerIgnored() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        _answer(key, 1, abi.encode(uint256(1e6))); // Morpho barely moved: check 1 FAILs, so ALL FAILs
        _sendVerdict(key);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.FAIL));
        _answer(key, 0, abi.encode(uint256(600e6))); // arrives after the verdict
        (,, bytes32 h) = re.readOf(key, 0);
        assertEq(h, bytes32(0), "not recorded");
    }

    function test_sendVerdict_refusesOtherBytes() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        _answerPost(key);
        bytes[] memory results = _results(key, 4);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.SpecMismatch.selector, key));
        re.sendVerdict(key, hex"00", lastPre, results);
        bytes[] memory pre = _pre4();
        pre[2] = abi.encode(uint256(1));
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.PreResultsMismatch.selector, key));
        re.sendVerdict(key, lastSpec, pre, results);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.ResultsLength.selector, uint256(3), uint256(4)));
        re.sendVerdict(key, lastSpec, lastPre, new bytes[](3));
        results[0] = abi.encode(uint256(10_000e6)); // a better answer than the one delivered
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.ResultMismatch.selector, uint256(0)));
        re.sendVerdict(key, lastSpec, lastPre, results);
        results[0] = ""; // leaving out an answered read
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.ResultMismatch.selector, uint256(0)));
        re.sendVerdict(key, lastSpec, lastPre, results);
    }

    /// @notice Every read answered and the root still unknown: INCONCLUSIVE, nothing sent, then nothing to send.
    function test_sendVerdict_inconclusive() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        _answer(key, 0, ""); // Read State's answer when the call reverts
        _answer(key, 1, abi.encode(uint256(400e6)));
        _sendVerdict(key);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.INCONCLUSIVE));
        assertEq(ugpc.count(), 0);
        bytes[] memory results = _results(key, 4);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NoVerdict.selector, key));
        re.sendVerdict(key, lastSpec, lastPre, results);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NothingToSend.selector, key));
        re.sendReads(key, lastSpec);
    }

    /// @notice A PRE answer the gateway could not read leaves its check UNKNOWN for good.
    function test_unreadablePreAnswer_inconclusive() public {
        _track(20);
        bytes[] memory pre = _pre4();
        pre[2] = ""; // the aUSDC read reverted at S
        bytes memory spec = abi.encode(_exampleSpec());
        _direct(PC_FOR_JOB, spec, pre, 10, 11);
        bytes32 key = _keyOf(CHAIN, 1, spec, pre, 10);
        lastSpec = spec;
        delete lastPre;
        for (uint256 i; i < 4; ++i) {
            lastPre.push(pre[i]);
        }
        _answer(key, 0, abi.encode(uint256(600e6)));
        _answer(key, 1, abi.encode(uint256(400e6)));
        _sendVerdict(key);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.INCONCLUSIVE));
    }

    /// @notice The first send is paid from the job's PC; a later one only by its caller, so nobody can burn the
    ///         job's PC by sending the verdict again and again.
    function test_sendVerdict_resendIsPaidByItsCaller() public {
        bytes32 key = _decided();
        uint256 left = _prepaidOf(key);
        assertEq(left, PC_FOR_JOB - 2 * READ_COST - OUTBOUND_FEE, "first send from the job's PC");
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.ResendUnpaid.selector, key));
        re.sendVerdict(key, "", new bytes[](0), new bytes[](0));
        uint256 before = stranger.balance;
        vm.prank(stranger);
        re.sendVerdict{value: 1 ether}(key, "", new bytes[](0), new bytes[](0)); // no bytes needed to resend
        assertEq(ugpc.count(), 2);
        assertEq(_prepaidOf(key), left, "the job's PC untouched");
        assertEq(stranger.balance, before - OUTBOUND_FEE, "the caller pays the fee and gets the rest back");
        assertEq(ugpc.out(0).req.payload, ugpc.out(1).req.payload, "the same verdict");
        assertEq(ugpc.out(0).req.revertRecipient, _providerUEA(CHAIN), "first send's unused gas: the verify's payer");
        assertEq(ugpc.out(1).req.revertRecipient, stranger, "a resend's unused gas: its payer");
    }

    function test_sendVerdict_firstSend_withoutPC_needsValue() public {
        JobSpec memory s = _exampleSpec();
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        bytes[] memory pre = _snapshot(jobId);
        vm.roll(block.number + 1);
        _work(600e6, 400e6);
        _submit(jobId);
        vm.roll(block.number + 1);
        PushFees memory f = _fees();
        f.pcForJob = 2 * READ_COST; // exactly the reads, nothing left for the verdict
        lastSpec = abi.encode(s);
        vm.prank(provider);
        gw.verify{value: INBOUND_GAS}(kernel_(), jobId, abi.encode(s), pre, f);
        bytes32 key = gw.snapshotKeyOf(kernel_(), jobId);
        _track(block.number);
        _inboundOk();
        _answerPost(key);
        bytes[] memory results = _results(key, 4);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.PrepaidTooLow.selector, uint256(1), uint256(0)));
        re.sendVerdict(key, lastSpec, lastPre, results);
        re.sendVerdict{value: OUTBOUND_FEE}(key, lastSpec, lastPre, results);
        assertEq(ugpc.count(), 1);
    }

    function test_sendVerdict_unsupportedGasToken() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        _answerPost(key);
        core.setGasToken(CHAIN_KEY, address(0));
        bytes[] memory results = _results(key, 4);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.ChainNotSupported.selector, CHAIN));
        re.sendVerdict(key, lastSpec, lastPre, results);
    }

    function test_sendVerdict_beforeVerify_notDecided() public {
        JobSpec memory s = _exampleSpec();
        s.reads[3].chainId = ARB;
        core.setChainHeight(ARB_KEY, 900);
        bytes32 key = _keyOf(CHAIN, 1, abi.encode(s), _pre3(), 10);
        _direct(PC_FOR_JOB, abi.encode(s), _pre3(), 10, 0);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NotDecided.selector, key));
        re.sendVerdict(key, abi.encode(s), _pre3(), new bytes[](4));
    }

    /// @notice The `reason` has the UniversalEvaluator's layout: the key (here the capture key), the spec, every
    ///         read's evidence in order, the verdict and the owner check (UNKNOWN: no wallet on a remote chain).
    function test_verdictReason_commitsToTheEvidence() public {
        bytes32 key = _decided();
        (bytes32 captureKey, bool pass, bytes32 reason) = _settleArgs(0);
        (,, bytes32 ck,,, bytes32 stored,,) = re.jobOf(key);
        assertEq(captureKey, ck);
        assertTrue(pass);
        assertEq(reason, stored);

        (uint64 sb, uint64 eb,,,,,,) = re.jobOf(key);
        bytes32[] memory leaves = new bytes32[](4);
        for (uint256 i; i < 4; ++i) {
            bool isPre = i >= 2;
            bytes memory raw = isPre ? lastPre[i] : delivered[key][i];
            (, uint256 requestId,) = re.readOf(key, i);
            uint256 value = abi.decode(raw, (uint256));
            leaves[i] = keccak256(abi.encode(i, requestId, isPre ? sb : eb, keccak256(raw), true, int256(value)));
        }
        assertEq(reason, keccak256(abi.encode(ck, keccak256(lastSpec), leaves, Verdict.PASS, OwnerCheck.UNKNOWN)));
    }

    // ───────────── reads inside `verify` ─────────────

    /// @notice Every POST read is `POST_AT_VERIFY`: the gateway reads them inside `verify`, and Push decides and sends
    ///         the verdict inside the verify inbound. No Read State request, nobody acting on Push.
    function test_fastPath_everyPostReadAtVerify_verdictFromTheInbound() public {
        (uint256 jobId, bytes32 key) = _verified(_atVerifySpec(), 600e6, 400e6);
        assertEq(lastVerify[0], abi.encode(uint256(600e6)), "read inside verify");
        _inboundOk();
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.PASS));
        (, uint256 r0,) = re.readOf(key, 0);
        assertEq(r0, 0, "no Read State request");
        assertEq(ugpc.count(), 1, "the verdict left from the inbound");
        assertTrue(_outbound());
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    /// @notice A `POST_AT_VERIFY` answer that fails an ALL decides the job inside the inbound, before the Read State
    ///         read is even sent.
    function test_fastPath_suppliedFailDecides_beforeReadState() public {
        JobSpec memory s = _exampleSpec();
        s.reads[0].at = ReadAt.POST_AT_VERIFY; // read 1 stays a Read State read
        (uint256 jobId, bytes32 key) = _verified(s, 1e6, 400e6); // Aave barely moved
        _track(block.number);
        _inboundOk();
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.FAIL));
        (, uint256 r1,) = re.readOf(key, 1);
        assertEq(r1, 0, "never sent");
        (, bool pass,) = _settleArgs(0);
        assertFalse(pass);
        assertTrue(_outbound());
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Rejected));
    }

    /// @notice A `POST_AT_VERIFY` answer and a Read State answer together: `sendVerdict` takes the `verify` answer as
    ///         given and checks it like any other.
    function test_mixed_atVerifyAndReadState_judgedWithBoth() public {
        JobSpec memory s = _exampleSpec();
        s.reads[0].at = ReadAt.POST_AT_VERIFY;
        (, bytes32 key) = _verified(s, 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.NONE), "check 1 still waits for Read State");
        _answer(key, 1, abi.encode(uint256(400e6)));
        bytes[] memory results = _results(key, 4);
        assertEq(results[0], abi.encode(uint256(600e6)), "the verify answer");
        results[0] = abi.encode(uint256(10_000e6));
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.ResultMismatch.selector, uint256(0)));
        re.sendVerdict(key, lastSpec, lastPre, results);
        _sendVerdict(key);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.PASS));
    }

    // ───────────── reads that can never be answered ─────────────

    /// @notice A read on a domain Read State blocks can never be answered: FAIL from the first inbound, the client
    ///         refunded at once (Phase 1 refuses such a job at `fund`; here the job is already funded).
    function test_blockedDomain_failsFromTheInbound() public {
        JobSpec memory s = _exampleSpec();
        s.reads[3].chainId = ARB; // a PRE read on Arbitrum: the snapshot sends an inbound
        core.setChainHeight(ARB_KEY, 900);
        vm.prank(readAdmin);
        readState.updateBlockedDomain(NS, ARB, true);
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        _snapshotPaying(jobId, INBOUND_GAS);
        _inboundOk();
        bytes32 key = gw.snapshotKeyOf(kernel_(), jobId);
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.FAIL));
        (bytes32 captureKey, bool pass,) = _settleArgs(0);
        assertFalse(pass);
        assertEq(captureKey, RemoteKeys.captureKey(key, 0, bytes32(0)), "no E yet");
        uint256 before = token.balanceOf(client);
        assertTrue(_outbound());
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Rejected));
        assertEq(token.balanceOf(client), before + BUDGET, "refunded before any work");
    }

    /// @notice With no PRE read on another chain the snapshot sends no inbound, so a POST read on a chain Push does not
    ///         track is first seen in the verify inbound. The FAIL decided there carries the capture key without E, and
    ///         the gateway takes it.
    function test_untrackedChain_firstSeenAtVerify_failIsApplied() public {
        JobSpec memory s = _exampleSpec();
        s.reads[1].chainId = ARB; // a POST read on a chain Push does not track; no PRE read elsewhere
        (uint256 jobId, bytes32 key) = _verified(s, 600e6, 400e6);
        _inboundOk();
        assertEq(uint8(_verdictOf(key)), uint8(Verdict.FAIL));
        uint256 before = token.balanceOf(client);
        assertTrue(_outbound());
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Rejected));
        assertEq(token.balanceOf(client), before + BUDGET);
    }

    /// @notice A FAIL decided at the snapshot that lands after the provider's `verify` is still applied.
    function test_earlyFail_landingAfterVerify_isApplied() public {
        JobSpec memory s = _exampleSpec();
        s.reads[3].chainId = ARB; // a PRE read on Arbitrum: the snapshot sends an inbound
        core.setChainHeight(ARB_KEY, 900);
        vm.prank(readAdmin);
        readState.updateBlockedDomain(NS, ARB, true);
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        bytes[] memory pre = _snapshotPaying(jobId, INBOUND_GAS);
        _inboundOk(); // FAIL decided; its outbound is on its way
        vm.roll(block.number + 1);
        _submit(jobId);
        _verify(jobId, s, pre); // the provider verifies before the FAIL lands
        assertTrue(_outbound());
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Rejected));
    }

    // ───────────── PC ─────────────

    /// @notice The job's unspent PC goes to whoever paid its latest inbound (here the provider, through the verify):
    ///         anyone may send it there once the verdict is out.
    function test_claimPrepaid_toThePayer_afterTheVerdict() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NotClaimable.selector, key));
        re.claimPrepaid(key);
        _answerPost(key);
        _sendVerdict(key);
        uint256 left = _prepaidOf(key);
        assertGt(left, 0);
        address uea = _providerUEA(CHAIN);
        uint256 before = uea.balance;
        vm.prank(stranger);
        re.claimPrepaid(key);
        assertEq(uea.balance, before + left);
        assertEq(_prepaidOf(key), 0);
    }

    /// @notice Each inbound's payer gets back what it paid for: the client's snapshot inbound pays the PRE read on
    ///         another chain, the provider's verify inbound the POST reads. A payer may take the job's unspent PC at
    ///         any time, so an abandoned job's PC is never stuck; taking it early only leaves the rest to be paid by
    ///         whoever sends it.
    function test_refunds_followWhoPaid() public {
        JobSpec memory s = _exampleSpec();
        s.reads[3].chainId = ARB; // a PRE read on Arbitrum: the client's snapshot inbound pays for it
        core.setChainHeight(ARB_KEY, 900);
        uint256 jobId = _create(s, address(0));
        _fund(jobId);
        bytes[] memory pre = _snapshotPaying(jobId, INBOUND_GAS);
        _inboundOk();
        bytes32 key = gw.snapshotKeyOf(kernel_(), jobId);
        (, uint256 preReq,) = re.readOf(key, 3);
        assertEq(readState.getPendingRead(preReq).revertRecipient, _clientUEA(CHAIN), "the client paid this read");

        // Bob never shows up: the client takes her PC back, no verdict needed
        uint256 left = _prepaidOf(key);
        assertEq(left, PC_FOR_JOB - (READ_FEE + 300_000 * BASE_FEE * 3), "the PRE read: fee + snapshot callback budget");
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NotClaimable.selector, key));
        re.claimPrepaid(key);
        vm.prank(_clientUEA(CHAIN));
        re.claimPrepaid(key);
        assertEq(_clientUEA(CHAIN).balance, left);
        assertEq(_prepaidOf(key), 0);

        // He does show up after all: his verify inbound pays for the POST reads, and the job is his to refund now
        _answerSave(key, 3, abi.encode(uint256(0)));
        vm.roll(block.number + 1);
        _work(600e6, 400e6);
        _submit(jobId);
        _verify(jobId, s, pre);
        _track(block.number);
        _inboundOk();
        (, uint256 postReq,) = re.readOf(key, 0);
        assertEq(readState.getPendingRead(postReq).revertRecipient, _providerUEA(CHAIN), "the provider paid this one");
        vm.prank(_clientUEA(CHAIN));
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.NotClaimable.selector, key));
        re.claimPrepaid(key);
    }

    function test_fund_unknownJob_andCredits() public {
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.UnknownJob.selector, bytes32(uint256(9))));
        re.fund{value: 1}(bytes32(uint256(9)));
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        uint256 before = _prepaidOf(key);
        vm.prank(stranger);
        re.fund{value: 3 ether}(key);
        assertEq(_prepaidOf(key), before + 3 ether);
    }

    function test_advance_onlySelf() public {
        vm.expectRevert(abi.encodeWithSelector(RemoteEvaluatorErrors.CallerIsNotSelf.selector, stranger));
        vm.prank(stranger);
        re.advance(bytes32(uint256(1)), "");
    }

    // ───────────── several chains ─────────────

    /// @notice Two remote chains: each gateway files jobs under its own chain, a job on one chain may read the other,
    ///         and each verdict goes back to its own gateway in its own chain's gas token.
    function test_twoChains() public {
        address bscGateway = makeAddr("bscGateway");
        address pBNB = makeAddr("pBNB");
        RemoteEvaluator.Remote[] memory two = new RemoteEvaluator.Remote[](2);
        two[0] = _one()[0];
        two[1] = RemoteEvaluator.Remote({
            chainId: "97", gateway: bscGateway, settleGasLimit: 600_000, senderCodeHash: senderCodeHash
        });
        RemoteEvaluator re2 = this.deployProxy(_config(two));
        address bscUEA = _ueaFor("97", RemoteKeys.senderOf(bscGateway, kernel_(), 7, VERIFY_SLOT, senderCodeHash));
        core.setGasToken("eip155:97", pBNB);
        core.setReadBaseFee(NS, "97", READ_FEE);
        core.setChainHeight("eip155:97", 500);
        _track(500);

        // a BSC job: reads 0, 2, 3 on BSC (2, 3 taken by its gateway at S), read 1 on Base Sepolia
        JobSpec memory s = _exampleSpec();
        s.reads[0].chainId = "97";
        s.reads[2].chainId = "97";
        s.reads[3].chainId = "97";
        bytes[] memory pre = _pre4();
        vm.deal(bscUEA, 10 ether);
        vm.prank(bscUEA);
        re2.onRemoteJob{value: PC_FOR_JOB}(kernel_(), 7, client, abi.encode(s), pre, 10, 11, new bytes[](4));
        bytes32 key = _keyOf("97", 7, abi.encode(s), pre, 10);
        (uint64 h0, uint256 r0,) = re2.readOf(key, 0);
        (uint64 h1, uint256 r1,) = re2.readOf(key, 1);
        assertEq(h0, 11, "BSC read at E");
        assertEq(h1, 500, "Base read at Push's tracked height for Base");
        assertTrue(_deliver(r0, abi.encode(uint256(600e6))));
        assertTrue(_deliver(r1, abi.encode(uint256(400e6))));
        bytes[] memory results = new bytes[](4);
        results[0] = abi.encode(uint256(600e6));
        results[1] = abi.encode(uint256(400e6));
        re2.sendVerdict(key, abi.encode(s), pre, results);
        MockUGPC.Out memory o = ugpc.out(ugpc.count() - 1);
        assertEq(o.req.recipient, abi.encodePacked(bscGateway));
        assertEq(o.req.token, pBNB);
        assertEq(o.req.gasLimit, 600_000);
        assertEq(o.req.revertRecipient, _clientUEA("97"));
    }

    // ───────────── gas ─────────────

    /// @notice Push gas for one verify inbound (the running example: 4 reads, 2 POST reads sent), so callers can size
    ///         `PushFees.gasLimit`.
    function test_gas_verifyInbound() public {
        (uint256 jobId,) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        address uea = _senderUEA(jobId, VERIFY_SLOT); // the UEA exists; the node deploys it outside the payload
        (UniversalPayload memory p,) = _lastPayload();
        vm.deal(uea, p.value);
        vm.prank(UE_MODULE, UE_MODULE);
        uint256 g = gasleft();
        IUEA(uea).executeUniversalTx(p, "");
        uint256 used = g - gasleft();
        console2.log("verify inbound gas, example job (UEA_EVM + onRemoteJob + 2 Read State requests):", used);
        assertLt(used, p.gasLimit);
    }

    function test_gas_fastPath() public {
        (uint256 jobId,) = _verified(_atVerifySpec(), 600e6, 400e6);
        address uea = _senderUEA(jobId, VERIFY_SLOT);
        (UniversalPayload memory p,) = _lastPayload();
        vm.deal(uea, p.value);
        vm.prank(UE_MODULE, UE_MODULE);
        uint256 g = gasleft();
        IUEA(uea).executeUniversalTx(p, "");
        uint256 used = g - gasleft();
        console2.log("verify inbound gas, every POST read at verify (judge + verdict outbound):", used);
        assertLt(used, p.gasLimit);
    }

    function test_gas_callback_and_sendVerdict() public {
        (, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        (, uint256 r0,) = re.readOf(key, 0);
        vm.prank(address(readState));
        uint256 g = gasleft();
        re.onUniversalData(r0, abi.encode(uint256(600e6)));
        console2.log("onUniversalData gas (hash only):", g - gasleft());
        delivered[key][0] = abi.encode(uint256(600e6));
        _answer(key, 1, abi.encode(uint256(400e6)));
        g = gasleft();
        _sendVerdict(key);
        console2.log("sendVerdict gas (judge 4 reads + outbound):", g - gasleft());
    }
}
