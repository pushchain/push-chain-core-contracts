// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {UniversalEvalBase} from "./UniversalEvalBase.t.sol";
import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {Verdict, OwnerCheck, ReadConfig} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {
    UniversalEvaluatorErrors,
    ReadRequestErrors,
    JobSpecErrors
} from "../../src/agentic-commerce-8183/libraries/Errors.sol";
import {RequestStatus, MAX_CALLBACK_GAS_LIMIT} from "../../src/libraries/ReadTypes.sol";
import {
    JobSpec,
    Read,
    Check,
    EvalType,
    Op,
    NodeKind,
    T_TUPLE,
    T_BYTES,
    T_ARRAY,
    T_UINT
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";

/// @notice The UniversalEvaluator end to end through the UniversalHook, against the real kernel and the real Read
///         State contract. The snapshot is taken inside `fund`; the "after" reads are sent by `submit`.
contract UniversalEvaluatorTest is UniversalEvalBase {
    // ───────────── happy path ─────────────

    /// @dev Bob's swap: 0 WETH before, 0.3905 after, at least 0.38 needed → complete, provider paid, no extra call.
    function test_UE01_swapPass_completesFromSubmit() public {
        uint256 jobId = _submittedSwap(0);
        uint256 providerBefore = token.balanceOf(provider);

        UniversalEvaluator.Evaluation memory e = ue.evaluationOf(jobId);
        assertTrue(e.endFixed && e.started, "submit fixed the blocks and sent the reads");
        assertEq(ue.endHeightOf(jobId, 0), START_HEIGHT + 120, "end block = tracked height at submit");
        assertEq(ue.fundHeightOf(jobId, 0), START_HEIGHT, "snapshot block = tracked height at fund");

        _answer(jobId, 0, abi.encode(uint256(0.3905e18)));

        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
        assertEq(token.balanceOf(provider) - providerBefore, BUDGET);
        e = ue.evaluationOf(jobId);
        assertTrue(e.done && e.applied);
        assertEq(uint8(e.verdict), uint8(Verdict.PASS));
    }

    function test_UE02_verdictIsNoneBeforeEvaluation() public {
        uint256 jobId = _createSpec(_swapSpec());
        assertEq(uint8(ue.evaluationOf(jobId).verdict), uint8(Verdict.NONE));
    }

    /// @dev The read goes out at the fixed block, paid fee + 1M gas × base fee × 3; unspent budget back to the client.
    function test_UE03_readAtFixedBlock_andPaid() public {
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        _answerSnapshot(jobId, 0, 0);
        core.setChainHeight(BASE_KEY, START_HEIGHT + 77);
        uint256 before = ue.prepaidOf(jobId);
        vm.recordLogs();
        _submit(jobId);

        uint256 requestId = ue.requestOf(jobId, 0);
        assertEq(_readSpecFromLogs(requestId).blockNumber, START_HEIGHT + 77);
        assertEq(before - ue.prepaidOf(jobId), READ_COST);
        assertEq(readState.getPendingRead(requestId).revertRecipient, address(agw));
    }

    // ───────────── FAIL is final ─────────────

    /// @dev NUM measures the change: WETH already in the CEA does not count, and the FAIL rejects at once.
    function test_UE04_failRejectsAtOnce_andRefundsClient() public {
        uint256 jobId = _submittedSwap(5e18);
        uint256 clientBefore = token.balanceOf(address(agw));
        _answer(jobId, 0, abi.encode(uint256(5.1e18))); // +0.1 only

        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Rejected));
        assertEq(token.balanceOf(address(agw)) - clientBefore, BUDGET);
        assertEq(uint8(ue.evaluationOf(jobId).verdict), uint8(Verdict.FAIL));
    }

    // ───────────── retries: provider only, same block, no limit ─────────────

    function test_UE05_errorAnswer_providerRetriesSameBlock_noLimit() public {
        uint256 jobId = _submittedSwap(0);
        uint64 fixedBlock = ue.endHeightOf(jobId, 0);
        _answer(jobId, 0, "");
        assertEq(uint8(ue.evaluationOf(jobId).verdict), uint8(Verdict.INCONCLUSIVE));

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.CallerIsNotProvider.selector, stranger));
        ue.retryReads{value: READ_COST}(jobId);

        core.setChainHeight(BASE_KEY, START_HEIGHT + 5000); // the chain moves on; the retry must not follow
        for (uint256 i; i < 5; ++i) {
            vm.recordLogs();
            vm.prank(provider);
            ue.retryReads{value: READ_COST}(jobId);
            assertEq(_readSpecFromLogs(ue.requestOf(jobId, 0)).blockNumber, fixedBlock);
            if (i < 4) _answer(jobId, 0, "");
        }
        _answer(jobId, 0, abi.encode(uint256(0.4e18)));
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    function test_UE06_expiredRead_retry() public {
        uint256 jobId = _submittedSwap(0);
        uint256 first = ue.requestOf(jobId, 0);

        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.NothingToRetry.selector, jobId));
        ue.retryReads(jobId); // still in flight

        vm.roll(block.number + 301);
        vm.prank(READ_MODULE);
        readState.expireExternalRead(first);
        vm.prank(provider);
        ue.retryReads{value: READ_COST}(jobId);
        assertTrue(ue.requestOf(jobId, 0) != first);
        _answer(jobId, 0, abi.encode(uint256(0.4e18)));
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    /// @dev No verdict: the job stays Submitted and the wallet busy until someone calls `claimRefund` after
    ///      `expiredAt + EVALUATOR_GRACE_PERIOD`. That transaction refunds the client and frees the wallet.
    function test_UE07_stuckJob_endsThroughClaimRefund() public {
        uint256 jobId = _submittedSwap(0);
        _answer(jobId, 0, "");
        assertTrue(hook.isAGWBusy(address(agw)));

        vm.warp(kernel.getJob(jobId).expiredAt + kernel.EVALUATOR_GRACE_PERIOD());
        assertTrue(hook.isAGWBusy(address(agw)), "eligible is not expired: someone must call claimRefund");
        uint256 clientBefore = token.balanceOf(address(agw));
        vm.prank(stranger);
        kernel.claimRefund(jobId);
        assertEq(token.balanceOf(address(agw)) - clientBefore, BUDGET);
        assertFalse(hook.isAGWBusy(address(agw)));
    }

    /// @dev ANY: one venue passes, the other answers with an error. One pass is enough.
    function test_UE08_anyPassesDespiteUnreadableBranch() public {
        uint256 jobId = _createSpec(_anySpec());
        _fund(jobId); // CMP only: nothing to snapshot
        assertTrue(ue.ready(jobId));
        _advance();
        _submit(jobId);
        _answer(jobId, 1, "");
        _answer(jobId, 0, abi.encode(uint256(100e6)));
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    // ───────────── when the reads can't go out inside submit ─────────────

    /// @dev PC short at submit: `submit` succeeds with its blocks fixed; the provider sends them later, at those blocks.
    function test_UE09_prepaidShort_submitSucceeds_providerSendsLater() public {
        uint256 jobId = _createSpec(_swapSpec());
        (uint256 snap,) = ue.prefundCost(jobId);
        _prefund(jobId, snap); // the snapshot only
        _fundWith(jobId, _fundParams(jobId));
        _answerSnapshot(jobId, 0, 0);
        core.setChainHeight(BASE_KEY, START_HEIGHT + 120);
        _submit(jobId);

        UniversalEvaluator.Evaluation memory e = ue.evaluationOf(jobId);
        assertTrue(e.endFixed);
        assertFalse(e.started);
        assertEq(ue.endHeightOf(jobId, 0), START_HEIGHT + 120);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.CallerIsNotProvider.selector, stranger));
        ue.sendReads{value: READ_COST}(jobId);

        core.setChainHeight(BASE_KEY, START_HEIGHT + 9000);
        vm.recordLogs();
        vm.prank(provider);
        ue.sendReads{value: READ_COST}(jobId);
        assertEq(_readSpecFromLogs(ue.requestOf(jobId, 0)).blockNumber, START_HEIGHT + 120);

        _answer(jobId, 0, abi.encode(uint256(0.4e18)));
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    /// @dev Read State paused at submit: `submit` is never blocked; the provider sends once it's back.
    function test_UE10_readStatePaused_submitSucceeds() public {
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        _answerSnapshot(jobId, 0, 0);
        vm.prank(readAdmin);
        readState.pause();
        _advance();
        _submit(jobId);
        assertTrue(ue.evaluationOf(jobId).endFixed);
        assertFalse(ue.evaluationOf(jobId).started);

        vm.prank(readAdmin);
        readState.unpause();
        vm.prank(provider);
        ue.sendReads(jobId); // the prepaid PC is still there
        assertTrue(ue.evaluationOf(jobId).started);

        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.AlreadyStarted.selector, jobId));
        ue.sendReads(jobId);
    }

    /// @dev Submitted before the snapshot was in: the end blocks are fixed at submit anyway; once the snapshot lands
    ///      the provider sends the reads at those blocks.
    function test_UE11_submitBeforeSnapshotReady_blocksStillFixed() public {
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        core.setChainHeight(BASE_KEY, START_HEIGHT + 50);
        _submit(jobId);
        assertTrue(ue.evaluationOf(jobId).endFixed);
        assertFalse(ue.evaluationOf(jobId).started);

        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.SnapshotNotReady.selector, jobId));
        ue.sendReads(jobId);

        _answerSnapshot(jobId, 0, 0);
        core.setChainHeight(BASE_KEY, START_HEIGHT + 900);
        vm.recordLogs();
        vm.prank(provider);
        ue.sendReads(jobId);
        assertEq(_readSpecFromLogs(ue.requestOf(jobId, 0)).blockNumber, START_HEIGHT + 50);
    }

    // ───────────── kernel refusals ─────────────

    function test_UE12_kernelPaused_settleLater() public {
        uint256 jobId = _submittedSwap(0);
        _pause();
        _answer(jobId, 0, abi.encode(uint256(0.4e18)));
        UniversalEvaluator.Evaluation memory e = ue.evaluationOf(jobId);
        assertTrue(e.done);
        assertFalse(e.applied);

        vm.prank(admin);
        kernel.unpause();
        ue.settle(jobId);
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));

        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.NothingToSettle.selector, jobId));
        ue.settle(jobId);
    }

    // ───────────── owner checkpoint: recorded only ─────────────

    function test_UE13_ownerCheck_clean_touched_unknown() public {
        uint256 a = _submittedSwap(0);
        _answer(a, 0, abi.encode(uint256(0.4e18)));
        assertEq(uint8(ue.evaluationOf(a).ownerCheck), uint8(OwnerCheck.CLEAN));

        uint256 b = _submittedSwap(0);
        vm.prank(owner);
        agw.execute(address(token), 0, abi.encodeCall(IERC20.approve, (address(1), 1))); // any owner action
        _answer(b, 0, abi.encode(uint256(0.4e18)));
        assertEq(uint8(ue.evaluationOf(b).ownerCheck), uint8(OwnerCheck.TOUCHED));
        assertEq(uint8(_status(b)), uint8(IAgenticCommerce.JobStatus.Completed), "recorded only");

        uint256 c = _submittedSwap(0);
        agw.setCounterBroken(true);
        _answer(c, 0, abi.encode(uint256(0.4e18)));
        assertEq(uint8(ue.evaluationOf(c).ownerCheck), uint8(OwnerCheck.UNKNOWN));
        assertEq(uint8(_status(c)), uint8(IAgenticCommerce.JobStatus.Completed), "never blocks settlement");
    }

    // ───────────── answer limits ─────────────

    /// @dev "bytes equals X": an answer of exactly MAX_RESULT_LENGTH (4,096) bytes decodes; one byte more is unreadable.
    function test_UE14_resultSizeCap_atAndAboveLimit() public {
        bytes memory payload = new bytes(4096 - 64); // abi.encode(bytes) adds an offset and a length word
        for (uint256 i; i < payload.length; ++i) {
            payload[i] = bytes1(uint8(i));
        }
        bytes memory answer = abi.encode(payload);
        assertEq(answer.length, 4096);

        JobSpec memory s = _swapSpec();
        s.reads[0].outputs = abi.encodePacked(T_TUPLE, uint8(1), T_BYTES);
        s.checks[0] = Check({read: 0, evalType: EvalType.CMP, op: Op.EQ, target: int256(uint256(keccak256(payload)))});

        uint256 over = _createSpec(s);
        _fund(over); // CMP only: nothing to snapshot
        _advance();
        _submit(over);
        _answer(over, 0, bytes.concat(answer, hex"00")); // 4,097 bytes
        (bool ok,) = ue.answerOf(over, 0);
        assertFalse(ok, "4,097 bytes: unreadable");
        assertEq(uint8(ue.evaluationOf(over).verdict), uint8(Verdict.INCONCLUSIVE));

        vm.warp(kernel.getJob(over).expiredAt + kernel.EVALUATOR_GRACE_PERIOD());
        kernel.claimRefund(over); // free the wallet
        _advance(); // a fresh height: the old one is older than MAX_HEIGHT_AGE after the warp
        uint256 at = _createSpec(s);
        _fund(at);
        _advance();
        _submit(at);
        _answer(at, 0, answer); // exactly 4,096 bytes
        (ok,) = ue.answerOf(at, 0);
        assertTrue(ok, "4,096 bytes: decoded");
        assertEq(uint8(_status(at)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    /// @dev "how many elements": a length word not backed by elements is not a value.
    function test_UE15_forgedArrayLength_unreadable() public {
        JobSpec memory s = _swapSpec();
        s.reads[0].outputs = abi.encodePacked(T_TUPLE, uint8(1), T_ARRAY, T_UINT);
        s.checks[0] = Check({read: 0, evalType: EvalType.CMP, op: Op.GTE, target: 2});
        uint256 jobId = _createSpec(s);
        _fund(jobId);
        _advance();
        _submit(jobId);

        bytes memory forged = abi.encode(uint256(0x20), uint256(1_000_000)); // offset, length, no elements
        _answer(jobId, 0, forged);
        (bool ok,) = ue.answerOf(jobId, 0);
        assertFalse(ok);

        uint256[] memory three = new uint256[](3);
        vm.prank(provider);
        ue.retryReads{value: READ_COST}(jobId);
        _answer(jobId, 0, abi.encode(three));
        (bool ok2, int256 v) = ue.answerOf(jobId, 0);
        assertTrue(ok2);
        assertEq(v, 3);
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    // ───────────── evidence ─────────────

    /// @dev The kernel `reason` commits to the spec and every read in index order, whatever order answers arrive in.
    function test_UE16_reasonCommitsToEvidence_inIndexOrder() public {
        uint256 jobId = _createSpec(_anySpec());
        _fund(jobId);
        _advance();
        _submit(jobId);
        bytes memory a1 = abi.encode(uint256(5e6));
        bytes memory a0 = abi.encode(uint256(100e6));
        uint256 r0 = ue.requestOf(jobId, 0);
        uint256 r1 = ue.requestOf(jobId, 1);
        vm.recordLogs();
        _answer(jobId, 1, a1); // out of order on purpose
        _answer(jobId, 0, a0);

        (bytes32 leaf0,) = ue.evidenceOf(jobId, 0);
        (bytes32 leaf1,) = ue.evidenceOf(jobId, 1);
        uint64 h = ue.endHeightOf(jobId, 0);
        assertEq(leaf0, keccak256(abi.encode(uint8(0), r0, h, keccak256(a0), true, int256(100e6))));
        assertEq(leaf1, keccak256(abi.encode(uint8(1), r1, h, keccak256(a1), true, int256(5e6))));

        bytes32[] memory afters = new bytes32[](2);
        afters[0] = leaf0;
        afters[1] = leaf1;
        bytes32[] memory befores = new bytes32[](2);
        bytes32 expected =
            keccak256(abi.encode(jobId, ue.cacheOf(jobId).specHash, befores, afters, Verdict.PASS, OwnerCheck.CLEAN));
        assertEq(ue.cacheOf(jobId).specHash, keccak256(bytes(kernel.getJob(jobId).description)));
        assertEq(_reasonFromLogs(), expected);
    }

    function _reasonFromLogs() internal returns (bytes32) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == UniversalEvaluator.Verified.selector) {
                (,, bytes32 reason) = abi.decode(logs[i].data, (Verdict, OwnerCheck, bytes32));
                return reason;
            }
        }
        revert("Verified not found");
    }

    // ───────────── PC ─────────────

    function test_UE17_claimPrepaid() public {
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        _prefund(jobId, 1 ether); // headroom for retries
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.JobStillLive.selector, jobId));
        ue.claimPrepaid(jobId);

        _answerSnapshot(jobId, 0, 0);
        _advance();
        _submit(jobId);
        _answer(jobId, 0, abi.encode(uint256(0.4e18)));

        uint256 before = address(agw).balance;
        ue.claimPrepaid(jobId);
        assertEq(address(agw).balance - before, 1 ether);
        assertEq(ue.prepaidOf(jobId), 0);
    }

    function test_UE18_prefundCost() public {
        uint256 jobId = _createSpec(_swapSpec());
        (uint256 snap, uint256 eval_) = ue.prefundCost(jobId);
        assertEq(snap, SNAPSHOT_COST);
        assertEq(eval_, READ_COST);
    }

    /// @dev An unfunded callback is never delivered by the node.
    function test_UE19_nodeRefusesUnfundedCallback() public {
        uint256 jobId = _submittedSwap(0);
        vm.fee(BASE_FEE * 4); // base fee rose past the 3x headroom before delivery
        assertFalse(_deliver(ue.requestOf(jobId, 0), abi.encode(uint256(0.4e18))));
        vm.fee(BASE_FEE);
        assertTrue(_deliver(ue.requestOf(jobId, 0), abi.encode(uint256(0.4e18))));
    }

    function test_UE20_sweepFees() public {
        vm.prank(admin);
        kernel.setEvaluatorFee(100); // 1%
        uint256 jobId = _submittedSwap(0);
        _answer(jobId, 0, abi.encode(uint256(0.4e18)));
        assertEq(token.balanceOf(address(ue)), BUDGET / 100);
        ue.sweepFees();
        assertEq(token.balanceOf(feeRecipient), BUDGET / 100);
    }

    // ───────────── access ─────────────

    function test_UE21_access() public {
        vm.startPrank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.CallerIsNotReadState.selector, stranger));
        ue.onUniversalData(1, "");
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.CallerIsNotHook.selector, stranger));
        ue.verifyFromSubmit(1);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.CallerIsNotHook.selector, stranger));
        ue.startSnapshot(1, "");
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.CallerIsNotHook.selector, stranger));
        ue.setSpec(1, "");
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.CallerIsNotSelf.selector, stranger));
        ue.sendFromSubmit(1);
        vm.stopPrank();
    }

    // ───────────── deployment ─────────────

    /// @dev Not upgradeable: every dependency and setting is fixed in the constructor, which refuses bad values.
    function test_UE22_constructor_fixesConfig_refusesBadValues() public {
        ReadConfig memory c = ue.readConfig();
        ReadConfig memory want = _config();
        assertEq(c.readTtl, want.readTtl);
        assertEq(c.callbackGasLimit, want.callbackGasLimit);
        assertEq(c.snapshotCallbackGasLimit, want.snapshotCallbackGasLimit);
        assertEq(c.budgetMultiplier, want.budgetMultiplier);
        assertEq(c.maxHeightAge, want.maxHeightAge);
        assertEq(address(ue.KERNEL()), address(kernel));
        assertEq(ue.HOOK(), address(hook));
        assertEq(address(ue.LOGIC()), address(logic));

        vm.expectRevert(UniversalEvaluatorErrors.ZeroValue.selector);
        new UniversalEvaluator(
            address(0), address(hook), address(readState), address(core), address(logic), feeRecipient, want
        );

        ReadConfig memory bad = _config();
        bad.callbackGasLimit = MAX_CALLBACK_GAS_LIMIT + 1;
        vm.expectRevert(UniversalEvaluatorErrors.ZeroValue.selector);
        new UniversalEvaluator(
            address(kernel), address(hook), address(readState), address(core), address(logic), feeRecipient, bad
        );

        bad = _config();
        bad.budgetMultiplier = 0;
        vm.expectRevert(UniversalEvaluatorErrors.ZeroValue.selector);
        new UniversalEvaluator(
            address(kernel), address(hook), address(readState), address(core), address(logic), feeRecipient, bad
        );

        bad = _config();
        bad.maxHeightAge = 0; // freshness can't be switched off
        vm.expectRevert(UniversalEvaluatorErrors.ZeroValue.selector);
        new UniversalEvaluator(
            address(kernel), address(hook), address(readState), address(core), address(logic), feeRecipient, bad
        );
    }

    // ───────────── retries, heights, domains ─────────────

    /// @dev Once the job has ended, its PC is the client's to claim: the provider can't spend it on retries.
    function test_UE23_retryAfterJobEnded_refused() public {
        uint256 jobId = _submittedSwap(0);
        _answer(jobId, 0, ""); // unreadable: INCONCLUSIVE
        assertEq(uint8(ue.evaluationOf(jobId).verdict), uint8(Verdict.INCONCLUSIVE));
        _prefund(jobId, READ_COST); // PC a retry could spend
        vm.warp(uint256(kernel.getJob(jobId).expiredAt) + kernel.EVALUATOR_GRACE_PERIOD());
        kernel.claimRefund(jobId);

        uint256 left = ue.prepaidOf(jobId);
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.WrongStatus.selector, jobId));
        ue.retryReads(jobId);
        assertEq(ue.prepaidOf(jobId), left, "client PC untouched");
    }

    /// @dev Every read's tracked height must be fresh at `fund`, not only the snapshot reads'.
    function test_UE24_staleHeightAtFund_refused() public {
        uint256 jobId = _createSpec(_anySpec()); // CMP only: no snapshot read
        (uint256 snap, uint256 eval_) = ue.prefundCost(jobId);
        _prefund(jobId, snap + eval_);
        uint256 seen = core.timestampObservedAtByChainNamespace(BASE_KEY);
        vm.warp(seen + _config().maxHeightAge + 1);
        bytes memory fp = _fundParams(jobId);
        vm.expectRevert(abi.encodeWithSelector(ReadRequestErrors.HeightStale.selector, BASE_KEY, seen));
        _fundWith(jobId, fp);
    }

    /// @dev A height that has not moved since `fund` can't hold the provider's work: `submit` reverts as a whole, and
    ///      goes through once the chain has moved on.
    function test_UE25_endHeightMustBeAboveFundHeight() public {
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        _answerSnapshot(jobId, 0, 0);
        vm.prank(provider); // the tracked height is still the one recorded at fund
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalEvaluatorErrors.EndHeightNotAfterFund.selector, jobId, 0, START_HEIGHT, START_HEIGHT
            )
        );
        kernel.submit(jobId, keccak256("done"), "");
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Funded), "submit undone");

        _advance();
        _submit(jobId);
        assertEq(ue.endHeightOf(jobId, 0), START_HEIGHT + 120);
        _answer(jobId, 0, abi.encode(uint256(0.4e18)));
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    /// @dev Fresh at `fund`, stale by `submit`: `submit` reverts `HeightStale`, and goes through after a fresh
    ///      observation.
    function test_UE28_staleHeightAtSubmit_reverts() public {
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        _answerSnapshot(jobId, 0, 0);
        _advance(); // the swap lands; observed now
        uint256 seen = core.timestampObservedAtByChainNamespace(BASE_KEY);
        vm.warp(seen + _config().maxHeightAge + 1); // and not observed since
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(ReadRequestErrors.HeightStale.selector, BASE_KEY, seen));
        kernel.submit(jobId, keccak256("done"), "");
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Funded), "submit undone");

        _advance(); // a fresh observation
        _submit(jobId);
        assertTrue(ue.evaluationOf(jobId).endFixed);
        assertTrue(ue.evaluationOf(jobId).started, "reads sent inside submit");
    }

    /// @dev At no gas level does `submit` succeed without fixing the end blocks, and `sendReads` never fixes them,
    ///      so the provider can't choose when the job is measured. `UniversalHook.designProofs.t.sol` shows the
    ///      earlier try/catch in the hook let a gas-starved `submit` through with no end blocks.
    function test_UE26_submitNeverSucceedsWithoutEndBlocks() public {
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        _answerSnapshot(jobId, 0, 0);
        _advance();
        bytes memory submitCall = abi.encodeCall(kernel.submit, (jobId, keccak256("done"), bytes("")));

        uint256 firstOk;
        uint256 okCount;
        for (uint256 g = 30_000; g < 900_000; g += 1_000) {
            uint256 snap = vm.snapshotState();
            vm.prank(provider);
            (bool ok,) = address(kernel).call{gas: g}(submitCall);
            bool submitted = _status(jobId) == IAgenticCommerce.JobStatus.Submitted;
            bool fixed_ = ue.evaluationOf(jobId).endFixed;
            vm.revertToState(snap);
            assertEq(submitted, ok, "Submitted exactly when the call succeeded");
            if (ok) {
                assertTrue(fixed_, "every successful submit fixed the end blocks");
                if (firstOk == 0) firstOk = g;
                ++okCount;
            }
        }
        assertTrue(firstOk != 0 && okCount > 100, "the scan reached gas levels where submit succeeds");
    }

    /// @dev `sendReads` only sends at blocks fixed in `submit`. The one way a Submitted job has none: the kernel admin
    ///      detached its hook before `submit`, so the hook never called the evaluator.
    function test_UE32_sendReads_requiresEndBlocksFixedInSubmit() public {
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        _answerSnapshot(jobId, 0, 0);
        uint256[] memory ids = new uint256[](1);
        ids[0] = jobId;
        vm.prank(admin);
        kernel.batchDetachHook(ids);
        _advance();
        _submit(jobId);
        assertFalse(ue.evaluationOf(jobId).endFixed);

        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.EndBlocksNotFixed.selector, jobId));
        ue.sendReads(jobId);
    }

    /// @dev Preflight only (the admin can still block the chain later): a read Read State would refuse fails `fund`.
    function test_UE27_blockedDomainAtFund_refused() public {
        uint256 jobId = _createSpec(_anySpec()); // CMP only: no snapshot read would reach Read State at fund
        (uint256 snap, uint256 eval_) = ue.prefundCost(jobId);
        _prefund(jobId, snap + eval_);
        vm.prank(readAdmin);
        readState.updateBlockedDomain(NS, BASE, true);
        bytes memory fp = _fundParams(jobId);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.ReadDomainBlocked.selector, 0));
        _fundWith(jobId, fp);
    }

    // ───────────── early finalisation, confirmation ceiling ─────────────

    /// @dev "Aave OR Morpho": the Aave answer alone decides the root, so the provider is paid without waiting for
    ///      the Morpho read, which never answers here. A late answer changes nothing.
    function test_UE29_rootDecided_paysWithoutWaitingForTheRest() public {
        uint256 jobId = _createSpec(_anySpec());
        _fund(jobId);
        _advance();
        _submit(jobId);
        _answer(jobId, 0, abi.encode(uint256(100e6))); // Aave: deposited
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed), "paid on the deciding answer");
        UniversalEvaluator.Evaluation memory e = ue.evaluationOf(jobId);
        assertEq(uint8(e.verdict), uint8(Verdict.PASS));
        assertEq(e.pending, 1, "the Morpho read was still out");

        _answer(jobId, 1, abi.encode(uint256(0))); // late: ignored
        (bool ok,) = ue.answerOf(jobId, 1);
        assertFalse(ok, "not recorded after the verdict");
    }

    /// @dev "All of these": the first FAIL decides, and the job is rejected at once.
    function test_UE30_allFailsOnFirstFail() public {
        JobSpec memory s = _anySpec();
        s.nodes[0].kind = NodeKind.ALL;
        uint256 jobId = _createSpec(s);
        _fund(jobId);
        _advance();
        _submit(jobId);
        _answer(jobId, 1, abi.encode(uint256(1e6))); // below 99.99: this branch fails
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Rejected));
    }

    /// @dev A read asking for more confirmations than the evaluator's ceiling could never be answered: `fund` refuses.
    function test_UE31_confirmationsAboveCeiling_refusedAtFund() public {
        JobSpec memory s = _anySpec();
        s.reads[1].minConfirmations = _config().maxConfirmations + 1;
        uint256 jobId = _createSpec(s);
        (uint256 snap, uint256 eval_) = ue.prefundCost(jobId);
        _prefund(jobId, snap + eval_);
        bytes memory fp = _fundParams(jobId);
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadConfirmations.selector, 1));
        _fundWith(jobId, fp);
    }
}
