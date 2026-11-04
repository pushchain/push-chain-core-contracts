// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {UniversalEvalBase} from "./UniversalEvalBase.t.sol";
import {MockScheduler} from "./mocks/MockScheduler.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {UniversalHookErrors} from "../../src/agentic-commerce-8183/libraries/Errors.sol";
import {JobDescription} from "../../src/agentic-commerce-8183/libraries/JobDescription.sol";
import {OwnerCheck, Verdict} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {
    JobSpec,
    Recurrence,
    AllowedMutability,
    RECURRING_JOB_PREFIX
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";

/// @notice Exposes `JobDescription`'s internal functions.
contract DescriptionHarness {
    function isRecurring(bytes memory d) external pure returns (bool) {
        return JobDescription.isRecurring(d);
    }

    function specBytes(bytes memory d) external pure returns (bytes memory) {
        return JobDescription.specBytes(d);
    }

    function recurrence(bytes memory d) external pure returns (Recurrence memory) {
        return JobDescription.recurrence(d);
    }

    function setIndex(bytes memory d, uint16 index) external pure returns (bytes memory) {
        JobDescription.setIndex(d, index);
        return d;
    }
}

/// @notice Recurring jobs: the description format, the evaluator reading it, and the hook running a series.
contract UniversalHookRecurringTest is UniversalEvalBase {
    MockScheduler internal scheduler;
    DescriptionHarness internal desc;

    uint32 internal constant PERIOD = 1 days;
    uint256 internal constant WINDOW = 12 hours;
    uint256 internal constant PASS_VALUE = 0.4e18;
    uint256 internal t0;

    event SeriesOpened(uint256 indexed seriesId, address indexed agw, uint16 count, uint32 period);
    event PeriodOpened(uint256 indexed seriesId, uint16 period, uint256 jobId);
    event RenewFailed(uint256 indexed seriesId, uint16 period, bytes reason);
    event PeriodFunded(uint256 indexed seriesId, uint16 period, uint256 jobId);
    event PeriodMissed(uint256 indexed seriesId, uint16 period, uint256 jobId, bytes reason);
    event SeriesClosed(uint256 indexed seriesId, UniversalHook.SeriesStatus status);

    function setUp() public override {
        super.setUp();
        scheduler = new MockScheduler();
        desc = new DescriptionHarness();
        _setScheduler(address(scheduler));
        vm.prank(owner);
        agw.setRenewer(address(hook));
        t0 = block.timestamp;
    }

    // ═════════════════════════════ JobDescription ═════════════════════════════

    function test_RJ01_plainDescription_notRecurring_specUnchanged() public view {
        bytes memory d = abi.encode(_swapSpec());
        assertFalse(desc.isRecurring(d));
        assertEq(keccak256(desc.specBytes(d)), keccak256(d));
        assertFalse(desc.isRecurring(hex"aabbcc"));
        assertFalse(desc.isRecurring(""));
    }

    function test_RJ02_recurringDescription_specBytesDecodes_originalUntouched() public view {
        JobSpec memory s = _swapSpec();
        bytes memory d = _recurring(s, _rec(3, 0));
        bytes memory before = bytes.concat(d);
        assertTrue(desc.isRecurring(d));
        bytes memory spec = desc.specBytes(d);
        assertEq(keccak256(abi.encode(abi.decode(spec, (JobSpec)))), keccak256(abi.encode(s)));
        assertEq(keccak256(d), keccak256(before));
    }

    /// @notice The design's claim: without the prefix, the rest still decodes as the JobSpec alone.
    function test_RJ03_withoutPrefix_decodesAsJobSpec() public view {
        JobSpec memory s = _swapSpec();
        bytes memory rest = abi.encode(s, _rec(3, 0));
        assertEq(keccak256(abi.encode(abi.decode(rest, (JobSpec)))), keccak256(abi.encode(s)));
    }

    function testFuzz_RJ04_recurrence_roundTrip(uint64 start, uint32 period, uint16 count, uint16 index, uint256 fee)
        public
        view
    {
        Recurrence memory r = Recurrence(start, period, count, index, fee);
        Recurrence memory got = desc.recurrence(_recurring(_swapSpec(), r));
        assertEq(got.start, start);
        assertEq(got.period, period);
        assertEq(got.count, count);
        assertEq(got.index, index);
        assertEq(got.feePerPeriod, fee);
    }

    function testFuzz_RJ05_setIndex_changesOnlyTheIndex(uint16 index) public view {
        JobSpec memory s = _swapSpec();
        Recurrence memory r = _rec(9, 0);
        bytes memory d = desc.setIndex(_recurring(s, r), index);
        r.index = index;
        assertEq(keccak256(d), keccak256(_recurring(s, r)));
    }

    function test_RJ06_recurrence_refusesMalformed() public {
        vm.expectRevert(bytes("not a recurring description"));
        desc.recurrence(abi.encode(_swapSpec()));
        vm.expectRevert(bytes("not a recurring description"));
        desc.recurrence(abi.encodePacked(RECURRING_JOB_PREFIX, uint256(0xc0)));
        // prefix + a plain spec: the offset word is 0x20, not 0xC0
        vm.expectRevert(bytes("bad recurrence"));
        desc.recurrence(abi.encodePacked(RECURRING_JOB_PREFIX, abi.encode(_swapSpec())));
        vm.expectRevert(bytes("not a recurring description"));
        desc.setIndex(abi.encode(_swapSpec()), 1);
    }

    // ═════════════════════════════ evaluator ═════════════════════════════

    function test_RJ10_evaluator_pricesRecurringLikePlain() public {
        uint256 plain = _createSpec(_swapSpec());
        uint256 recurring = _createAt(_recurring(_swapSpec(), _rec(3, 0)), t0 + WINDOW);
        (uint256 s1, uint256 e1) = ue.prefundCost(plain);
        (uint256 s2, uint256 e2) = ue.prefundCost(recurring);
        assertEq(s1, s2);
        assertEq(e1, e2);
        assertGt(s2, 0);
    }

    function test_RJ11_evaluator_judgesPeriodZero() public {
        uint256 id = _openSeries(3);
        assertEq(ue.specHashOf(id), keccak256(bytes(kernel.getJob(id).description)));
        _pass(id);
        assertEq(uint8(ue.evaluationOf(id).verdict), uint8(Verdict.PASS));
    }

    // ═════════════════════════════ opening a series ═════════════════════════════

    function test_RJ20_open_recordsSeries_booksPeriodOne() public {
        Recurrence memory r = _rec(3, 0);
        uint256 id = _createAt(_recurring(_swapSpec(), r), t0 + WINDOW);
        (uint256 snap, uint256 eval_) = ue.prefundCost(id);
        _prefund(id, snap + eval_);
        bytes memory params = _fundParams(id);
        vm.expectEmit(address(hook));
        emit SeriesOpened(id, address(agw), 3, PERIOD);
        _fundWith(id, params);

        UniversalHook.Series memory s = hook.seriesOf(id);
        assertEq(s.agw, address(agw));
        assertEq(s.count, 3);
        assertEq(s.next, 1);
        assertEq(uint8(s.status), uint8(UniversalHook.SeriesStatus.Live));
        assertEq(s.window, WINDOW);
        assertEq(s.provider, provider);
        assertEq(s.start, t0);
        assertEq(s.period, PERIOD);
        assertEq(s.rulesId, RULES);
        assertEq(s.fee, BUDGET);
        assertEq(s.lastJob, id);
        assertEq(hook.liveSeriesOf(address(agw)), id);
        assertEq(hook.seriesOfJob(id), id);

        assertEq(scheduler.count(), 2);
        MockScheduler.Booking memory renewAt = scheduler.booking(0);
        MockScheduler.Booking memory fundAt = scheduler.booking(1);
        assertEq(renewAt.target, address(hook));
        assertEq(keccak256(renewAt.data), keccak256(abi.encodeCall(UniversalHook.renew, (id))));
        assertEq(renewAt.executeAt, t0 + PERIOD);
        assertEq(keccak256(fundAt.data), keccak256(abi.encodeCall(UniversalHook.fundNext, (id))));
        assertEq(fundAt.executeAt, t0 + PERIOD + hook.FUND_DELAY());
    }

    function test_RJ21_open_refusesLaterPeriodIndex() public {
        uint256 id = _createAt(_recurring(_swapSpec(), _rec(3, 1)), t0 + WINDOW);
        _expectFundRevert(id, abi.encodeWithSelector(UniversalHookErrors.NotSeriesJob.selector, id));
    }

    function test_RJ22_open_refusesSinglePeriod() public {
        uint256 id = _createAt(_recurring(_swapSpec(), _rec(1, 0)), t0 + WINDOW);
        _expectFundRevert(id, abi.encodeWithSelector(UniversalHookErrors.SeriesTooShort.selector, uint16(1)));
    }

    function test_RJ23_open_refusesStartInTheFuture() public {
        Recurrence memory r = _rec(3, 0);
        r.start = uint64(t0 + 1);
        uint256 id = _createAt(_recurring(_swapSpec(), r), r.start + WINDOW);
        _expectFundRevert(id, abi.encodeWithSelector(UniversalHookErrors.OutsidePeriodZero.selector, r.start, PERIOD));
    }

    function test_RJ24_open_refusesAfterPeriodZero() public {
        Recurrence memory r = _rec(3, 0);
        r.start = uint64(t0 - PERIOD);
        uint256 id = _createAt(_recurring(_swapSpec(), r), t0 + 6 hours);
        _expectFundRevert(id, abi.encodeWithSelector(UniversalHookErrors.OutsidePeriodZero.selector, r.start, PERIOD));
    }

    /// @notice Window + the kernel's 1h grace must fit before the next `fundNext` (period + 1h): at most a period.
    function test_RJ25_open_refusesWindowLongerThanPeriod() public {
        uint256 id = _createAt(_recurring(_swapSpec(), _rec(3, 0)), t0 + PERIOD + 1);
        _expectFundRevert(
            id, abi.encodeWithSelector(UniversalHookErrors.SeriesWindow.selector, uint256(PERIOD) + 1, PERIOD)
        );
    }

    function test_RJ26_open_acceptsWindowOfExactlyAPeriod() public {
        uint256 id = _createAt(_recurring(_swapSpec(), _rec(3, 0)), t0 + PERIOD);
        _fund(id);
        assertEq(hook.seriesOf(id).window, PERIOD);
    }

    /// @notice A renewed job is funded `FUND_DELAY` after it opens: a shorter window would already be over.
    function test_RJ27_open_refusesWindowNotPastFundDelay() public {
        uint256 id = _createAt(_recurring(_swapSpec(), _rec(3, 0)), t0 + 1 hours);
        _expectFundRevert(id, abi.encodeWithSelector(UniversalHookErrors.SeriesWindow.selector, uint256(1 hours), PERIOD));
    }

    function test_RJ28_open_refusesFeeOtherThanBudget() public {
        Recurrence memory r = _rec(3, 0);
        r.feePerPeriod = BUDGET + 1;
        uint256 id = _createAt(_recurring(_swapSpec(), r), t0 + WINDOW);
        _expectFundRevert(
            id, abi.encodeWithSelector(UniversalHookErrors.SeriesFeeMismatch.selector, BUDGET, BUDGET + 1)
        );
    }

    function test_RJ29_open_refusesReplaceableCriteria() public {
        JobSpec memory s = _swapSpec();
        s.allowedMutability = AllowedMutability.BOTH;
        uint256 id = _createAt(_recurring(s, _rec(3, 0)), t0 + WINDOW);
        _expectFundRevert(
            id, abi.encodeWithSelector(UniversalHookErrors.SeriesSpecReplaceable.selector, AllowedMutability.BOTH)
        );
    }

    function test_RJ30_open_refusesWithoutScheduler() public {
        vm.store(address(hook), bytes32(uint256(55)), bytes32(0));
        assertEq(hook.SCHEDULER(), address(0));
        uint256 id = _createAt(_recurring(_swapSpec(), _rec(3, 0)), t0 + WINDOW);
        _expectFundRevert(id, abi.encodeWithSelector(UniversalHookErrors.SchedulerNotSet.selector));
    }

    function test_RJ31_open_refusesOtherEvaluator() public {
        vm.prank(owner);
        agw.execute(
            address(kernel),
            0,
            abi.encodeCall(
                kernel.createJob,
                (provider, stranger, t0 + WINDOW, string(_recurring(_swapSpec(), _rec(3, 0))), address(hook))
            )
        );
        uint256 id = kernel.jobCounter();
        vm.prank(provider);
        kernel.setBudget(id, BUDGET, "");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.RecurringNeedsEvaluator.selector, id));
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (id, BUDGET, abi.encode(RULES))));
    }

    function test_RJ32_open_refusesSecondSeries() public {
        uint256 first = _openSeries(3);
        _pass(first);
        uint256 second = _createAt(_recurring(_swapSpec(), _rec(3, 0)), block.timestamp + WINDOW);
        _expectFundRevert(
            second, abi.encodeWithSelector(UniversalHookErrors.SeriesRunning.selector, address(agw), first)
        );
    }

    // ═════════════════════════════ one-off jobs while a series runs ═════════════════════════════

    function test_RJ40_oneOff_refusedWhileSeriesLive() public {
        uint256 id = _openSeries(3);
        _pass(id);
        uint256 oneOff = _createSpec(_swapSpec());
        _expectFundRevert(oneOff, abi.encodeWithSelector(UniversalHookErrors.SeriesRunning.selector, address(agw), id));
    }

    function test_RJ41_oneOff_allowedAfterCancel() public {
        uint256 id = _openSeries(3);
        _pass(id);
        _cancel(id);
        uint256 oneOff = _createSpec(_swapSpec());
        _fund(oneOff);
        assertEq(uint8(kernel.getJob(oneOff).status), uint8(IAgenticCommerce.JobStatus.Funded));
    }

    // ═════════════════════════════ running a series ═════════════════════════════

    /// @notice Three periods, each opened by `renew`, priced by the provider, funded by `fundNext`, judged PASS.
    function test_RJ50_fullSeries_everyPeriodFundedAndJudged() public {
        uint256 id = _openSeries(3);
        bytes memory description0 = bytes(kernel.getJob(id).description);
        _pass(id);
        uint64 checkpoints = agw.checkpointCount();

        for (uint16 i = 1; i < 3; ++i) {
            uint256 job = _renew(id, i);
            IAgenticCommerce.Job memory j = kernel.getJob(job);
            assertEq(j.client, address(agw));
            assertEq(j.provider, provider);
            assertEq(j.evaluator, address(ue));
            assertEq(j.hook, address(hook));
            assertEq(j.expiredAt, t0 + uint256(PERIOD) * i + WINDOW);
            bytes memory expected = bytes.concat(description0);
            JobDescription.setIndex(expected, i);
            assertEq(keccak256(bytes(j.description)), keccak256(expected));
            assertEq(desc.recurrence(bytes(j.description)).index, i);
            assertEq(hook.seriesOfJob(job), id);

            _price(job);
            (uint256 snap, uint256 eval_) = ue.prefundCost(job);
            _toFundNext(id, i);
            uint256 pcBefore = address(agw).balance;
            vm.expectEmit(address(hook));
            emit PeriodFunded(id, i, job);
            _runFundNext(i);
            assertEq(pcBefore - address(agw).balance, (snap + eval_) * 15_000 / 10_000, "prepay headroom");
            assertEq(uint8(kernel.getJob(job).status), uint8(IAgenticCommerce.JobStatus.Funded));
            assertEq(hook.rulesOfJob(job), RULES);
            assertEq(hook.seriesOf(id).lastJob, job);

            _pass(job);
            assertEq(uint8(ue.evaluationOf(job).ownerCheck), uint8(OwnerCheck.CLEAN), "renewals are not owner calls");
        }

        UniversalHook.Series memory s = hook.seriesOf(id);
        assertEq(uint8(s.status), uint8(UniversalHook.SeriesStatus.Ended));
        assertEq(s.next, 3);
        assertEq(hook.liveSeriesOf(address(agw)), 0);
        assertEq(scheduler.count(), 4, "no booking after the last period");
        assertEq(agw.checkpointCount(), checkpoints, "the owner door was never used");

        uint256 oneOff = _createSpec(_swapSpec());
        _fund(oneOff); // allowed again
    }

    function test_RJ51_lastPeriod_closesSeriesEnded() public {
        uint256 id = _openSeries(2);
        _pass(id);
        uint256 job = _renew(id, 1);
        _price(job);
        _toFundNext(id, 1);
        vm.expectEmit(address(hook));
        emit SeriesClosed(id, UniversalHook.SeriesStatus.Ended);
        _runFundNext(1);
        assertEq(scheduler.count(), 2);
    }

    /// @notice The provider never prices the period: `fund` fails on the budget, the period is missed, all of its
    ///         funding is undone, and the next period is still booked.
    function test_RJ52_unpricedPeriod_missed_nextBooked() public {
        uint256 id = _openSeries(4);
        _pass(id);
        uint256 job = _renew(id, 1);
        uint256 pcBefore = address(agw).balance;

        _toFundNext(id, 1);
        vm.expectEmit(address(hook));
        emit PeriodMissed(id, 1, job, abi.encodeWithSelector(IAgenticCommerce.BudgetMismatch.selector));
        _runFundNext(1);

        assertEq(uint8(kernel.getJob(job).status), uint8(IAgenticCommerce.JobStatus.Open));
        assertEq(address(agw).balance, pcBefore, "prefund undone");
        assertEq(ue.prepaidOf(job), 0);
        UniversalHook.Series memory s = hook.seriesOf(id);
        assertEq(s.misses, 1);
        assertEq(s.next, 2);
        assertEq(s.pendingJob, 0);
        assertEq(s.lastJob, id);
        assertEq(uint8(s.status), uint8(UniversalHook.SeriesStatus.Live));
        assertEq(scheduler.count(), 4);
        assertEq(scheduler.booking(2).executeAt, t0 + 2 * uint256(PERIOD));
    }

    function test_RJ53_threeMissesInARow_lapse() public {
        uint256 id = _openSeries(6);
        _pass(id);
        for (uint16 i = 1; i <= 3; ++i) {
            _renew(id, i);
            _toFundNext(id, i);
            if (i == 3) {
                vm.expectEmit(address(hook));
                emit SeriesClosed(id, UniversalHook.SeriesStatus.Lapsed);
            }
            _runFundNext(i);
        }
        UniversalHook.Series memory s = hook.seriesOf(id);
        assertEq(uint8(s.status), uint8(UniversalHook.SeriesStatus.Lapsed));
        assertEq(s.misses, 3);
        assertEq(hook.liveSeriesOf(address(agw)), 0);
        assertEq(scheduler.count(), 6, "nothing booked after the lapse");

        uint256 oneOff = _createSpec(_swapSpec());
        _fund(oneOff);
    }

    function test_RJ54_fundedPeriod_resetsMisses() public {
        uint256 id = _openSeries(6);
        _pass(id);
        _renew(id, 1);
        _fundNext(id, 1); // missed
        _renew(id, 2);
        _fundNext(id, 2); // missed
        assertEq(hook.seriesOf(id).misses, 2);
        uint256 job = _renew(id, 3);
        _price(job);
        _fundNext(id, 3);
        assertEq(hook.seriesOf(id).misses, 0);
        assertEq(uint8(hook.seriesOf(id).status), uint8(UniversalHook.SeriesStatus.Live));
    }

    /// @notice The wallet has no renewal rule: `renew` fails without reverting, `fundNext` counts the miss.
    function test_RJ55_renewFails_periodMissed() public {
        uint256 id = _openSeries(3);
        _pass(id);
        agw.setRenewalBroken(true);
        uint256 jobs = kernel.jobCounter();
        _warp(id, 1, 0);
        vm.expectEmit(address(hook));
        emit RenewFailed(id, 1, abi.encodeWithSignature("Error(string)", "no renewal rule"));
        assertTrue(scheduler.run(0));
        assertEq(kernel.jobCounter(), jobs);
        _toFundNext(id, 1);
        vm.expectEmit(address(hook));
        emit PeriodMissed(id, 1, 0, "");
        _runFundNext(1);
        assertEq(hook.seriesOf(id).misses, 1);
    }

    /// @notice The last period's job was submitted but never judged: `fundNext` refunds it first, then funds.
    function test_RJ56_stuckPreviousJob_refundedThenNextFunded() public {
        uint256 id = _openSeries(3);
        _answerSnapshot(id, SWAP_PRE, 0);
        _advance();
        _submit(id); // no answer ever comes
        uint256 job = _renew(id, 1);
        _price(job);
        uint256 balBefore = token.balanceOf(address(agw));
        _fundNext(id, 1);
        assertEq(uint8(kernel.getJob(id).status), uint8(IAgenticCommerce.JobStatus.Expired));
        assertEq(token.balanceOf(address(agw)), balBefore + BUDGET - BUDGET, "refund in, next budget out");
        assertEq(uint8(kernel.getJob(job).status), uint8(IAgenticCommerce.JobStatus.Funded));
    }

    function test_RJ57_walletFundedThePeriodItself_counted() public {
        uint256 id = _openSeries(3);
        _pass(id);
        uint256 job = _renew(id, 1);
        _price(job);
        _advance();
        _fund(job); // the owner funds it through the owner door
        _fundNext(id, 1);
        assertEq(hook.seriesOf(id).misses, 0);
        assertEq(hook.seriesOf(id).lastJob, job);
    }

    /// @notice No standing allowance: the hook approves exactly the period's budget, which `fund` then spends.
    function test_RJ58_noAllowance_periodApprovedExactly() public {
        uint256 id = _openSeries(3);
        _pass(id);
        vm.prank(owner);
        agw.execute(address(token), 0, abi.encodeCall(token.approve, (address(kernel), 0)));
        uint256 job = _renew(id, 1);
        _price(job);
        _fundNext(id, 1);
        assertEq(uint8(kernel.getJob(job).status), uint8(IAgenticCommerce.JobStatus.Funded));
        assertEq(token.allowance(address(agw), address(kernel)), 0);
    }

    /// @notice A standing allowance larger than the fee is left alone, less what `fund` spends.
    function test_RJ59_standingAllowance_notOverwritten() public {
        uint256 id = _openSeries(3);
        _pass(id);
        uint256 job = _renew(id, 1);
        _price(job);
        _fundNext(id, 1);
        assertEq(token.allowance(address(agw), address(kernel)), type(uint256).max);
    }

    // ═════════════════════════════ scheduler calls ═════════════════════════════

    function test_RJ60_onlySchedulerCallsRenewAndFundNext() public {
        uint256 id = _openSeries(3);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.CallerIsNotScheduler.selector, stranger));
        hook.renew(id);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.CallerIsNotScheduler.selector, stranger));
        hook.fundNext(id);
    }

    function test_RJ61_earlyAndDuplicateCalls_doNothing() public {
        uint256 id = _openSeries(3);
        _pass(id);
        uint256 jobs = kernel.jobCounter();

        _call(abi.encodeCall(UniversalHook.renew, (id))); // before period 1
        assertEq(kernel.jobCounter(), jobs);

        uint256 job = _renew(id, 1);
        _call(abi.encodeCall(UniversalHook.renew, (id))); // again
        assertEq(kernel.jobCounter(), job);

        _call(abi.encodeCall(UniversalHook.fundNext, (id))); // before FUND_DELAY
        assertEq(hook.seriesOf(id).next, 1);

        _price(job);
        _fundNext(id, 1);
        _call(abi.encodeCall(UniversalHook.fundNext, (id))); // again: period 2 isn't due
        assertEq(hook.seriesOf(id).next, 2);
        assertEq(scheduler.count(), 4);
    }

    function test_RJ62_fundPeriod_onlyTheHookItself() public {
        uint256 id = _openSeries(3);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.CallerIsNotSelf.selector, stranger));
        hook.fundPeriod(id, id);
    }

    /// @notice A recurring description the wallet creates itself for a later period is not part of any series.
    function test_RJ63_laterPeriodJob_onlyThroughRenew() public {
        uint256 id = _openSeries(3);
        _pass(id);
        _cancel(id);
        uint256 forged = _createAt(_recurring(_swapSpec(), _rec(3, 1)), block.timestamp + WINDOW);
        _expectFundRevert(forged, abi.encodeWithSelector(UniversalHookErrors.NotSeriesJob.selector, forged));
    }

    // ═════════════════════════════ cancel ═════════════════════════════

    function test_RJ70_cancel_onlyTheWallet_stopsTheSeries() public {
        uint256 id = _openSeries(3);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.CallerIsNotSeriesWallet.selector, stranger));
        hook.cancelSeries(id);

        vm.expectEmit(address(hook));
        emit SeriesClosed(id, UniversalHook.SeriesStatus.Cancelled);
        _cancel(id);
        assertEq(uint8(hook.seriesOf(id).status), uint8(UniversalHook.SeriesStatus.Cancelled));
        assertEq(hook.liveSeriesOf(address(agw)), 0);

        _pass(id); // the funded period still runs to its verdict
        uint256 jobs = kernel.jobCounter();
        _warp(id, 1, 0);
        assertTrue(scheduler.run(0));
        assertEq(kernel.jobCounter(), jobs, "renew does nothing");
        _warp(id, 1, hook.FUND_DELAY());
        assertTrue(scheduler.run(1));
        assertEq(scheduler.count(), 2, "nothing booked");

        vm.prank(address(agw));
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.SeriesNotLive.selector, id));
        hook.cancelSeries(id);
    }

    // ═════════════════════════════ scheduler setting and storage ═════════════════════════════

    function test_RJ80_setScheduler_onlyProxyAdmin() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.CallerIsNotProxyAdmin.selector, stranger));
        hook.setScheduler(stranger);

        address admin = _proxyAdmin();
        address impl = address(uint160(uint256(vm.load(address(hook), ERC1967Utils.IMPLEMENTATION_SLOT))));
        vm.prank(proxyAdminOwner);
        vm.expectRevert(); // zero address
        ProxyAdmin(admin).upgradeAndCall(
            ITransparentUpgradeableProxy(address(hook)), impl, abi.encodeCall(UniversalHook.setScheduler, (address(0)))
        );
        _setScheduler(stranger);
        assertEq(hook.SCHEDULER(), stranger);
    }

    /// @notice The new state takes slots 55–58 from the gap; everything before stays where it was.
    function test_RJ81_storageSlots() public {
        uint256 id = _openSeries(3);
        assertEq(address(uint160(uint256(vm.load(address(hook), bytes32(uint256(0)))))), address(kernel));
        assertEq(address(uint160(uint256(vm.load(address(hook), bytes32(uint256(50)))))), address(factory));
        assertEq(address(uint160(uint256(vm.load(address(hook), bytes32(uint256(51)))))), address(engine));
        assertEq(address(uint160(uint256(vm.load(address(hook), bytes32(uint256(54)))))), address(ue));
        assertEq(address(uint160(uint256(vm.load(address(hook), bytes32(uint256(55)))))), address(scheduler));
        bytes32 live = keccak256(abi.encode(address(agw), uint256(57)));
        assertEq(uint256(vm.load(address(hook), live)), id);
        bytes32 ofJob = keccak256(abi.encode(id, uint256(58)));
        assertEq(uint256(vm.load(address(hook), ofJob)), id);
    }

    // ═════════════════════════════ helpers ═════════════════════════════

    function _rec(uint16 count, uint16 index) internal view returns (Recurrence memory) {
        return Recurrence({start: uint64(t0), period: PERIOD, count: count, index: index, feePerPeriod: BUDGET});
    }

    function _recurring(JobSpec memory s, Recurrence memory r) internal pure returns (bytes memory) {
        return abi.encodePacked(RECURRING_JOB_PREFIX, abi.encode(s, r));
    }

    /// @notice The wallet creates a job with this description and expiry; the provider prices it.
    function _createAt(bytes memory description, uint256 expiredAt) internal returns (uint256 jobId) {
        vm.prank(owner);
        agw.execute(
            address(kernel),
            0,
            abi.encodeCall(kernel.createJob, (provider, address(ue), expiredAt, string(description), address(hook)))
        );
        jobId = kernel.jobCounter();
        vm.prank(provider);
        kernel.setBudget(jobId, BUDGET, "");
    }

    function _openSeries(uint16 count) internal returns (uint256 id) {
        id = _createAt(_recurring(_swapSpec(), _rec(count, 0)), t0 + WINDOW);
        _fund(id);
    }

    /// @notice Prefunds, then expects `fund` to revert with `err`.
    function _expectFundRevert(uint256 jobId, bytes memory err) internal {
        (uint256 s, uint256 e) = ue.prefundCost(jobId);
        _prefund(jobId, s + e);
        bytes memory params = _fundParams(jobId);
        vm.expectRevert(err);
        _fundWith(jobId, params);
    }

    /// @notice Snapshot answered, work lands, submitted, POST answered: PASS.
    function _pass(uint256 jobId) internal {
        _answerSnapshot(jobId, SWAP_PRE, 0);
        _advance();
        _submit(jobId);
        _answer(jobId, 0, abi.encode(PASS_VALUE));
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    function _price(uint256 jobId) internal {
        vm.prank(provider);
        kernel.setBudget(jobId, BUDGET, "");
    }

    function _warp(uint256 id, uint16 period, uint256 offset) internal {
        vm.warp(uint256(hook.seriesOf(id).start) + uint256(PERIOD) * period + offset);
    }

    /// @notice Runs period `i`'s `renew` booking at the period's start; returns the job it opened.
    function _renew(uint256 id, uint16 i) internal returns (uint256 jobId) {
        _warp(id, i, 0);
        assertTrue(scheduler.run(2 * (uint256(i) - 1)));
        jobId = hook.seriesOf(id).pendingJob;
    }

    /// @notice Runs period `i`'s `fundNext` booking `FUND_DELAY` after the period's start, heights fresh.
    function _fundNext(uint256 id, uint16 i) internal {
        _toFundNext(id, i);
        _runFundNext(i);
    }

    function _toFundNext(uint256 id, uint16 i) internal {
        _warp(id, i, hook.FUND_DELAY());
        _advance();
    }

    function _runFundNext(uint16 i) internal {
        assertTrue(scheduler.run(2 * (uint256(i) - 1) + 1));
    }

    function _cancel(uint256 id) internal {
        vm.prank(owner);
        agw.execute(address(hook), 0, abi.encodeCall(UniversalHook.cancelSeries, (id)));
    }

    function _call(bytes memory data) internal {
        (bool ok,) = scheduler.call(address(hook), data);
        assertTrue(ok);
    }

    function _proxyAdmin() internal view returns (address) {
        return address(uint160(uint256(vm.load(address(hook), ERC1967Utils.ADMIN_SLOT))));
    }

    function _setScheduler(address s) internal {
        address impl = address(uint160(uint256(vm.load(address(hook), ERC1967Utils.IMPLEMENTATION_SLOT))));
        vm.prank(proxyAdminOwner);
        ProxyAdmin(_proxyAdmin()).upgradeAndCall(
            ITransparentUpgradeableProxy(address(hook)), impl, abi.encodeCall(UniversalHook.setScheduler, (s))
        );
    }
}
