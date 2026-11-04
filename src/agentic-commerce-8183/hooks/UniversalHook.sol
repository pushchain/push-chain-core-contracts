// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {BaseERC8183Hook} from "./BaseERC8183Hook.sol";
import {IAgenticCommerce} from "../interfaces/IAgenticCommerce.sol";
import {IAGWFactory} from "../interfaces/external/IAGWFactory.sol";
import {ISmartSession} from "../interfaces/external/ISmartSession.sol";
import {IUniversalEvaluator} from "../interfaces/IUniversalEvaluator.sol";
import {IUniversalScheduler} from "../interfaces/IUniversalScheduler.sol";
import {IAGWRenewal} from "../interfaces/external/IAGWRenewal.sol";
import {JobSpec, AllowedMutability, Recurrence} from "../libraries/JobSpecTypes.sol";
import {JobDescription} from "../libraries/JobDescription.sol";   // enum AllowedMutability { BOTH, NONE, CLIENT, PROVIDER }
import {ERC8183HookErrors, UniversalHookErrors} from "../libraries/Errors.sol";

/// @title UniversalHook
/// @notice The one hook for evaluated jobs: binds the job to the funding AGW's rules set, controls who may
///         replace the job's spec, and hands the spec to the UniversalEvaluator.
/// @dev - Rules binding: `beforeAction(fund)`, for every job; any revert leaves the job Open, nothing escrowed.
///      - Spec: the provider may replace it in `setBudget`, the client in `fund`, as the `allowedMutability` flag in the
///        createJob description allows. Frozen in `afterAction(fund)`.
///      - Stateless for evaluation: the evaluator holds the spec, prepaid PC, snapshot answers and rounds.
///      - Recurring jobs: funding a job whose description carries a `Recurrence` (period 0) opens a series. Push's
///        scheduler then calls `renew` at each period's start (the AGW creates that period's job) and `fundNext`
///        `FUND_DELAY` later (the AGW prefunds and funds it). A period that can't be funded is missed; `MAX_MISSES`
///        in a row lapse the series. While a series is live, the AGW's one-off jobs are refused.
///      - Storage continues the base at slot 50.
contract UniversalHook is BaseERC8183Hook {
    /// @notice The job ↔ rules set record.
    struct Binding {
        address agw;
        bytes32 rulesId;
    }

    enum SeriesStatus {
        None,
        Live,
        Ended,
        Lapsed,
        Cancelled
    }

    /// @notice A recurring job's series. Its id is period 0's job id.
    struct Series {
        address agw;
        uint16 count; // periods in the series
        uint16 next; // the period `renew` and `fundNext` act on next
        uint8 misses; // periods missed in a row
        SeriesStatus status;
        uint32 window; // a period's job expires `window` after the period starts
        address provider;
        uint64 start;
        uint32 period;
        bytes32 rulesId;
        uint256 fee; // the budget funded each period
        uint256 lastJob; // the last period's funded job
        uint256 pendingJob; // the job `renew` opened for period `next`, not yet funded
    }

    // ───────── events ─────────

    /// @notice A job was bound to an AGW's rules set at `fund`.
    event RulesBound(uint256 indexed jobId, address indexed agw, bytes32 indexed rulesId);
    /// @notice The spec was replaced (by the provider in setBudget, or the client in fund).
    event SpecReplaced(uint256 indexed jobId, bool byProvider, bytes32 specHash);
    /// @notice The spec was frozen at `fund` and handed to the evaluator.
    event SpecFrozen(uint256 indexed jobId, bytes32 specHash);
    /// @notice The scheduler that calls `renew` and `fundNext` was set.
    event SchedulerSet(address scheduler);
    /// @notice Period 0 was funded and the series opened.
    event SeriesOpened(uint256 indexed seriesId, address indexed agw, uint16 count, uint32 period);
    /// @notice `renew` had the AGW create a period's job.
    event PeriodOpened(uint256 indexed seriesId, uint16 period, uint256 jobId);
    /// @notice `renew` could not open a period's job.
    event RenewFailed(uint256 indexed seriesId, uint16 period, bytes reason);
    /// @notice A period's job was funded.
    event PeriodFunded(uint256 indexed seriesId, uint16 period, uint256 jobId);
    /// @notice A period was missed: no job, or its funding failed.
    event PeriodMissed(uint256 indexed seriesId, uint16 period, uint256 jobId, bytes reason);
    /// @notice The series stopped: every period done, too many missed, or cancelled.
    event SeriesClosed(uint256 indexed seriesId, SeriesStatus status);

    // ───────── storage — slots 50..103 (base owns 0..49) ─────────

    /// @notice AGW factory, used to prove the client is an AGW.
    address public AGW_FACTORY;                                  // slot 50
    /// @notice SmartSession engine, used to prove the rules set is live.
    address public SESSION_ENGINE;                               // slot 51
    /// @notice Job id → bound rules set.
    /// @dev - `rulesId` is not globally unique across wallets; always read with `agw`.
    mapping(uint256 => Binding) internal _bindings;             // slot 52
    /// @notice AGW → last job bound; active only while that job is Funded or Submitted.
    mapping(address => uint256) internal _lastBoundJob;         // slot 53
    /// @notice The UniversalEvaluator. Jobs with a different evaluator only get the rules binding.
    address public EVALUATOR;                                   // slot 54
    /// @notice Push's scheduler; the only caller of `renew` and `fundNext`.
    address public SCHEDULER;                                   // slot 55
    /// @notice Series id → series.
    mapping(uint256 => Series) internal _series;                // slot 56
    /// @notice AGW → its live series, or 0.
    mapping(address => uint256) internal _liveSeries;           // slot 57
    /// @notice Job id → the series it belongs to, or 0.
    mapping(uint256 => uint256) internal _seriesOfJob;          // slot 58
    uint256[45] private __gap;                                  // slots 59..103

    /// @notice Time between a period's `renew` and its `fundNext`: the provider prices the job in between.
    uint256 public constant FUND_DELAY = 1 hours;
    /// @notice Periods missed in a row that lapse a series.
    uint8 public constant MAX_MISSES = 3;
    /// @notice Each period's read prepayment, in basis points of the evaluator's estimate.
    uint256 public constant PREFUND_HEADROOM_BPS = 15_000;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the proxy.
    function initialize(address kernel_, address agwFactory_, address sessionEngine_, address evaluator_)
        external
        initializer
    {
        if (agwFactory_ == address(0) || sessionEngine_ == address(0) || evaluator_ == address(0)) revert ERC8183HookErrors.ZeroAddress();
        __BaseERC8183Hook_init(kernel_);
        AGW_FACTORY = agwFactory_;
        SESSION_ENGINE = sessionEngine_;
        EVALUATOR = evaluator_;
    }

    /// @notice The AGW's active job under this hook, or 0 if it has none.
    /// @dev - Active = the last job bound for the AGW is Funded or Submitted in the kernel.
    function activeJobOf(address agw) public view returns (uint256 jobId) {
        jobId = _lastBoundJob[agw];
        if (jobId == 0) return 0;
        IAgenticCommerce.JobStatus s = IAgenticCommerce(KERNEL).getJob(jobId).status;
        if (s != IAgenticCommerce.JobStatus.Funded && s != IAgenticCommerce.JobStatus.Submitted) return 0;
    }

    /// @notice The rules set the job was bound to at `fund`, or zero.
    function rulesOfJob(uint256 jobId) external view returns (bytes32) {
        return _bindings[jobId].rulesId;
    }

    /// @notice The AGW the job was bound to at `fund`, or zero.
    function agwOfJob(uint256 jobId) external view returns (address) {
        return _bindings[jobId].agw;
    }

    /// @notice A series, by id (period 0's job id).
    function seriesOf(uint256 seriesId) external view returns (Series memory) {
        return _series[seriesId];
    }

    /// @notice The AGW's live series, or 0.
    function liveSeriesOf(address agw) external view returns (uint256) {
        return _liveSeries[agw];
    }

    /// @notice The series a job belongs to, or 0.
    function seriesOfJob(uint256 jobId) external view returns (uint256) {
        return _seriesOfJob[jobId];
    }

    /// @notice Sets the scheduler. Only the proxy's admin, so only inside `ProxyAdmin.upgradeAndCall`.
    function setScheduler(address scheduler_) external {
        if (msg.sender != ERC1967Utils.getAdmin()) revert UniversalHookErrors.CallerIsNotProxyAdmin(msg.sender);
        if (scheduler_ == address(0)) revert ERC8183HookErrors.ZeroAddress();
        SCHEDULER = scheduler_;
        emit SchedulerSet(scheduler_);
    }

    // ───────── setBudget: the provider may replace the spec ─────────

    /// @dev setBudget's optParams (provider): empty = keep the spec · otherwise = abi.encode(JobSpec), the replacement.
    function _postSetBudget(uint256 jobId, address, uint256, bytes memory newSpec) internal override {
        if (newSpec.length == 0) return;                                          // price only, spec unchanged
        IAgenticCommerce.Job memory job = IAgenticCommerce(KERNEL).getJob(jobId);
        if (job.evaluator != EVALUATOR) return;                                   // not evaluated by us

        AllowedMutability flag = _flag(bytes(job.description));
        if (flag != AllowedMutability.BOTH && flag != AllowedMutability.PROVIDER) revert UniversalHookErrors.SpecChangeNotAllowed(flag);
        _requireSameFlag(newSpec, flag);

        IUniversalEvaluator(EVALUATOR).setSpec(jobId, newSpec);
        emit SpecReplaced(jobId, true, keccak256(newSpec));
    }

    // ───────── fund (before): rules binding ─────────

    /// @dev Checks, in order: optParams shape · client is an AGW · rules set live · AGW has no active job · series rules
    ///      (`_checkSeries`).
    ///      - `caller` is the job's client — the kernel checks it before calling the hook.
    ///      - Runs in `beforeAction`, so any revert leaves the job Open with no escrow moved.
    function _preFund(uint256 jobId, address caller, bytes memory optParams) internal override {
        (bytes32 rulesId, , ) = _parseFundParams(optParams);
        if (!IAGWFactory(AGW_FACTORY).isWallet(caller)) revert UniversalHookErrors.CallerIsNotAGW(caller);
        if (!ISmartSession(SESSION_ENGINE).isPermissionEnabled(rulesId, caller)) {
            revert UniversalHookErrors.RulesNotLive(caller, rulesId);
        }
        uint256 active = activeJobOf(caller);
        if (active != 0) revert UniversalHookErrors.WalletHasActiveJob(caller, active);
        _checkSeries(jobId, caller, rulesId);

        _bindings[jobId] = Binding({agw: caller, rulesId: rulesId});
        _lastBoundJob[caller] = jobId;
        emit RulesBound(jobId, caller, rulesId);
    }

    // ───────── fund (after): the client may replace the spec; freeze it; start the snapshot ─────────

    /// @dev - The final spec: the client's replacement if sent, else the provider's (stored in the evaluator), else the description.
    ///      - It must hash to `expectedSpecHash`, so nobody can swap it between the client's look and its fund.
    ///      - `startSnapshot` stores it, freezes it and fires the PRE_EXECUTION reads; if it reverts, so does fund.
    function _postFund(uint256 jobId, address, bytes memory optParams) internal override {
        IAgenticCommerce.Job memory job = IAgenticCommerce(KERNEL).getJob(jobId);
        if (job.evaluator != EVALUATOR) return;                                   // not evaluated by us: rules binding only

        (, bytes32 expectedSpecHash, bytes memory newSpec) = _parseFundParams(optParams);
        AllowedMutability flag = _flag(bytes(job.description));

        bytes memory spec;
        if (newSpec.length > 0) {                                                 // the client replaces it
            if (flag != AllowedMutability.BOTH && flag != AllowedMutability.CLIENT) revert UniversalHookErrors.SpecChangeNotAllowed(flag);
            _requireSameFlag(newSpec, flag);
            spec = newSpec;
            emit SpecReplaced(jobId, false, keccak256(newSpec));
        } else {                                                                  // keep the current one
            spec = IUniversalEvaluator(EVALUATOR).currentSpec(jobId);             //   the provider's replacement, if any
            if (spec.length == 0) spec = bytes(job.description);                  //   else the createJob description
        }

        bytes32 actual = keccak256(spec);
        if (actual != expectedSpecHash) revert UniversalHookErrors.SpecHashMismatch(expectedSpecHash, actual);

        IUniversalEvaluator(EVALUATOR).startSnapshot(jobId, spec);
        emit SpecFrozen(jobId, actual);
        if (_seriesOfJob[jobId] == jobId) _book(jobId, _series[jobId], 1); // period 0 opened a series
    }

    // ───────── submit (after): fix the end blocks, send the reads ─────────

    /// @dev Not in try/catch: if the evaluator can't fix the end blocks (a stale or unmoved height, or too little
    ///      gas), `submit` reverts and the provider submits again later. A catch here would let a provider send
    ///      just enough gas for the evaluator call to fail, then pick its own end blocks with `retryEvaluation`.
    ///      Sending the reads stays best effort: the evaluator catches that part itself, after fixing the blocks.
    ///      `virtual` as every handler in BaseERC8183Hook is; the tests replay the earlier try/catch with it.
    function _postSubmit(uint256 jobId, address, bytes32, bytes memory) internal virtual override {
        if (IAgenticCommerce(KERNEL).getJob(jobId).evaluator != EVALUATOR) return;
        IUniversalEvaluator(EVALUATOR).verifyFromSubmit(jobId);
    }

    // ───────── helpers ─────────

    /// @dev fund's optParams:
    ///      - 32 bytes: just the rulesId, for binding only. Only for jobs not evaluated by us:
    ///        for ours, the zero expectedSpecHash can never match, so fund reverts.
    ///      - otherwise: abi.encode(bytes32 rulesId, bytes32 expectedSpecHash, bytes newSpec); empty newSpec = keep the spec.
    function _parseFundParams(bytes memory p)
        internal
        pure
        returns (bytes32 rulesId, bytes32 expectedSpecHash, bytes memory newSpec)
    {
        if (p.length == 32) return (abi.decode(p, (bytes32)), bytes32(0), "");
        if (p.length < 128) revert UniversalHookErrors.InvalidOptParams(p.length);                   // smallest valid encoding: 4 words
        return abi.decode(p, (bytes32, bytes32, bytes));
    }

    /// @dev The governing flag: always the one in the createJob description.
    function _flag(bytes memory description) internal pure returns (AllowedMutability) {
        return abi.decode(JobDescription.specBytes(description), (JobSpec)).allowedMutability;
    }

    /// @dev A replacement must keep the same flag, so neither side can lock the other out by switching it.
    function _requireSameFlag(bytes memory newSpec, AllowedMutability flag) internal pure {
        AllowedMutability got = abi.decode(JobDescription.specBytes(newSpec), (JobSpec)).allowedMutability;              // not a JobSpec → reverts
        if (got != flag) revert UniversalHookErrors.FlagChanged(flag, got);
    }

    // ───────── recurring jobs ─────────

    modifier onlyScheduler() {
        if (msg.sender != SCHEDULER) revert UniversalHookErrors.CallerIsNotScheduler(msg.sender);
        _;
    }

    /// @notice Has the series' AGW create the job of period `next`. Called by the scheduler at the period's start.
    /// @dev Never reverts once the call is the scheduler's: a stale call does nothing, a failure is an event and
    ///      `fundNext` counts the period as missed.
    function renew(uint256 seriesId) external onlyScheduler {
        Series storage s = _series[seriesId];
        uint16 i = s.next;
        if (s.status != SeriesStatus.Live || s.pendingJob != 0 || block.timestamp < _periodStart(s, i)) return;

        bytes memory d = bytes(IAgenticCommerce(KERNEL).getJob(seriesId).description);
        JobDescription.setIndex(d, i);
        bytes memory create = abi.encodeCall(
            IAgenticCommerce.createJob, (s.provider, EVALUATOR, _periodStart(s, i) + s.window, string(d), address(this))
        );
        try IAGWRenewal(s.agw).executeRenewal(KERNEL, 0, create) returns (bytes memory ret) {
            uint256 jobId = ret.length == 32 ? abi.decode(ret, (uint256)) : 0;
            if (!_isPeriodJob(s, jobId, d)) {
                emit RenewFailed(seriesId, i, ret);
                return;
            }
            s.pendingJob = jobId;
            _seriesOfJob[jobId] = seriesId;
            emit PeriodOpened(seriesId, i, jobId);
        } catch (bytes memory err) {
            emit RenewFailed(seriesId, i, err);
        }
    }

    /// @notice Has the series' AGW prefund and fund the job of period `next`, then books the next period. Called by
    ///         the scheduler `FUND_DELAY` after the period's start.
    /// @dev - First ends the last period's job if the kernel lets anyone do so (`claimRefund`), so it doesn't block.
    ///      - A failed funding is a missed period, not a revert: the series goes on until `MAX_MISSES` in a row.
    function fundNext(uint256 seriesId) external onlyScheduler {
        Series storage s = _series[seriesId];
        uint16 i = s.next;
        if (s.status != SeriesStatus.Live || block.timestamp < _periodStart(s, i) + FUND_DELAY) return;

        _endIfOver(s.lastJob);
        uint256 jobId = s.pendingJob;
        bool funded;
        if (jobId == 0) {
            emit PeriodMissed(seriesId, i, 0, "");
        } else if (IAgenticCommerce(KERNEL).getJob(jobId).status != IAgenticCommerce.JobStatus.Open) {
            funded = true; // the wallet funded it itself
        } else {
            try this.fundPeriod(seriesId, jobId) {
                funded = true;
            } catch (bytes memory err) {
                emit PeriodMissed(seriesId, i, jobId, err);
            }
        }

        s.pendingJob = 0;
        s.next = i + 1;
        if (funded) {
            s.misses = 0;
            s.lastJob = jobId;
            emit PeriodFunded(seriesId, i, jobId);
        } else if (++s.misses >= MAX_MISSES) {
            return _close(seriesId, s, SeriesStatus.Lapsed);
        }
        if (s.next >= s.count) _close(seriesId, s, SeriesStatus.Ended);
        else _book(seriesId, s, s.next);
    }

    /// @notice One period's funding, run by `fundNext` on itself so a failure undoes all of it: prefund the reads
    ///         (`PREFUND_HEADROOM_BPS` of the estimate), approve the budget if the wallet's allowance to the kernel
    ///         doesn't cover it (an approval would overwrite a larger one), fund with the series' rules set.
    function fundPeriod(uint256 seriesId, uint256 jobId) external {
        if (msg.sender != address(this)) revert UniversalHookErrors.CallerIsNotSelf(msg.sender);
        Series storage s = _series[seriesId];
        IAgenticCommerce k = IAgenticCommerce(KERNEL);
        IAGWRenewal agw = IAGWRenewal(s.agw);

        (uint256 snapshot, uint256 evaluation) = IUniversalEvaluator(EVALUATOR).prefundCost(jobId);
        uint256 prepay = (snapshot + evaluation) * PREFUND_HEADROOM_BPS / 10_000;
        agw.executeRenewal(EVALUATOR, prepay, abi.encodeCall(IUniversalEvaluator.prefund, (jobId)));
        IERC20 token = k.paymentToken();
        if (token.allowance(s.agw, KERNEL) < s.fee) {
            agw.executeRenewal(address(token), 0, abi.encodeCall(IERC20.approve, (KERNEL, s.fee)));
        }
        bytes memory params = abi.encode(s.rulesId, keccak256(bytes(k.getJob(jobId).description)), bytes(""));
        agw.executeRenewal(KERNEL, 0, abi.encodeCall(IAgenticCommerce.fund, (jobId, s.fee, params)));
    }

    /// @notice Stops the series. The series' AGW only. Periods already funded run to their verdict.
    function cancelSeries(uint256 seriesId) external {
        Series storage s = _series[seriesId];
        if (msg.sender != s.agw) revert UniversalHookErrors.CallerIsNotSeriesWallet(msg.sender);
        if (s.status != SeriesStatus.Live) revert UniversalHookErrors.SeriesNotLive(seriesId);
        _close(seriesId, s, SeriesStatus.Cancelled);
    }

    /// @dev At `fund`, before the binding:
    ///      - a later period (opened by `renew`): nothing more to check;
    ///      - otherwise refused while the AGW has a live series;
    ///      - a recurring description is period 0, which opens the series (`_openSeries`).
    function _checkSeries(uint256 jobId, address agw, bytes32 rulesId) internal {
        if (_seriesOfJob[jobId] != 0) return;
        uint256 live = _liveSeries[agw];
        if (live != 0) revert UniversalHookErrors.SeriesRunning(agw, live);
        IAgenticCommerce.Job memory job = IAgenticCommerce(KERNEL).getJob(jobId);
        bytes memory d = bytes(job.description);
        if (JobDescription.isRecurring(d)) _openSeries(jobId, job, agw, rulesId, d);
    }

    /// @dev Period 0 must be:
    ///      - judged by the UniversalEvaluator, with criteria nobody may replace (`NONE`), since every later period
    ///        reuses them as signed here;
    ///      - funded inside period 0, at the agreed fee, with at least two periods;
    ///      - over in time: its job window plus the kernel's evaluator grace fits before the next period's
    ///        `fundNext`, so a job stuck without a verdict can be refunded first. The window must outlast
    ///        `FUND_DELAY`, or a renewed job would expire before it is funded.
    function _openSeries(uint256 jobId, IAgenticCommerce.Job memory job, address agw, bytes32 rulesId, bytes memory d)
        internal
    {
        if (SCHEDULER == address(0)) revert UniversalHookErrors.SchedulerNotSet();
        if (job.evaluator != EVALUATOR) revert UniversalHookErrors.RecurringNeedsEvaluator(jobId);
        Recurrence memory r = JobDescription.recurrence(d);
        if (r.index != 0) revert UniversalHookErrors.NotSeriesJob(jobId);
        if (r.count < 2) revert UniversalHookErrors.SeriesTooShort(r.count);
        if (block.timestamp < r.start || block.timestamp >= uint256(r.start) + r.period) {
            revert UniversalHookErrors.OutsidePeriodZero(r.start, r.period);
        }
        uint256 window = uint256(job.expiredAt) - r.start; // expiredAt > now >= start
        uint256 grace = IAgenticCommerce(KERNEL).EVALUATOR_GRACE_PERIOD();
        if (window <= FUND_DELAY || window + grace > uint256(r.period) + FUND_DELAY || window > type(uint32).max) {
            revert UniversalHookErrors.SeriesWindow(window, r.period);
        }
        if (job.budget != r.feePerPeriod) revert UniversalHookErrors.SeriesFeeMismatch(job.budget, r.feePerPeriod);
        AllowedMutability flag = _flag(d);
        if (flag != AllowedMutability.NONE) revert UniversalHookErrors.SeriesSpecReplaceable(flag);

        _series[jobId] = Series({
            agw: agw,
            count: r.count,
            next: 1,
            misses: 0,
            status: SeriesStatus.Live,
            // forge-lint: disable-next-line(unsafe-typecast)
            window: uint32(window), // safe: checked above
            provider: job.provider,
            start: r.start,
            period: r.period,
            rulesId: rulesId,
            fee: r.feePerPeriod,
            lastJob: jobId,
            pendingJob: 0
        });
        _liveSeries[agw] = jobId;
        _seriesOfJob[jobId] = jobId;
        emit SeriesOpened(jobId, agw, r.count, r.period);
    }

    /// @dev Books period `i`'s `renew` at its start and its `fundNext` `FUND_DELAY` later.
    function _book(uint256 seriesId, Series storage s, uint16 i) internal {
        uint256 at = _periodStart(s, i);
        // forge-lint: disable-next-line(unsafe-typecast)
        IUniversalScheduler(SCHEDULER).schedule(address(this), abi.encodeCall(this.renew, (seriesId)), uint64(at));
        IUniversalScheduler(SCHEDULER).schedule(
            // forge-lint: disable-next-line(unsafe-typecast)
            address(this), abi.encodeCall(this.fundNext, (seriesId)), uint64(at + FUND_DELAY)
        );
    }

    function _close(uint256 seriesId, Series storage s, SeriesStatus status) internal {
        s.status = status;
        if (_liveSeries[s.agw] == seriesId) delete _liveSeries[s.agw];
        emit SeriesClosed(seriesId, status);
    }

    /// @dev Ends a Funded or Submitted job the kernel will refund to anyone; otherwise leaves it.
    function _endIfOver(uint256 jobId) internal {
        if (jobId == 0) return;
        IAgenticCommerce.JobStatus st = IAgenticCommerce(KERNEL).getJob(jobId).status;
        if (st != IAgenticCommerce.JobStatus.Funded && st != IAgenticCommerce.JobStatus.Submitted) return;
        try IAgenticCommerce(KERNEL).claimRefund(jobId) {} catch {}
    }

    /// @dev The job `renew` was told about is the period's: the series' AGW, this hook and evaluator, the description.
    function _isPeriodJob(Series storage s, uint256 jobId, bytes memory d) internal view returns (bool) {
        if (jobId == 0) return false;
        IAgenticCommerce.Job memory job = IAgenticCommerce(KERNEL).getJob(jobId);
        return job.client == s.agw && job.hook == address(this) && job.evaluator == EVALUATOR
            && job.status == IAgenticCommerce.JobStatus.Open && keccak256(bytes(job.description)) == keccak256(d);
    }

    function _periodStart(Series storage s, uint16 i) internal view returns (uint256) {
        return uint256(s.start) + uint256(s.period) * i;
    }
}
