// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalEvalBase} from "./UniversalEvalBase.t.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {Verdict} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {
    JobSpec,
    Read,
    Check,
    Logic,
    EvalType,
    Op,
    LogicKind,
    ReadAt,
    CriteriaMutability,
    T_TUPLE,
    T_UINT,
    T_INT,
    T_BOOL,
    T_ADDRESS,
    T_STRING,
    T_ARRAY
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";

/// @notice A catalogue of criteria, each run end to end (kernel, hook, evaluator, Read State), mostly as one job that
///         passes and one that fails.
contract UniversalEvaluatorCriteriaTest is UniversalEvalBase {
    IAgenticCommerce.JobStatus internal constant COMPLETED = IAgenticCommerce.JobStatus.Completed;
    IAgenticCommerce.JobStatus internal constant REJECTED = IAgenticCommerce.JobStatus.Rejected;
    IAgenticCommerce.JobStatus internal constant SUBMITTED = IAgenticCommerce.JobStatus.Submitted;

    address internal usdc = makeAddr("USDC");
    address internal vault = makeAddr("vault");
    address internal aavePool = makeAddr("aavePool");
    address internal spark = makeAddr("spark");
    address internal positions = makeAddr("positions");
    address internal perp = makeAddr("perp");

    // ───────────── one value against a fixed number ─────────────

    /// @dev CMP: "the CEA holds at least 100 aUSDC after the job". The target itself passes.
    function test_CR01_cmp_balanceAtLeast() public {
        JobSpec memory s = _spec1(_single(_balanceRead(ausdc, cea)), _cmp(0, Op.GTE, 100e6));
        _expect(s, _ans(_u(100e6)), COMPLETED);
        _expect(s, _ans(_u(100e6 - 1)), REJECTED);
    }

    /// @dev BOOL: "the vault is not paused after the job".
    function test_CR02_bool_notPaused() public {
        JobSpec memory s = _spec1(_single(_call(vault, "paused()", "", _out(T_BOOL), _u8(0))), _bool(0, false));
        _expect(s, _ans(abi.encode(false)), COMPLETED);
        _expect(s, _ans(abi.encode(true)), REJECTED);
    }

    /// @dev A struct field: Aave's `getReserveData(usdc).currentLiquidityRate` (field [0, 2]) is at least 4%.
    function test_CR03_cmp_structField() public {
        Read memory rate = _call(aavePool, "getReserveData(address)", abi.encode(usdc), _reserveOutputs(), _u8(0, 2));
        JobSpec memory s = _spec1(_single(rate), _cmp(0, Op.GTE, 0.04e27));
        _expect(s, _ans(_reserveAnswer(0.052e27)), COMPLETED);
        _expect(s, _ans(_reserveAnswer(0.03e27)), REJECTED);
    }

    /// @dev An address: "position 1234 is owned by the CEA".
    function test_CR04_cmp_addressIsCEA() public {
        Read memory holder = _call(positions, "ownerOf(uint256)", abi.encode(uint256(1234)), _out(T_ADDRESS), _u8(0));
        // forge-lint: disable-next-line(unsafe-typecast)
        JobSpec memory s = _spec1(_single(holder), _cmp(0, Op.EQ, int256(uint256(uint160(cea)))));
        _expect(s, _ans(abi.encode(cea)), COMPLETED);
        _expect(s, _ans(abi.encode(stranger)), REJECTED);
    }

    /// @dev A signed value: "the position's PnL is at least -5".
    function test_CR05_cmp_signedValue() public {
        JobSpec memory s = _spec1(
            _single(_call(perp, "pnlOf(address)", abi.encode(cea), _out(T_INT), _u8(0))), _cmp(0, Op.GTE, -5e18)
        );
        _expect(s, _ans(abi.encode(int256(-3e18))), COMPLETED);
        _expect(s, _ans(abi.encode(int256(-10e18))), REJECTED);
    }

    /// @dev A string, compared by its hash: "the vault's name is 'Aave USDC'".
    function test_CR06_cmp_stringEquals() public {
        JobSpec memory s = _spec1(
            _single(_call(vault, "name()", "", _out(T_STRING), _u8(0))),
            // forge-lint: disable-next-line(unsafe-typecast)
            _cmp(0, Op.EQ, int256(uint256(keccak256("Aave USDC"))))
        );
        _expect(s, _ans(abi.encode("Aave USDC")), COMPLETED);
        _expect(s, _ans(abi.encode("Fake USDC")), REJECTED);
    }

    /// @dev An array, compared by its length: "the CEA holds at least 2 positions".
    function test_CR07_cmp_arrayLength() public {
        bytes memory outs = abi.encodePacked(T_TUPLE, uint8(1), T_ARRAY, T_UINT);
        JobSpec memory s = _spec1(
            _single(_call(positions, "positionsOf(address)", abi.encode(cea), outs, _u8(0))), _cmp(0, Op.GTE, 2)
        );
        _expect(s, _ans(abi.encode(new uint256[](2))), COMPLETED);
        _expect(s, _ans(abi.encode(new uint256[](1))), REJECTED);
    }

    /// @dev Two values from one call `(uint256 shares, bool locked)`: at least 10 shares AND not locked.
    function test_CR08_twoFieldsOfOneCall() public {
        bytes memory outs = abi.encodePacked(T_TUPLE, uint8(2), T_UINT, T_BOOL);
        Read[] memory reads = _r(
            _call(vault, "positionOf(address)", abi.encode(cea), outs, _u8(0)),
            _call(vault, "positionOf(address)", abi.encode(cea), outs, _u8(1))
        );
        JobSpec memory s = _specOf(reads, _c(_cmp(0, Op.GTE, 10), _bool(1, false)), LogicKind.ALL, 0);
        bytes memory open_ = abi.encode(uint256(10), false);
        bytes memory locked = abi.encode(uint256(10), true);
        _expect(s, _ans(open_, open_), COMPLETED);
        _expect(s, _ans(locked, locked), REJECTED);
    }

    // ───────────── change during the job: the same call before and after ─────────────

    /// @dev NUM, before minus after: "spent at most 100 USDC".
    function test_CR09_num_spentAtMost() public {
        JobSpec memory s = _spec1(_beforeAfter(usdc), _num(1, 0, Op.LTE, 100e6));
        _expect(s, _ans(_u(420e6), _u(500e6)), COMPLETED); // spent 80
        _expect(s, _ans(_u(350e6), _u(500e6)), REJECTED); // spent 150
    }

    /// @dev NUM EQ 0: "the collateral did not move".
    function test_CR10_num_unchanged() public {
        JobSpec memory s = _spec1(_beforeAfter(weth), _num(0, 1, Op.EQ, 0));
        _expect(s, _ans(_u(5e18), _u(5e18)), COMPLETED);
        _expect(s, _ans(_u(5e18 + 1), _u(5e18)), REJECTED);
    }

    /// @dev PCT: "the deposit earned at least 4%". Exactly 4% passes.
    function test_CR11_pct_yieldAtLeast() public {
        JobSpec memory s = _spec1(_beforeAfter(ausdc), _pct(0, 1, Op.GTE, 400));
        _expect(s, _ans(_u(104e6), _u(100e6)), COMPLETED);
        _expect(s, _ans(_u(103.99e6), _u(100e6)), REJECTED);
    }

    /// @dev PCT with a negative target: "lost at most 1%".
    function test_CR12_pct_lossAtMost() public {
        JobSpec memory s = _spec1(_beforeAfter(ausdc), _pct(0, 1, Op.GTE, -100));
        _expect(s, _ans(_u(99e6), _u(100e6)), COMPLETED);
        _expect(s, _ans(_u(98.99e6), _u(100e6)), REJECTED);
    }

    /// @dev A change from zero has no percentage: PCT FAILS, whatever the target.
    function test_CR13_pct_fromZeroFails() public {
        _expect(_spec1(_beforeAfter(ausdc), _pct(0, 1, Op.GTE, 0)), _ans(_u(100e6), _u(0)), REJECTED);
    }

    /// @dev CMP on a PRE read, a precondition: "Aave held at least 1M USDC when the job started" AND "deposited".
    ///      Judged when the evaluation starts; a failure rejects on the first usable answer.
    function test_CR14_cmp_preconditionAtStart() public {
        Read[] memory reads = _r(_balanceRead(ausdc, cea), _pre(_balanceRead(usdc, aavePool)));
        JobSpec memory s = _specOf(reads, _c(_cmp(0, Op.GTE, 99.99e6), _cmp(1, Op.GTE, 1_000_000e6)), LogicKind.ALL, 0);
        _expect(s, _ans(_u(100e6), _u(2_000_000e6)), COMPLETED);
        _expect(s, _ans(_u(100e6), _u(500_000e6)), REJECTED);
    }

    // ───────────── one read against another ─────────────

    /// @dev NUM between two reads after the job: "a ≥ b", then "a − b > 1".
    function test_CR15_num_readAgainstRead() public {
        Read[] memory reads = _r(_balanceRead(ausdc, cea), _balanceRead(morphoVault, cea));
        JobSpec memory s = _spec1(reads, _num(0, 1, Op.GTE, 0));
        _expect(s, _ans(_u(5e6), _u(5e6)), COMPLETED);
        _expect(s, _ans(_u(4e6), _u(5e6)), REJECTED);

        s = _spec1(reads, _num(0, 1, Op.GT, 1));
        _expect(s, _ans(_u(7), _u(5)), COMPLETED);
        _expect(s, _ans(_u(6), _u(5)), REJECTED);
    }

    /// @dev PCT between two reads: "Aave holds at least 5% more than Morpho".
    function test_CR16_pct_readAgainstRead() public {
        Read[] memory reads = _r(_balanceRead(ausdc, cea), _balanceRead(morphoVault, cea));
        JobSpec memory s = _spec1(reads, _pct(0, 1, Op.GTE, 500));
        _expect(s, _ans(_u(105e6), _u(100e6)), COMPLETED);
        _expect(s, _ans(_u(104.99e6), _u(100e6)), REJECTED);
    }

    /// @dev Across chains and moments: "the CEA on Base holds after the job at least what the CEA on Ethereum held
    ///      before it".
    function test_CR17_crossChain_afterAgainstBefore() public {
        _track("1");
        Read[] memory reads = _r(_balanceRead(weth, cea), _pre(_on(_balanceRead(weth, cea), "1")));
        JobSpec memory s = _spec1(reads, _num(0, 1, Op.GTE, 0));
        _expect(s, _ans(_u(100e18), _u(100e18)), COMPLETED);
        _expect(s, _ans(_u(99e18), _u(100e18)), REJECTED);
    }

    // ───────────── pass logic ─────────────

    /// @dev AT_LEAST 2 of 3 venues: settled by the second answer when it can be, else by the third.
    function test_CR18_atLeastTwoOfThree() public {
        Read[] memory reads = _r(_balanceRead(ausdc, cea), _balanceRead(morphoVault, cea), _balanceRead(spark, cea));
        Check[] memory checks = _c(_cmp(0, Op.GTE, 99.99e6), _cmp(1, Op.GTE, 99.99e6), _cmp(2, Op.GTE, 99.99e6));
        JobSpec memory s = _specOf(reads, checks, LogicKind.AT_LEAST, 2);

        uint256 jobId = _expect(s, _ans(_u(100e6), _u(100e6), _u(0)), COMPLETED);
        assertEq(ue.evaluationOf(jobId).pending, 1, "passed on the second answer");
        jobId = _expect(s, _ans(_u(0), _u(0), _u(100e6)), REJECTED);
        assertEq(ue.evaluationOf(jobId).pending, 1, "failed on the second answer");
        jobId = _expect(s, _ans(_u(100e6), _u(0), _u(100e6)), COMPLETED);
        assertEq(ue.evaluationOf(jobId).pending, 0, "needed the third");
    }

    /// @dev Nested: (Aave deposited AND Aave rate ≥ 4%) OR (Morpho deposited AND Morpho rate ≥ 4%).
    function test_CR19_nestedAnyOfAll() public {
        Read[] memory reads = _r(
            _balanceRead(ausdc, cea),
            _call(aavePool, "getReserveData(address)", abi.encode(usdc), _reserveOutputs(), _u8(0, 2)),
            _balanceRead(morphoVault, cea),
            _call(morphoVault, "supplyRate()", "", _out(T_UINT), _u8(0))
        );
        Check[] memory checks =
            _c(_cmp(0, Op.GTE, 99.99e6), _cmp(1, Op.GTE, 0.04e27), _cmp(2, Op.GTE, 99.99e6), _cmp(3, Op.GTE, 0.04e18));
        Logic[] memory logic = new Logic[](7);
        logic[0] = Logic({kind: LogicKind.ANY, check: 0, children: _u8(1, 2), k: 0});
        logic[1] = Logic({kind: LogicKind.ALL, check: 0, children: _u8(3, 4), k: 0});
        logic[2] = Logic({kind: LogicKind.ALL, check: 0, children: _u8(5, 6), k: 0});
        for (uint8 i; i < 4; ++i) {
            logic[3 + i] = _checkNode(i);
        }
        JobSpec memory s = _spec(reads, checks, logic);

        // Aave's rate is too low, Morpho has both.
        _expect(s, _ans(_u(100e6), _reserveAnswer(0.03e27), _u(100e6), _u(0.05e18)), COMPLETED);
        // Each branch misses one.
        _expect(s, _ans(_u(100e6), _reserveAnswer(0.03e27), _u(0), _u(0.05e18)), REJECTED);
    }

    /// @dev One read in two checks: "holds at least 100 after the job" AND "grew by at least 10 during it".
    function test_CR20_oneReadInTwoChecks() public {
        JobSpec memory s =
            _specOf(_beforeAfter(ausdc), _c(_cmp(0, Op.GTE, 100e6), _num(0, 1, Op.GTE, 10e6)), LogicKind.ALL, 0);
        _expect(s, _ans(_u(105e6), _u(95e6)), COMPLETED);
        _expect(s, _ans(_u(105e6), _u(100e6)), REJECTED); // above 100, but grew by 5 only
    }

    // ───────────── values that can't be judged ─────────────

    /// @dev ANY over an unreadable answer and a FAIL is INCONCLUSIVE; the provider resends the unreadable read at the
    ///      same block, and its answer decides.
    function test_CR21_unreadable_thenResent() public {
        uint256 jobId = _run(_anySpec(), _ans("", _u(0)));
        assertEq(uint8(ue.evaluationOf(jobId).verdict), uint8(Verdict.INCONCLUSIVE));
        assertEq(uint8(_status(jobId)), uint8(SUBMITTED));

        vm.prank(provider);
        ue.sendReads{value: READ_COST}(jobId);
        _answer(jobId, 0, _u(100e6));
        assertEq(uint8(_status(jobId)), uint8(COMPLETED));
    }

    /// @dev A difference that overflows int256 is UNKNOWN, never a revert: the job is INCONCLUSIVE and stays open.
    function test_CR22_overflow_isUnknown() public {
        Read[] memory reads = _r(
            _call(perp, "pnlOf(address)", abi.encode(cea), _out(T_INT), _u8(0)),
            _call(perp, "pnlOf(address)", abi.encode(stranger), _out(T_INT), _u8(0))
        );
        uint256 jobId =
            _run(_spec1(reads, _num(0, 1, Op.GT, 0)), _ans(abi.encode(type(int256).max), abi.encode(int256(-1))));
        assertEq(uint8(ue.evaluationOf(jobId).verdict), uint8(Verdict.INCONCLUSIVE));
        assertEq(uint8(_status(jobId)), uint8(SUBMITTED));
    }

    // ───────────── sums: several reads on one side ─────────────

    /// @dev CMP on a sum: "aUSDC + Morpho assets ≥ 999.9" after a split deposit. The split is the provider's choice.
    function test_CR23_sum_splitDeposit() public {
        Read[] memory reads = _r(
            _balanceRead(ausdc, cea), _call(morphoVault, "maxWithdraw(address)", abi.encode(cea), _out(T_UINT), _u8(0))
        );
        JobSpec memory s = _spec1(reads, _cmp(_u8(0, 1), Op.GTE, 999.9e6));
        _expect(s, _ans(_u(600e6), _u(399.9e6)), COMPLETED);
        _expect(s, _ans(_u(999.9e6), _u(0)), COMPLETED); // all in Aave
        _expect(s, _ans(_u(600e6), _u(399.8e6)), REJECTED);
    }

    /// @dev PCT on sums: "earned at least 4% across Aave and Morpho combined". Reads 0, 1 after; 2, 3 before.
    function test_CR24_sum_combinedYield() public {
        JobSpec memory s = _spec1(_twoVenuesBeforeAfter(), _pct(_u8(0, 1), _u8(2, 3), Op.GTE, 400));
        // 600 + 400 → 630 + 410: +4% overall, though Aave made 5% and Morpho 2.5%
        _expect(s, _ans(_u(630e6), _u(410e6), _u(600e6), _u(400e6)), COMPLETED);
        _expect(s, _ans(_u(620e6), _u(410e6), _u(600e6), _u(400e6)), REJECTED); // +3%
    }

    /// @dev NUM on sums: "at least 999.9 more across both venues than before the job", whatever was there already.
    function test_CR25_sum_depositedDuringJob() public {
        JobSpec memory s = _spec1(_twoVenuesBeforeAfter(), _num(_u8(0, 1), _u8(2, 3), Op.GTE, 999.9e6));
        _expect(s, _ans(_u(700e6), _u(449.9e6), _u(100e6), _u(50e6)), COMPLETED);
        _expect(s, _ans(_u(700e6), _u(449.8e6), _u(100e6), _u(50e6)), REJECTED);
    }

    /// @dev A sum across chains: "the CEAs hold at least 1,000 USDC on Base and Arbitrum together".
    function test_CR26_sum_acrossChains() public {
        _track("42161");
        Read[] memory reads = _r(_balanceRead(usdc, cea), _on(_balanceRead(usdc, cea), "42161"));
        JobSpec memory s = _spec1(reads, _cmp(_u8(0, 1), Op.GTE, 1_000e6));
        _expect(s, _ans(_u(700e6), _u(300e6)), COMPLETED);
        _expect(s, _ans(_u(700e6), _u(299e6)), REJECTED);
    }

    /// @dev A sum on the right: "b > a + c".
    function test_CR27_sum_onTheRight() public {
        Read[] memory reads = _r(_balanceRead(weth, cea), _balanceRead(ausdc, cea), _balanceRead(morphoVault, cea));
        JobSpec memory s = _spec1(reads, _num(_u8(0), _u8(1, 2), Op.GT, 0));
        _expect(s, _ans(_u(10), _u(4), _u(5)), COMPLETED);
        _expect(s, _ans(_u(9), _u(4), _u(5)), REJECTED);
    }

    // ───────────── runner ─────────────

    /// @dev One job end to end: fund, answer the PRE reads, move every chain on, submit, then answer the POST reads in
    ///      index order until the job ends. `answers[i]` is read i's raw answer.
    function _run(JobSpec memory s, bytes[] memory answers) internal returns (uint256 jobId) {
        jobId = _createSpec(s);
        _fund(jobId);
        for (uint256 i; i < s.reads.length; ++i) {
            if (s.reads[i].at == ReadAt.PRE_EXECUTION) _answer(jobId, i, answers[i]);
        }
        for (uint256 i; i < s.reads.length; ++i) {
            _move(s.reads[i].chainId);
        }
        _submit(jobId);
        for (uint256 i; i < s.reads.length; ++i) {
            if (_status(jobId) != SUBMITTED) break;
            if (s.reads[i].at == ReadAt.POST_EXECUTION) _answer(jobId, i, answers[i]);
        }
    }

    function _expect(JobSpec memory s, bytes[] memory answers, IAgenticCommerce.JobStatus want)
        internal
        returns (uint256 jobId)
    {
        jobId = _run(s, answers);
        assertEq(uint8(_status(jobId)), uint8(want), "job status");
    }

    // ───────────── specs ─────────────

    function _spec(Read[] memory reads, Check[] memory checks, Logic[] memory logic)
        internal
        view
        returns (JobSpec memory s)
    {
        s.executeBy = uint64(block.timestamp + 1 hours);
        s.failFinalAt = uint64(block.timestamp + 2 hours);
        s.reads = reads;
        s.checks = checks;
        s.logic = logic;
        s.mutability = CriteriaMutability.NONE;
    }

    /// @dev One check, as the root.
    function _spec1(Read[] memory reads, Check memory c) internal view returns (JobSpec memory) {
        Check[] memory checks = new Check[](1);
        checks[0] = c;
        Logic[] memory logic = new Logic[](1);
        logic[0] = _checkNode(0);
        return _spec(reads, checks, logic);
    }

    /// @dev Every check under one root of `kind`.
    function _specOf(Read[] memory reads, Check[] memory checks, LogicKind kind, uint8 k)
        internal
        view
        returns (JobSpec memory)
    {
        Logic[] memory logic = new Logic[](1 + checks.length);
        uint8[] memory kids = new uint8[](checks.length);
        for (uint256 i; i < checks.length; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            kids[i] = uint8(1 + i); // safe: at most MAX_CHECKS
            // forge-lint: disable-next-line(unsafe-typecast)
            logic[1 + i] = _checkNode(uint8(i));
        }
        logic[0] = Logic({kind: kind, check: 0, children: kids, k: k});
        return _spec(reads, checks, logic);
    }

    // ───────────── reads ─────────────

    /// @dev A view on Base, read after the job.
    function _call(address target, string memory sig, bytes memory args, bytes memory outputs, uint8[] memory field)
        internal
        pure
        returns (Read memory r)
    {
        r = _balanceRead(target, address(0));
        r.selector = bytes4(keccak256(bytes(sig)));
        r.args = args;
        r.outputs = outputs;
        r.field = field;
    }

    /// @dev The CEA's `token` balance: read 0 after the job, read 1 before it.
    function _beforeAfter(address token_) internal view returns (Read[] memory) {
        return _r(_balanceRead(token_, cea), _pre(_balanceRead(token_, cea)));
    }

    /// @dev aUSDC and Morpho balances: reads 0, 1 after the job, reads 2, 3 before it.
    function _twoVenuesBeforeAfter() internal view returns (Read[] memory) {
        return _r(
            _balanceRead(ausdc, cea),
            _balanceRead(morphoVault, cea),
            _pre(_balanceRead(ausdc, cea)),
            _pre(_balanceRead(morphoVault, cea))
        );
    }

    /// @dev A function returning one value of type `code`.
    function _out(uint8 code) internal pure returns (bytes memory) {
        return abi.encodePacked(T_TUPLE, uint8(1), code);
    }

    function _r(Read memory a, Read memory b) internal pure returns (Read[] memory x) {
        x = new Read[](2);
        (x[0], x[1]) = (a, b);
    }

    function _r(Read memory a, Read memory b, Read memory c) internal pure returns (Read[] memory x) {
        x = new Read[](3);
        (x[0], x[1], x[2]) = (a, b, c);
    }

    function _r(Read memory a, Read memory b, Read memory c, Read memory d) internal pure returns (Read[] memory x) {
        x = new Read[](4);
        (x[0], x[1], x[2], x[3]) = (a, b, c, d);
    }

    // ───────────── checks ─────────────

    function _bool(uint8 read, bool want) internal pure returns (Check memory) {
        return Check({
            left: _u8(read), right: _none(), evalType: EvalType.BOOL, op: Op.EQ, target: want ? int256(1) : int256(0)
        });
    }

    function _cmp(uint8 read, Op op, int256 target) internal pure returns (Check memory) {
        return _cmp(_u8(read), op, target);
    }

    function _cmp(uint8[] memory left, Op op, int256 target) internal pure returns (Check memory) {
        return Check({left: left, right: _none(), evalType: EvalType.CMP, op: op, target: target});
    }

    function _num(uint8 left, uint8 right, Op op, int256 target) internal pure returns (Check memory) {
        return _num(_u8(left), _u8(right), op, target);
    }

    function _num(uint8[] memory left, uint8[] memory right, Op op, int256 target)
        internal
        pure
        returns (Check memory)
    {
        return Check({left: left, right: right, evalType: EvalType.NUM, op: op, target: target});
    }

    function _pct(uint8 left, uint8 right, Op op, int256 target) internal pure returns (Check memory) {
        return _pct(_u8(left), _u8(right), op, target);
    }

    function _pct(uint8[] memory left, uint8[] memory right, Op op, int256 target)
        internal
        pure
        returns (Check memory)
    {
        return Check({left: left, right: right, evalType: EvalType.PCT, op: op, target: target});
    }

    function _c(Check memory a, Check memory b) internal pure returns (Check[] memory x) {
        x = new Check[](2);
        (x[0], x[1]) = (a, b);
    }

    function _c(Check memory a, Check memory b, Check memory c) internal pure returns (Check[] memory x) {
        x = new Check[](3);
        (x[0], x[1], x[2]) = (a, b, c);
    }

    function _c(Check memory a, Check memory b, Check memory c, Check memory d)
        internal
        pure
        returns (Check[] memory x)
    {
        x = new Check[](4);
        (x[0], x[1], x[2], x[3]) = (a, b, c, d);
    }

    // ───────────── answers ─────────────

    function _u(uint256 v) internal pure returns (bytes memory) {
        return abi.encode(v);
    }

    function _ans(bytes memory a) internal pure returns (bytes[] memory x) {
        x = new bytes[](1);
        x[0] = a;
    }

    function _ans(bytes memory a, bytes memory b) internal pure returns (bytes[] memory x) {
        x = new bytes[](2);
        (x[0], x[1]) = (a, b);
    }

    function _ans(bytes memory a, bytes memory b, bytes memory c) internal pure returns (bytes[] memory x) {
        x = new bytes[](3);
        (x[0], x[1], x[2]) = (a, b, c);
    }

    function _ans(bytes memory a, bytes memory b, bytes memory c, bytes memory d)
        internal
        pure
        returns (bytes[] memory x)
    {
        x = new bytes[](4);
        (x[0], x[1], x[2], x[3]) = (a, b, c, d);
    }
}
