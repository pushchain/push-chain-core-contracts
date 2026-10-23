// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";

import {EvmReadLib} from "../../src/agentic-commerce-8183/evaluator/EvmReadLib.sol";
import {JobSpecLib} from "../../src/agentic-commerce-8183/evaluator/JobSpecLib.sol";
import {ReferenceJudge} from "./helpers/ReferenceJudge.sol";
import {Answer, Verdict} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {JobSpecErrors} from "../../src/agentic-commerce-8183/libraries/Errors.sol";
import {
    JobSpec,
    Read,
    Check,
    Logic,
    Evaluation,
    Operation,
    LogicKind,
    ReadAt,
    MAX_READS,
    MAX_CHECKS,
    T_UINT,
    T_INT,
    T_BOOL,
    T_ADDRESS,
    T_BYTESN,
    T_BYTES,
    T_STRING,
    T_TUPLE,
    T_ARRAY,
    T_FIXED_ARRAY
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {V2Decoder} from "./helpers/V2Decoder.sol";

/// @notice Exposes the internal libraries.
contract LibHarness {
    function decode(bytes memory outputs, uint8[] memory field, bytes calldata res)
        external
        pure
        returns (bool, int256)
    {
        return EvmReadLib.decode(outputs, field, res);
    }

    function isValidShape(bytes memory outputs, uint8[] memory field) external pure returns (bool) {
        return EvmReadLib.isValidShape(outputs, field);
    }

    /// @dev A test ceiling; the evaluator takes it from its deployment config.
    uint256 internal constant MAX_CONFIRMATIONS = 64;

    function validate(JobSpec memory s) external pure {
        JobSpecLib.validate(s, MAX_CONFIRMATIONS);
    }

    function verdict(Check[] memory checks, Logic[] memory logic, Answer[] memory values)
        external
        pure
        returns (Verdict)
    {
        return ReferenceJudge.verdict(checks, logic, values);
    }

    /// @notice The evaluator's path: each check judged alone, then the packed tree.
    function verdictPacked(Check[] memory checks, Logic[] memory logic, Answer[] memory values)
        external
        pure
        returns (Verdict)
    {
        uint32 res;
        for (uint256 i; i < checks.length; ++i) {
            Check memory c = checks[i];
            uint32 right = JobSpecLib.packSide(c.right);
            Answer memory b;
            if (right != 0) b = _sum(right, values);
            Answer memory a = _sum(JobSpecLib.packSide(c.left), values);
            res = JobSpecLib.setCheck(res, i, JobSpecLib.checkResult(c.evaluation, c.operation, c.target, a, b));
        }
        return JobSpecLib.verdictPacked(JobSpecLib.packLogic(logic), logic.length, res);
    }

    /// @dev As the evaluator's `_sum`, over `values` instead of storage.
    function _sum(uint256 mask, Answer[] memory values) internal pure returns (Answer memory total) {
        total.ok = true;
        for (uint256 r; mask != 0; ++r) {
            if (mask & 1 != 0) {
                if (!values[r].ok) return Answer(false, 0);
                (total.ok, total.value) = JobSpecLib.add(total.value, values[r].value);
                if (!total.ok) return total;
            }
            mask >>= 1;
        }
    }
}

contract JobSpecLibrariesTest is Test {
    LibHarness internal lib;
    V2Decoder internal v2;

    function setUp() public {
        lib = new LibHarness();
        v2 = new V2Decoder();
    }

    function _f(uint8 a) internal pure returns (uint8[] memory x) {
        x = new uint8[](1);
        x[0] = a;
    }

    function _f(uint8 a, uint8 b) internal pure returns (uint8[] memory x) {
        x = new uint8[](2);
        x[0] = a;
        x[1] = b;
    }

    function _none() internal pure returns (uint8[] memory) {}

    /// @dev A bitmask of reads as an increasing list of indexes.
    function _toSide(uint256 mask) internal pure returns (uint8[] memory side) {
        side = new uint8[](32);
        uint256 n;
        for (uint256 r; mask != 0; ++r) {
            // forge-lint: disable-next-line(unsafe-typecast)
            if (mask & 1 != 0) side[n++] = uint8(r);
            mask >>= 1;
        }
        assembly ("memory-safe") {
            mstore(side, n)
        }
    }

    // ───────────── decoder ─────────────

    function test_DEC01_basicValues() public view {
        bytes memory o = abi.encodePacked(T_TUPLE, uint8(1), T_UINT);
        (bool ok, int256 v) = lib.decode(o, _f(0), abi.encode(uint256(42)));
        assertTrue(ok);
        assertEq(v, 42);
        (ok,) = lib.decode(o, _f(0), abi.encode(type(uint256).max));
        assertFalse(ok, "uint above int256 max is not representable");
        (ok,) = lib.decode(o, _f(0), hex"0102");
        assertFalse(ok, "short answer");
        (ok,) = lib.decode(o, _f(0), "");
        assertFalse(ok, "error answer");
    }

    function test_DEC02_structField_aaveRate() public view {
        bytes memory o = abi.encodePacked(
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
        uint256[15] memory w;
        w[2] = 0.052e27;
        (bool ok, int256 v) = lib.decode(o, _f(0, 2), abi.encode(w));
        assertTrue(ok);
        assertEq(v, 0.052e27);
        assertTrue(lib.isValidShape(o, _f(0, 2)));
    }

    function test_DEC03_dynamicValues() public view {
        // returns (uint256 a, (bool b, bytes d))
        bytes memory o = abi.encodePacked(T_TUPLE, uint8(2), T_UINT, T_TUPLE, uint8(2), T_BOOL, T_BYTES);
        bytes memory res = abi.encode(uint256(7), Inner(true, hex"abcd"));
        (bool ok, int256 v) = lib.decode(o, _f(1, 0), res);
        assertTrue(ok);
        assertEq(v, 1);
        (ok, v) = lib.decode(o, _f(1, 1), res);
        assertTrue(ok);
        assertEq(v, int256(uint256(keccak256(hex"abcd"))));

        // returns (string[]) : element 1, and the length
        bytes memory o2 = abi.encodePacked(T_TUPLE, uint8(1), T_ARRAY, T_STRING);
        string[] memory arr = new string[](2);
        arr[0] = "WETH";
        arr[1] = "USDC";
        bytes memory res2 = abi.encode(arr);
        (ok, v) = lib.decode(o2, _f(0, 1), res2);
        assertTrue(ok);
        assertEq(v, int256(uint256(keccak256("USDC"))));
        (ok, v) = lib.decode(o2, _f(0), res2);
        assertTrue(ok);
        assertEq(v, 2);
        (ok,) = lib.decode(o2, _f(0, 2), res2);
        assertFalse(ok, "index past the array");
    }

    struct Inner {
        bool b;
        bytes d;
    }

    /// @dev Same answers as the V2 design's decoder on every valid shape (its one divergence, a struct leaf, is
    ///      refused by the shape check and tested separately).
    function testFuzz_DEC04_conformsToV2(uint256 a, int256 b, bool c, address d, bytes32 e, bytes memory f)
        public
        view
    {
        bytes memory o = abi.encodePacked(T_TUPLE, uint8(6), T_UINT, T_INT, T_BOOL, T_ADDRESS, T_BYTESN, T_BYTES);
        bytes memory res = abi.encode(a, b, c, d, e, f);
        for (uint8 i; i < 6; ++i) {
            (bool ok1, int256 v1) = lib.decode(o, _f(i), res);
            (bool ok2, int256 v2_) = v2.decodeAnswer(o, _f(i), res);
            assertEq(ok1, ok2);
            assertEq(v1, v2_);
        }
    }

    /// @dev Any bytes at all: the decoder never reverts, a not-ok answer always carries value 0, and for
    ///      `returns (uint256)` the result matches an independent check of the first word.
    function testFuzz_DEC05_neverRevertsOnGarbage(bytes calldata res) public view {
        // returns (uint256): ok exactly when a whole first word is there and fits int256
        (bool ok, int256 v) = lib.decode(abi.encodePacked(T_TUPLE, uint8(1), T_UINT), _f(0), res);
        bool expectOk = res.length >= 32 && uint256(bytes32(res[0:32])) <= uint256(type(int256).max);
        assertEq(ok, expectOk, "uint256 ok");
        if (expectOk) assertEq(v, int256(uint256(bytes32(res[0:32]))), "uint256 value");
        else assertEq(v, 0, "not ok carries 0");

        bytes memory o = abi.encodePacked(T_TUPLE, uint8(2), T_UINT, T_TUPLE, uint8(2), T_BOOL, T_BYTES);
        (ok, v) = lib.decode(o, _f(1, 1), res);
        if (!ok) assertEq(v, 0, "not ok carries 0 (nested bytes)");
        bytes memory o2 = abi.encodePacked(T_TUPLE, uint8(1), T_ARRAY, T_ARRAY, T_STRING);
        uint8[] memory f3 = new uint8[](3);
        f3[1] = 1;
        f3[2] = 2;
        (ok, v) = lib.decode(o2, f3, res);
        if (!ok) assertEq(v, 0, "not ok carries 0 (string[][])");
    }

    /// @dev An array's length counts only if that many element heads are present.
    function test_DEC07_arrayLength_mustBeBacked() public view {
        bytes memory o = abi.encodePacked(T_TUPLE, uint8(1), T_ARRAY, T_UINT);
        (bool ok,) = lib.decode(o, _f(0), abi.encode(uint256(0x20), uint256(3))); // claims 3, has none
        assertFalse(ok);
        (ok,) = lib.decode(o, _f(0), abi.encode(uint256(0x20), type(uint256).max)); // would wrap negative
        assertFalse(ok);
        uint256[] memory three = new uint256[](3);
        int256 v;
        (ok, v) = lib.decode(o, _f(0), abi.encode(three));
        assertTrue(ok);
        assertEq(v, 3);
        // dynamic elements: the offset table must be present
        bytes memory o2 = abi.encodePacked(T_TUPLE, uint8(1), T_ARRAY, T_STRING);
        (ok,) = lib.decode(o2, _f(0), abi.encode(uint256(0x20), uint256(2), uint256(0x40))); // 2 claimed, 1 offset
        assertFalse(ok);
    }

    function test_DEC06_structLeaf_notAValue() public view {
        bytes memory o = abi.encodePacked(T_TUPLE, uint8(1), T_TUPLE, uint8(2), T_UINT, T_UINT);
        (bool ok,) = lib.decode(o, _f(0), abi.encode(uint256(1), uint256(2)));
        assertFalse(ok);
        assertFalse(lib.isValidShape(o, _f(0)));
    }

    // ───────────── shape check ─────────────

    function test_SHP01_refusals() public view {
        bytes memory ok1 = abi.encodePacked(T_TUPLE, uint8(1), T_UINT);
        assertTrue(lib.isValidShape(ok1, _f(0)));
        assertFalse(lib.isValidShape(abi.encodePacked(T_TUPLE, uint8(1), T_UINT, T_UINT), _f(0)), "trailing type");
        assertFalse(lib.isValidShape(abi.encodePacked(T_TUPLE, uint8(1), uint8(99)), _f(0)), "unknown code");
        assertFalse(lib.isValidShape(abi.encodePacked(T_TUPLE, uint8(0)), _f(0)), "empty tuple");
        assertFalse(lib.isValidShape(abi.encodePacked(T_UINT), _f(0)), "top is not a tuple");
        assertFalse(lib.isValidShape(ok1, _f(1)), "field past the tuple");
        assertFalse(lib.isValidShape(ok1, _f(0, 0)), "into a basic value");
        assertFalse(lib.isValidShape(ok1, new uint8[](0)), "empty field");
        assertFalse(
            lib.isValidShape(abi.encodePacked(T_TUPLE, uint8(1), T_FIXED_ARRAY, uint8(3), T_UINT), _f(0, 3)),
            "past a fixed array"
        );
        assertTrue(lib.isValidShape(abi.encodePacked(T_TUPLE, uint8(1), T_FIXED_ARRAY, uint8(3), T_UINT), _f(0, 2)));
        bytes memory big = new bytes(129);
        assertFalse(lib.isValidShape(big, _f(0)), "too long");
        // the fixed part of the return list must fit MAX_RESULT_LENGTH (4,096 bytes = 128 words)
        assertTrue(lib.isValidShape(abi.encodePacked(T_TUPLE, uint8(1), T_FIXED_ARRAY, uint8(128), T_UINT), _f(0, 0)));
        assertFalse(
            lib.isValidShape(abi.encodePacked(T_TUPLE, uint8(1), T_FIXED_ARRAY, uint8(129), T_UINT), _f(0, 0)),
            "head over 4,096 bytes"
        );
    }

    // ───────────── spec validation ─────────────

    function _read() internal pure returns (Read memory) {
        return Read({
            chainNamespace: "eip155",
            chainId: "8453",
            minConfirmations: 3,
            target: address(0xBEEF),
            selector: bytes4(keccak256("balanceOf(address)")),
            args: abi.encode(address(0xCEA)),
            outputs: abi.encodePacked(T_TUPLE, uint8(1), T_UINT),
            field: _f(0),
            at: ReadAt.POST_EXECUTION
        });
    }

    /// @dev The balance after (read 0) grew by at least 1 over the balance before (read 1).
    function _spec() internal pure returns (JobSpec memory s) {
        s.reads = new Read[](2);
        s.reads[0] = _read();
        s.reads[1] = _read();
        s.reads[1].at = ReadAt.PRE_EXECUTION;
        s.checks = new Check[](1);
        s.checks[0] = Check({
            left: _f(0), right: _f(1), evaluation: Evaluation.NUMBER, operation: Operation.GREATER_OR_EQUAL, target: 1
        });
        s.logic = new Logic[](1);
        s.logic[0] = Logic({kind: LogicKind.CHECK, check: 0, children: new uint8[](0), k: 0});
    }

    /// @dev A valid spec passes; one with no POST_EXECUTION read is refused, as the work would never be measured.
    function test_RUL01_validSpec_needsPostExecutionRead() public {
        lib.validate(_spec());
        lib.validate(_twoVenue());

        JobSpec memory s = _spec();
        s.reads[0].at = ReadAt.PRE_EXECUTION;
        vm.expectRevert(JobSpecErrors.NoPostExecutionRead.selector);
        lib.validate(s);
    }

    function test_RUL02_refusals() public {
        JobSpec memory s = _spec();
        s.reads[0].minConfirmations = 0;
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadConfirmations.selector, 0));
        lib.validate(s);

        s = _spec();
        s.reads[0].target = address(0);
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadTarget.selector, 0));
        lib.validate(s);

        s = _spec();
        s.reads[0].chainId = "";
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadChain.selector, 0));
        lib.validate(s);

        s = _spec();
        s.reads[0].field = _f(1);
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadShape.selector, 0));
        lib.validate(s);

        s = _spec();
        s.checks[0].evaluation = Evaluation.BOOLEAN;
        s.checks[0].right = _none();
        s.checks[0].operation = Operation.EQUAL;
        s.checks[0].target = 2;
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckTarget.selector, 0));
        lib.validate(s);

        s = _spec();
        s.reads[0].args = new bytes(513);
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadArgs.selector, 0));
        lib.validate(s);

        s = _spec();
        s.reads[0].chainNamespace = "eip155-but-much-longer-than-thirty-two-bytes";
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadChain.selector, 0));
        lib.validate(s);

        s = _spec();
        s.reads = new Read[](0);
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadCount.selector, 0));
        lib.validate(s);
    }

    function test_RUL03_logicRefusals() public {
        JobSpec memory s = _twoVenue();
        s.logic[0].children = _f(2, 1); // out of order
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.LogicShape.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.logic[0].children = _f(1, 1); // duplicate child: would count one venue twice
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.LogicShape.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.logic[0].kind = LogicKind.AT_LEAST;
        s.logic[0].k = 3;
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.LogicShape.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.logic[1].check = 9;
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.LogicShape.selector, 1));
        lib.validate(s);
    }

    /// @dev Only what the evaluator can encode, answer and count toward the verdict is accepted.
    function test_RUL04_encodableAnswerableAndAllUsed() public {
        JobSpec memory s = _spec();
        s.reads[0].chainNamespace = "solana"; // requests are EVM calls only
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadChain.selector, 0));
        lib.validate(s);

        s = _spec();
        s.reads[0].minConfirmations = 65; // above the evaluator's ceiling (64 here)
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadConfirmations.selector, 0));
        lib.validate(s);
        s.reads[0].minConfirmations = 64;
        lib.validate(s);

        s = _spec();
        s.checks[0] = Check({
            left: _f(0), right: _none(), evaluation: Evaluation.BOOLEAN, operation: Operation.NOT_EQUAL, target: 1
        }); // BOOLEAN is `== target`
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckOp.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.logic[0] = Logic({kind: LogicKind.CHECK, check: 0, children: new uint8[](0), k: 0}); // 1 and 2 cut off
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.LogicUnreachable.selector, 1));
        lib.validate(s);

        s = _twoVenue();
        s.logic[2].check = 0; // check 1 no longer used
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckUnused.selector, 1));
        lib.validate(s);

        s = _twoVenue();
        s.checks[1].left = _f(0); // read 1 no longer read
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadUnused.selector, 1));
        lib.validate(s);

        s = _twoVenue();
        s.logic = new Logic[](5); // a shared child is fine: 0 → {1, 2}, 1 → {3}, 2 → {3, 4}
        s.logic[0] = Logic({kind: LogicKind.ALL, check: 0, children: _f(1, 2), k: 0});
        s.logic[1] = Logic({kind: LogicKind.ANY, check: 0, children: _f(3), k: 0});
        s.logic[2] = Logic({kind: LogicKind.ANY, check: 0, children: _f(3, 4), k: 0});
        s.logic[3] = Logic({kind: LogicKind.CHECK, check: 0, children: new uint8[](0), k: 0});
        s.logic[4] = Logic({kind: LogicKind.CHECK, check: 1, children: new uint8[](0), k: 0});
        lib.validate(s);
    }

    /// @dev Sides name existing reads, in increasing order, none on both sides; their lengths fit the type.
    function test_RUL05_checkSides() public {
        JobSpec memory s = _spec();
        s.checks[0].right = _f(0); // read 0 on both sides
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckRead.selector, 0));
        lib.validate(s);

        s = _spec();
        s.checks[0].right = _f(2); // no such read
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckRead.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.checks[0].left = _f(1, 0); // out of order
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckRead.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.checks[0].left = _f(0, 0); // repeated
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckRead.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.checks[0].right = _f(1); // COMPARE compares with `target`, not a side
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckSides.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.checks[0].left = _none(); // nothing to compare
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckSides.selector, 0));
        lib.validate(s);

        s = _spec();
        s.checks[0].right = _none(); // NUMBER needs a right side
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckSides.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.checks[0] = Check({
            left: _f(0, 1), right: _none(), evaluation: Evaluation.BOOLEAN, operation: Operation.EQUAL, target: 1
        });
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckSides.selector, 0)); // BOOLEAN reads one value
        lib.validate(s);

        s = _twoVenue(); // a sum on the left: read 0 + read 1
        s.checks[0].left = _f(0, 1);
        lib.validate(s);

        s = _twoVenue(); // two POST reads on different chains: read 1 − read 0
        s.reads[1].chainId = "1";
        s.checks[0] = Check({
            left: _f(1), right: _f(0), evaluation: Evaluation.NUMBER, operation: Operation.GREATER_THAN, target: 0
        });
        lib.validate(s);
    }

    /// @dev Up to MAX_READS (32) reads: here 16 checks, each a POST read against its own PRE read.
    function test_RUL06_maxReads() public {
        JobSpec memory s;
        s.reads = new Read[](MAX_READS);
        s.checks = new Check[](MAX_READS / 2);
        s.logic = new Logic[](1 + MAX_READS / 2);
        uint8[] memory kids = new uint8[](MAX_READS / 2);
        for (uint256 i; i < MAX_READS / 2; ++i) {
            s.reads[i] = _read();
            s.reads[i + MAX_READS / 2] = _read();
            s.reads[i + MAX_READS / 2].at = ReadAt.PRE_EXECUTION;
            // forge-lint: disable-next-line(unsafe-typecast)
            s.checks[i] = Check({
                left: _f(uint8(i)),
                right: _f(uint8(i + MAX_READS / 2)),
                evaluation: Evaluation.NUMBER,
                operation: Operation.GREATER_OR_EQUAL,
                target: 0
            });
            // forge-lint: disable-next-line(unsafe-typecast)
            s.logic[1 + i] = Logic({kind: LogicKind.CHECK, check: uint8(i), children: new uint8[](0), k: 0});
            // forge-lint: disable-next-line(unsafe-typecast)
            kids[i] = uint8(1 + i);
        }
        s.logic[0] = Logic({kind: LogicKind.ALL, check: 0, children: kids, k: 0});
        lib.validate(s);

        Read[] memory more = new Read[](MAX_READS + 1);
        for (uint256 i; i < MAX_READS; ++i) {
            more[i] = s.reads[i];
        }
        more[MAX_READS] = _read();
        s.reads = more;
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadCount.selector, MAX_READS + 1));
        lib.validate(s);
    }

    /// @dev Terms are not capped: 16 checks each summing all 32 reads pass. A real spec is bounded by the 32 KB
    ///      description cap (UniversalEvaluator.gas.t.sol measures the heaviest that fits).
    function test_RUL07_termsUncapped() public view {
        lib.validate(_sums(MAX_CHECKS, MAX_READS));
    }

    /// @dev `nChecks` COMPARE checks, each summing reads 0 to `width - 1`, all under one ALL root.
    function _sums(uint256 nChecks, uint256 width) internal pure returns (JobSpec memory s) {
        s.reads = new Read[](width);
        uint8[] memory side = new uint8[](width);
        for (uint256 j; j < width; ++j) {
            s.reads[j] = _read();
            // forge-lint: disable-next-line(unsafe-typecast)
            side[j] = uint8(j);
        }
        s.checks = new Check[](nChecks);
        s.logic = new Logic[](1 + nChecks);
        uint8[] memory kids = new uint8[](nChecks);
        for (uint256 i; i < nChecks; ++i) {
            s.checks[i] = Check({
                left: side,
                right: _none(),
                evaluation: Evaluation.COMPARE,
                operation: Operation.GREATER_OR_EQUAL,
                target: 1
            });
            // forge-lint: disable-next-line(unsafe-typecast)
            s.logic[1 + i] = Logic({kind: LogicKind.CHECK, check: uint8(i), children: new uint8[](0), k: 0});
            // forge-lint: disable-next-line(unsafe-typecast)
            kids[i] = uint8(1 + i);
        }
        s.logic[0] = Logic({kind: LogicKind.ALL, check: 0, children: kids, k: 0});
    }

    function _twoVenue() internal pure returns (JobSpec memory s) {
        s.reads = new Read[](2);
        s.reads[0] = _read();
        s.reads[1] = _read();
        s.checks = new Check[](2);
        s.checks[0] = Check({
            left: _f(0),
            right: _none(),
            evaluation: Evaluation.COMPARE,
            operation: Operation.GREATER_OR_EQUAL,
            target: 1
        });
        s.checks[1] = Check({
            left: _f(1),
            right: _none(),
            evaluation: Evaluation.COMPARE,
            operation: Operation.GREATER_OR_EQUAL,
            target: 1
        });
        s.logic = new Logic[](3);
        s.logic[0] = Logic({kind: LogicKind.ANY, check: 0, children: _f(1, 2), k: 0});
        s.logic[1] = Logic({kind: LogicKind.CHECK, check: 0, children: new uint8[](0), k: 0});
        s.logic[2] = Logic({kind: LogicKind.CHECK, check: 1, children: new uint8[](0), k: 0});
    }

    // ───────────── judge ─────────────

    /// @dev One check under a CHECK root, `left` as read 0 and `right` as read 1.
    function _one(Check memory c, Answer memory left, Answer memory right) internal view returns (Verdict) {
        Check[] memory cs = new Check[](1);
        cs[0] = c;
        Logic[] memory n = new Logic[](1);
        n[0] = Logic({kind: LogicKind.CHECK, check: 0, children: new uint8[](0), k: 0});
        Answer[] memory v = new Answer[](2);
        v[0] = left;
        v[1] = right;
        return lib.verdict(cs, n, v);
    }

    function test_JDG01_numPctAndOverflow() public view {
        Check[] memory c = new Check[](1);
        Answer[] memory a = new Answer[](1);
        Answer[] memory b = new Answer[](1);

        c[0] = Check({
            left: _f(0),
            right: _f(1),
            evaluation: Evaluation.NUMBER,
            operation: Operation.GREATER_OR_EQUAL,
            target: 0.38e18
        });
        a[0] = Answer(true, 0.39e18);
        b[0] = Answer(true, 0);
        assertEq(uint8(_one(c[0], a[0], b[0])), uint8(Verdict.PASS));

        a[0] = Answer(true, type(int256).max);
        b[0] = Answer(true, type(int256).min);
        assertEq(uint8(_one(c[0], a[0], b[0])), uint8(Verdict.INCONCLUSIVE), "overflow is unknown, never a revert");

        c[0] = Check({
            left: _f(0),
            right: _f(1),
            evaluation: Evaluation.PERCENTAGE,
            operation: Operation.GREATER_OR_EQUAL,
            target: 1
        });
        a[0] = Answer(true, 100.012e6);
        b[0] = Answer(true, 100e6);
        assertEq(uint8(_one(c[0], a[0], b[0])), uint8(Verdict.PASS), "1.2 bps >= 1 bps");
        b[0] = Answer(true, 0);
        assertEq(uint8(_one(c[0], a[0], b[0])), uint8(Verdict.FAIL), "PERCENTAGE from zero fails");
    }

    /// @dev PERCENTAGE is compared exactly (no rounding toward zero), and an overflow on either side is UNKNOWN.
    function test_JDG03_pctExact() public view {
        Check[] memory c = new Check[](1);
        Answer[] memory a = new Answer[](1);
        Answer[] memory b = new Answer[](1);

        // A tiny loss: -1 out of 1e6 is -0.01 bps. Dividing first gave 0 and passed ">= 0".
        c[0] = Check({
            left: _f(0),
            right: _f(1),
            evaluation: Evaluation.PERCENTAGE,
            operation: Operation.GREATER_OR_EQUAL,
            target: 0
        });
        a[0] = Answer(true, 1e6 - 1);
        b[0] = Answer(true, 1e6);
        assertEq(uint8(_one(c[0], a[0], b[0])), uint8(Verdict.FAIL), "a loss is not >= 0%");
        c[0].operation = Operation.LESS_THAN;
        assertEq(uint8(_one(c[0], a[0], b[0])), uint8(Verdict.PASS), "a loss is < 0%");

        // Negative target: "lost at most 1%" as change >= -100 bps.
        c[0] = Check({
            left: _f(0),
            right: _f(1),
            evaluation: Evaluation.PERCENTAGE,
            operation: Operation.GREATER_OR_EQUAL,
            target: -100
        });
        a[0] = Answer(true, 99e6);
        b[0] = Answer(true, 100e6); // exactly -1%
        assertEq(uint8(_one(c[0], a[0], b[0])), uint8(Verdict.PASS));
        a[0] = Answer(true, 99e6 - 1); // a hair over 1%
        assertEq(uint8(_one(c[0], a[0], b[0])), uint8(Verdict.FAIL));

        // EQUAL is exact: 1.2 bps is not 1 bp (dividing first said it was).
        c[0] = Check({
            left: _f(0), right: _f(1), evaluation: Evaluation.PERCENTAGE, operation: Operation.EQUAL, target: 1
        });
        a[0] = Answer(true, 100.012e6);
        b[0] = Answer(true, 100e6);
        assertEq(uint8(_one(c[0], a[0], b[0])), uint8(Verdict.FAIL));

        // Overflow on either side is UNKNOWN, never a revert.
        c[0] = Check({
            left: _f(0),
            right: _f(1),
            evaluation: Evaluation.PERCENTAGE,
            operation: Operation.GREATER_OR_EQUAL,
            target: type(int256).max
        });
        a[0] = Answer(true, 3);
        b[0] = Answer(true, 2); // target * before overflows
        assertEq(uint8(_one(c[0], a[0], b[0])), uint8(Verdict.INCONCLUSIVE));
        c[0].target = 1;
        a[0] = Answer(true, type(int256).max);
        b[0] = Answer(true, 1); // delta * 10_000 overflows
        assertEq(uint8(_one(c[0], a[0], b[0])), uint8(Verdict.INCONCLUSIVE));
    }

    /// @dev Where neither product overflows, PERCENTAGE equals the exact comparison `delta * 10_000 op target * before`,
    ///      for every operator and any signs.
    function testFuzz_JDG04_pctMatchesExactComparison(int120 afterV, int120 beforeV, int120 target, uint8 opSeed)
        public
        view
    {
        vm.assume(beforeV > 0);
        Operation op = Operation(opSeed % 6);
        Check memory c =
            Check({left: _f(0), right: _f(1), evaluation: Evaluation.PERCENTAGE, operation: op, target: target});

        int256 lhs = (int256(afterV) - int256(beforeV)) * 10_000; // fits: |delta| < 2^121, times 2^14
        int256 rhs = int256(target) * int256(beforeV); // fits: under 2^240
        bool pass = op == Operation.EQUAL
            ? lhs == rhs
            : op == Operation.NOT_EQUAL
                ? lhs != rhs
                : op == Operation.GREATER_THAN
                    ? lhs > rhs
                    : op == Operation.GREATER_OR_EQUAL ? lhs >= rhs : op == Operation.LESS_THAN ? lhs < rhs : lhs <= rhs;
        assertEq(uint8(_one(c, Answer(true, afterV), Answer(true, beforeV))), uint8(pass ? Verdict.PASS : Verdict.FAIL));
    }

    /// @dev The evaluator's packed path agrees with the reference judge on random three-valued inputs.
    function testFuzz_JDG02_packedEqualsReference(uint256 seed) public view {
        uint256 nChecks = 1 + (seed % 16);
        uint256 nLogic = 1 + ((seed >> 8) % 32);
        uint256 nReads = 2 + ((seed >> 16) % (MAX_READS - 1));
        Answer[] memory values = new Answer[](nReads);
        for (uint256 i; i < nReads; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, "r", i)));
            values[i] = Answer(r % 5 != 0, int256((r >> 8) % 5));
        }
        Check[] memory checks = new Check[](nChecks);
        for (uint256 i; i < nChecks; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            Evaluation e = Evaluation(r % 4);
            // Valid sides: left from reads [0, p), right from [p, nReads), each non-empty where the type needs it.
            uint256 p = 1 + (r >> 24) % (nReads - 1);
            uint256 left = (r >> 32) & ((uint256(1) << p) - 1);
            if (left == 0 || e == Evaluation.BOOLEAN) left = uint256(1) << ((r >> 32) % p);
            uint256 right;
            if (e == Evaluation.NUMBER || e == Evaluation.PERCENTAGE) {
                right = ((r >> 96) << p) & ((uint256(1) << nReads) - 1);
                if (right == 0) right = uint256(1) << p;
            }
            checks[i] = Check({
                left: _toSide(left),
                right: _toSide(right),
                evaluation: e,
                operation: Operation((r >> 8) % 6),
                target: int256((r >> 16) % 5)
            });
        }
        Logic[] memory logic = new Logic[](nLogic);
        for (uint256 i; i < nLogic; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, "n", i)));
            uint256 kids;
            uint8[] memory tmp = new uint8[](32);
            for (uint256 j = i + 1; j < nLogic; ++j) {
                // forge-lint: disable-next-line(unsafe-typecast)
                if ((r >> j) & 1 == 1) tmp[kids++] = uint8(j);
            }
            if (kids == 0) {
                // forge-lint: disable-next-line(unsafe-typecast)
                logic[i] = Logic({kind: LogicKind.CHECK, check: uint8(r % nChecks), children: new uint8[](0), k: 0});
            } else {
                uint8[] memory ch = new uint8[](kids);
                for (uint256 j; j < kids; ++j) {
                    ch[j] = tmp[j];
                }
                LogicKind kind = LogicKind(1 + ((r >> 40) % 3));
                // forge-lint: disable-next-line(unsafe-typecast)
                uint8 k = uint8(1 + ((r >> 48) % kids));
                logic[i] = Logic({kind: kind, check: 0, children: ch, k: k});
            }
        }
        assertEq(uint8(lib.verdict(checks, logic, values)), uint8(lib.verdictPacked(checks, logic, values)));
    }

    /// @dev Every operator, with the value below, at and above the target: on COMPARE (the value), NUMBER (a difference)
    ///      and PERCENTAGE (a change in bps from a base of 10,000).
    function test_JDG05_everyOperator() public view {
        bool[3][6] memory want = [
            [false, true, false], // EQUAL
            [true, false, true], // NOT_EQUAL
            [false, false, true], // GREATER_THAN
            [false, true, true], // GREATER_OR_EQUAL
            [true, false, false], // LESS_THAN
            [true, true, false] // LESS_OR_EQUAL
        ];
        int256[3] memory values = [int256(99), 100, 101];
        for (uint256 op; op < 6; ++op) {
            for (uint256 j; j < 3; ++j) {
                uint8 expected = uint8(want[op][j] ? Verdict.PASS : Verdict.FAIL);
                int256 v = values[j];
                Check memory c = Check({
                    left: _f(0), right: _none(), evaluation: Evaluation.COMPARE, operation: Operation(op), target: 100
                });
                assertEq(uint8(_one(c, Answer(true, v), Answer(false, 0))), expected, "COMPARE");
                c = Check({
                    left: _f(0), right: _f(1), evaluation: Evaluation.NUMBER, operation: Operation(op), target: 100
                });
                assertEq(uint8(_one(c, Answer(true, v - 50), Answer(true, -50))), expected, "NUMBER");
                c = Check({
                    left: _f(0), right: _f(1), evaluation: Evaluation.PERCENTAGE, operation: Operation(op), target: 100
                });
                assertEq(uint8(_one(c, Answer(true, 10_000 + v), Answer(true, 10_000))), expected, "PERCENTAGE");
            }
        }
    }

    /// @dev BOOLEAN is `left == target`, the target 0 or 1.
    function test_JDG06_bool() public view {
        for (int256 t; t < 2; ++t) {
            for (int256 v; v < 2; ++v) {
                Check memory c = Check({
                    left: _f(0), right: _none(), evaluation: Evaluation.BOOLEAN, operation: Operation.EQUAL, target: t
                });
                assertEq(uint8(_one(c, Answer(true, v), Answer(false, 0))), uint8(v == t ? Verdict.PASS : Verdict.FAIL));
            }
        }
    }

    /// @dev A value that could not be read leaves every check using it UNKNOWN: `left` for all four types, `right`
    ///      for NUMBER and PERCENTAGE.
    function test_JDG07_unreadableValues() public view {
        Answer memory none = Answer(false, 0);
        Answer memory one = Answer(true, 1);
        for (uint256 e; e < 4; ++e) {
            bool pair = e >= uint256(Evaluation.NUMBER);
            Check memory c = Check({
                left: _f(0),
                right: pair ? _f(1) : _none(),
                evaluation: Evaluation(e),
                operation: Operation.EQUAL,
                target: pair ? int256(0) : int256(1)
            });
            assertEq(uint8(_one(c, one, one)), uint8(Verdict.PASS), "both readable");
            assertEq(uint8(_one(c, none, one)), uint8(Verdict.INCONCLUSIVE), "left unreadable");
            if (pair) assertEq(uint8(_one(c, one, none)), uint8(Verdict.INCONCLUSIVE), "right unreadable");
        }
    }

    /// @dev ALL, ANY and AT_LEAST over checks that PASS, FAIL or are UNKNOWN: decided once no UNKNOWN can change them.
    function test_JDG08_logicOverUnknowns() public view {
        (uint8 p, uint8 f, uint8 u) = (JobSpecLib.PASS, JobSpecLib.FAIL, JobSpecLib.UNKNOWN);
        _logic(LogicKind.ALL, 0, [p, p, p], Verdict.PASS);
        _logic(LogicKind.ALL, 0, [p, p, u], Verdict.INCONCLUSIVE);
        _logic(LogicKind.ALL, 0, [p, f, u], Verdict.FAIL);
        _logic(LogicKind.ANY, 0, [f, f, f], Verdict.FAIL);
        _logic(LogicKind.ANY, 0, [f, f, u], Verdict.INCONCLUSIVE);
        _logic(LogicKind.ANY, 0, [u, p, f], Verdict.PASS);
        _logic(LogicKind.AT_LEAST, 2, [p, p, u], Verdict.PASS);
        _logic(LogicKind.AT_LEAST, 2, [p, f, u], Verdict.INCONCLUSIVE);
        _logic(LogicKind.AT_LEAST, 2, [f, f, u], Verdict.FAIL);
        _logic(LogicKind.AT_LEAST, 3, [p, p, u], Verdict.INCONCLUSIVE);
        _logic(LogicKind.AT_LEAST, 1, [f, f, p], Verdict.PASS);
    }

    /// @dev Three COMPARE checks under one `kind` root, each forced to PASS, FAIL or UNKNOWN; both judges must agree.
    function _logic(LogicKind kind, uint8 k, uint8[3] memory results, Verdict want) internal view {
        Check[] memory checks = new Check[](3);
        Answer[] memory values = new Answer[](3);
        Logic[] memory logic = new Logic[](4);
        uint8[] memory kids = new uint8[](3);
        for (uint8 i; i < 3; ++i) {
            checks[i] = Check({
                left: _f(i), right: _none(), evaluation: Evaluation.COMPARE, operation: Operation.EQUAL, target: 1
            });
            values[i] = Answer(results[i] != JobSpecLib.UNKNOWN, results[i] == JobSpecLib.PASS ? int256(1) : int256(0));
            logic[1 + i] = Logic({kind: LogicKind.CHECK, check: i, children: new uint8[](0), k: 0});
            kids[i] = 1 + i;
        }
        logic[0] = Logic({kind: kind, check: 0, children: kids, k: k});
        assertEq(uint8(lib.verdict(checks, logic, values)), uint8(want), "reference");
        assertEq(uint8(lib.verdictPacked(checks, logic, values)), uint8(want), "packed");
    }

    /// @dev Each side is the sum of its reads; one unreadable read, or a sum that overflows, leaves the check UNKNOWN.
    function test_JDG09_sides() public view {
        Answer[] memory v = new Answer[](5);
        v[0] = Answer(true, 3);
        v[1] = Answer(true, 4);
        v[2] = Answer(true, 5);
        v[3] = Answer(false, 0); // unreadable
        v[4] = Answer(true, type(int256).max);

        _judged(
            Check({
                left: _f(0, 1),
                right: _none(),
                evaluation: Evaluation.COMPARE,
                operation: Operation.GREATER_OR_EQUAL,
                target: 7
            }),
            v,
            Verdict.PASS
        );
        _judged(
            Check({
                left: _f(0, 1),
                right: _none(),
                evaluation: Evaluation.COMPARE,
                operation: Operation.GREATER_OR_EQUAL,
                target: 8
            }),
            v,
            Verdict.FAIL
        );
        _judged(
            Check({left: _f(0, 1), right: _f(2), evaluation: Evaluation.NUMBER, operation: Operation.EQUAL, target: 2}),
            v,
            Verdict.PASS
        ); // 7 - 5
        _judged(
            Check({
                left: _f(2), right: _f(0, 1), evaluation: Evaluation.NUMBER, operation: Operation.LESS_THAN, target: 0
            }),
            v,
            Verdict.PASS
        ); // 5 - 7
        // (7 - 5) / 5 = +40%
        _judged(
            Check({
                left: _f(0, 1),
                right: _f(2),
                evaluation: Evaluation.PERCENTAGE,
                operation: Operation.EQUAL,
                target: 4000
            }),
            v,
            Verdict.PASS
        );
        _judged(
            Check({
                left: _f(0, 3),
                right: _none(),
                evaluation: Evaluation.COMPARE,
                operation: Operation.GREATER_OR_EQUAL,
                target: 0
            }),
            v,
            Verdict.INCONCLUSIVE
        );
        _judged(
            Check({
                left: _f(2),
                right: _f(1, 3),
                evaluation: Evaluation.NUMBER,
                operation: Operation.GREATER_OR_EQUAL,
                target: 0
            }),
            v,
            Verdict.INCONCLUSIVE
        );
        _judged(
            Check({
                left: _f(1, 4),
                right: _none(),
                evaluation: Evaluation.COMPARE,
                operation: Operation.GREATER_OR_EQUAL,
                target: 0
            }),
            v,
            Verdict.INCONCLUSIVE
        );
    }

    /// @dev One check under a CHECK root over `values`, through both judges.
    function _judged(Check memory c, Answer[] memory values, Verdict want) internal view {
        Check[] memory cs = new Check[](1);
        cs[0] = c;
        Logic[] memory n = new Logic[](1);
        n[0] = Logic({kind: LogicKind.CHECK, check: 0, children: new uint8[](0), k: 0});
        assertEq(uint8(lib.verdict(cs, n, values)), uint8(want), "reference");
        assertEq(uint8(lib.verdictPacked(cs, n, values)), uint8(want), "packed");
    }
}
