// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";

import {AnswerDecoder} from "../../src/agentic-commerce-8183/evaluator/AnswerDecoder.sol";
import {JobSpecRules} from "../../src/agentic-commerce-8183/evaluator/JobSpecRules.sol";
import {JobSpecJudge} from "../../src/agentic-commerce-8183/evaluator/JobSpecJudge.sol";
import {Answer, Verdict} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {JobSpecErrors} from "../../src/agentic-commerce-8183/libraries/Errors.sol";
import {
    JobSpec,
    Read,
    Check,
    Node,
    EvalType,
    Op,
    NodeKind,
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
        return AnswerDecoder.decode(outputs, field, res);
    }

    function isValidShape(bytes memory outputs, uint8[] memory field) external pure returns (bool) {
        return AnswerDecoder.isValidShape(outputs, field);
    }

    /// @dev A test ceiling; the evaluator takes it from its deployment config.
    uint256 internal constant MAX_CONFIRMATIONS = 64;

    function validate(JobSpec memory s) external pure {
        JobSpecRules.validate(s, MAX_CONFIRMATIONS);
    }

    function snapshotReads(JobSpec memory s) external pure returns (bool[] memory, uint256) {
        return JobSpecRules.snapshotReads(s);
    }

    function verdict(Check[] memory checks, Node[] memory nodes, Answer[] memory afters, Answer[] memory befores)
        external
        pure
        returns (Verdict)
    {
        return JobSpecJudge.verdict(checks, nodes, afters, befores);
    }

    /// @notice The evaluator's path: each check judged alone, then the packed tree.
    function verdictPacked(Check[] memory checks, Node[] memory nodes, Answer[] memory afters, Answer[] memory befores)
        external
        pure
        returns (Verdict)
    {
        uint32 res;
        for (uint256 i; i < checks.length; ++i) {
            Check memory c = checks[i];
            res = JobSpecJudge.setCheck(res, i, JobSpecJudge.checkResult(c, afters[c.read], befores[c.read]));
        }
        return JobSpecJudge.verdictPacked(JobSpecJudge.packNodes(nodes), nodes.length, res);
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
            field: _f(0)
        });
    }

    function _spec() internal pure returns (JobSpec memory s) {
        s.executeBy = 100;
        s.failFinalAt = 200;
        s.reads = new Read[](1);
        s.reads[0] = _read();
        s.checks = new Check[](1);
        s.checks[0] = Check({read: 0, evalType: EvalType.NUM, op: Op.GTE, target: 1});
        s.nodes = new Node[](1);
        s.nodes[0] = Node({kind: NodeKind.CHECK, check: 0, children: new uint8[](0), k: 0});
    }

    /// @dev A valid spec passes, and the snapshot covers exactly the reads a NUM or PCT check compares against.
    function test_RUL01_validSpec_andSnapshotReads() public view {
        lib.validate(_spec());
        (bool[] memory need, uint256 count) = lib.snapshotReads(_spec()); // one NUM check on read 0
        assertEq(need.length, 1);
        assertTrue(need[0]);
        assertEq(count, 1);

        JobSpec memory s = _twoVenue(); // CMP only
        lib.validate(s);
        (need, count) = lib.snapshotReads(s);
        assertFalse(need[0]);
        assertFalse(need[1]);
        assertEq(count, 0);

        s.checks[1].evalType = EvalType.PCT; // read 1 now needs a before value; read 0 (CMP) still doesn't
        (need, count) = lib.snapshotReads(s);
        assertFalse(need[0]);
        assertTrue(need[1]);
        assertEq(count, 1);

        s.checks[0].evalType = EvalType.NUM; // and now read 0 too
        (need, count) = lib.snapshotReads(s);
        assertTrue(need[0]);
        assertTrue(need[1]);
        assertEq(count, 2);
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
        s.checks[0].evalType = EvalType.BOOL;
        s.checks[0].op = Op.EQ;
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

    function test_RUL03_nodeRefusals() public {
        JobSpec memory s = _twoVenue();
        s.nodes[0].children = _f(2, 1); // out of order
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.NodeShape.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.nodes[0].children = _f(1, 1); // duplicate child: would count one venue twice
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.NodeShape.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.nodes[0].kind = NodeKind.AT_LEAST;
        s.nodes[0].k = 3;
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.NodeShape.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.nodes[1].check = 9;
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.NodeShape.selector, 1));
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
        s.checks[0] = Check({read: 0, evalType: EvalType.BOOL, op: Op.NEQ, target: 1}); // BOOL is `== target`
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckOp.selector, 0));
        lib.validate(s);

        s = _twoVenue();
        s.nodes[0] = Node({kind: NodeKind.CHECK, check: 0, children: new uint8[](0), k: 0}); // 1 and 2 cut off
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.NodeUnreachable.selector, 1));
        lib.validate(s);

        s = _twoVenue();
        s.nodes[2].check = 0; // check 1 no longer used
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckUnused.selector, 1));
        lib.validate(s);

        s = _twoVenue();
        s.checks[1].read = 0; // read 1 no longer read
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadUnused.selector, 1));
        lib.validate(s);

        s = _twoVenue();
        s.nodes = new Node[](5); // a shared child is fine: 0 → {1, 2}, 1 → {3}, 2 → {3, 4}
        s.nodes[0] = Node({kind: NodeKind.ALL, check: 0, children: _f(1, 2), k: 0});
        s.nodes[1] = Node({kind: NodeKind.ANY, check: 0, children: _f(3), k: 0});
        s.nodes[2] = Node({kind: NodeKind.ANY, check: 0, children: _f(3, 4), k: 0});
        s.nodes[3] = Node({kind: NodeKind.CHECK, check: 0, children: new uint8[](0), k: 0});
        s.nodes[4] = Node({kind: NodeKind.CHECK, check: 1, children: new uint8[](0), k: 0});
        lib.validate(s);
    }

    function _twoVenue() internal pure returns (JobSpec memory s) {
        s.executeBy = 100;
        s.failFinalAt = 200;
        s.reads = new Read[](2);
        s.reads[0] = _read();
        s.reads[1] = _read();
        s.checks = new Check[](2);
        s.checks[0] = Check({read: 0, evalType: EvalType.CMP, op: Op.GTE, target: 1});
        s.checks[1] = Check({read: 1, evalType: EvalType.CMP, op: Op.GTE, target: 1});
        s.nodes = new Node[](3);
        s.nodes[0] = Node({kind: NodeKind.ANY, check: 0, children: _f(1, 2), k: 0});
        s.nodes[1] = Node({kind: NodeKind.CHECK, check: 0, children: new uint8[](0), k: 0});
        s.nodes[2] = Node({kind: NodeKind.CHECK, check: 1, children: new uint8[](0), k: 0});
    }

    // ───────────── judge ─────────────

    function test_JDG01_numPctAndOverflow() public view {
        Check[] memory c = new Check[](1);
        Node[] memory n = new Node[](1);
        n[0] = Node({kind: NodeKind.CHECK, check: 0, children: new uint8[](0), k: 0});
        Answer[] memory a = new Answer[](1);
        Answer[] memory b = new Answer[](1);

        c[0] = Check({read: 0, evalType: EvalType.NUM, op: Op.GTE, target: 0.38e18});
        a[0] = Answer(true, 0.39e18);
        b[0] = Answer(true, 0);
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(Verdict.PASS));

        a[0] = Answer(true, type(int256).max);
        b[0] = Answer(true, type(int256).min);
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(Verdict.INCONCLUSIVE), "overflow is unknown, never a revert");

        c[0] = Check({read: 0, evalType: EvalType.PCT, op: Op.GTE, target: 1});
        a[0] = Answer(true, 100.012e6);
        b[0] = Answer(true, 100e6);
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(Verdict.PASS), "1.2 bps >= 1 bps");
        b[0] = Answer(true, 0);
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(Verdict.FAIL), "PCT from zero fails");
    }

    /// @dev PCT is compared exactly (no rounding toward zero), and an overflow on either side is UNKNOWN.
    function test_JDG03_pctExact() public view {
        Check[] memory c = new Check[](1);
        Node[] memory n = new Node[](1);
        n[0] = Node({kind: NodeKind.CHECK, check: 0, children: new uint8[](0), k: 0});
        Answer[] memory a = new Answer[](1);
        Answer[] memory b = new Answer[](1);

        // A tiny loss: -1 out of 1e6 is -0.01 bps. Dividing first gave 0 and passed ">= 0".
        c[0] = Check({read: 0, evalType: EvalType.PCT, op: Op.GTE, target: 0});
        a[0] = Answer(true, 1e6 - 1);
        b[0] = Answer(true, 1e6);
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(Verdict.FAIL), "a loss is not >= 0%");
        c[0].op = Op.LT;
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(Verdict.PASS), "a loss is < 0%");

        // Negative target: "lost at most 1%" as change >= -100 bps.
        c[0] = Check({read: 0, evalType: EvalType.PCT, op: Op.GTE, target: -100});
        a[0] = Answer(true, 99e6);
        b[0] = Answer(true, 100e6); // exactly -1%
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(Verdict.PASS));
        a[0] = Answer(true, 99e6 - 1); // a hair over 1%
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(Verdict.FAIL));

        // EQ is exact: 1.2 bps is not 1 bp (dividing first said it was).
        c[0] = Check({read: 0, evalType: EvalType.PCT, op: Op.EQ, target: 1});
        a[0] = Answer(true, 100.012e6);
        b[0] = Answer(true, 100e6);
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(Verdict.FAIL));

        // Overflow on either side is UNKNOWN, never a revert.
        c[0] = Check({read: 0, evalType: EvalType.PCT, op: Op.GTE, target: type(int256).max});
        a[0] = Answer(true, 3);
        b[0] = Answer(true, 2); // target * before overflows
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(Verdict.INCONCLUSIVE));
        c[0].target = 1;
        a[0] = Answer(true, type(int256).max);
        b[0] = Answer(true, 1); // delta * 10_000 overflows
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(Verdict.INCONCLUSIVE));
    }

    /// @dev Where neither product overflows, PCT equals the exact comparison `delta * 10_000 op target * before`,
    ///      for every operator and any signs.
    function testFuzz_JDG04_pctMatchesExactComparison(int120 afterV, int120 beforeV, int120 target, uint8 opSeed)
        public
        view
    {
        vm.assume(beforeV > 0);
        Op op = Op(opSeed % 6);
        Check[] memory c = new Check[](1);
        c[0] = Check({read: 0, evalType: EvalType.PCT, op: op, target: target});
        Node[] memory n = new Node[](1);
        n[0] = Node({kind: NodeKind.CHECK, check: 0, children: new uint8[](0), k: 0});
        Answer[] memory a = new Answer[](1);
        a[0] = Answer(true, afterV);
        Answer[] memory b = new Answer[](1);
        b[0] = Answer(true, beforeV);

        int256 lhs = (int256(afterV) - int256(beforeV)) * 10_000; // fits: |delta| < 2^121, times 2^14
        int256 rhs = int256(target) * int256(beforeV); // fits: under 2^240
        bool pass = op == Op.EQ
            ? lhs == rhs
            : op == Op.NEQ
                ? lhs != rhs
                : op == Op.GT ? lhs > rhs : op == Op.GTE ? lhs >= rhs : op == Op.LT ? lhs < rhs : lhs <= rhs;
        assertEq(uint8(lib.verdict(c, n, a, b)), uint8(pass ? Verdict.PASS : Verdict.FAIL));
    }

    /// @dev The evaluator's packed path agrees with the reference judge on random three-valued inputs.
    function testFuzz_JDG02_packedEqualsReference(uint256 seed) public view {
        uint256 nChecks = 1 + (seed % 16);
        uint256 nNodes = 1 + ((seed >> 8) % 32);
        Check[] memory checks = new Check[](nChecks);
        Answer[] memory afters = new Answer[](nChecks);
        Answer[] memory befores = new Answer[](nChecks);
        for (uint256 i; i < nChecks; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            // forge-lint: disable-next-line(unsafe-typecast)
            checks[i] =
                Check({read: uint8(i), evalType: EvalType(r % 4), op: Op((r >> 8) % 6), target: int256((r >> 16) % 5)});
            afters[i] = Answer((r >> 32) % 5 != 0, int256((r >> 40) % 5));
            befores[i] = Answer((r >> 48) % 7 != 0, int256((r >> 56) % 5));
        }
        Node[] memory nodes = new Node[](nNodes);
        for (uint256 i; i < nNodes; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, "n", i)));
            uint256 kids;
            uint8[] memory tmp = new uint8[](32);
            for (uint256 j = i + 1; j < nNodes; ++j) {
                // forge-lint: disable-next-line(unsafe-typecast)
                if ((r >> j) & 1 == 1) tmp[kids++] = uint8(j);
            }
            if (kids == 0) {
                // forge-lint: disable-next-line(unsafe-typecast)
                nodes[i] = Node({kind: NodeKind.CHECK, check: uint8(r % nChecks), children: new uint8[](0), k: 0});
            } else {
                uint8[] memory ch = new uint8[](kids);
                for (uint256 j; j < kids; ++j) {
                    ch[j] = tmp[j];
                }
                NodeKind kind = NodeKind(1 + ((r >> 40) % 3));
                // forge-lint: disable-next-line(unsafe-typecast)
                uint8 k = uint8(1 + ((r >> 48) % kids));
                nodes[i] = Node({kind: kind, check: 0, children: ch, k: k});
            }
        }
        assertEq(
            uint8(lib.verdict(checks, nodes, afters, befores)), uint8(lib.verdictPacked(checks, nodes, afters, befores))
        );
    }
}
