// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {
    Evaluation,
    Operation,
    LogicKind,
    Logic,
    AllowedMutability,
    ReadAt,
    Read,
    Check,
    JobSpec,
    T_UINT,
    T_ADDRESS,
    T_TUPLE
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {BuilderFixtures} from "./JobSpecBuilder.t.sol";
import {V2Decoder} from "./helpers/V2Decoder.sol";
import {EvaluatorSpecCheck, JobSpecErrors} from "./helpers/EvaluatorSpecCheck.sol";
import {BuildContext, JobSpecTemplate, ReadTemplate} from "../../src/agentic-commerce-8183/libraries/Types.sol";

/// @notice TEST ONLY: an external entry point to the evaluator's validation, so a test can expect its revert.
contract EvaluatorSpecCheckHarness {
    function validate(bytes calldata spec, uint256 maxConfirmations) external pure {
        EvaluatorSpecCheck.validate(abi.decode(spec, (JobSpec)), maxConfirmations);
    }
}

/// @title UniversalMarketplace — conformance with the UniversalEvaluator (agreed format, 8666c2a)
/// @notice What the marketplace builds must be exactly what the examples write by hand, every read it builds must
///         decode in the V2 evaluator's decoder, and every spec it builds from a well-formed template must pass the
///         evaluator's own validation (which runs inside `fund`).
contract UniversalMarketplaceConformanceTest is BuilderFixtures {
    V2Decoder internal decoder;
    EvaluatorSpecCheckHarness internal evaluatorCheck;

    /// @dev The demo evaluator's `maxConfirmations`.
    uint256 internal constant MAX_CONFIRMATIONS = 64;

    function setUp() public override {
        super.setUp();
        decoder = new V2Decoder();
        evaluatorCheck = new EvaluatorSpecCheckHarness();
    }

    // ═════════════════════════════ the examples, built by the marketplace ═════════════════════════════

    function test_MC01_lendingExample_equalsV2Doc() public view {
        JobSpec memory built = _build(_lending(), _ctx(100e6, _noParams()));
        address cea = builder.ceaFor(AGW, ETH_HASH);

        Read[] memory reads = new Read[](2);
        reads[0] = _docRead("1", 12, AUSDC_ETH, BALANCE_OF, abi.encode(cea), _docUintOutputs(), _f(0));
        reads[1] =
            _docRead("1", 12, AAVE_POOL_ETH, GET_RESERVE_DATA, abi.encode(USDC_ETH), _docReserveOutputs(), _f2(0, 2));
        Check[] memory checks = new Check[](2);
        checks[0] = _docCheck(_one(0), _none(), Evaluation.COMPARE, Operation.GREATER_OR_EQUAL, 99.99e6);
        checks[1] = _docCheck(_one(1), _none(), Evaluation.COMPARE, Operation.GREATER_OR_EQUAL, 0.04e27);
        Logic[] memory logic = new Logic[](3);
        logic[0] = _node(LogicKind.ALL, _kids(1, 2), 0);
        logic[1] = _leaf(0);
        logic[2] = _leaf(1);

        _assertSpecEq(built, _docSpec(reads, checks, logic));
    }

    function test_MC02_swapExample_equalsV2Doc() public view {
        JobSpec memory built = _build(_swap(), _ctx(0, _oneParam(0.38e18)));
        address cea = builder.ceaFor(AGW, BASE_HASH);

        Read[] memory reads = new Read[](2);
        reads[0] = _docRead("8453", 3, WETH_BASE, BALANCE_OF, abi.encode(cea), _docUintOutputs(), _f(0));
        reads[1] = _docRead("8453", 3, WETH_BASE, BALANCE_OF, abi.encode(cea), _docUintOutputs(), _f(0));
        reads[1].at = ReadAt.PRE_EXECUTION;
        Check[] memory checks = new Check[](1);
        checks[0] = _docCheck(_one(0), _one(1), Evaluation.NUMBER, Operation.GREATER_OR_EQUAL, 0.38e18);
        Logic[] memory logic = new Logic[](2);
        logic[0] = _node(LogicKind.ALL, _one(1), 0);
        logic[1] = _leaf(0);

        _assertSpecEq(built, _docSpec(reads, checks, logic));
    }

    function test_MC03_orAndAtLeastExamples() public view {
        address cea = builder.ceaFor(AGW, ETH_HASH);

        // ANY: "Aave or Morpho", spelled out in full.
        JobSpec memory either = _build(_either(), _ctx(100e6, _noParams()));
        Read[] memory reads = new Read[](2);
        reads[0] = _docRead("1", 12, AUSDC_ETH, BALANCE_OF, abi.encode(cea), _docUintOutputs(), _f(0));
        reads[1] = _docRead("1", 12, MORPHO_VAULT, MAX_WITHDRAW, abi.encode(cea), _docUintOutputs(), _f(0));
        Check[] memory checks = new Check[](2);
        checks[0] = _docCheck(_one(0), _none(), Evaluation.COMPARE, Operation.GREATER_OR_EQUAL, 99.99e6);
        checks[1] = _docCheck(_one(1), _none(), Evaluation.COMPARE, Operation.GREATER_OR_EQUAL, 99.99e6);
        Logic[] memory logic = new Logic[](3);
        logic[0] = _node(LogicKind.ANY, _kids(1, 2), 0);
        logic[1] = _leaf(0);
        logic[2] = _leaf(1);
        _assertSpecEq(either, _docSpec(reads, checks, logic));

        // Nested: ANY over two ALL entries, ALL(checks 0, 1) and ALL(checks 2, 3), each check a leaf.
        JobSpec memory nested = _build(_nested(), _ctx(100e6, _noParams()));
        Logic[] memory tree = new Logic[](7);
        tree[0] = _node(LogicKind.ANY, _kids(1, 2), 0);
        tree[1] = _node(LogicKind.ALL, _kids(3, 4), 0);
        tree[2] = _node(LogicKind.ALL, _kids(5, 6), 0);
        for (uint8 i; i < 4; ++i) {
            tree[i + 3] = _leaf(i);
        }
        _assertLogicEq(nested.logic, tree);

        // AT_LEAST: "at least 2 of 3", each ≥ 99.99 USDC.
        JobSpec memory twoOfThree = _build(_twoOfThree(), _ctx(300e6, _noParams()));
        Logic[] memory atLeast = new Logic[](4);
        atLeast[0] = _node(LogicKind.AT_LEAST, _kids3(1, 2, 3), 2);
        for (uint8 i; i < 3; ++i) {
            atLeast[i + 1] = _leaf(i);
            assertEq(twoOfThree.checks[i].target, 99.99e6, "AT_LEAST: target");
        }
        _assertLogicEq(twoOfThree.logic, atLeast);
    }

    /// @dev The ABI head of a built JobSpec is five words: reads, checks, logic (offsets), allowedMutability, origin.
    ///      No timing words follow.
    function test_MC05_fieldOrder() public view {
        bytes memory built = builder.build(abi.encode(_lending()), _ctx(100e6, _noParams()));
        JobSpec memory s = abi.decode(built, (JobSpec));
        assertEq(abi.encode(s), built, "round-trips");
        // `built` is abi.encode(spec): word 0 is the tuple's offset (32), the head starts at byte 32.
        assertEq(_word(built, 0), 32, "tuple offset");
        assertEq(_word(built, 1 + 3), uint256(AllowedMutability.NONE), "head 3: allowedMutability");
        assertEq(_word(built, 1 + 3), 1, "NONE is 1");
        assertEq(bytes32(_word(built, 1 + 4)), keccak256("origin"), "head 4: origin");
        assertEq(_word(built, 1 + 0), 5 * 32, "head 0: reads, the first dynamic tail right after the 5-word head");
        assertGt(_word(built, 1 + 1), _word(built, 1 + 0), "head 1: checks after reads");
        assertGt(_word(built, 1 + 2), _word(built, 1 + 1), "head 2: logic after checks");
    }

    /// @dev Every example template, built for a job, passes the evaluator's own validation.
    function test_MC06_builtSpecsPassEvaluatorValidate() public view {
        evaluatorCheck.validate(builder.build(abi.encode(_lending()), _ctx(100e6, _noParams())), MAX_CONFIRMATIONS);
        evaluatorCheck.validate(builder.build(abi.encode(_swap()), _ctx(0, _oneParam(0.38e18))), MAX_CONFIRMATIONS);
        evaluatorCheck.validate(builder.build(abi.encode(_either()), _ctx(100e6, _noParams())), MAX_CONFIRMATIONS);
        evaluatorCheck.validate(builder.build(abi.encode(_twoOfThree()), _ctx(300e6, _noParams())), MAX_CONFIRMATIONS);
        evaluatorCheck.validate(builder.build(abi.encode(_nested()), _ctx(100e6, _noParams())), MAX_CONFIRMATIONS);
    }

    /// @dev The builder does not judge, so a template the evaluator would refuse still builds; the evaluator check
    ///      catches it. This is what keeps MC06 honest.
    function test_MC07_badTemplateFailsEvaluatorValidate() public {
        // an unused read
        JobSpecTemplate memory t = _lending();
        ReadTemplate[] memory reads = new ReadTemplate[](3);
        (reads[0], reads[1]) = (t.reads[0], t.reads[1]);
        reads[2] = _balanceOfCEA("1", SPARK);
        t.reads = reads;
        bytes memory spec = builder.build(abi.encode(t), _ctx(100e6, _noParams()));
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.ReadUnused.selector, 2));
        evaluatorCheck.validate(spec, MAX_CONFIRMATIONS);

        // no POST_EXECUTION read
        t = _swap();
        t.reads[0].at = ReadAt.PRE_EXECUTION;
        spec = builder.build(abi.encode(t), _ctx(0, _oneParam(1)));
        vm.expectRevert(JobSpecErrors.NoPostExecutionRead.selector);
        evaluatorCheck.validate(spec, MAX_CONFIRMATIONS);
    }

    function _word(bytes memory b, uint256 i) internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), mul(i, 0x20)))
        }
    }

    // ═════════════════════════════ the reference decoder reads what the builder writes ═════════════════════════════

    /// @dev Every read the marketplace builds for the examples decodes in the V2 decoder.
    function test_MC04_referenceDecoder_agrees() public view {
        _assertBuiltReadsDecode(_build(_lending(), _ctx(100e6, _noParams())));
        _assertBuiltReadsDecode(_build(_swap(), _ctx(0, _oneParam(0.38e18))));
        _assertBuiltReadsDecode(_build(_either(), _ctx(100e6, _noParams())));
        _assertBuiltReadsDecode(_build(_twoOfThree(), _ctx(300e6, _noParams())));
        _assertBuiltReadsDecode(_build(_nested(), _ctx(100e6, _noParams())));
    }

    // ═════════════════════════════ the doc's spellings ═════════════════════════════

    function _docSpec(Read[] memory reads, Check[] memory checks, Logic[] memory logic)
        internal
        pure
        returns (JobSpec memory)
    {
        return JobSpec({
            reads: reads,
            checks: checks,
            logic: logic,
            allowedMutability: AllowedMutability.NONE,
            origin: keccak256("origin")
        });
    }

    function _docCheck(uint8[] memory left, uint8[] memory right, Evaluation e, Operation op, int256 target)
        internal
        pure
        returns (Check memory)
    {
        return Check({left: left, right: right, evaluation: e, operation: op, target: target});
    }

    function _docRead(
        string memory chainId,
        uint16 confirmations,
        address target,
        bytes4 selector,
        bytes memory args,
        bytes memory outputs,
        uint8[] memory field
    ) internal pure returns (Read memory) {
        return Read({
            chainNamespace: "eip155",
            chainId: chainId,
            minConfirmations: confirmations,
            target: target,
            selector: selector,
            args: args,
            outputs: outputs,
            field: field,
            at: ReadAt.POST_EXECUTION
        });
    }

    function _docUintOutputs() internal pure returns (bytes memory) {
        return abi.encodePacked(T_TUPLE, uint8(1), T_UINT);
    }

    /// @dev Line for line as the doc writes `getReserveData`'s outputs.
    function _docReserveOutputs() internal pure returns (bytes memory) {
        return bytes.concat(
            abi.encodePacked(T_TUPLE, uint8(1)),
            abi.encodePacked(T_TUPLE, uint8(15)),
            abi.encodePacked(T_TUPLE, uint8(1), T_UINT),
            abi.encodePacked(T_UINT),
            abi.encodePacked(T_UINT),
            abi.encodePacked(T_UINT, T_UINT, T_UINT),
            abi.encodePacked(T_UINT, T_UINT),
            abi.encodePacked(T_ADDRESS, T_ADDRESS, T_ADDRESS, T_ADDRESS),
            abi.encodePacked(T_UINT, T_UINT, T_UINT)
        );
    }

    /// @dev ReserveData with field k (k ≥ 1) = 1000 + k; `rate`, when non-zero, replaces currentLiquidityRate.
    function _reserveAnswer(uint256 rate) internal pure returns (bytes memory res) {
        res = abi.encode(uint256(1)); // configuration: a 1-field struct
        for (uint256 k = 1; k < 15; ++k) {
            uint256 w = k == 2 && rate != 0 ? rate : 1000 + k;
            res = bytes.concat(res, bytes32(w));
        }
    }

    // ═════════════════════════════ assertions ═════════════════════════════

    /// @dev Every built read decodes in the V2 decoder, at a UINT leaf, to the value its answer holds.
    function _assertBuiltReadsDecode(JobSpec memory spec) internal view {
        for (uint256 i; i < spec.reads.length; ++i) {
            Read memory r = spec.reads[i];
            bool isReserve = keccak256(r.outputs) == keccak256(_docReserveOutputs());
            bytes memory res = isReserve ? _reserveAnswer(0.052e27) : abi.encode(uint256(100e6 + i));
            // forge-lint: disable-next-line(unsafe-typecast)
            _decodes(r.outputs, r.field, res, isReserve ? int256(0.052e27) : int256(100e6 + i)); // i < 16
        }
    }

    function _decodes(bytes memory outputs, uint8[] memory field, bytes memory res, int256 value) internal view {
        (bool located, uint8 leaf,) = decoder.locate(outputs, field, res);
        assertTrue(located, "decoder: located");
        assertEq(leaf, T_UINT, "decoder: leaf");
        (bool ok, int256 v) = decoder.decodeAnswer(outputs, field, res);
        assertTrue(ok, "decoder: ok");
        assertEq(v, value, "decoder: value");
    }

    function _assertSpecEq(JobSpec memory a, JobSpec memory b) internal pure {
        assertEq(a.origin, b.origin, "origin");
        assertEq(a.reads.length, b.reads.length, "reads.length");
        for (uint256 i; i < a.reads.length; ++i) {
            _assertReadEq(a.reads[i], b.reads[i]);
        }
        assertEq(a.checks.length, b.checks.length, "checks.length");
        for (uint256 i; i < a.checks.length; ++i) {
            _assertBytesEq(a.checks[i].left, b.checks[i].left, "check.left");
            _assertBytesEq(a.checks[i].right, b.checks[i].right, "check.right");
            assertEq(uint8(a.checks[i].evaluation), uint8(b.checks[i].evaluation), "check.evaluation");
            assertEq(uint8(a.checks[i].operation), uint8(b.checks[i].operation), "check.operation");
            assertEq(a.checks[i].target, b.checks[i].target, "check.target");
        }
        _assertLogicEq(a.logic, b.logic);
        assertEq(uint8(a.allowedMutability), uint8(b.allowedMutability), "allowedMutability");
        assertEq(abi.encode(a), abi.encode(b), "description bytes");
    }

    function _assertReadEq(Read memory a, Read memory b) internal pure {
        assertEq(a.chainNamespace, b.chainNamespace, "read.chainNamespace");
        assertEq(a.chainId, b.chainId, "read.chainId");
        assertEq(a.minConfirmations, b.minConfirmations, "read.minConfirmations");
        assertEq(a.target, b.target, "read.target");
        assertEq(a.selector, b.selector, "read.selector");
        assertEq(a.args, b.args, "read.args");
        assertEq(a.outputs, b.outputs, "read.outputs");
        _assertBytesEq(a.field, b.field, "read.field");
        assertEq(uint8(a.at), uint8(b.at), "read.at");
    }

    function _assertLogicEq(Logic[] memory a, Logic[] memory b) internal pure {
        assertEq(a.length, b.length, "logic.length");
        for (uint256 i; i < a.length; ++i) {
            assertEq(uint8(a[i].kind), uint8(b[i].kind), "logic.kind");
            assertEq(a[i].k, b[i].k, "logic.k");
            assertEq(a[i].check, b[i].check, "logic.check");
            _assertBytesEq(a[i].children, b[i].children, "logic.children");
        }
    }

    function _assertBytesEq(uint8[] memory a, uint8[] memory b, string memory what) internal pure {
        assertEq(a.length, b.length, what);
        for (uint256 i; i < a.length; ++i) {
            assertEq(a[i], b[i], what);
        }
    }
}
