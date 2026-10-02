// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {
    EvalType,
    Op,
    NodeKind,
    Node,
    Read,
    Check,
    JobSpec,
    T_UINT,
    T_ADDRESS,
    T_TUPLE
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {BuilderFixtures} from "./JobSpecBuilder.t.sol";
import {V2Decoder} from "./helpers/V2Decoder.sol";
import {BuildContext} from "../../src/agentic-commerce-8183/libraries/Types.sol";

/// @title UniversalMarketplace — conformance with the Universal Evaluator V2 design (PRD 09 §7.5)
/// @notice What the marketplace builds must be exactly what the V2 doc's examples write by hand, and every read it
///         builds must decode in the V2 evaluator's decoder.
contract UniversalMarketplaceConformanceTest is BuilderFixtures {
    V2Decoder internal decoder;

    uint64 internal executeBy;
    uint64 internal failFinalAt;

    function setUp() public override {
        super.setUp();
        decoder = new V2Decoder();
        executeBy = uint64(block.timestamp + 1 hours); // the doc's times
        failFinalAt = uint64(block.timestamp + 2 hours);
    }

    // ═════════════════════════════ the doc's specs, built by the marketplace ═════════════════════════════

    function test_MC01_lendingExample_equalsV2Doc() public view {
        JobSpec memory built = _build(_lending(), _docCtx(100e6, _noParams()));
        address cea = builder.ceaFor(AGW, ETH_HASH);

        Read[] memory reads = new Read[](2);
        reads[0] = _docRead("1", 12, AUSDC_ETH, BALANCE_OF, abi.encode(cea), _docUintOutputs(), _f(0));
        reads[1] =
            _docRead("1", 12, AAVE_POOL_ETH, GET_RESERVE_DATA, abi.encode(USDC_ETH), _docReserveOutputs(), _f2(0, 2));
        Check[] memory checks = new Check[](2);
        checks[0] = Check({read: 0, evalType: EvalType.CMP, op: Op.GTE, target: 99.99e6});
        checks[1] = Check({read: 1, evalType: EvalType.CMP, op: Op.GTE, target: 0.04e27});
        Node[] memory nodes = new Node[](3);
        nodes[0] = Node({kind: NodeKind.ALL, check: 0, children: _kids(1, 2), k: 0});
        nodes[1] = Node({kind: NodeKind.CHECK, check: 0, children: new uint8[](0), k: 0});
        nodes[2] = Node({kind: NodeKind.CHECK, check: 1, children: new uint8[](0), k: 0});

        _assertSpecEq(built, _docSpec(reads, checks, nodes));
    }

    function test_MC02_swapExample_equalsV2Doc() public view {
        JobSpec memory built = _build(_swap(), _docCtx(0, _oneParam(0.38e18)));
        address cea = builder.ceaFor(AGW, BASE_HASH);

        Read[] memory reads = new Read[](1);
        reads[0] = _docRead("8453", 3, WETH_BASE, BALANCE_OF, abi.encode(cea), _docUintOutputs(), _f(0));
        Check[] memory checks = new Check[](1);
        checks[0] = Check({read: 0, evalType: EvalType.NUM, op: Op.GTE, target: 0.38e18});
        Node[] memory nodes = new Node[](1);
        nodes[0] = Node({kind: NodeKind.CHECK, check: 0, children: new uint8[](0), k: 0});

        _assertSpecEq(built, _docSpec(reads, checks, nodes));
    }

    function test_MC03_orAndAtLeastExamples() public view {
        address cea = builder.ceaFor(AGW, ETH_HASH);

        // ANY: "Aave or Morpho", spelled out in full in the doc.
        JobSpec memory either = _build(_either(), _docCtx(100e6, _noParams()));
        Read[] memory reads = new Read[](2);
        reads[0] = _docRead("1", 12, AUSDC_ETH, BALANCE_OF, abi.encode(cea), _docUintOutputs(), _f(0));
        reads[1] = _docRead("1", 12, MORPHO_VAULT, MAX_WITHDRAW, abi.encode(cea), _docUintOutputs(), _f(0));
        Check[] memory checks = new Check[](2);
        checks[0] = Check({read: 0, evalType: EvalType.CMP, op: Op.GTE, target: 99.99e6});
        checks[1] = Check({read: 1, evalType: EvalType.CMP, op: Op.GTE, target: 99.99e6});
        Node[] memory nodes = new Node[](3);
        nodes[0] = Node({kind: NodeKind.ANY, check: 0, children: _kids(1, 2), k: 0});
        nodes[1] = Node({kind: NodeKind.CHECK, check: 0, children: new uint8[](0), k: 0});
        nodes[2] = Node({kind: NodeKind.CHECK, check: 1, children: new uint8[](0), k: 0});
        _assertSpecEq(either, _docSpec(reads, checks, nodes));

        // Nested: the doc draws the tree only. ANY(ALL(3,4), ALL(5,6)), CHECK i on checks[i].
        JobSpec memory nested = _build(_nested(), _docCtx(100e6, _noParams()));
        Node[] memory tree = new Node[](7);
        tree[0] = Node({kind: NodeKind.ANY, check: 0, children: _kids(1, 2), k: 0});
        tree[1] = Node({kind: NodeKind.ALL, check: 0, children: _kids(3, 4), k: 0});
        tree[2] = Node({kind: NodeKind.ALL, check: 0, children: _kids(5, 6), k: 0});
        for (uint8 i; i < 4; ++i) {
            tree[3 + i] = Node({kind: NodeKind.CHECK, check: i, children: new uint8[](0), k: 0});
        }
        _assertNodesEq(nested.nodes, tree);

        // AT_LEAST: "at least 2 of 3", each ≥ 99.99 USDC.
        JobSpec memory twoOfThree = _build(_twoOfThree(), _docCtx(300e6, _noParams()));
        Node[] memory atLeast = new Node[](4);
        atLeast[0] = Node({kind: NodeKind.AT_LEAST, check: 0, children: _kids3(1, 2, 3), k: 2});
        for (uint8 i; i < 3; ++i) {
            atLeast[1 + i] = Node({kind: NodeKind.CHECK, check: i, children: new uint8[](0), k: 0});
            assertEq(twoOfThree.checks[i].target, 99.99e6, "AT_LEAST: target");
        }
        _assertNodesEq(twoOfThree.nodes, atLeast);
    }

    // ═════════════════════════════ the reference decoder reads what the builder writes ═════════════════════════════

    /// @dev Every read the marketplace builds for the doc's examples decodes in the V2 decoder.
    function test_MC04_referenceDecoder_agrees() public view {
        _assertBuiltReadsDecode(_build(_lending(), _docCtx(100e6, _noParams())));
        _assertBuiltReadsDecode(_build(_swap(), _docCtx(0, _oneParam(0.38e18))));
        _assertBuiltReadsDecode(_build(_either(), _docCtx(100e6, _noParams())));
        _assertBuiltReadsDecode(_build(_twoOfThree(), _docCtx(300e6, _noParams())));
        _assertBuiltReadsDecode(_build(_nested(), _docCtx(100e6, _noParams())));
    }

    // ═════════════════════════════ the doc's spellings ═════════════════════════════

    /// @dev The doc's times: execute within 1 h, FAIL final 1 h later.
    function _docCtx(uint256 principal, int256[] memory params) internal view returns (BuildContext memory ctx) {
        ctx = _ctx(principal, params);
        // forge-lint: disable-next-line(unsafe-typecast)
        ctx.executeBy = uint48(executeBy); // now + 1 h
        // forge-lint: disable-next-line(unsafe-typecast)
        ctx.settleWindow = uint32(failFinalAt - executeBy); // 1 h
    }

    function _docSpec(Read[] memory reads, Check[] memory checks, Node[] memory nodes)
        internal
        view
        returns (JobSpec memory)
    {
        return JobSpec({
            executeBy: executeBy,
            failFinalAt: failFinalAt,
            reads: reads,
            checks: checks,
            nodes: nodes,
            origin: keccak256("origin")
        });
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
            field: field
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
        assertEq(a.executeBy, b.executeBy, "executeBy");
        assertEq(a.failFinalAt, b.failFinalAt, "failFinalAt");
        assertEq(a.origin, b.origin, "origin");
        assertEq(a.reads.length, b.reads.length, "reads.length");
        for (uint256 i; i < a.reads.length; ++i) {
            _assertReadEq(a.reads[i], b.reads[i]);
        }
        assertEq(a.checks.length, b.checks.length, "checks.length");
        for (uint256 i; i < a.checks.length; ++i) {
            assertEq(a.checks[i].read, b.checks[i].read, "check.read");
            assertEq(uint8(a.checks[i].evalType), uint8(b.checks[i].evalType), "check.evalType");
            assertEq(uint8(a.checks[i].op), uint8(b.checks[i].op), "check.op");
            assertEq(a.checks[i].target, b.checks[i].target, "check.target");
        }
        _assertNodesEq(a.nodes, b.nodes);
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
    }

    function _assertNodesEq(Node[] memory a, Node[] memory b) internal pure {
        assertEq(a.length, b.length, "nodes.length");
        for (uint256 i; i < a.length; ++i) {
            assertEq(uint8(a[i].kind), uint8(b[i].kind), "node.kind");
            assertEq(a[i].check, b[i].check, "node.check");
            assertEq(a[i].k, b[i].k, "node.k");
            _assertBytesEq(a[i].children, b[i].children, "node.children");
        }
    }

    function _assertBytesEq(uint8[] memory a, uint8[] memory b, string memory what) internal pure {
        assertEq(a.length, b.length, what);
        for (uint256 i; i < a.length; ++i) {
            assertEq(a[i], b[i], what);
        }
    }
}
