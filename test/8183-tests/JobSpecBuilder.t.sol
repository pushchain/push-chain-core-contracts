// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";

import {TemplateParts} from "./helpers/TemplateParts.sol";
import {UniversalMarketplaceErrors} from "../../src/agentic-commerce-8183/libraries/Errors.sol";
import {JobSpecBuilder} from "../../src/agentic-commerce-8183/libraries/JobSpecBuilder.sol";
import {
    EvalType,
    Op,
    NodeKind,
    Node,
    JobSpec,
    T_TUPLE,
    T_ADDRESS
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {
    FillSource,
    Fill,
    ReadTemplate,
    TargetSource,
    CheckTemplate,
    ParamBounds,
    EvaluationTemplate,
    BuildContext
} from "../../src/agentic-commerce-8183/libraries/Types.sol";

/// @notice TEST ONLY: calls JobSpecBuilder the way the marketplace does. Under DELEGATECALL the library asks
///         `address(this)` (this harness) for CEAs, so the harness answers `expectedCEAOf` like a marketplace:
///         a deterministic stand-in per (agw, chain) for chains the test supports, `ChainNotSupported` otherwise.
contract JobSpecBuilderHarness {
    mapping(bytes32 => bool) internal supported;

    function setSupported(bytes32 chainHash, bool on) external {
        supported[chainHash] = on;
    }

    function build(bytes memory evaluation, BuildContext memory ctx) external view returns (bytes memory) {
        return JobSpecBuilder.build(evaluation, ctx);
    }

    function expectedCEAOf(address agw, bytes32 chainHash) external view returns (address) {
        if (!supported[chainHash]) revert UniversalMarketplaceErrors.ChainNotSupported(chainHash);
        return ceaFor(agw, chainHash);
    }

    function ceaFor(address agw, bytes32 chainHash) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encode("cea", agw, chainHash)))));
    }
}

/// @notice The V2 doc's templates and build helpers, shared by the builder and conformance suites.
abstract contract BuilderFixtures is Test, TemplateParts {
    JobSpecBuilderHarness internal builder;

    bytes32 internal constant ETH_HASH = keccak256("eip155:1");
    bytes32 internal constant BASE_HASH = keccak256("eip155:8453");

    address internal AGW = makeAddr("agw");
    address internal AUSDC_ETH = makeAddr("aUSDC.eth");
    address internal AAVE_POOL_ETH = makeAddr("AavePool.eth");
    address internal USDC_ETH = makeAddr("USDC.eth");
    address internal MORPHO_VAULT = makeAddr("MorphoVault.eth");
    address internal SPARK = makeAddr("Spark.eth");
    address internal WETH_BASE = makeAddr("WETH.base");

    function setUp() public virtual {
        builder = new JobSpecBuilderHarness();
        builder.setSupported(ETH_HASH, true);
        builder.setSupported(BASE_HASH, true);
    }

    // ───────── the V2 doc's templates ─────────

    /// @dev "Deposit into Aave v3 on Ethereum at ≥ 4%": deposited ≥ 99.99% of principal AND rate ≥ 4% (ray).
    function _lending() internal view returns (EvaluationTemplate memory t) {
        t.reads = new ReadTemplate[](2);
        t.reads[0] = _balanceOfCEA("1", AUSDC_ETH);
        t.reads[1] =
            _read("1", AAVE_POOL_ETH, GET_RESERVE_DATA, abi.encode(USDC_ETH), _noFills(), _reserveDataOut(), _f2(0, 2));
        t.checks = new CheckTemplate[](2);
        t.checks[0] = _chk(0, EvalType.CMP, Op.GTE, TargetSource.PRINCIPAL_BPS, 9999);
        t.checks[1] = _chk(1, EvalType.CMP, Op.GTE, TargetSource.FIXED, 0.04e27);
        t.nodes = new Node[](3);
        t.nodes[0] = _parent(NodeKind.ALL, _kids(1, 2), 0);
        t.nodes[1] = _checkNode(0);
        t.nodes[2] = _checkNode(1);
        t.params = new ParamBounds[](0);
    }

    /// @dev "The CEA receives at least minOut WETH on Base": one NUM check, `minOut` is the user's param 0.
    function _swap() internal view returns (EvaluationTemplate memory t) {
        t.reads = new ReadTemplate[](1);
        t.reads[0] = _balanceOfCEA("8453", WETH_BASE);
        t.reads[0].minConfirmations = 3;
        t.checks = new CheckTemplate[](1);
        t.checks[0] = _chk(0, EvalType.NUM, Op.GTE, TargetSource.PARAM, 0);
        t.nodes = new Node[](1);
        t.nodes[0] = _checkNode(0);
        t.params = new ParamBounds[](1);
        t.params[0] = ParamBounds({min: 1, max: 1e30});
    }

    /// @dev "Aave OR Morpho": ANY over two CMP checks.
    function _either() internal view returns (EvaluationTemplate memory t) {
        t.reads = new ReadTemplate[](2);
        t.reads[0] = _balanceOfCEA("1", AUSDC_ETH);
        t.reads[1] = _read("1", MORPHO_VAULT, MAX_WITHDRAW, new bytes(32), _ceaFill(0), _uintOut(), _f(0));
        t.checks = new CheckTemplate[](2);
        t.checks[0] = _chk(0, EvalType.CMP, Op.GTE, TargetSource.PRINCIPAL_BPS, 9999);
        t.checks[1] = _chk(1, EvalType.CMP, Op.GTE, TargetSource.PRINCIPAL_BPS, 9999);
        t.nodes = new Node[](3);
        t.nodes[0] = _parent(NodeKind.ANY, _kids(1, 2), 0);
        t.nodes[1] = _checkNode(0);
        t.nodes[2] = _checkNode(1);
        t.params = new ParamBounds[](0);
    }

    /// @dev "At least 2 of Aave, Morpho, Spark".
    function _twoOfThree() internal view returns (EvaluationTemplate memory t) {
        t.reads = new ReadTemplate[](3);
        t.reads[0] = _balanceOfCEA("1", AUSDC_ETH);
        t.reads[1] = _read("1", MORPHO_VAULT, MAX_WITHDRAW, new bytes(32), _ceaFill(0), _uintOut(), _f(0));
        t.reads[2] = _balanceOfCEA("1", SPARK);
        t.checks = new CheckTemplate[](3);
        for (uint8 i; i < 3; ++i) {
            t.checks[i] = _chk(i, EvalType.CMP, Op.GTE, TargetSource.FIXED, 99.99e6);
        }
        t.nodes = new Node[](4);
        t.nodes[0] = _parent(NodeKind.AT_LEAST, _kids3(1, 2, 3), 2);
        t.nodes[1] = _checkNode(0);
        t.nodes[2] = _checkNode(1);
        t.nodes[3] = _checkNode(2);
        t.params = new ParamBounds[](0);
    }

    /// @dev "(Aave deposited AND Aave ≥ 4%) OR (Morpho deposited AND Morpho rate ≥ 4%)".
    function _nested() internal view returns (EvaluationTemplate memory t) {
        t.reads = new ReadTemplate[](4);
        t.reads[0] = _balanceOfCEA("1", AUSDC_ETH);
        t.reads[1] =
            _read("1", AAVE_POOL_ETH, GET_RESERVE_DATA, abi.encode(USDC_ETH), _noFills(), _reserveDataOut(), _f2(0, 2));
        t.reads[2] = _read("1", MORPHO_VAULT, MAX_WITHDRAW, new bytes(32), _ceaFill(0), _uintOut(), _f(0));
        t.reads[3] = _read("1", MORPHO_VAULT, bytes4(keccak256("supplyRate()")), "", _noFills(), _uintOut(), _f(0));
        t.checks = new CheckTemplate[](4);
        t.checks[0] = _chk(0, EvalType.CMP, Op.GTE, TargetSource.FIXED, 99.99e6);
        t.checks[1] = _chk(1, EvalType.CMP, Op.GTE, TargetSource.FIXED, 0.04e27);
        t.checks[2] = _chk(2, EvalType.CMP, Op.GTE, TargetSource.FIXED, 99.99e6);
        t.checks[3] = _chk(3, EvalType.CMP, Op.GTE, TargetSource.FIXED, 0.04e18);
        t.nodes = new Node[](7);
        t.nodes[0] = _parent(NodeKind.ANY, _kids(1, 2), 0);
        t.nodes[1] = _parent(NodeKind.ALL, _kids(3, 4), 0);
        t.nodes[2] = _parent(NodeKind.ALL, _kids(5, 6), 0);
        t.nodes[3] = _checkNode(0);
        t.nodes[4] = _checkNode(1);
        t.nodes[5] = _checkNode(2);
        t.nodes[6] = _checkNode(3);
        t.params = new ParamBounds[](0);
    }

    // ───────── building ─────────

    function _ctx(uint256 principal, int256[] memory params) internal view returns (BuildContext memory) {
        return BuildContext({
            agw: AGW,
            principal: principal,
            executeBy: 1_800_000_000,
            settleWindow: 2 hours,
            params: params,
            origin: keccak256("origin")
        });
    }

    function _build(EvaluationTemplate memory t, BuildContext memory ctx) internal view returns (JobSpec memory) {
        return abi.decode(builder.build(abi.encode(t), ctx), (JobSpec));
    }

    function _noParams() internal pure returns (int256[] memory) {
        return new int256[](0);
    }

    function _oneParam(int256 v) internal pure returns (int256[] memory p) {
        p = new int256[](1);
        p[0] = v;
    }
}

/// @title JobSpecBuilder — unit suite.
contract JobSpecBuilderTest is BuilderFixtures {
    /// @dev `positionManager.ownerOf(1234) == CEA` on Ethereum: a CEA-target check, and no CEA fill.
    function _ownerIsCEA() internal pure returns (EvaluationTemplate memory t) {
        t.reads = new ReadTemplate[](1);
        t.reads[0] = _read(
            "1",
            address(0x9051),
            bytes4(keccak256("ownerOf(uint256)")),
            abi.encode(uint256(1234)),
            _noFills(),
            abi.encodePacked(T_TUPLE, uint8(1), T_ADDRESS),
            _f(0)
        );
        t.checks = new CheckTemplate[](1);
        t.checks[0] = _chk(0, EvalType.CMP, Op.EQ, TargetSource.CEA, 0);
        t.nodes = new Node[](1);
        t.nodes[0] = _checkNode(0);
        t.params = new ParamBounds[](0);
    }

    function test_JB01_fills() public view {
        // one read on Ethereum and one on Base: each gets its own chain's CEA
        EvaluationTemplate memory t = _either();
        t.reads[1] = _balanceOfCEA("8453", WETH_BASE);
        t.checks[1] = _chk(1, EvalType.CMP, Op.GTE, TargetSource.FIXED, 1);
        JobSpec memory s = _build(t, _ctx(100e6, _noParams()));
        assertEq(s.reads[0].args, abi.encode(builder.ceaFor(AGW, ETH_HASH)), "eth read: eth CEA");
        assertEq(s.reads[1].args, abi.encode(builder.ceaFor(AGW, BASE_HASH)), "base read: base CEA");
        assertTrue(builder.ceaFor(AGW, ETH_HASH) != builder.ceaFor(AGW, BASE_HASH));

        // PARAM fills, positive and negative; untouched words keep their bytes
        EvaluationTemplate memory p = _swap();
        p.params[0] = ParamBounds({min: type(int256).min, max: type(int256).max});
        p.reads[0].args = abi.encode(uint256(7), uint256(0), uint256(9));
        p.reads[0].fills = new Fill[](2);
        p.reads[0].fills[0] = Fill({word: 1, source: FillSource.PARAM, param: 0});
        p.reads[0].fills[1] = Fill({word: 2, source: FillSource.CEA, param: 0});
        s = _build(p, _ctx(1, _oneParam(-5)));
        assertEq(s.reads[0].args, abi.encode(uint256(7), int256(-5), builder.ceaFor(AGW, BASE_HASH)));
    }

    function test_JB02_targets() public view {
        // PRINCIPAL_BPS rounds down: 100_000_001 × 9999 / 10_000 = 99_990_000.9999 → 99_990_000
        JobSpec memory s = _build(_lending(), _ctx(100_000_001, _noParams()));
        assertEq(s.checks[0].target, 99_990_000);
        assertEq(s.checks[1].target, 0.04e27, "FIXED");
        s = _build(_lending(), _ctx(100e6, _noParams()));
        assertEq(s.checks[0].target, 99.99e6, "exact");

        s = _build(_swap(), _ctx(1, _oneParam(0.38e18)));
        assertEq(s.checks[0].target, 0.38e18, "PARAM");

        s = _build(_ownerIsCEA(), _ctx(1, _noParams()));
        assertEq(s.checks[0].target, int256(uint256(uint160(builder.ceaFor(AGW, ETH_HASH)))), "CEA");
        assertEq(s.reads[0].args, abi.encode(uint256(1234)), "a read without fills is copied as is");
    }

    function test_JB03_timingAndOrigin() public view {
        EvaluationTemplate memory t = _nested();
        JobSpec memory s = _build(t, _ctx(100e6, _noParams()));
        assertEq(s.executeBy, 1_800_000_000);
        assertEq(s.failFinalAt, 1_800_000_000 + 2 hours);
        assertEq(s.origin, keccak256("origin"));
        assertEq(keccak256(abi.encode(s.nodes)), keccak256(abi.encode(t.nodes)), "nodes verbatim");
        for (uint256 i; i < t.reads.length; ++i) {
            assertEq(s.reads[i].chainNamespace, t.reads[i].chainNamespace);
            assertEq(s.reads[i].chainId, t.reads[i].chainId);
            assertEq(s.reads[i].minConfirmations, t.reads[i].minConfirmations);
            assertEq(s.reads[i].target, t.reads[i].target);
            assertEq(s.reads[i].selector, t.reads[i].selector);
            assertEq(s.reads[i].outputs, t.reads[i].outputs);
            assertEq(keccak256(abi.encode(s.reads[i].field)), keccak256(abi.encode(t.reads[i].field)));
        }
        for (uint256 i; i < t.checks.length; ++i) {
            assertEq(s.checks[i].read, t.checks[i].read);
            assertEq(uint8(s.checks[i].evalType), uint8(t.checks[i].evalType));
            assertEq(uint8(s.checks[i].op), uint8(t.checks[i].op));
        }
    }

    function test_JB04_params() public {
        bytes memory swap = abi.encode(_swap());
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.ParamCountMismatch.selector, 1, 0));
        builder.build(swap, _ctx(1, _noParams()));

        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.ParamOutOfRange.selector, 0, int256(0)));
        builder.build(swap, _ctx(1, _oneParam(0)));
        vm.expectRevert(
            abi.encodeWithSelector(UniversalMarketplaceErrors.ParamOutOfRange.selector, 0, int256(1e30 + 1))
        );
        builder.build(swap, _ctx(1, _oneParam(1e30 + 1)));
        builder.build(swap, _ctx(1, _oneParam(1))); // both bounds are inclusive
        builder.build(swap, _ctx(1, _oneParam(1e30)));
    }

    function test_JB05_targetOverflow() public {
        // PRINCIPAL_BPS: the product principal × bps overflows. (Once it fits, the quotient is at most
        // uint256.max / 10_000, always inside int256: this is the one overflow there is.)
        EvaluationTemplate memory t = _lending();
        t.checks[0].value = 2;
        bytes memory enc = abi.encode(t);
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.TargetOverflow.selector, 0));
        builder.build(enc, _ctx(2 ** 255, _noParams()));
        // the largest principal whose product fits builds
        uint256 largest = type(uint256).max / 2;
        JobSpec memory s = _build(t, _ctx(largest, _noParams()));
        assertEq(uint256(s.checks[0].target), largest * 2 / 10_000);
    }

    function test_JB06_fillOutOfBounds() public {
        // a fill on the last word builds; one word further does not, whatever its source
        EvaluationTemplate memory t = _swap();
        t.reads[0].args = new bytes(64);
        t.reads[0].fills[0].word = 1;
        _build(t, _ctx(1, _oneParam(1)));

        t.reads[0].fills[0].word = 2;
        bytes memory enc = abi.encode(t);
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.FillOutOfBounds.selector, 0, 0));
        builder.build(enc, _ctx(1, _oneParam(1)));

        t = _swap();
        t.reads[0].fills = new Fill[](2);
        t.reads[0].fills[0] = Fill({word: 0, source: FillSource.CEA, param: 0});
        t.reads[0].fills[1] = Fill({word: 1, source: FillSource.PARAM, param: 0}); // args are one word long
        enc = abi.encode(t);
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.FillOutOfBounds.selector, 0, 1));
        builder.build(enc, _ctx(1, _oneParam(1)));
    }

    function test_JB07_ceaOnUnsupportedChain() public {
        bytes32 polygon = keccak256("eip155:137");
        EvaluationTemplate memory t = _swap();
        t.reads[0].chainId = "137"; // a CEA fill on a chain without a CEA deployment
        bytes memory enc = abi.encode(t);
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.ChainNotSupported.selector, polygon));
        builder.build(enc, _ctx(1, _oneParam(1)));

        t = _ownerIsCEA();
        t.reads[0].chainId = "137"; // a CEA target on such a chain
        enc = abi.encode(t);
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.ChainNotSupported.selector, polygon));
        builder.build(enc, _ctx(1, _noParams()));

        // no CEA anywhere: no chain is asked, so an unsupported chain is fine
        t = _ownerIsCEA();
        t.reads[0].chainId = "137";
        t.checks[0] = _chk(0, EvalType.CMP, Op.EQ, TargetSource.FIXED, 7);
        _build(t, _ctx(1, _noParams()));
    }

    /// @dev The builder does not judge criteria: a template the evaluator could not run (an unread read, an
    ///      unreachable node, outputs that are not types) still builds, copied as given.
    function test_JB08_doesNotJudgeTheTemplate() public view {
        EvaluationTemplate memory t = _lending();
        ReadTemplate[] memory reads = new ReadTemplate[](3);
        (reads[0], reads[1]) = (t.reads[0], t.reads[1]);
        reads[2] = _read("1", SPARK, BALANCE_OF, "", _noFills(), hex"ff00", new uint8[](0));
        t.reads = reads;
        Node[] memory nodes = new Node[](4);
        (nodes[0], nodes[1], nodes[2]) = (t.nodes[0], t.nodes[1], t.nodes[2]);
        nodes[3] = _checkNode(1); // reached by nobody
        t.nodes = nodes;
        JobSpec memory s = _build(t, _ctx(100e6, _noParams()));
        assertEq(s.reads.length, 3);
        assertEq(s.reads[2].outputs, hex"ff00");
        assertEq(s.nodes.length, 4);
    }

    function test_JB09_malformedTemplate_reverts() public {
        // Not an abi-encoded EvaluationTemplate: the decode fails with no revert data. A bare expectRevert is the
        // only possible assertion.
        vm.expectRevert();
        builder.build(hex"deadbeef", _ctx(1, _noParams()));
    }

    // ═════════════════════════════ fuzz ═════════════════════════════

    function testFuzz_JB10_inBoundsNeverReverts(uint256 principal, int256 minOut) public view {
        principal = bound(principal, 0, 2 ** 200);
        minOut = bound(minOut, 1, 1e30);
        JobSpec memory s = _build(_swap(), _ctx(principal, _oneParam(minOut)));
        assertEq(s.checks[0].target, minOut);
        _assertStructural(s);

        s = _build(_lending(), _ctx(principal, _noParams()));
        assertEq(uint256(s.checks[0].target), principal * 9999 / 10_000);
        _assertStructural(s);
    }

    function testFuzz_JB11_deterministic(uint256 principal, bytes32 origin) public view {
        principal = bound(principal, 0, 2 ** 200);
        BuildContext memory ctx = _ctx(principal, _noParams());
        ctx.origin = origin;
        bytes memory a = builder.build(abi.encode(_nested()), ctx);
        bytes memory b = builder.build(abi.encode(_nested()), ctx);
        assertEq(keccak256(a), keccak256(b));
    }

    /// @dev The structural rules the evaluator relies on, checked on the BUILT spec of a well-formed template.
    function _assertStructural(JobSpec memory s) internal pure {
        for (uint256 i; i < s.checks.length; ++i) {
            assertLt(s.checks[i].read, s.reads.length);
        }
        for (uint256 i; i < s.nodes.length; ++i) {
            for (uint256 j; j < s.nodes[i].children.length; ++j) {
                assertGt(s.nodes[i].children[j], i);
                assertLt(s.nodes[i].children[j], s.nodes.length);
            }
        }
    }
}
