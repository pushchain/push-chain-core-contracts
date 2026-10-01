// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {UniversalMarketplaceEvaluation} from "../../src/agentic-commerce-8183/UniversalMarketplaceEvaluation.sol";
import {TemplateParts} from "./helpers/TemplateParts.sol";
import {IUniversalMarketplaceErrors} from "../../src/agentic-commerce-8183/interfaces/IUniversalMarketplace.sol";
import {
    IEvaluationMarket,
    Fill,
    FillSource,
    ReadTemplate,
    TargetSource,
    CheckTemplate,
    ParamBounds,
    EvaluationTemplate,
    BuildContext
} from "../../src/agentic-commerce-8183/interfaces/IUniversalMarketplaceEvaluation.sol";
import {
    EvalType,
    Op,
    NodeKind,
    Node,
    JobSpec,
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

/// @notice The marketplace views the evaluation contract reads. OBSERVER, NOT ORACLE: it answers chain
///         configuration the test sets; the CEA it returns is a deterministic stand-in derived from (agw, chain),
///         so a test can tell two chains' CEAs apart.
contract MockMarket is IEvaluationMarket {
    bytes32 public pushChainHash;
    mapping(bytes32 => bool) internal supported;

    constructor(bytes32 push) {
        pushChainHash = push;
    }

    function setSupported(bytes32 chainHash, bool on) external {
        supported[chainHash] = on;
    }

    function ceaDeployment(bytes32 chainHash) external view returns (address ceaFactory, address ceaProxyImpl) {
        if (supported[chainHash]) return (address(0xFAC7), address(0x1A1));
        return (address(0), address(0));
    }

    function expectedCEAOf(address agw, bytes32 chainHash) external view returns (address) {
        require(supported[chainHash], "MockMarket: unsupported");
        return ceaFor(agw, chainHash);
    }

    function ceaFor(address agw, bytes32 chainHash) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encode("cea", agw, chainHash)))));
    }
}

/// @notice Template builders shared by the evaluation and conformance suites.
abstract contract EvaluationFixtures is Test, TemplateParts {
    UniversalMarketplaceEvaluation internal evaluation;
    MockMarket internal market;

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
        evaluation = new UniversalMarketplaceEvaluation();
        market = new MockMarket(keccak256(bytes(string.concat("eip155:", Strings.toString(block.chainid)))));
        market.setSupported(ETH_HASH, true);
        market.setSupported(BASE_HASH, true);
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

    // ───────── calling the contract ─────────

    function _validate(EvaluationTemplate memory t) internal view {
        evaluation.validateTemplate(abi.encode(t), address(market));
    }

    function _expectInvalid(EvaluationTemplate memory t, string memory reason) internal {
        bytes memory enc = abi.encode(t);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.InvalidCard.selector, reason));
        evaluation.validateTemplate(enc, address(market));
    }

    function _ctx(uint256 principal, int256[] memory params) internal view returns (BuildContext memory) {
        return BuildContext({
            market: address(market),
            agw: AGW,
            principal: principal,
            executeBy: 1_800_000_000,
            settleWindow: 2 hours,
            params: params,
            origin: keccak256("origin")
        });
    }

    function _build(EvaluationTemplate memory t, BuildContext memory ctx) internal view returns (JobSpec memory) {
        return abi.decode(evaluation.build(abi.encode(t), ctx), (JobSpec));
    }

    function _noParams() internal pure returns (int256[] memory) {
        return new int256[](0);
    }

    function _oneParam(int256 v) internal pure returns (int256[] memory p) {
        p = new int256[](1);
        p[0] = v;
    }
}

/// @title UniversalMarketplaceEvaluation — unit suite (PRD 09 §7.2).
contract UniversalMarketplaceEvaluationTest is EvaluationFixtures {
    // ═════════════════════════════ valid templates ═════════════════════════════

    function test_ME01_validTemplates() public view {
        _validate(_lending());
        _validate(_swap());
        _validate(_either());
        _validate(_twoOfThree());
        _validate(_nested());
    }

    // ═════════════════════════════ sizes and params ═════════════════════════════

    function test_ME02_sizes() public {
        EvaluationTemplate memory t = _lending();
        t.reads = new ReadTemplate[](0);
        _expectInvalid(t, "eval: read count");

        t = _lending();
        t.checks = new CheckTemplate[](0);
        _expectInvalid(t, "eval: check count");

        t = _lending();
        t.nodes = new Node[](0);
        _expectInvalid(t, "eval: node count");

        t = _lending();
        t.params = new ParamBounds[](9);
        _expectInvalid(t, "eval: param count");

        // 17 reads / 17 checks / 33 nodes: built so every other rule would pass
        _expectInvalid(_wide(17, 16, 0), "eval: read count");
        _expectInvalid(_wide(16, 17, 0), "eval: check count");
        _expectInvalid(_wide(16, 16, 33), "eval: node count");

        // the boundaries pass: 16 reads, 16 checks, 32 nodes, 8 params
        EvaluationTemplate memory ok = _wide(16, 16, 32);
        ok.params = new ParamBounds[](8);
        _validate(ok);
    }

    /// @dev `nReads` CEA balance reads, `nChecks` CMP checks (check i reads read i % nReads), and a node tree of
    ///      `nNodes` (0 = the minimum: one root over every check). The root is AT_LEAST 1 over the CHECK nodes; any
    ///      extra nodes are chained ALL nodes so every node stays reachable and children stay above parents.
    function _wide(uint256 nReads, uint256 nChecks, uint256 nNodes)
        internal
        pure
        returns (EvaluationTemplate memory t)
    {
        t.reads = new ReadTemplate[](nReads);
        for (uint256 i; i < nReads; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            t.reads[i] = _balanceOfCEA("1", address(uint160(0x1000 + i))); // i < 17: a distinct small address
        }
        t.checks = new CheckTemplate[](nChecks);
        for (uint256 i; i < nChecks; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            t.checks[i] = _chk(uint8(i % nReads), EvalType.CMP, Op.GTE, TargetSource.FIXED, 1); // < 17 reads
        }
        uint256 extra = nNodes > nChecks + 1 ? nNodes - nChecks - 1 : 0;
        uint256 total = 1 + extra + nChecks;
        t.nodes = new Node[](total);
        // nodes[0 .. extra]: a chain of ALL nodes, each over the next; the last chain node holds the CHECK nodes
        for (uint256 i; i < extra; ++i) {
            uint8[] memory c = new uint8[](1);
            // forge-lint: disable-next-line(unsafe-typecast)
            c[0] = uint8(i + 1); // < 33 nodes
            t.nodes[i] = _parent(NodeKind.ALL, c, 0);
        }
        uint8[] memory leaves = new uint8[](nChecks > 16 ? 16 : nChecks);
        for (uint256 i; i < leaves.length; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            leaves[i] = uint8(extra + 1 + i); // < 33 nodes
        }
        t.nodes[extra] = _parent(NodeKind.AT_LEAST, leaves, 1);
        for (uint256 i; i < nChecks; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            t.nodes[extra + 1 + i] = _checkNode(uint8(i)); // < 17 checks
        }
        t.params = new ParamBounds[](0);
    }

    function test_ME03_paramBounds() public {
        EvaluationTemplate memory t = _swap();
        t.params[0] = ParamBounds({min: 2, max: 1});
        _expectInvalid(t, "eval: param bounds");
        t.params[0] = ParamBounds({min: 7, max: 7}); // a single allowed value is fine
        _validate(t);
    }

    // ═════════════════════════════ reads ═════════════════════════════

    function test_ME04_reads() public {
        EvaluationTemplate memory t = _lending();
        t.reads[0].chainNamespace = "solana";
        _expectInvalid(t, "eval: read namespace");

        string[4] memory badIds = ["", "1a", "-1", "123456789012345678901"];
        for (uint256 i; i < badIds.length; ++i) {
            t = _lending();
            t.reads[0].chainId = badIds[i];
            _expectInvalid(t, "eval: read chain id");
        }
        t = _lending();
        t.reads[0].chainId = "12345678901234567890"; // 20 digits: shape OK, then unsupported → cea chain
        _expectInvalid(t, "eval: cea chain");

        t = _lending();
        t.reads[0].chainId = Strings.toString(block.chainid); // Push itself
        _expectInvalid(t, "eval: read on push");

        t = _lending();
        t.reads[0].minConfirmations = 0;
        _expectInvalid(t, "eval: confirmations");

        t = _lending();
        t.reads[1].target = address(0);
        _expectInvalid(t, "eval: read target");

        t = _lending();
        t.reads[1].args = new bytes(31);
        _expectInvalid(t, "eval: args");
        t.reads[1].args = new bytes(544);
        _expectInvalid(t, "eval: args");
        t.reads[1].args = new bytes(512); // the boundary passes
        _validate(t);
    }

    function test_ME04b_fills() public {
        EvaluationTemplate memory t = _lending();
        t.reads[0].args = new bytes(160);
        t.reads[0].fills = new Fill[](5);
        for (uint8 i; i < 5; ++i) {
            t.reads[0].fills[i] = Fill({word: i, source: FillSource.CEA, param: 0});
        }
        _expectInvalid(t, "eval: fill count");

        t = _lending();
        t.reads[0].fills[0].word = 1; // args hold one word
        _expectInvalid(t, "eval: fill");

        t = _lending();
        t.reads[0].args = new bytes(64);
        t.reads[0].fills = new Fill[](2);
        t.reads[0].fills[0] = Fill({word: 0, source: FillSource.CEA, param: 0});
        t.reads[0].fills[1] = Fill({word: 0, source: FillSource.CEA, param: 0}); // same word twice
        _expectInvalid(t, "eval: fill");

        t = _lending();
        t.reads[0].fills[0].param = 1; // CEA fills take no param
        _expectInvalid(t, "eval: fill");

        t = _swap();
        t.reads[0].args = new bytes(64);
        t.reads[0].fills = new Fill[](2);
        t.reads[0].fills[0] = Fill({word: 0, source: FillSource.CEA, param: 0});
        t.reads[0].fills[1] = Fill({word: 1, source: FillSource.PARAM, param: 1}); // only param 0 exists
        _expectInvalid(t, "eval: fill");
        t.reads[0].fills[1].param = 0;
        _validate(t);

        t = _lending();
        market.setSupported(ETH_HASH, false); // a CEA fill on a chain with no CEA deployment
        _expectInvalid(t, "eval: cea chain");
    }

    // ═════════════════════════════ outputs and field ═════════════════════════════

    function _withOutputs(bytes memory outputs, uint8[] memory field)
        internal
        view
        returns (EvaluationTemplate memory t)
    {
        t = _lending();
        t.reads[1].outputs = outputs;
        t.reads[1].field = field;
    }

    function test_ME05_outputsWalker() public {
        _expectInvalid(_withOutputs("", _f(0)), "eval: outputs");
        _expectInvalid(_withOutputs(new bytes(257), _f(0)), "eval: outputs");
        _expectInvalid(_withOutputs(abi.encodePacked(T_UINT), _f(0)), "eval: outputs"); // top is not a TUPLE
        _expectInvalid(_withOutputs(abi.encodePacked(T_TUPLE, uint8(1), uint8(0)), _f(0)), "eval: outputs");
        _expectInvalid(_withOutputs(abi.encodePacked(T_TUPLE, uint8(1), uint8(11)), _f(0)), "eval: outputs");
        _expectInvalid(_withOutputs(abi.encodePacked(T_TUPLE, uint8(0)), _f(0)), "eval: outputs");
        _expectInvalid(_withOutputs(abi.encodePacked(T_TUPLE, uint8(33)), _f(0)), "eval: outputs");
        _expectInvalid(
            _withOutputs(abi.encodePacked(T_TUPLE, uint8(1), T_FIXED_ARRAY, uint8(0), T_UINT), _f2(0, 0)),
            "eval: outputs"
        );
        _expectInvalid(
            _withOutputs(abi.encodePacked(T_TUPLE, uint8(1), T_FIXED_ARRAY, uint8(33), T_UINT), _f2(0, 0)),
            "eval: outputs"
        );
        _expectInvalid(_withOutputs(abi.encodePacked(T_TUPLE, uint8(2), T_UINT), _f(0)), "eval: outputs"); // truncated
        _expectInvalid(_withOutputs(abi.encodePacked(T_TUPLE, uint8(1), T_UINT, T_UINT), _f(0)), "eval: outputs");
        _expectInvalid(_withOutputs(abi.encodePacked(T_TUPLE), _f(0)), "eval: outputs"); // count missing
        _expectInvalid(_withOutputs(abi.encodePacked(T_TUPLE, uint8(1), T_ARRAY), _f(0)), "eval: outputs");

        // depth: TUPLE + 7 nested ARRAYs + UINT = 9 levels is refused; one ARRAY fewer (8 levels) passes
        bytes memory deep = abi.encodePacked(T_TUPLE, uint8(1));
        for (uint256 i; i < 7; ++i) {
            deep = abi.encodePacked(deep, T_ARRAY);
        }
        _expectInvalid(_withOutputs(abi.encodePacked(deep, T_UINT), _f(0)), "eval: outputs");
        bytes memory ok = abi.encodePacked(T_TUPLE, uint8(1));
        for (uint256 i; i < 6; ++i) {
            ok = abi.encodePacked(ok, T_ARRAY);
        }
        _validate(_withOutputs(abi.encodePacked(ok, T_UINT), _f(0))); // field [0] → the outer array's length
    }

    function test_ME06_fieldPaths() public {
        bytes memory two = abi.encodePacked(T_TUPLE, uint8(2), T_UINT, T_TUPLE, uint8(2), T_BOOL, T_BYTES);
        _expectInvalid(_withOutputs(two, new uint8[](0)), "eval: field");
        _expectInvalid(_withOutputs(two, new uint8[](9)), "eval: field");
        _expectInvalid(_withOutputs(two, _f(2)), "eval: field"); // TUPLE index ≥ n
        _expectInvalid(_withOutputs(two, _f2(0, 0)), "eval: field"); // into a basic value
        _expectInvalid(_withOutputs(two, _f(1)), "eval: field"); // leaf is a TUPLE
        bytes memory fixedArr = abi.encodePacked(T_TUPLE, uint8(1), T_FIXED_ARRAY, uint8(3), T_UINT);
        _expectInvalid(_withOutputs(fixedArr, _f2(0, 3)), "eval: field"); // FIXED_ARRAY index ≥ k
        _expectInvalid(_withOutputs(fixedArr, _f(0)), "eval: field"); // leaf is a FIXED_ARRAY
        _validate(_withOutputs(fixedArr, _f2(0, 2)));

        // every reachable leaf type validates (each with a CMP check the type allows)
        _validate(_withOutputs(two, _f(0))); // UINT
        _validate(_leafCase(T_INT, Op.GTE));
        _validate(_leafCase(T_ADDRESS, Op.EQ));
        _validate(_leafCase(T_BYTESN, Op.NEQ));
        _validate(_leafCase(T_BYTES, Op.EQ));
        _validate(_leafCase(T_STRING, Op.EQ));
        // any ARRAY index is allowed: the evaluator decides at answer time
        _validate(_withOutputs(abi.encodePacked(T_TUPLE, uint8(1), T_ARRAY, T_UINT), _f2(0, 200)));
        _validate(_withOutputs(abi.encodePacked(T_TUPLE, uint8(1), T_ARRAY, T_UINT), _f(0))); // the length
        // BOOL leaf with a BOOL check
        EvaluationTemplate memory b = _withOutputs(two, _f2(1, 0));
        b.checks[1] = _chk(1, EvalType.BOOL, Op.EQ, TargetSource.FIXED, 1);
        _validate(b);
    }

    function _leafCase(uint8 code, Op op) internal view returns (EvaluationTemplate memory t) {
        t = _withOutputs(abi.encodePacked(T_TUPLE, uint8(1), code), _f(0));
        t.checks[1] = _chk(1, EvalType.CMP, op, TargetSource.FIXED, 1);
    }

    // ═════════════════════════════ checks ═════════════════════════════

    function test_ME07_checks() public {
        EvaluationTemplate memory t = _lending();
        t.checks[1].read = 2;
        _expectInvalid(t, "eval: check read");

        bytes memory boolOut = abi.encodePacked(T_TUPLE, uint8(1), T_BOOL);
        // BOOL: leaf must be bool, op EQ, FIXED, value 0/1
        t = _lending();
        t.checks[1] = _chk(1, EvalType.BOOL, Op.EQ, TargetSource.FIXED, 1); // reads[1] leaf is UINT
        _expectInvalid(t, "eval: check type");
        t = _withOutputs(boolOut, _f(0));
        t.checks[1] = _chk(1, EvalType.BOOL, Op.NEQ, TargetSource.FIXED, 1);
        _expectInvalid(t, "eval: check type");
        t.checks[1] = _chk(1, EvalType.BOOL, Op.EQ, TargetSource.FIXED, 2);
        _expectInvalid(t, "eval: check type");
        t.checks[1] = _chk(1, EvalType.BOOL, Op.EQ, TargetSource.PARAM, 0);
        _expectInvalid(t, "eval: check type");
        t.checks[1] = _chk(1, EvalType.BOOL, Op.EQ, TargetSource.FIXED, 0);
        _validate(t);

        // CMP: ordering ops only on numeric leaves
        t = _leafCase(T_ADDRESS, Op.GT);
        _expectInvalid(t, "eval: check type");
        t = _leafCase(T_STRING, Op.LTE);
        _expectInvalid(t, "eval: check type");
        // NUM / PCT: numeric leaves only
        t = _leafCase(T_BYTESN, Op.EQ);
        t.checks[1].evalType = EvalType.NUM;
        _expectInvalid(t, "eval: check type");
        t = _leafCase(T_BOOL, Op.EQ);
        t.checks[1].evalType = EvalType.PCT;
        _expectInvalid(t, "eval: check type");
        t = _leafCase(T_INT, Op.LT);
        t.checks[1].evalType = EvalType.PCT;
        _validate(t);

        // PRINCIPAL_BPS
        t = _lending();
        t.checks[0].evalType = EvalType.PCT;
        _expectInvalid(t, "eval: principal bps");
        t = _lending();
        t.checks[0].value = 0;
        _expectInvalid(t, "eval: principal bps");
        t.checks[0].value = 1_000_001;
        _expectInvalid(t, "eval: principal bps");
        t.checks[0].value = 1_000_000; // the boundary passes
        _validate(t);
        t = _leafCase(T_ADDRESS, Op.EQ);
        t.checks[1].source = TargetSource.PRINCIPAL_BPS;
        t.checks[1].value = 10_000;
        _expectInvalid(t, "eval: principal bps");

        // PARAM
        t = _swap();
        t.checks[0].value = 1;
        _expectInvalid(t, "eval: check param");
        t.checks[0].value = -1;
        _expectInvalid(t, "eval: check param");

        // CEA target: CMP, address leaf, EQ / NEQ, value 0, a chain with a CEA deployment
        t = _leafCase(T_ADDRESS, Op.EQ);
        t.checks[1].source = TargetSource.CEA;
        t.checks[1].value = 0;
        _validate(t);
        t.checks[1].op = Op.GT;
        _expectInvalid(t, "eval: check type"); // the leaf rule fires first
        t = _leafCase(T_ADDRESS, Op.NEQ);
        t.checks[1].source = TargetSource.CEA;
        t.checks[1].value = 1;
        _expectInvalid(t, "eval: check cea");
        t = _leafCase(T_UINT, Op.EQ);
        t.checks[1].source = TargetSource.CEA;
        _expectInvalid(t, "eval: check cea");
        t = _leafCase(T_ADDRESS, Op.EQ);
        t.checks[1].source = TargetSource.CEA;
        t.checks[1].evalType = EvalType.NUM; // NUM on an address leaf fails the type rule first
        _expectInvalid(t, "eval: check type");

        // a CEA target on a chain without a CEA deployment — every other CEA rule satisfied (value 0, CMP, EQ,
        // address leaf), so the chain rule is the one that fires
        t = _leafCase(T_ADDRESS, Op.EQ);
        t.reads[1].chainId = "10";
        t.checks[1].source = TargetSource.CEA;
        t.checks[1].value = 0;
        market.setSupported(keccak256("eip155:10"), false);
        _expectInvalid(t, "eval: check cea");
        market.setSupported(keccak256("eip155:10"), true); // the same template on a supported chain validates
        _validate(t);
    }

    // ═════════════════════════════ nodes and graph ═════════════════════════════

    function test_ME08_nodes() public {
        EvaluationTemplate memory t = _lending();
        t.nodes[1].check = 2;
        _expectInvalid(t, "eval: node");
        t = _lending();
        t.nodes[1].children = _kids(2, 2);
        _expectInvalid(t, "eval: node");
        t = _lending();
        t.nodes[1].k = 1;
        _expectInvalid(t, "eval: node");
        t = _lending();
        t.nodes[0].children = new uint8[](0);
        _expectInvalid(t, "eval: node");
        t = _lending();
        t.nodes[0].children = new uint8[](17);
        _expectInvalid(t, "eval: node");
        t = _lending();
        t.nodes[0].k = 1; // ALL takes no k
        _expectInvalid(t, "eval: node");
        t = _lending();
        t.nodes[0].kind = NodeKind.AT_LEAST;
        t.nodes[0].k = 0;
        _expectInvalid(t, "eval: node");
        t.nodes[0].k = 3;
        _expectInvalid(t, "eval: node");
        t.nodes[0].k = 2;
        _validate(t);

        // children: after the parent, inside the list, no repeats
        t = _lending();
        t.nodes[0].children = _kids(0, 2);
        _expectInvalid(t, "eval: node child");
        t = _lending();
        t.nodes[0].children = _kids(1, 3);
        _expectInvalid(t, "eval: node child");
        t = _lending();
        t.nodes[0].children = _kids(1, 1);
        _expectInvalid(t, "eval: node child");

        // unreachable node, unused check, unused read
        t = _lending();
        t.nodes[0].children = _f(1);
        _expectInvalid(t, "eval: unreachable node");
        t = _lending();
        t.nodes[2] = _checkNode(0); // check 1 no longer used
        _expectInvalid(t, "eval: unused check");
        t = _lending();
        t.checks[1].read = 0; // read 1 no longer used
        _expectInvalid(t, "eval: unused read");

        // a single CHECK root is a whole template
        _validate(_swap());
    }

    function test_ME09_jobSpecific() public {
        EvaluationTemplate memory t = _lending();
        t.reads[0].fills = new Fill[](0); // no CEA anywhere: says nothing about this user's job
        _expectInvalid(t, "eval: not job specific");

        // a CEA target alone makes it job specific
        t.reads[1].outputs = abi.encodePacked(T_TUPLE, uint8(1), T_ADDRESS);
        t.reads[1].field = _f(0);
        t.checks[1] = _chk(1, EvalType.CMP, Op.EQ, TargetSource.CEA, 0);
        _validate(t);

        // a CEA fill alone is enough too
        _validate(_lending());
    }

    function test_ME09b_malformedTemplate_reverts() public {
        // Not an abi-encoded EvaluationTemplate: the decode fails with no revert data. A bare expectRevert is the
        // only possible assertion; the property is that garbage never validates.
        vm.expectRevert();
        evaluation.validateTemplate(hex"deadbeef", address(market));
    }

    // ═════════════════════════════ build ═════════════════════════════

    function test_ME10_build_fills() public view {
        // one read on Ethereum and one on Base: each gets its own chain's CEA
        EvaluationTemplate memory t = _either();
        t.reads[1] = _balanceOfCEA("8453", WETH_BASE);
        t.checks[1] = _chk(1, EvalType.CMP, Op.GTE, TargetSource.FIXED, 1);
        JobSpec memory s = _build(t, _ctx(100e6, _noParams()));
        assertEq(s.reads[0].args, abi.encode(market.ceaFor(AGW, ETH_HASH)), "eth read: eth CEA");
        assertEq(s.reads[1].args, abi.encode(market.ceaFor(AGW, BASE_HASH)), "base read: base CEA");
        assertTrue(market.ceaFor(AGW, ETH_HASH) != market.ceaFor(AGW, BASE_HASH));

        // PARAM fills, positive and negative; untouched words keep their bytes
        EvaluationTemplate memory p = _swap();
        p.params[0] = ParamBounds({min: type(int256).min, max: type(int256).max});
        p.reads[0].args = abi.encode(uint256(7), uint256(0), uint256(9));
        p.reads[0].fills = new Fill[](2);
        p.reads[0].fills[0] = Fill({word: 1, source: FillSource.PARAM, param: 0});
        p.reads[0].fills[1] = Fill({word: 2, source: FillSource.CEA, param: 0});
        s = _build(p, _ctx(1, _oneParam(-5)));
        assertEq(s.reads[0].args, abi.encode(uint256(7), int256(-5), market.ceaFor(AGW, BASE_HASH)));
    }

    function test_ME11_build_targets() public view {
        // PRINCIPAL_BPS rounds down: 100_000_001 × 9999 / 10_000 = 99_990_000.9999 → 99_990_000
        JobSpec memory s = _build(_lending(), _ctx(100_000_001, _noParams()));
        assertEq(s.checks[0].target, 99_990_000);
        assertEq(s.checks[1].target, 0.04e27, "FIXED");
        s = _build(_lending(), _ctx(100e6, _noParams()));
        assertEq(s.checks[0].target, 99.99e6, "exact");

        s = _build(_swap(), _ctx(1, _oneParam(0.38e18)));
        assertEq(s.checks[0].target, 0.38e18, "PARAM");

        EvaluationTemplate memory t = _leafCase(T_ADDRESS, Op.EQ);
        t.checks[1].source = TargetSource.CEA;
        t.checks[1].value = 0;
        s = _build(t, _ctx(1, _noParams()));
        assertEq(s.checks[1].target, int256(uint256(uint160(market.ceaFor(AGW, ETH_HASH)))), "CEA");
    }

    function test_ME12_build_timingAndOrigin() public view {
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

    function test_ME13_build_errors() public {
        bytes memory swap = abi.encode(_swap());
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.ParamCountMismatch.selector, 1, 0));
        evaluation.build(swap, _ctx(1, _noParams()));

        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.ParamOutOfRange.selector, 0, int256(0)));
        evaluation.build(swap, _ctx(1, _oneParam(0)));
        vm.expectRevert(
            abi.encodeWithSelector(IUniversalMarketplaceErrors.ParamOutOfRange.selector, 0, int256(1e30 + 1))
        );
        evaluation.build(swap, _ctx(1, _oneParam(1e30 + 1)));
        evaluation.build(swap, _ctx(1, _oneParam(1))); // both bounds are inclusive
        evaluation.build(swap, _ctx(1, _oneParam(1e30)));

        // PRINCIPAL_BPS: the product principal × bps overflows. (Once it fits, the quotient is at most
        // uint256.max / 10_000, always inside int256 — so this is the one overflow there is.)
        EvaluationTemplate memory t = _lending();
        t.checks[0].value = 2;
        bytes memory enc = abi.encode(t);
        vm.expectRevert(abi.encodeWithSelector(IUniversalMarketplaceErrors.TargetOverflow.selector, 0));
        evaluation.build(enc, _ctx(2 ** 255, _noParams()));
        // the largest principal whose product fits builds
        uint256 largest = type(uint256).max / 2;
        JobSpec memory s = _build(t, _ctx(largest, _noParams()));
        assertEq(uint256(s.checks[0].target), largest * 2 / 10_000);
    }

    // ═════════════════════════════ fuzz ═════════════════════════════

    function testFuzz_ME14_build_inBoundsNeverReverts(uint256 principal, int256 minOut) public view {
        principal = bound(principal, 0, 2 ** 200);
        minOut = bound(minOut, 1, 1e30);
        JobSpec memory s = _build(_swap(), _ctx(principal, _oneParam(minOut)));
        assertEq(s.checks[0].target, minOut);
        _assertStructural(s);

        s = _build(_lending(), _ctx(principal, _noParams()));
        assertEq(uint256(s.checks[0].target), principal * 9999 / 10_000);
        _assertStructural(s);
    }

    function testFuzz_ME15_build_deterministic(uint256 principal, bytes32 origin) public view {
        principal = bound(principal, 0, 2 ** 200);
        BuildContext memory ctx = _ctx(principal, _noParams());
        ctx.origin = origin;
        bytes memory a = evaluation.build(abi.encode(_nested()), ctx);
        bytes memory b = evaluation.build(abi.encode(_nested()), ctx);
        assertEq(keccak256(a), keccak256(b));
    }

    /// @dev Random outputs / field bytes either validate or are refused with exactly "eval: outputs" or
    ///      "eval: field" — never a panic, never another error.
    function testFuzz_ME16_walker_namedErrorsOnly(bytes memory outputs, uint8 f0, uint8 f1, uint8 depth) public view {
        vm.assume(outputs.length <= 64);
        EvaluationTemplate memory t = _lending();
        t.reads[1].outputs = outputs;
        t.reads[1].field = depth % 2 == 0 ? _f(f0) : _f2(f0, f1);
        try evaluation.validateTemplate(abi.encode(t), address(market)) {}
        catch (bytes memory err) {
            bool named = keccak256(err)
                    == keccak256(
                        abi.encodeWithSelector(IUniversalMarketplaceErrors.InvalidCard.selector, "eval: outputs")
                    )
                || keccak256(err)
                    == keccak256(
                        abi.encodeWithSelector(IUniversalMarketplaceErrors.InvalidCard.selector, "eval: field")
                    )
                || keccak256(err)
                    == keccak256(
                        abi.encodeWithSelector(IUniversalMarketplaceErrors.InvalidCard.selector, "eval: check type")
                    );
            assertTrue(named, "walker raised something other than its named errors");
        }
    }

    /// @dev The structural rules the evaluator relies on, checked on the BUILT spec.
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
