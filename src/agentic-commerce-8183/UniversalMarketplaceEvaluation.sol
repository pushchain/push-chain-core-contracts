// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUniversalMarketplaceErrors} from "./interfaces/IUniversalMarketplace.sol";
import {
    IUniversalMarketplaceEvaluation,
    IEvaluationMarket,
    Fill,
    FillSource,
    ReadTemplate,
    TargetSource,
    CheckTemplate,
    ParamBounds,
    EvaluationTemplate,
    BuildContext
} from "./interfaces/IUniversalMarketplaceEvaluation.sol";
import {
    EvalType,
    Op,
    NodeKind,
    Node,
    Read,
    Check,
    JobSpec,
    T_UINT,
    T_INT,
    T_BOOL,
    T_ADDRESS,
    T_STRING,
    T_TUPLE,
    T_ARRAY,
    T_FIXED_ARRAY,
    MAX_READS,
    MAX_CHECKS,
    MAX_NODES
} from "./libraries/JobSpecTypes.sol";

/// @title UniversalMarketplaceEvaluation
/// @notice The evaluation side of an agent card: validates a card's `EvaluationTemplate` at registration, and
///         builds each job's `JobSpec` (the `createJob` description) from it at `startJob`.
/// @dev - Stateless and not upgradeable. A rule change is a new deployment and a marketplace upgrade that points at it.
///      - Split out of UniversalMarketplace for EIP-170, like UniversalMarketplaceTerms.
///      - Reverts with IUniversalMarketplaceErrors, so a revert bubbles through the marketplace with the selector
///        its callers expect. Every registration refusal is `InvalidCard("eval: …")`.
///      - The `outputs` / `field` rules mirror the V2 evaluator's decoder (`_locate`), so every built read is one
///        the evaluator can decode.
contract UniversalMarketplaceEvaluation is IUniversalMarketplaceEvaluation, IUniversalMarketplaceErrors {
    uint256 internal constant MAX_PARAMS = 8;
    uint256 internal constant MAX_FILLS = 4;
    uint256 internal constant MAX_ARGS = 512;
    uint256 internal constant MAX_OUTPUTS = 256;
    uint256 internal constant MAX_DEPTH = 8;
    uint256 internal constant MAX_FIELD = 8;
    uint256 internal constant MAX_COMPOSITE = 32;
    uint256 internal constant MAX_CHILDREN = 16;
    uint256 internal constant MAX_CHAIN_ID_DIGITS = 20;
    int256 internal constant MAX_PRINCIPAL_BPS = 1_000_000;
    uint256 internal constant BPS = 10_000;

    // ═════════════════════════════════ validate ═════════════════════════════════

    /// @inheritdoc IUniversalMarketplaceEvaluation
    /// @dev Order: sizes → reads → checks → nodes → graph (reachability, used checks, used reads) → job specific.
    function validateTemplate(bytes calldata evaluation, address market) external view {
        EvaluationTemplate memory t = abi.decode(evaluation, (EvaluationTemplate));
        _validateSizes(t);

        IEvaluationMarket m = IEvaluationMarket(market);
        bytes32 push = m.pushChainHash();
        uint256 nReads = t.reads.length;
        uint8[] memory leaves = new uint8[](nReads);
        bool jobSpecific;
        for (uint256 i; i < nReads; ++i) {
            bool ceaFill;
            (leaves[i], ceaFill) = _validateRead(t.reads[i], t.params.length, m, push);
            jobSpecific = jobSpecific || ceaFill;
        }

        bool[] memory readUsed = new bool[](nReads);
        for (uint256 j; j < t.checks.length; ++j) {
            CheckTemplate memory c = t.checks[j];
            if (c.read >= nReads) revert InvalidCard("eval: check read");
            bool ceaTarget = _validateCheck(c, leaves[c.read], t.params.length);
            if (ceaTarget && !_hasCEADeployment(m, _chainHash(t.reads[c.read]))) revert InvalidCard("eval: check cea");
            readUsed[c.read] = true;
            jobSpecific = jobSpecific || ceaTarget;
        }

        _validateNodes(t.nodes, t.checks.length);
        _validateGraph(t.nodes, t.checks.length);
        for (uint256 i; i < nReads; ++i) {
            if (!readUsed[i]) revert InvalidCard("eval: unused read");
        }
        if (!jobSpecific) revert InvalidCard("eval: not job specific");
    }

    /// @dev Template-level caps and param bounds.
    function _validateSizes(EvaluationTemplate memory t) internal pure {
        if (t.reads.length == 0 || t.reads.length > MAX_READS) revert InvalidCard("eval: read count");
        if (t.checks.length == 0 || t.checks.length > MAX_CHECKS) revert InvalidCard("eval: check count");
        if (t.nodes.length == 0 || t.nodes.length > MAX_NODES) revert InvalidCard("eval: node count");
        if (t.params.length > MAX_PARAMS) revert InvalidCard("eval: param count");
        for (uint256 i; i < t.params.length; ++i) {
            if (t.params[i].min > t.params[i].max) revert InvalidCard("eval: param bounds");
        }
    }

    /// @dev One read: chain, call shape, fills, return types. Returns the leaf type `field` selects, and whether
    ///      the read carries a CEA fill (which makes the template job specific).
    function _validateRead(ReadTemplate memory r, uint256 nParams, IEvaluationMarket m, bytes32 push)
        internal
        view
        returns (uint8 leaf, bool ceaFill)
    {
        if (keccak256(bytes(r.chainNamespace)) != keccak256("eip155")) revert InvalidCard("eval: read namespace");
        if (!_isChainId(bytes(r.chainId))) revert InvalidCard("eval: read chain id");
        bytes32 chainHash = _chainHash(r);
        if (chainHash == push) revert InvalidCard("eval: read on push");
        if (r.minConfirmations == 0) revert InvalidCard("eval: confirmations");
        if (r.target == address(0)) revert InvalidCard("eval: read target");
        if (r.args.length % 32 != 0 || r.args.length > MAX_ARGS) revert InvalidCard("eval: args");

        ceaFill = _validateFills(r.fills, r.args.length, nParams);
        if (ceaFill && !_hasCEADeployment(m, chainHash)) revert InvalidCard("eval: cea chain");

        _validateOutputs(r.outputs);
        leaf = _leafOf(r.outputs, r.field);
    }

    /// @dev Fills: at most four, each inside `args`, no word twice; CEA takes no param, PARAM names a real param.
    function _validateFills(Fill[] memory fills, uint256 argsLength, uint256 nParams)
        internal
        pure
        returns (bool ceaFill)
    {
        if (fills.length > MAX_FILLS) revert InvalidCard("eval: fill count");
        for (uint256 i; i < fills.length; ++i) {
            Fill memory f = fills[i];
            if (32 * uint256(f.word) + 32 > argsLength) revert InvalidCard("eval: fill");
            for (uint256 j; j < i; ++j) {
                if (fills[j].word == f.word) revert InvalidCard("eval: fill");
            }
            if (f.source == FillSource.CEA) {
                if (f.param != 0) revert InvalidCard("eval: fill");
                ceaFill = true;
            } else if (f.param >= nParams) {
                revert InvalidCard("eval: fill");
            }
        }
    }

    /// @dev One check's type and target rules. Returns whether its target is the CEA.
    function _validateCheck(CheckTemplate memory c, uint8 leaf, uint256 nParams) internal pure returns (bool) {
        if (!_typeAllows(c, leaf)) revert InvalidCard("eval: check type");
        if (c.source == TargetSource.PRINCIPAL_BPS) {
            bool numericCmp = c.evalType == EvalType.CMP || c.evalType == EvalType.NUM;
            if (!numericCmp || !_isNumeric(leaf) || c.value < 1 || c.value > MAX_PRINCIPAL_BPS) {
                revert InvalidCard("eval: principal bps");
            }
        } else if (c.source == TargetSource.PARAM) {
            if (c.value < 0 || uint256(c.value) >= nParams) revert InvalidCard("eval: check param");
        } else if (c.source == TargetSource.CEA) {
            if (c.evalType != EvalType.CMP || leaf != T_ADDRESS || c.value != 0) revert InvalidCard("eval: check cea");
            return true;
        }
        return false;
    }

    /// @dev The evaluation type against the selected value's type.
    ///      - BOOL: a bool, compared with EQ to a FIXED 0 or 1.
    ///      - CMP: any value; addresses, bytesN, bytes and strings only with EQ / NEQ.
    ///      - NUM / PCT: integers or an array's length.
    function _typeAllows(CheckTemplate memory c, uint8 leaf) internal pure returns (bool) {
        if (c.evalType == EvalType.BOOL) {
            return leaf == T_BOOL && c.op == Op.EQ && c.source == TargetSource.FIXED && (c.value == 0 || c.value == 1);
        }
        if (c.evalType == EvalType.CMP) {
            bool equality = c.op == Op.EQ || c.op == Op.NEQ;
            return _isNumeric(leaf) || leaf == T_BOOL || equality;
        }
        return _isNumeric(leaf);
    }

    function _isNumeric(uint8 leaf) internal pure returns (bool) {
        return leaf == T_UINT || leaf == T_INT || leaf == T_ARRAY;
    }

    /// @dev Per-node shape, and children strictly after the parent, inside the list, without repeats.
    function _validateNodes(Node[] memory nodes, uint256 nChecks) internal pure {
        for (uint256 i; i < nodes.length; ++i) {
            Node memory n = nodes[i];
            uint256 kids = n.children.length;
            if (n.kind == NodeKind.CHECK) {
                if (n.check >= nChecks || kids != 0 || n.k != 0) revert InvalidCard("eval: node");
                continue;
            }
            if (kids == 0 || kids > MAX_CHILDREN) revert InvalidCard("eval: node");
            bool kValid = n.kind == NodeKind.AT_LEAST ? (n.k >= 1 && n.k <= kids) : n.k == 0;
            if (!kValid) revert InvalidCard("eval: node");
            for (uint256 j; j < kids; ++j) {
                uint256 c = n.children[j];
                if (c <= i || c >= nodes.length) revert InvalidCard("eval: node child");
                for (uint256 q; q < j; ++q) {
                    if (n.children[q] == c) revert InvalidCard("eval: node child");
                }
            }
        }
    }

    /// @dev Every non-root node is somebody's child, and every check is some CHECK node's.
    function _validateGraph(Node[] memory nodes, uint256 nChecks) internal pure {
        bool[] memory reached = new bool[](nodes.length);
        bool[] memory checkUsed = new bool[](nChecks);
        for (uint256 i; i < nodes.length; ++i) {
            Node memory n = nodes[i];
            if (n.kind == NodeKind.CHECK) checkUsed[n.check] = true;
            for (uint256 j; j < n.children.length; ++j) {
                reached[n.children[j]] = true;
            }
        }
        for (uint256 i = 1; i < nodes.length; ++i) {
            if (!reached[i]) revert InvalidCard("eval: unreachable node");
        }
        for (uint256 i; i < nChecks; ++i) {
            if (!checkUsed[i]) revert InvalidCard("eval: unused check");
        }
    }

    // ───────── return types (`outputs`) and the path into them (`field`) ─────────

    /// @dev 1-256 bytes, a TUPLE at the top, and every byte consumed by exactly one well-formed type.
    function _validateOutputs(bytes memory types) internal pure {
        if (types.length == 0 || types.length > MAX_OUTPUTS || uint8(types[0]) != T_TUPLE) {
            revert InvalidCard("eval: outputs");
        }
        if (_skip(types, 0, 1) != types.length) revert InvalidCard("eval: outputs");
    }

    /// @dev The position right after the type starting at `t`, checking it on the way. `depth` counts this type's
    ///      own level, the top TUPLE being 1; depth above MAX_DEPTH is refused, which also bounds the recursion.
    function _skip(bytes memory types, uint256 t, uint256 depth) internal pure returns (uint256) {
        if (depth > MAX_DEPTH || t >= types.length) revert InvalidCard("eval: outputs");
        uint8 code = uint8(types[t]);
        if (code >= T_UINT && code <= T_STRING) return t + 1;
        if (code == T_ARRAY) return _skip(types, t + 1, depth + 1);
        if (code != T_TUPLE && code != T_FIXED_ARRAY) revert InvalidCard("eval: outputs");

        if (t + 1 >= types.length) revert InvalidCard("eval: outputs");
        uint256 n = uint8(types[t + 1]);
        if (n == 0 || n > MAX_COMPOSITE) revert InvalidCard("eval: outputs");
        if (code == T_FIXED_ARRAY) return _skip(types, t + 2, depth + 1);
        uint256 c = t + 2;
        for (uint256 j; j < n; ++j) {
            c = _skip(types, c, depth + 1);
        }
        return c;
    }

    /// @dev Walks `field` through `types` exactly as the evaluator's `_locate` does, and returns the leaf's code.
    ///      The leaf must be a value the evaluator can turn into a number: never a TUPLE or a FIXED_ARRAY.
    ///      `types` has already passed `_validateOutputs`.
    function _leafOf(bytes memory types, uint8[] memory field) internal pure returns (uint8 leaf) {
        if (field.length == 0 || field.length > MAX_FIELD) revert InvalidCard("eval: field");
        uint256 t;
        for (uint256 i; i < field.length; ++i) {
            uint8 code = uint8(types[t]);
            uint256 idx = field[i];
            if (code == T_TUPLE) {
                if (idx >= uint8(types[t + 1])) revert InvalidCard("eval: field");
                uint256 c = t + 2;
                for (uint256 j; j < idx; ++j) {
                    c = _skip(types, c, 1);
                }
                t = c;
            } else if (code == T_ARRAY) {
                t = t + 1; // any index: the array's length is only known from the answer
            } else if (code == T_FIXED_ARRAY) {
                if (idx >= uint8(types[t + 1])) revert InvalidCard("eval: field");
                t = t + 2;
            } else {
                revert InvalidCard("eval: field"); // a basic value has nothing inside it
            }
        }
        leaf = uint8(types[t]);
        if (leaf == T_TUPLE || leaf == T_FIXED_ARRAY) revert InvalidCard("eval: field");
    }

    // ───────── helpers ─────────

    /// @dev 1-20 ASCII digits.
    function _isChainId(bytes memory id) internal pure returns (bool) {
        if (id.length == 0 || id.length > MAX_CHAIN_ID_DIGITS) return false;
        for (uint256 i; i < id.length; ++i) {
            if (id[i] < 0x30 || id[i] > 0x39) return false;
        }
        return true;
    }

    /// @dev keccak256 of the read's CAIP-2 string, the key of the marketplace's CEA deployments.
    function _chainHash(ReadTemplate memory r) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(r.chainNamespace, ":", r.chainId));
    }

    function _hasCEADeployment(IEvaluationMarket m, bytes32 chainHash) internal view returns (bool) {
        (address ceaFactory,) = m.ceaDeployment(chainHash);
        return ceaFactory != address(0);
    }

    // ═════════════════════════════════ build ═════════════════════════════════

    /// @inheritdoc IUniversalMarketplaceEvaluation
    function build(bytes calldata evaluation, BuildContext calldata ctx) external view returns (bytes memory) {
        EvaluationTemplate memory t = abi.decode(evaluation, (EvaluationTemplate));
        _checkParams(t.params, ctx.params);

        JobSpec memory spec;
        spec.executeBy = uint64(ctx.executeBy);
        spec.failFinalAt = uint64(ctx.executeBy) + ctx.settleWindow;
        spec.origin = ctx.origin;
        spec.nodes = t.nodes;

        uint256 nReads = t.reads.length;
        address[] memory cea = new address[](nReads); // per read, computed at most once
        spec.reads = new Read[](nReads);
        for (uint256 i; i < nReads; ++i) {
            spec.reads[i] = _buildRead(t.reads[i], ctx, cea, i);
        }
        spec.checks = new Check[](t.checks.length);
        for (uint256 j; j < t.checks.length; ++j) {
            spec.checks[j] = _buildCheck(t.checks[j], j, t.reads, ctx, cea);
        }
        return abi.encode(spec);
    }

    /// @dev One per template param, each inside its inclusive bounds.
    function _checkParams(ParamBounds[] memory bounds, int256[] calldata params) internal pure {
        if (params.length != bounds.length) revert ParamCountMismatch(bounds.length, params.length);
        for (uint256 i; i < params.length; ++i) {
            if (params[i] < bounds[i].min || params[i] > bounds[i].max) revert ParamOutOfRange(i, params[i]);
        }
    }

    /// @dev The template read, with its fills written into a fresh copy of `args`.
    function _buildRead(ReadTemplate memory r, BuildContext calldata ctx, address[] memory cea, uint256 i)
        internal
        view
        returns (Read memory out)
    {
        bytes memory args = bytes.concat(r.args); // a copy: the template stays untouched
        for (uint256 f; f < r.fills.length; ++f) {
            Fill memory fill = r.fills[f];
            bytes32 word = fill.source == FillSource.CEA
                ? bytes32(uint256(uint160(_ceaOf(r, ctx, cea, i))))
                : bytes32(uint256(ctx.params[fill.param]));
            uint256 at = 32 * uint256(fill.word);
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                mstore(add(add(args, 0x20), at), word)
            }
        }
        out = Read({
            chainNamespace: r.chainNamespace,
            chainId: r.chainId,
            minConfirmations: r.minConfirmations,
            target: r.target,
            selector: r.selector,
            args: args,
            outputs: r.outputs,
            field: r.field
        });
    }

    /// @dev The check with its target resolved.
    function _buildCheck(
        CheckTemplate memory c,
        uint256 j,
        ReadTemplate[] memory reads,
        BuildContext calldata ctx,
        address[] memory cea
    ) internal view returns (Check memory) {
        int256 target = c.value;
        if (c.source == TargetSource.PRINCIPAL_BPS) {
            // bps ≤ 1e6, so once the product fits uint256 the quotient is far below int256's maximum.
            uint256 bps = uint256(c.value);
            if (ctx.principal > type(uint256).max / bps) revert TargetOverflow(j);
            // forge-lint: disable-next-line(unsafe-typecast)
            target = int256((ctx.principal * bps) / BPS); // ≤ uint256.max / 10_000 < int256.max: cannot truncate
        } else if (c.source == TargetSource.PARAM) {
            target = ctx.params[uint256(c.value)];
        } else if (c.source == TargetSource.CEA) {
            target = int256(uint256(uint160(_ceaOf(reads[c.read], ctx, cea, c.read))));
        }
        return Check({read: c.read, evalType: c.evalType, op: c.op, target: target});
    }

    /// @dev The AGW's CEA on read `i`'s chain, asked of the marketplace once per read.
    function _ceaOf(ReadTemplate memory r, BuildContext calldata ctx, address[] memory cea, uint256 i)
        internal
        view
        returns (address)
    {
        if (cea[i] == address(0)) cea[i] = IEvaluationMarket(ctx.market).expectedCEAOf(ctx.agw, _chainHash(r));
        return cea[i];
    }
}
