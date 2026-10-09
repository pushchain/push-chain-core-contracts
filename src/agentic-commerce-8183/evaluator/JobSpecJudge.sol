// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Check, Node, EvalType, Op, NodeKind} from "../libraries/JobSpecTypes.sol";
import {Answer, Verdict} from "./EvaluationTypes.sol";

/// @title JobSpecJudge — a job's verdict from its answers
/// @notice Every check comes out PASS, FAIL or UNKNOWN; nodes combine them; the root is the verdict.
/// @dev - Rules are the V2 design's:
///        BOOL `after == target` · CMP `after op target` · NUM `(after - before) op target` ·
///        PCT: the change in basis points, `(after - before) * 10_000 / before op target`, and PCT with
///        `before <= 0` FAILS.
///      - PCT is compared exactly, as `(after - before) * 10_000 op target * before` (`before > 0` keeps the
///        direction). Dividing first would round toward zero, so a tiny loss would read as 0 and pass `>= 0`.
///      - Never reverts on any answer: an overflow makes the check UNKNOWN.
///      - Assumes `JobSpecRules.validate` passed, so indexes are in range and children come after parents.
library JobSpecJudge {
    uint8 internal constant UNKNOWN = 0;
    uint8 internal constant PASS = 1;
    uint8 internal constant FAIL = 2;

    /// @notice The verdict, unpacked: the readable reference judge. The evaluator runs `verdictPacked`; the test
    ///         suite checks the two agree on random inputs (`testFuzz_JDG02_packedEqualsReference`). Not called
    ///         on-chain, so it adds no bytecode.
    /// @param checks  The job's checks.
    /// @param nodes   The job's pass logic; `nodes[0]` is the root.
    /// @param afters  The round's answer for each read.
    /// @param befores The snapshot answer for each read (only read for NUM / PCT checks).
    function verdict(Check[] memory checks, Node[] memory nodes, Answer[] memory afters, Answer[] memory befores)
        internal
        pure
        returns (Verdict)
    {
        uint8[] memory checkRes = new uint8[](checks.length);
        for (uint256 i; i < checks.length; ++i) {
            Check memory c = checks[i];
            checkRes[i] = checkResult(c, afters[c.read], befores[c.read]);
        }

        uint8[] memory nodeRes = new uint8[](nodes.length);
        for (uint256 i = nodes.length; i > 0; --i) {
            nodeRes[i - 1] = _node(nodes[i - 1], nodeRes, checkRes);
        }

        uint8 root = nodeRes[0];
        if (root == PASS) return Verdict.PASS;
        if (root == FAIL) return Verdict.FAIL;
        return Verdict.INCONCLUSIVE;
    }

    /// @notice One check: PASS, FAIL or UNKNOWN.
    function checkResult(Check memory c, Answer memory a, Answer memory b) internal pure returns (uint8) {
        if (!a.ok) return UNKNOWN;
        if (c.evalType == EvalType.BOOL) return a.value == c.target ? PASS : FAIL;
        if (c.evalType == EvalType.CMP) return _cmp(a.value, c.op, c.target) ? PASS : FAIL;

        if (!b.ok) return UNKNOWN;
        (bool ok, int256 delta) = _sub(a.value, b.value);
        if (!ok) return UNKNOWN;
        if (c.evalType == EvalType.NUM) return _cmp(delta, c.op, c.target) ? PASS : FAIL;

        // PCT, in basis points, compared without dividing
        if (b.value <= 0) return FAIL;
        (bool okL, int256 lhs) = _mul(delta, 10_000);
        (bool okR, int256 rhs) = _mul(c.target, b.value);
        if (!okL || !okR) return UNKNOWN;
        return _cmp(lhs, c.op, rhs) ? PASS : FAIL;
    }

    /// @dev One node from its already-decided children.
    function _node(Node memory n, uint8[] memory nodeRes, uint8[] memory checkRes) private pure returns (uint8) {
        if (n.kind == NodeKind.CHECK) return checkRes[n.check];

        uint256 total = n.children.length;
        uint256 pass;
        uint256 fail;
        for (uint256 j; j < total; ++j) {
            uint8 r = nodeRes[n.children[j]];
            if (r == PASS) ++pass;
            else if (r == FAIL) ++fail;
        }
        uint256 need = n.kind == NodeKind.ALL ? total : n.kind == NodeKind.ANY ? 1 : n.k;
        if (pass >= need) return PASS; // enough passed
        if (total - fail < need) return FAIL; // not enough left that could pass
        return UNKNOWN;
    }

    // ───────────────────────────── packed form ─────────────────────────────
    //
    // The evaluator judges each check as its read's answer arrives, so the last callback only walks the tree.
    // Check results: 2 bits per check (UNKNOWN 0, PASS 1, FAIL 2), check i at bits [2i, 2i+1], in a uint32.
    // Nodes: 64 bits per node, 4 per word, node i at bits [64·(i%4), +64) of word i/4:
    //   bits 0-7 kind · 8-15 check · 16-23 k · 24-55 children as a bitmask (bit j: node j is a child).

    /// @notice Packs `nodes` into words of four. Assumes `JobSpecRules.validate` passed (at most 32 nodes).
    function packNodes(Node[] memory nodes) internal pure returns (uint256[] memory words) {
        words = new uint256[]((nodes.length + 3) / 4);
        for (uint256 i; i < nodes.length; ++i) {
            Node memory n = nodes[i];
            uint256 mask;
            for (uint256 j; j < n.children.length; ++j) {
                mask |= uint256(1) << n.children[j];
            }
            uint256 packed = uint256(uint8(n.kind)) | (uint256(n.check) << 8) | (uint256(n.k) << 16) | (mask << 24);
            words[i / 4] |= packed << (64 * (i % 4));
        }
    }

    /// @notice Sets check `index`'s result in `checkRes`.
    function setCheck(uint32 checkRes, uint256 index, uint8 result) internal pure returns (uint32) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return checkRes | uint32(uint256(result) << (2 * index)); // safe: index < 16, so the shift stays below 32
    }

    /// @notice The verdict from packed nodes and packed check results.
    function verdictPacked(uint256[] memory words, uint256 nNodes, uint32 checkRes) internal pure returns (Verdict) {
        uint256 nodeRes; // 2 bits per node, as checkRes
        for (uint256 i = nNodes; i > 0; --i) {
            uint256 idx = i - 1;
            uint256 packed = (words[idx / 4] >> (64 * (idx % 4))) & type(uint64).max;
            // The casts below pick one byte out of the packed node (layout above): dropping the rest is the intent.
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8 kind = uint8(packed);
            uint8 r;
            if (kind == uint8(NodeKind.CHECK)) {
                // forge-lint: disable-next-line(unsafe-typecast)
                r = uint8((uint256(checkRes) >> (2 * uint8(packed >> 8))) & 3);
            } else {
                uint256 mask = (packed >> 24) & type(uint32).max;
                uint256 total;
                uint256 pass;
                uint256 fail;
                for (uint256 j = idx + 1; j < nNodes; ++j) {
                    if (mask & (uint256(1) << j) == 0) continue;
                    ++total;
                    uint256 c = (nodeRes >> (2 * j)) & 3;
                    if (c == PASS) ++pass;
                    else if (c == FAIL) ++fail;
                }
                // forge-lint: disable-next-line(unsafe-typecast)
                uint256 need = kind == uint8(NodeKind.ALL) ? total : kind == uint8(NodeKind.ANY) ? 1 : uint8(packed >> 16);
                r = pass >= need ? PASS : total - fail < need ? FAIL : UNKNOWN;
            }
            nodeRes |= uint256(r) << (2 * idx);
        }
        uint256 root = nodeRes & 3;
        if (root == PASS) return Verdict.PASS;
        if (root == FAIL) return Verdict.FAIL;
        return Verdict.INCONCLUSIVE;
    }

    /// @dev `a * b`, or not-ok on overflow.
    function _mul(int256 a, int256 b) private pure returns (bool, int256) {
        if (a == 0 || b == 0) return (true, 0);
        if ((a == -1 && b == type(int256).min) || (b == -1 && a == type(int256).min)) return (false, 0);
        unchecked {
            int256 c = a * b;
            if (c / b != a) return (false, 0);
            return (true, c);
        }
    }

    /// @dev `a - b`, or not-ok on overflow.
    function _sub(int256 a, int256 b) private pure returns (bool, int256) {
        unchecked {
            int256 c = a - b;
            if ((b > 0 && c > a) || (b < 0 && c < a)) return (false, 0);
            return (true, c);
        }
    }

    function _cmp(int256 x, Op op, int256 y) private pure returns (bool) {
        if (op == Op.EQ) return x == y;
        if (op == Op.NEQ) return x != y;
        if (op == Op.GT) return x > y;
        if (op == Op.GTE) return x >= y;
        if (op == Op.LT) return x < y;
        return x <= y;
    }
}
