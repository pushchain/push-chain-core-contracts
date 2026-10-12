// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {
    JobSpec,
    Read,
    Check,
    Node,
    EvalType,
    Op,
    NodeKind,
    MAX_READS,
    MAX_CHECKS,
    MAX_NODES
} from "../libraries/JobSpecTypes.sol";
import {Answer, Verdict, MAX_ARGS_LENGTH, MAX_CHAIN_STRING_LENGTH} from "./EvaluationTypes.sol";
import {EvmReadLib} from "./EvmReadLib.sol";
import {JobSpecErrors} from "../libraries/Errors.sol";

/// @title JobSpecLib — what a `JobSpec` must satisfy, and how it is judged
/// @notice Internal functions, compiled into the UniversalEvaluator.
/// @dev Checking (`validate`, run when the spec is frozen inside `fund`, so a refused spec reverts the funding):
///      - Structural checks only. Whether the criteria mean what the client wants is not checkable here.
///      - `executeBy` and `failFinalAt` are not checked: the evaluator does not use them (the end blocks are fixed at
///        `submit`, and a FAIL there is final).
///      - Every rule is one the evaluator relies on, so a funded job can always be judged: indexes are in range,
///        nodes form a graph evaluable from last to first, every read is one the evaluator can encode and decodes in
///        bounded work, and every node, check and read counts toward the verdict.
///      Judging (every check comes out PASS, FAIL or UNKNOWN; nodes combine them; the root is the verdict):
///      - Rules are the V2 design's:
///        BOOL `after == target` · CMP `after op target` · NUM `(after - before) op target` ·
///        PCT: the change in basis points, `(after - before) * 10_000 / before op target`, and PCT with
///        `before <= 0` FAILS.
///      - PCT is compared exactly, as `(after - before) * 10_000 op target * before` (`before > 0` keeps the
///        direction). Dividing first would round toward zero, so a tiny loss would read as 0 and pass `>= 0`.
///      - Never reverts on any answer: an overflow makes the check UNKNOWN.
///      - The readable, unpacked reference judge lives in the tests (`helpers/ReferenceJudge.sol`); the suite checks
///        `verdictPacked` agrees with it on random inputs.
library JobSpecLib {
    /// @notice A check's or a node's result.
    uint8 internal constant UNKNOWN = 0;
    uint8 internal constant PASS = 1;
    uint8 internal constant FAIL = 2;

    // ───────────────────────────── checking ─────────────────────────────

    /// @notice Reverts with a `JobSpecErrors` error unless `s` can be judged.
    /// @param s                The criteria.
    /// @param maxConfirmations The evaluator's ceiling on `Read.minConfirmations`, so every read can be answered.
    function validate(JobSpec memory s, uint256 maxConfirmations) internal pure {
        uint256 nReads = s.reads.length;
        uint256 nChecks = s.checks.length;
        uint256 nNodes = s.nodes.length;
        if (nReads == 0 || nReads > MAX_READS) revert JobSpecErrors.ReadCount(nReads);
        if (nChecks == 0 || nChecks > MAX_CHECKS) revert JobSpecErrors.CheckCount(nChecks);
        if (nNodes == 0 || nNodes > MAX_NODES) revert JobSpecErrors.NodeCount(nNodes);

        for (uint256 i; i < nReads; ++i) {
            Read memory r = s.reads[i];
            uint256 nsLen = bytes(r.chainNamespace).length;
            uint256 idLen = bytes(r.chainId).length;
            if (nsLen == 0 || idLen == 0 || nsLen > MAX_CHAIN_STRING_LENGTH || idLen > MAX_CHAIN_STRING_LENGTH) {
                revert JobSpecErrors.ReadChain(i);
            }
            // Requests are encoded as EVM calls only; another namespace needs its own encoder first.
            if (keccak256(bytes(r.chainNamespace)) != EvmReadLib.EVM_NAMESPACE_HASH) {
                revert JobSpecErrors.ReadChain(i);
            }
            if (r.minConfirmations == 0 || r.minConfirmations > maxConfirmations) {
                revert JobSpecErrors.ReadConfirmations(i);
            }
            if (r.target == address(0)) revert JobSpecErrors.ReadTarget(i);
            if (r.args.length > MAX_ARGS_LENGTH) revert JobSpecErrors.ReadArgs(i);
            if (!EvmReadLib.isValidShape(r.outputs, r.field)) revert JobSpecErrors.ReadShape(i);
        }

        for (uint256 i; i < nChecks; ++i) {
            Check memory c = s.checks[i];
            if (c.read >= nReads) revert JobSpecErrors.CheckRead(i);
            if (c.evalType == EvalType.BOOL) {
                if (c.op != Op.EQ) revert JobSpecErrors.CheckOp(i); // BOOL is `after == target`
                if (c.target != 0 && c.target != 1) revert JobSpecErrors.CheckTarget(i);
            }
        }

        for (uint256 i; i < nNodes; ++i) {
            if (!_nodeOk(s.nodes[i], i, nNodes, nChecks)) revert JobSpecErrors.NodeShape(i);
        }
        _requireAllUsed(s);
    }

    /// @dev Everything counts toward the verdict: every node is reachable from the root, every check is used by a
    ///      reachable CHECK node, every read by a used check. Nothing is paid for or shown without affecting payment.
    ///      Children come after their parents (`_nodeOk`), so one forward pass finds every reachable node. A node may
    ///      have several parents; that changes nothing in the verdict.
    function _requireAllUsed(JobSpec memory s) private pure {
        uint256 reached = 1; // the root
        uint256 usedChecks;
        for (uint256 i; i < s.nodes.length; ++i) {
            if ((reached >> i) & 1 == 0) revert JobSpecErrors.NodeUnreachable(i);
            Node memory n = s.nodes[i];
            if (n.kind == NodeKind.CHECK) {
                usedChecks |= uint256(1) << n.check;
            } else {
                for (uint256 j; j < n.children.length; ++j) {
                    reached |= uint256(1) << n.children[j];
                }
            }
        }
        uint256 usedReads;
        for (uint256 i; i < s.checks.length; ++i) {
            if ((usedChecks >> i) & 1 == 0) revert JobSpecErrors.CheckUnused(i);
            usedReads |= uint256(1) << s.checks[i].read;
        }
        for (uint256 i; i < s.reads.length; ++i) {
            if ((usedReads >> i) & 1 == 0) revert JobSpecErrors.ReadUnused(i);
        }
    }

    /// @notice Which reads the "before" snapshot needs: every read used by a NUM or PCT check.
    /// @return need  `need[i]` is true when read `i` is snapshotted.
    /// @return count How many reads are snapshotted.
    function snapshotReads(JobSpec memory s) internal pure returns (bool[] memory need, uint256 count) {
        need = new bool[](s.reads.length);
        for (uint256 i; i < s.checks.length; ++i) {
            Check memory c = s.checks[i];
            if ((c.evalType == EvalType.NUM || c.evalType == EvalType.PCT) && !need[c.read]) {
                need[c.read] = true;
                ++count;
            }
        }
    }

    /// @dev - CHECK: a check in range, no children.
    ///      - ALL / ANY / AT_LEAST: one or more children, strictly increasing, each after this node and in range,
    ///        so the tree is acyclic and no child is counted twice.
    ///      - AT_LEAST: `1 <= k <= children`.
    function _nodeOk(Node memory n, uint256 i, uint256 nNodes, uint256 nChecks) private pure returns (bool) {
        if (n.kind == NodeKind.CHECK) return n.check < nChecks && n.children.length == 0;
        uint256 len = n.children.length;
        if (len == 0) return false;
        uint256 prev = i;
        for (uint256 j; j < len; ++j) {
            uint256 c = n.children[j];
            if (c <= prev || c >= nNodes) return false;
            prev = c;
        }
        if (n.kind == NodeKind.AT_LEAST) return n.k >= 1 && n.k <= len;
        return true;
    }

    // ───────────────────────────── judging ─────────────────────────────

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

    // ───────────────────────────── packed form ─────────────────────────────
    //
    // The evaluator judges each check as its read's answer arrives, so the last callback only walks the tree.
    // Check results: 2 bits per check (UNKNOWN 0, PASS 1, FAIL 2), check i at bits [2i, 2i+1], in a uint32.
    // Nodes: 64 bits per node, 4 per word, node i at bits [64·(i%4), +64) of word i/4:
    //   bits 0-7 kind · 8-15 check · 16-23 k · 24-55 children as a bitmask (bit j: node j is a child).

    /// @notice Packs `nodes` into words of four. Assumes `validate` passed (at most 32 nodes).
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
