// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

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
    MAX_LOGIC
} from "../libraries/JobSpecTypes.sol";
import {Answer, Verdict, MAX_ARGS_LENGTH, MAX_CHAIN_STRING_LENGTH} from "./EvaluationTypes.sol";
import {EvmReadLib} from "./EvmReadLib.sol";
import {JobSpecErrors} from "../libraries/Errors.sol";

/// @title JobSpecLib — what a `JobSpec` must satisfy, and how it is judged
/// @notice `validate` is public: the library is deployed once and linked into the UniversalEvaluator, which
///         DELEGATECALLs it (compiled in, it put the evaluator over EIP-170). The rest is internal, compiled in.
/// @dev Checking (`validate`, run when the spec is frozen inside `fund`, so a refused spec reverts the funding):
///      - Structural checks only. Whether the criteria mean what the client wants is not checkable here.
///      - Every rule is one the evaluator relies on, so a funded job can always be judged: indexes are in range,
///        the logic forms a graph evaluable from last to first, every read is one the evaluator can encode and
///        decodes in bounded work, every logic entry, check and read counts toward the verdict, at least one read is
///        POST_EXECUTION.
///      Judging (every check comes out PASS, FAIL or UNKNOWN; the logic combines them; the root is the verdict):
///      - Each side is the sum of its reads; a side with a missing or unreadable read, or a sum that overflows, is
///        UNKNOWN. With L = Σleft and R = Σright:
///        BOOLEAN `L == target` · COMPARE `L op target` · NUMBER `(L - R) op target` ·
///        PERCENTAGE: the difference in basis points, `(L - R) * 10_000 / R op target`, and PERCENTAGE with `R <= 0` FAILS.
///      - PERCENTAGE is compared exactly, as `(L - R) * 10_000 op target * R` (`R > 0` keeps the direction). Dividing
///        first would round toward zero, so a tiny loss would read as 0 and pass `>= 0`.
///      - Never reverts on any answer: an overflow makes the check UNKNOWN.
///      - The readable, unpacked reference judge lives in the tests (`helpers/ReferenceJudge.sol`); the suite checks
///        `verdictPacked` agrees with it on random inputs.
library JobSpecLib {
    /// @notice A check's or a logic entry's result.
    uint8 internal constant UNKNOWN = 0;
    uint8 internal constant PASS = 1;
    uint8 internal constant FAIL = 2;

    // ───────────────────────────── checking ─────────────────────────────

    /// @notice Reverts with a `JobSpecErrors` error unless `s` can be judged.
    /// @param s                The criteria.
    /// @param maxConfirmations The evaluator's ceiling on `Read.minConfirmations`, so every read can be answered.
    function validate(JobSpec memory s, uint256 maxConfirmations) public pure {
        uint256 nReads = s.reads.length;
        uint256 nChecks = s.checks.length;
        uint256 nLogic = s.logic.length;
        if (nReads == 0 || nReads > MAX_READS) revert JobSpecErrors.ReadCount(nReads);
        if (nChecks == 0 || nChecks > MAX_CHECKS) revert JobSpecErrors.CheckCount(nChecks);
        if (nLogic == 0 || nLogic > MAX_LOGIC) revert JobSpecErrors.LogicCount(nLogic);

        bool anyPost;
        for (uint256 i; i < nReads; ++i) {
            Read memory r = s.reads[i];
            if (r.at == ReadAt.POST_EXECUTION) anyPost = true;
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
        if (!anyPost) revert JobSpecErrors.NoPostExecutionRead();

        for (uint256 i; i < nChecks; ++i) {
            Check memory c = s.checks[i];
            (bool okL, uint256 left) = _side(c.left, nReads);
            (bool okR, uint256 right) = _side(c.right, nReads);
            if (!okL || !okR || (left & right) != 0) revert JobSpecErrors.CheckRead(i);
            uint256 nl = c.left.length;
            uint256 nr = c.right.length;
            bool sides = c.evaluation == Evaluation.BOOLEAN ? nl == 1 && nr == 0 : nl != 0 && (nr != 0) == isPair(c.evaluation);
            if (!sides) revert JobSpecErrors.CheckSides(i);
            if (c.evaluation == Evaluation.BOOLEAN) {
                if (c.operation != Operation.EQUAL) revert JobSpecErrors.CheckOp(i); // BOOLEAN is `left == target`
                if (c.target != 0 && c.target != 1) revert JobSpecErrors.CheckTarget(i);
            }
        }

        for (uint256 i; i < nLogic; ++i) {
            if (!_logicOk(s.logic[i], i, nLogic, nChecks)) revert JobSpecErrors.LogicShape(i);
        }
        _requireAllUsed(s);
    }

    /// @dev A side's reads as a bitmask, if every index is below `nReads` and above the one before it.
    function _side(uint8[] memory side, uint256 nReads) private pure returns (bool, uint256 mask) {
        uint256 next; // the lowest index allowed next
        for (uint256 j; j < side.length; ++j) {
            uint256 r = side[j];
            if (r < next || r >= nReads) return (false, 0);
            mask |= uint256(1) << r;
            next = r + 1;
        }
        return (true, mask);
    }

    /// @dev Everything counts toward the verdict: every logic entry is reachable from the root, every check is used by
    ///      a reachable CHECK entry, every read by a used check. Nothing is paid for or shown without affecting payment.
    ///      Children come after their parents (`_logicOk`), so one forward pass finds every reachable entry. An entry
    ///      may have several parents; that changes nothing in the verdict.
    function _requireAllUsed(JobSpec memory s) private pure {
        uint256 reached = 1; // the root
        uint256 usedChecks;
        for (uint256 i; i < s.logic.length; ++i) {
            if ((reached >> i) & 1 == 0) revert JobSpecErrors.LogicUnreachable(i);
            Logic memory n = s.logic[i];
            if (n.kind == LogicKind.CHECK) {
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
            Check memory c = s.checks[i];
            usedReads |= uint256(packSide(c.left) | packSide(c.right));
        }
        for (uint256 i; i < s.reads.length; ++i) {
            if ((usedReads >> i) & 1 == 0) revert JobSpecErrors.ReadUnused(i);
        }
    }

    /// @notice Whether the type compares two sides (NUMBER / PERCENTAGE) rather than one side with `target`.
    function isPair(Evaluation e) internal pure returns (bool) {
        return e == Evaluation.NUMBER || e == Evaluation.PERCENTAGE;
    }

    /// @notice A side's reads as a bitmask (bit i: read i). Assumes `validate` passed (indexes below 32).
    function packSide(uint8[] memory side) internal pure returns (uint32 mask) {
        for (uint256 j; j < side.length; ++j) {
            mask |= uint32(1) << side[j];
        }
    }

    /// @dev - CHECK: a check in range, no children.
    ///      - ALL / ANY / AT_LEAST: one or more children, strictly increasing, each after this entry and in range,
    ///        so the tree is acyclic and no child is counted twice.
    ///      - AT_LEAST: `1 <= k <= children`.
    function _logicOk(Logic memory n, uint256 i, uint256 nLogic, uint256 nChecks) private pure returns (bool) {
        if (n.kind == LogicKind.CHECK) return n.check < nChecks && n.children.length == 0;
        uint256 len = n.children.length;
        if (len == 0) return false;
        uint256 prev = i;
        for (uint256 j; j < len; ++j) {
            uint256 c = n.children[j];
            if (c <= prev || c >= nLogic) return false;
            prev = c;
        }
        if (n.kind == LogicKind.AT_LEAST) return n.k >= 1 && n.k <= len;
        return true;
    }

    // ───────────────────────────── judging ─────────────────────────────

    /// @notice One check: PASS, FAIL or UNKNOWN. `a` is the `left` side's sum, `b` the `right` side's.
    function checkResult(Evaluation e, Operation op, int256 target, Answer memory a, Answer memory b)
        internal
        pure
        returns (uint8)
    {
        if (!a.ok) return UNKNOWN;
        if (e == Evaluation.BOOLEAN) return a.value == target ? PASS : FAIL;
        if (e == Evaluation.COMPARE) return _cmp(a.value, op, target) ? PASS : FAIL;

        if (!b.ok) return UNKNOWN;
        (bool ok, int256 delta) = _sub(a.value, b.value);
        if (!ok) return UNKNOWN;
        if (e == Evaluation.NUMBER) return _cmp(delta, op, target) ? PASS : FAIL;

        // PERCENTAGE, in basis points, compared without dividing
        if (b.value <= 0) return FAIL;
        (bool okL, int256 lhs) = _mul(delta, 10_000);
        (bool okR, int256 rhs) = _mul(target, b.value);
        if (!okL || !okR) return UNKNOWN;
        return _cmp(lhs, op, rhs) ? PASS : FAIL;
    }

    /// @notice `a + b`, or not-ok on overflow. Adds up a side.
    function add(int256 a, int256 b) internal pure returns (bool, int256) {
        unchecked {
            int256 c = a + b;
            if ((b > 0 && c < a) || (b < 0 && c > a)) return (false, 0);
            return (true, c);
        }
    }

    // ───────────────────────────── packed form ─────────────────────────────
    //
    // The evaluator judges each check as soon as its reads' values are in, so the last callback only walks the tree.
    // Check results: 2 bits per check (UNKNOWN 0, PASS 1, FAIL 2), check i at bits [2i, 2i+1], in a uint32.
    // Logic: 64 bits per entry, 4 per word, entry i at bits [64·(i%4), +64) of word i/4:
    //   bits 0-7 kind · 8-15 check · 16-23 k · 24-55 children as a bitmask (bit j: entry j is a child).

    /// @notice Packs `logic` into words of four. Assumes `validate` passed (at most 32 entries).
    function packLogic(Logic[] memory logic) internal pure returns (uint256[] memory words) {
        words = new uint256[]((logic.length + 3) / 4);
        for (uint256 i; i < logic.length; ++i) {
            Logic memory n = logic[i];
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

    /// @notice The verdict from packed logic and packed check results.
    function verdictPacked(uint256[] memory words, uint256 nLogic, uint32 checkRes) internal pure returns (Verdict) {
        uint256 logicRes; // 2 bits per entry, as checkRes
        for (uint256 i = nLogic; i > 0; --i) {
            uint256 idx = i - 1;
            uint256 packed = (words[idx / 4] >> (64 * (idx % 4))) & type(uint64).max;
            // The casts below pick one byte out of the packed entry (layout above): dropping the rest is the intent.
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8 kind = uint8(packed);
            uint8 r;
            if (kind == uint8(LogicKind.CHECK)) {
                // forge-lint: disable-next-line(unsafe-typecast)
                r = uint8((uint256(checkRes) >> (2 * uint8(packed >> 8))) & 3);
            } else {
                uint256 mask = (packed >> 24) & type(uint32).max;
                uint256 total;
                uint256 pass;
                uint256 fail;
                for (uint256 j = idx + 1; j < nLogic; ++j) {
                    if (mask & (uint256(1) << j) == 0) continue;
                    ++total;
                    uint256 c = (logicRes >> (2 * j)) & 3;
                    if (c == PASS) ++pass;
                    else if (c == FAIL) ++fail;
                }
                // forge-lint: disable-next-line(unsafe-typecast)
                uint256 need = kind == uint8(LogicKind.ALL) ? total : kind == uint8(LogicKind.ANY) ? 1 : uint8(packed >> 16);
                r = pass >= need ? PASS : total - fail < need ? FAIL : UNKNOWN;
            }
            logicRes |= uint256(r) << (2 * idx);
        }
        uint256 root = logicRes & 3;
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

    function _cmp(int256 x, Operation op, int256 y) private pure returns (bool) {
        if (op == Operation.EQUAL) return x == y;
        if (op == Operation.NOT_EQUAL) return x != y;
        if (op == Operation.GREATER_THAN) return x > y;
        if (op == Operation.GREATER_OR_EQUAL) return x >= y;
        if (op == Operation.LESS_THAN) return x < y;
        return x <= y;
    }
}
