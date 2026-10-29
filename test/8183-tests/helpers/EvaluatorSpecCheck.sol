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
    MAX_LOGIC,
    T_UINT,
    T_STRING,
    T_BYTES,
    T_TUPLE,
    T_ARRAY,
    T_FIXED_ARRAY
} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";

library JobSpecErrors {
    /// @notice The encoded spec is longer than `MAX_DESCRIPTION_LENGTH`.
    error SpecTooLong(uint256 length);
    /// @notice `reads.length` is 0 or above `MAX_READS`.
    error ReadCount(uint256 count);
    /// @notice `checks.length` is 0 or above `MAX_CHECKS`.
    error CheckCount(uint256 count);
    /// @notice `logic.length` is 0 or above `MAX_LOGIC`.
    error LogicCount(uint256 count);
    /// @notice A read names an empty or too long chain namespace or chain id, or a namespace other than `eip155`.
    error ReadChain(uint256 read);
    /// @notice A read asks for zero confirmations, or more than the evaluator's maximum.
    error ReadConfirmations(uint256 read);
    /// @notice A read targets address zero.
    error ReadTarget(uint256 read);
    /// @notice A read's `args` are longer than `MAX_ARGS_LENGTH`.
    error ReadArgs(uint256 read);
    /// @notice A read's `outputs` / `field` do not name one value of a well-formed return type that fits
    ///         `MAX_RESULT_LENGTH`.
    error ReadShape(uint256 read);
    /// @notice A check side names a read that does not exist or is not in increasing order, or both sides name
    ///         the same read.
    error CheckRead(uint256 check);
    /// @notice A check's sides don't fit its type: BOOLEAN one `left` read and no `right` · COMPARE no `right` ·
    ///         NUMBER / PERCENTAGE both sides.
    error CheckSides(uint256 check);
    /// @notice No read is POST_EXECUTION, so the provider's work would never be measured.
    error NoPostExecutionRead();
    /// @notice A BOOLEAN check's target is neither 0 nor 1.
    error CheckTarget(uint256 check);
    /// @notice A BOOLEAN check's operator is not `EQUAL`.
    error CheckOp(uint256 check);
    /// @notice A logic entry is malformed: bad check index, children out of order or out of range, or a bad `k`.
    error LogicShape(uint256 entry);
    /// @notice A logic entry no path from the root reaches.
    error LogicUnreachable(uint256 entry);
    /// @notice A check no reachable logic entry uses.
    error CheckUnused(uint256 check);
    /// @notice A read no used check reads.
    error ReadUnused(uint256 read);
}

/// @title EvaluatorSpecCheck — TEST ONLY: the UniversalEvaluator's spec validation, copied from 8666c2a
/// @notice `validate` is the evaluator's `JobSpecLib.validate`, which the UniversalHook runs inside `fund`: a spec it
///         refuses reverts the funding. The conformance suite holds every built spec to it.
/// @dev - Source: `feat/universal-evaluator-pre-post-reads` @ 8666c2a: `evaluator/JobSpecLib.sol` (validate and its
///        helpers), `evaluator/EvmReadLib.sol` (isValidShape and its helpers), `libraries/Errors.sol`
///        (`JobSpecErrors`), `evaluator/EvaluationTypes.sol` (the limits). Bodies copied verbatim; the only edits are
///        `validate` made internal and the two `EvmReadLib.` qualifiers dropped; the layout is `forge fmt`'s.
///      - Do not "fix" it here: a divergence is a finding. Re-copy when the agreed evaluator commit moves.
library EvaluatorSpecCheck {
    uint256 internal constant MAX_ARGS_LENGTH = 512;
    uint256 internal constant MAX_CHAIN_STRING_LENGTH = 32;
    uint256 internal constant MAX_RESULT_LENGTH = 4096;
    uint256 internal constant MAX_OUTPUTS_LENGTH = 128;
    uint256 internal constant MAX_FIELD_DEPTH = 8;
    uint256 internal constant MAX_TYPE_DEPTH = 8;
    bytes32 internal constant EVM_NAMESPACE_HASH = keccak256("eip155");

    /// @notice Reverts with a `JobSpecErrors` error unless `s` can be judged.
    /// @param s                The criteria.
    /// @param maxConfirmations The evaluator's ceiling on `Read.minConfirmations`, so every read can be answered.
    function validate(JobSpec memory s, uint256 maxConfirmations) internal pure {
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
            if (keccak256(bytes(r.chainNamespace)) != EVM_NAMESPACE_HASH) {
                revert JobSpecErrors.ReadChain(i);
            }
            if (r.minConfirmations == 0 || r.minConfirmations > maxConfirmations) {
                revert JobSpecErrors.ReadConfirmations(i);
            }
            if (r.target == address(0)) revert JobSpecErrors.ReadTarget(i);
            if (r.args.length > MAX_ARGS_LENGTH) revert JobSpecErrors.ReadArgs(i);
            if (!isValidShape(r.outputs, r.field)) revert JobSpecErrors.ReadShape(i);
        }
        if (!anyPost) revert JobSpecErrors.NoPostExecutionRead();

        for (uint256 i; i < nChecks; ++i) {
            Check memory c = s.checks[i];
            (bool okL, uint256 left) = _side(c.left, nReads);
            (bool okR, uint256 right) = _side(c.right, nReads);
            if (!okL || !okR || (left & right) != 0) revert JobSpecErrors.CheckRead(i);
            uint256 nl = c.left.length;
            uint256 nr = c.right.length;
            bool sides =
                c.evaluation == Evaluation.BOOLEAN ? nl == 1 && nr == 0 : nl != 0 && (nr != 0) == isPair(c.evaluation);
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

    /// @notice Whether `outputs` is a well-formed return-type list and `field` names one value in it.
    /// @dev - `outputs` is exactly one TUPLE (the return list), with no trailing bytes.
    ///      - Every code is known; TUPLE and FIXED_ARRAY have at least one member.
    ///      - `field` indexes are inside every TUPLE and FIXED_ARRAY it passes; ARRAY indexes are checked
    ///        against the answer at decode time.
    ///      - The value `field` lands on is not a TUPLE or FIXED_ARRAY.
    ///      - The return list's fixed part (its head) fits `MAX_RESULT_LENGTH`, so any answer of this shape fits
    ///        unless its variable-length data (bytes, string, arrays) is what makes it longer.
    function isValidShape(bytes memory outputs, uint8[] memory field) internal pure returns (bool) {
        if (outputs.length < 3 || outputs.length > MAX_OUTPUTS_LENGTH) return false;
        if (field.length == 0 || field.length > MAX_FIELD_DEPTH) return false;
        if (uint8(outputs[0]) != T_TUPLE) return false;
        (bool ok, uint256 end) = _wellFormed(outputs, 0, 0);
        if (!ok || end != outputs.length) return false;

        uint256 head;
        uint256 member = 2;
        for (uint256 j; j < uint8(outputs[1]); ++j) {
            head += _headWords(outputs, member);
            member = _skip(outputs, member);
        }
        if (head * 32 > MAX_RESULT_LENGTH) return false;

        uint256 t;
        for (uint256 i; i < field.length; ++i) {
            uint8 code = uint8(outputs[t]);
            uint256 idx = field[i];
            if (code == T_TUPLE) {
                if (idx >= uint8(outputs[t + 1])) return false;
                uint256 c = t + 2;
                for (uint256 j; j < idx; ++j) {
                    c = _skip(outputs, c);
                }
                t = c;
            } else if (code == T_ARRAY) {
                t = t + 1;
            } else if (code == T_FIXED_ARRAY) {
                if (idx >= uint8(outputs[t + 1])) return false;
                t = t + 2;
            } else {
                return false; // can't go inside a basic value
            }
        }
        uint8 leaf = uint8(outputs[t]);
        return leaf != T_TUPLE && leaf != T_FIXED_ARRAY;
    }

    /// @dev One type starting at `t` is complete and known; returns where it ends.
    function _wellFormed(bytes memory types, uint256 t, uint256 depth) private pure returns (bool, uint256) {
        if (depth > MAX_TYPE_DEPTH || t >= types.length) return (false, 0);
        uint8 code = uint8(types[t]);
        if (code >= T_UINT && code <= T_STRING) return (true, t + 1);
        if (code == T_ARRAY) return _wellFormed(types, t + 1, depth + 1);
        if (code != T_TUPLE && code != T_FIXED_ARRAY) return (false, 0);
        if (t + 1 >= types.length) return (false, 0);
        uint256 n = uint8(types[t + 1]);
        if (n == 0) return (false, 0);
        if (code == T_FIXED_ARRAY) return _wellFormed(types, t + 2, depth + 1);
        uint256 c = t + 2;
        for (uint256 j; j < n; ++j) {
            bool ok;
            (ok, c) = _wellFormed(types, c, depth + 1);
            if (!ok) return (false, 0);
        }
        return (true, c);
    }

    /// @dev bytes, string and T[] are dynamic; a struct or T[k] is dynamic if anything inside is.
    function _isDynamic(bytes memory types, uint256 t) private pure returns (bool) {
        uint8 code = uint8(types[t]);
        if (code == T_BYTES || code == T_STRING || code == T_ARRAY) return true;
        if (code == T_FIXED_ARRAY) return _isDynamic(types, t + 2);
        if (code == T_TUPLE) {
            uint256 c = t + 2;
            for (uint256 j; j < uint8(types[t + 1]); ++j) {
                if (_isDynamic(types, c)) return true;
                c = _skip(types, c);
            }
        }
        return false;
    }

    /// @dev Slots a value takes in its parent's head: 1 if dynamic (a pointer), else its full size.
    function _headWords(bytes memory types, uint256 t) private pure returns (uint256 n) {
        if (_isDynamic(types, t)) return 1;
        uint8 code = uint8(types[t]);
        if (code == T_FIXED_ARRAY) return uint8(types[t + 1]) * _headWords(types, t + 2);
        if (code == T_TUPLE) {
            uint256 c = t + 2;
            for (uint256 j; j < uint8(types[t + 1]); ++j) {
                n += _headWords(types, c);
                c = _skip(types, c);
            }
            return n;
        }
        return 1;
    }

    /// @dev The position in `types` right after the type starting at `t`.
    function _skip(bytes memory types, uint256 t) private pure returns (uint256) {
        uint8 code = uint8(types[t]);
        if (code == T_ARRAY) return _skip(types, t + 1);
        if (code == T_FIXED_ARRAY) return _skip(types, t + 2);
        if (code == T_TUPLE) {
            uint256 c = t + 2;
            for (uint256 j; j < uint8(types[t + 1]); ++j) {
                c = _skip(types, c);
            }
            return c;
        }
        return t + 1;
    }
}
