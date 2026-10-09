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
import {AnswerDecoder} from "./AnswerDecoder.sol";
import {ReadRequest} from "./ReadRequest.sol";
import {MAX_ARGS_LENGTH, MAX_CHAIN_STRING_LENGTH} from "./EvaluationTypes.sol";
import {JobSpecErrors} from "../libraries/Errors.sol";

/// @title JobSpecRules — what a `JobSpec` must satisfy before a job can be funded
/// @notice Structural checks only. Whether the criteria mean what the client wants is not checkable here.
/// @dev - Run by the UniversalEvaluator when the spec is frozen inside `fund`, so a refused spec reverts the funding.
///      - `executeBy` and `failFinalAt` are not checked: the evaluator does not use them (the end blocks are fixed at
///        `submit`, and a FAIL there is final).
///      - Every rule here is one the evaluator relies on, so a funded job can always be judged:
///        indexes are in range, nodes form a graph evaluable from last to first, every read is one the evaluator
///        can encode and decodes in bounded work, and every node, check and read counts toward the verdict.
library JobSpecRules {
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
            if (keccak256(bytes(r.chainNamespace)) != ReadRequest.EVM_NAMESPACE_HASH) {
                revert JobSpecErrors.ReadChain(i);
            }
            if (r.minConfirmations == 0 || r.minConfirmations > maxConfirmations) {
                revert JobSpecErrors.ReadConfirmations(i);
            }
            if (r.target == address(0)) revert JobSpecErrors.ReadTarget(i);
            if (r.args.length > MAX_ARGS_LENGTH) revert JobSpecErrors.ReadArgs(i);
            if (!AnswerDecoder.isValidShape(r.outputs, r.field)) revert JobSpecErrors.ReadShape(i);
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
}
