// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Check, Node, NodeKind} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {Answer, Verdict} from "../../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {JobSpecLib} from "../../../src/agentic-commerce-8183/evaluator/JobSpecLib.sol";

/// @title ReferenceJudge — the verdict, unpacked
/// @notice The readable judge the evaluator's packed one (`JobSpecLib.verdictPacked`) is checked against on random
///         inputs (`testFuzz_JDG02_packedEqualsReference`). Test-only: the evaluator never runs it.
library ReferenceJudge {
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
            checkRes[i] = JobSpecLib.checkResult(c, afters[c.read], befores[c.read]);
        }

        uint8[] memory nodeRes = new uint8[](nodes.length);
        for (uint256 i = nodes.length; i > 0; --i) {
            nodeRes[i - 1] = _node(nodes[i - 1], nodeRes, checkRes);
        }

        uint8 root = nodeRes[0];
        if (root == JobSpecLib.PASS) return Verdict.PASS;
        if (root == JobSpecLib.FAIL) return Verdict.FAIL;
        return Verdict.INCONCLUSIVE;
    }

    /// @dev One node from its already-decided children.
    function _node(Node memory n, uint8[] memory nodeRes, uint8[] memory checkRes) private pure returns (uint8) {
        if (n.kind == NodeKind.CHECK) return checkRes[n.check];

        uint256 total = n.children.length;
        uint256 pass;
        uint256 fail;
        for (uint256 j; j < total; ++j) {
            uint8 r = nodeRes[n.children[j]];
            if (r == JobSpecLib.PASS) ++pass;
            else if (r == JobSpecLib.FAIL) ++fail;
        }
        uint256 need = n.kind == NodeKind.ALL ? total : n.kind == NodeKind.ANY ? 1 : n.k;
        if (pass >= need) return JobSpecLib.PASS; // enough passed
        if (total - fail < need) return JobSpecLib.FAIL; // not enough left that could pass
        return JobSpecLib.UNKNOWN;
    }
}
