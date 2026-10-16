// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Check, Logic, LogicKind} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {Answer, Verdict} from "../../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {JobSpecLib} from "../../../src/agentic-commerce-8183/evaluator/JobSpecLib.sol";

/// @title ReferenceJudge — the verdict, unpacked
/// @notice The readable judge the evaluator's packed one (`JobSpecLib.verdictPacked`) is checked against on random
///         inputs (`testFuzz_JDG02_packedEqualsReference`). Test-only: the evaluator never runs it.
library ReferenceJudge {
    /// @param checks  The job's checks.
    /// @param logic   The job's pass logic; `logic[0]` is the root.
    /// @param values  Each read's value (a PRE read's snapshot, a POST read's answer).
    function verdict(Check[] memory checks, Logic[] memory logic, Answer[] memory values)
        internal
        pure
        returns (Verdict)
    {
        uint8[] memory checkRes = new uint8[](checks.length);
        for (uint256 i; i < checks.length; ++i) {
            Check memory c = checks[i];
            checkRes[i] = JobSpecLib.checkResult(
                c.evaluation, c.operation, c.target, _sum(c.left, values), _sum(c.right, values)
            );
        }

        uint8[] memory logicRes = new uint8[](logic.length);
        for (uint256 i = logic.length; i > 0; --i) {
            logicRes[i - 1] = _entry(logic[i - 1], logicRes, checkRes);
        }

        uint8 root = logicRes[0];
        if (root == JobSpecLib.PASS) return Verdict.PASS;
        if (root == JobSpecLib.FAIL) return Verdict.FAIL;
        return Verdict.INCONCLUSIVE;
    }

    /// @dev A side's sum, read by read: unknown if any read is unreadable or the sum overflows.
    function _sum(uint8[] memory side, Answer[] memory values) private pure returns (Answer memory total) {
        total.ok = true;
        for (uint256 j; j < side.length; ++j) {
            Answer memory v = values[side[j]];
            if (!v.ok) return Answer(false, 0);
            (total.ok, total.value) = JobSpecLib.add(total.value, v.value);
            if (!total.ok) return Answer(false, 0);
        }
    }

    /// @dev One logic entry's result, from its already-decided children.
    function _entry(Logic memory n, uint8[] memory logicRes, uint8[] memory checkRes) private pure returns (uint8) {
        if (n.kind == LogicKind.CHECK) return checkRes[n.check];

        uint256 total = n.children.length;
        uint256 pass;
        uint256 fail;
        for (uint256 j; j < total; ++j) {
            uint8 r = logicRes[n.children[j]];
            if (r == JobSpecLib.PASS) ++pass;
            else if (r == JobSpecLib.FAIL) ++fail;
        }
        uint256 need = n.kind == LogicKind.ALL ? total : n.kind == LogicKind.ANY ? 1 : n.k;
        if (pass >= need) return JobSpecLib.PASS; // enough passed
        if (total - fail < need) return JobSpecLib.FAIL; // not enough left that could pass
        return JobSpecLib.UNKNOWN;
    }
}
