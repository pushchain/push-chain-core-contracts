// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";

import {UniversalEvalBase} from "./UniversalEvalBase.t.sol";
import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {
    JobSpec,
    Read,
    Check,
    Logic,
    Evaluation,
    Operation,
    LogicKind,
    AllowedMutability,
    ReadAt,
    MAX_READS,
    MAX_CHECKS,
    MAX_LOGIC
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {Verdict, MAX_DESCRIPTION_LENGTH} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";

/// @notice The callbacks must fit Read State's gas limits for the largest spec the rules allow.
/// @dev Reads are 15-field structs. A spec must also fit MAX_DESCRIPTION_LENGTH (32 KB), which keeps every count from
///      being at its maximum at once, and is what bounds the terms (read indexes across all checks' sides), so the
///      worst cases are split:
///      - GAS01, the most logic: 32 entries over 16 NUMBER checks, each a POST read against a PRE read (8 of each);
///      - GAS03, the most reads: 32 POST reads and as many terms as still fit, across 16 checks that all wait for
///        the last answer;
///      - GAS04, the most terms: 20 POST reads, every check summing as many of them as fit.
///      A callback that runs out of gas fails again on every retry, so this is a hard ceiling, not an optimisation.
contract UniversalEvaluatorGasTest is UniversalEvalBase {
    /// @dev GAS01's reads: 0..7 POST, 8..15 their PRE copies.
    uint256 internal constant VENUES = 8;

    function _maxSpec() internal view returns (JobSpec memory s) {
        s = _frame(2 * VENUES, MAX_LOGIC);
        for (uint256 i; i < 2 * VENUES; ++i) {
            s.reads[i] = _reserveRead(i % VENUES, i < VENUES ? ReadAt.POST_EXECUTION : ReadAt.PRE_EXECUTION);
        }
        for (uint256 i; i < MAX_CHECKS; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8 venue = uint8(i % VENUES);
            // forge-lint: disable-next-line(unsafe-typecast)
            s.checks[i] = Check({
                left: _u8(venue),
                right: _u8(venue + uint8(VENUES)),
                evaluation: Evaluation.NUMBER,
                operation: Operation.GREATER_OR_EQUAL,
                target: 1
            });
        }
    }

    /// @dev The most terms that still fit MAX_DESCRIPTION_LENGTH with `nReads` POST reads: `perCheck` per check.
    function _mostTermsSpec(uint256 nReads) internal view returns (JobSpec memory best, uint256 perCheck) {
        for (uint256 t = 2; t <= nReads; ++t) {
            JobSpec memory s = _termsSpec(nReads, t);
            if (abi.encode(s).length > MAX_DESCRIPTION_LENGTH) break;
            (best, perCheck) = (s, t);
        }
    }

    /// @dev `nReads` POST reads; check i is `(reads 0..a-1 + the last read) - (b reads from a window) >= 0`, with
    ///      `a + 1 + b == perCheck` and `a + 1 >= b`, so equal answers PASS. The windows slide so every read is used.
    ///      Every check includes the last read, so its answer, delivered last, sums every side.
    function _termsSpec(uint256 nReads, uint256 perCheck) internal view returns (JobSpec memory s) {
        s = _frame(nReads, 1 + MAX_CHECKS);
        for (uint256 i; i < nReads; ++i) {
            s.reads[i] = _reserveRead(i, ReadAt.POST_EXECUTION);
        }
        uint256 a = (perCheck + 1) / 2 - 1;
        uint256 b = perCheck - a - 1;
        uint8[] memory left = new uint8[](a + 1);
        for (uint256 j; j < a; ++j) {
            // forge-lint: disable-next-line(unsafe-typecast)
            left[j] = uint8(j);
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        left[a] = uint8(nReads - 1);
        uint256 lastStart = nReads - 1 - b; // the window must end before the last read
        for (uint256 i; i < MAX_CHECKS; ++i) {
            uint256 start = a + i * b;
            if (start > lastStart) start = lastStart;
            uint8[] memory right = new uint8[](b);
            for (uint256 j; j < b; ++j) {
                // forge-lint: disable-next-line(unsafe-typecast)
                right[j] = uint8(start + j);
            }
            s.checks[i] = Check({
                left: left, right: right, evaluation: Evaluation.NUMBER, operation: Operation.GREATER_OR_EQUAL, target: 0
            });
        }
    }

    /// @dev `nReads` reads and MAX_CHECKS checks to fill in, and a root ALL over `nLogic - 1` COMPARE entries, so every
    ///      entry is reachable and every check used.
    function _frame(uint256 nReads, uint256 nLogic) internal view returns (JobSpec memory s) {
        s.reads = new Read[](nReads);
        s.checks = new Check[](MAX_CHECKS);
        s.logic = new Logic[](nLogic);
        uint8[] memory children = new uint8[](nLogic - 1);
        for (uint256 i; i < nLogic - 1; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            children[i] = uint8(i + 1);
        }
        s.logic[0] = Logic({kind: LogicKind.ALL, check: 0, children: children, k: 0});
        for (uint256 i = 1; i < nLogic; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            s.logic[i] = _checkLogic(uint8((i - 1) % MAX_CHECKS));
        }
        s.allowedMutability = AllowedMutability.NONE;
    }

    /// @dev Aave's `getReserveData` on venue `venue`, its rate (field [0, 2]).
    function _reserveRead(uint256 venue, ReadAt at) internal pure returns (Read memory) {
        return Read({
            chainNamespace: NS,
            chainId: BASE,
            minConfirmations: 3,
            target: address(uint160(0x1000 + venue)),
            selector: bytes4(keccak256("getReserveData(address)")),
            args: abi.encode(address(uint160(0x2000 + venue))),
            outputs: _reserveOutputs(),
            field: _u8(0, 2),
            at: at
        });
    }

    function test_GAS01_maxSpec_callbacksFit() public {
        // `--isolate` runs each call as its own transaction, which does not carry `vm.fee`; with a zero base fee
        // the node's budget rule is trivially met everywhere. Gas use does not depend on the base fee.
        vm.fee(0);
        JobSpec memory s = _maxSpec();
        assertLe(abi.encode(s).length, MAX_DESCRIPTION_LENGTH, "fits the description cap");
        uint256 jobId = _createSpec(s);
        _fund(jobId);
        for (uint256 i = VENUES; i < 2 * VENUES; ++i) {
            assertTrue(_deliverExpectingSuccess(ue.requestOf(jobId, i), _reserveAnswer(100)), "snapshot cb");
        }
        assertTrue(ue.ready(jobId));
        _advance();

        // `submit` fixes the 8 end blocks and sends the 8 POST reads; the provider pays this gas.
        uint256 g0 = gasleft();
        _submit(jobId);
        console2.log("submit incl. 8 reads, gas:", g0 - gasleft());
        assertTrue(ue.evaluationOf(jobId).started, "reads sent inside submit");

        for (uint256 i; i < VENUES - 1; ++i) {
            assertTrue(_deliverExpectingSuccess(ue.requestOf(jobId, i), _reserveAnswer(200)), "answer cb");
        }
        uint256 g = gasleft();
        assertTrue(
            _deliverExpectingSuccess(ue.requestOf(jobId, VENUES - 1), _reserveAnswer(200)),
            "final callback ran out of gas"
        );
        console2.log("fulfil incl. final callback, gas:", g - gasleft());

        UniversalEvaluator.Evaluation memory e = ue.evaluationOf(jobId);
        assertTrue(e.done && e.applied);
        assertEq(uint8(e.verdict), uint8(Verdict.PASS));
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    function test_GAS03_mostReads_finalCallbackFits() public {
        _mostTermsFit(MAX_READS);
    }

    function test_GAS04_mostTerms_finalCallbackFits() public {
        _mostTermsFit(20);
    }

    /// @dev The heaviest spec with `nReads` POST reads: every answer but the last leaves the job waiting; the last
    ///      sums every term and settles, inside the callback gas limit.
    function _mostTermsFit(uint256 nReads) internal {
        vm.fee(0);
        (JobSpec memory s, uint256 perCheck) = _mostTermsSpec(nReads);
        assertGt(perCheck, 0, "no spec fits the description cap");
        console2.log("reads:", nReads, "terms:", perCheck * MAX_CHECKS);
        console2.log("description bytes:", abi.encode(s).length);
        uint256 jobId = _createSpec(s);
        _fund(jobId);
        _advance();
        uint256 g0 = gasleft();
        _submit(jobId);
        console2.log("submit incl. reads, gas:", g0 - gasleft());

        for (uint256 i; i < nReads - 1; ++i) {
            assertTrue(_deliverExpectingSuccess(ue.requestOf(jobId, i), _reserveAnswer(100)), "answer cb");
        }
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Submitted), "every check waits for the last");
        uint256 g = gasleft();
        assertTrue(
            _deliverExpectingSuccess(ue.requestOf(jobId, nReads - 1), _reserveAnswer(100)),
            "final callback ran out of gas"
        );
        console2.log("fulfil incl. final callback, gas:", g - gasleft());
        assertEq(uint8(ue.evaluationOf(jobId).verdict), uint8(Verdict.PASS));
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    /// @dev The common case: one read, one NUMBER check. What a provider's `submit` costs.
    function test_GAS02_swap_submitGas() public {
        vm.fee(0);
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        assertTrue(_deliverExpectingSuccess(ue.requestOf(jobId, SWAP_PRE), abi.encode(uint256(0))));
        core.setChainHeight(BASE_KEY, START_HEIGHT + 120);
        uint256 g0 = gasleft();
        _submit(jobId);
        console2.log("swap submit incl. 1 read, gas:", g0 - gasleft());
        uint256 g = gasleft();
        assertTrue(_deliverExpectingSuccess(ue.requestOf(jobId, 0), abi.encode(uint256(0.4e18))));
        console2.log("swap fulfil incl. final callback, gas:", g - gasleft());
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    /// @dev Delivers and requires that Read State reports `ReadFulfilled`, not `CallbackFailed`.
    function _deliverExpectingSuccess(uint256 requestId, bytes memory result) internal returns (bool) {
        vm.recordLogs();
        if (!_deliver(requestId, result)) return false;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (
                logs[i].emitter == address(readState) && logs[i].topics[0] == IUniversalCallback.CallbackFailed.selector
            ) {
                return false;
            }
        }
        return true;
    }
}
