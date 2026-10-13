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
    EvalType,
    Op,
    LogicKind,
    CriteriaMutability,
    ReadAt,
    MAX_READS,
    MAX_CHECKS,
    MAX_NODES
} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {Verdict} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";

/// @notice The callbacks must fit Read State's gas limits for the largest spec the rules allow.
/// @dev Worst case: 32 reads of a 15-field struct (16 POST, 16 PRE), 16 NUM checks, each a POST read against its
///      own PRE read, and 32 nodes.
///      A callback that runs out of gas is never retried, so this is a hard ceiling, not an optimisation.
contract UniversalEvaluatorGasTest is UniversalEvalBase {
    uint256 internal constant HALF = MAX_READS / 2;

    function _maxSpec() internal view returns (JobSpec memory s) {
        s.executeBy = uint64(block.timestamp + 1 hours);
        s.failFinalAt = uint64(block.timestamp + 2 hours);
        s.reads = new Read[](MAX_READS);
        s.checks = new Check[](MAX_CHECKS);
        s.logic = new Logic[](MAX_NODES);
        for (uint256 i; i < MAX_READS; ++i) {
            uint256 venue = i % HALF; // read i + HALF is read i's PRE copy
            s.reads[i] = Read({
                chainNamespace: NS,
                chainId: BASE,
                minConfirmations: 3,
                target: address(uint160(0x1000 + venue)),
                selector: bytes4(keccak256("getReserveData(address)")),
                args: abi.encode(address(uint160(0x2000 + venue))),
                outputs: _reserveOutputs(),
                field: _u8(0, 2),
                at: i < HALF ? ReadAt.POST_EXECUTION : ReadAt.PRE_EXECUTION
            });
        }
        for (uint256 i; i < MAX_CHECKS; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            s.checks[i] = Check({left: uint8(i), right: uint8(i + HALF), evalType: EvalType.NUM, op: Op.GTE, target: 1});
        }
        // Root ALL over the other 31 nodes, each a CHECK node, so every node is reachable and every check used.
        uint8[] memory children = new uint8[](MAX_NODES - 1);
        for (uint256 i; i < MAX_NODES - 1; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            children[i] = uint8(i + 1);
        }
        s.logic[0] = Logic({kind: LogicKind.ALL, check: 0, children: children, k: 0});
        for (uint256 i = 1; i < MAX_NODES; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            s.logic[i] = _checkNode(uint8((i - 1) % MAX_CHECKS));
        }
        s.mutability = CriteriaMutability.NONE;
    }

    function test_GAS01_maxSpec_callbacksFit() public {
        // `--isolate` runs each call as its own transaction, which does not carry `vm.fee`; with a zero base fee
        // the node's budget rule is trivially met everywhere. Gas use does not depend on the base fee.
        vm.fee(0);
        uint256 jobId = _createSpec(_maxSpec());
        _fund(jobId);
        for (uint256 i = HALF; i < MAX_READS; ++i) {
            assertTrue(_deliverExpectingSuccess(ue.requestOf(jobId, i), _reserveAnswer(100)), "snapshot cb");
        }
        assertTrue(ue.ready(jobId));
        _advance();

        // `submit` fixes 16 end blocks and sends the 16 POST reads; the provider pays this gas.
        uint256 g0 = gasleft();
        _submit(jobId);
        console2.log("submit incl. 16 reads, gas:", g0 - gasleft());
        assertTrue(ue.evaluationOf(jobId).started, "reads sent inside submit");

        for (uint256 i; i < HALF - 1; ++i) {
            assertTrue(_deliverExpectingSuccess(ue.requestOf(jobId, i), _reserveAnswer(200)), "answer cb");
        }
        uint256 g = gasleft();
        assertTrue(
            _deliverExpectingSuccess(ue.requestOf(jobId, HALF - 1), _reserveAnswer(200)),
            "final callback ran out of gas"
        );
        console2.log("fulfil incl. final callback, gas:", g - gasleft());

        UniversalEvaluator.Evaluation memory e = ue.evaluationOf(jobId);
        assertTrue(e.done && e.applied);
        assertEq(uint8(e.verdict), uint8(Verdict.PASS));
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    /// @dev The common case: one read, one NUM check. What a provider's `submit` costs.
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
