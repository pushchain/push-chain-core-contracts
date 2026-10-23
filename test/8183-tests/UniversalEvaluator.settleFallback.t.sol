// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {UniversalEvalBase} from "./UniversalEvalBase.t.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {Verdict} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";

/// @notice The shipped hook, plus a switch that makes `afterAction(complete)` burn all its gas: a stand-in for a
///         kernel or hook that grew too heavy for the callback. Test-only.
contract HeavyCompleteHook is UniversalHook {
    bool public heavy;

    function setHeavy(bool heavy_) external {
        heavy = heavy_;
    }

    function _postComplete(uint256, address, bytes32, bytes memory) internal view override {
        while (heavy) {}
    }
}

/// @notice A kernel `complete` that runs out of gas inside the final callback costs the callback nothing: the verdict
///         is stored before the kernel call, which keeps 1/64 of the gas, so the callback still succeeds and anyone
///         can `settle` it later.
contract UniversalEvaluatorSettleFallbackTest is UniversalEvalBase {
    event SettleFailed(uint256 indexed jobId, bytes reason);

    function _deployPair() internal override {
        HeavyCompleteHook hookImpl = new HeavyCompleteHook();
        address predictedEvaluator = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        bytes memory hookInit = abi.encodeCall(
            UniversalHook.initialize, (address(kernel), address(factory), address(engine), predictedEvaluator)
        );
        hook = UniversalHook(address(new TransparentUpgradeableProxy(address(hookImpl), proxyAdminOwner, hookInit)));
        ue = new UniversalEvaluator(
            address(kernel), address(hook), address(readState), address(core), feeRecipient, _config()
        );
        require(address(ue) == predictedEvaluator, "evaluator address prediction");
    }

    function test_UE40_completeOutOfGas_verdictStored_settleLater() public {
        uint256 jobId = _submittedSwap(0);
        HeavyCompleteHook(address(hook)).setHeavy(true);

        vm.recordLogs();
        _answer(jobId, 0, abi.encode(uint256(0.4e18))); // decides PASS
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool settleFailed;
        for (uint256 i; i < logs.length; ++i) {
            assertTrue(
                logs[i].emitter != address(readState)
                    || logs[i].topics[0] != IUniversalCallback.CallbackFailed.selector,
                "the callback itself failed"
            );
            if (logs[i].emitter == address(ue) && logs[i].topics[0] == SettleFailed.selector) settleFailed = true;
        }
        assertTrue(settleFailed, "SettleFailed");

        UniversalEvaluator.Evaluation memory e = ue.evaluationOf(jobId);
        assertTrue(e.done);
        assertEq(uint8(e.verdict), uint8(Verdict.PASS));
        assertFalse(e.applied);
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Submitted));

        HeavyCompleteHook(address(hook)).setHeavy(false);
        vm.prank(stranger);
        ue.settle(jobId);
        assertTrue(ue.evaluationOf(jobId).applied);
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }
}
