// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {UniversalEvalBase} from "./UniversalEvalBase.t.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {UniversalEvaluatorLogic} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluatorLogic.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {IUniversalEvaluator} from "../../src/agentic-commerce-8183/interfaces/IUniversalEvaluator.sol";

/// @notice The hook design's `_postSubmit`, as written there: `verifyFromSubmit` inside try/catch, so `submit` never
///         fails on it. Test-only; everything else is the shipped UniversalHook.
contract DesignSubmitHook is UniversalHook {
    /// @notice The design's event for a skipped verify (the shipped hook no longer has it).
    event AutoVerifySkipped(uint256 indexed jobId);

    function _postSubmit(uint256 jobId, address, bytes32, bytes memory) internal override {
        if (IAgenticCommerce(KERNEL).getJob(jobId).evaluator != EVALUATOR) return;
        try IUniversalEvaluator(EVALUATOR).verifyFromSubmit(jobId) {} // never blocks submit
            catch {
            emit AutoVerifySkipped(jobId); // e.g. not enough prepaid: verify by hand
        }
    }
}

/// @notice Why the shipped hook calls `verifyFromSubmit` without try/catch: this suite runs the design's version and
///         shows the problem. The shipped version's guarantee is `test_UE26_submitNeverSucceedsWithoutEndBlocks`.
contract UniversalHookDesignProofsTest is UniversalEvalBase {
    event AutoVerifySkipped(uint256 indexed jobId);

    /// @dev The fixture's pair, with the hook running the design's `_postSubmit`.
    function _deployPair() internal override {
        logic = new UniversalEvaluatorLogic();
        DesignSubmitHook hookImpl = new DesignSubmitHook();
        address predictedEvaluator = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        bytes memory hookInit = abi.encodeCall(
            UniversalHook.initialize, (address(kernel), address(factory), address(engine), predictedEvaluator)
        );
        hook = UniversalHook(address(new TransparentUpgradeableProxy(address(hookImpl), proxyAdminOwner, hookInit)));
        ue = new UniversalEvaluator(
            address(kernel), address(hook), address(readState), address(core), address(logic), feeRecipient, _config()
        );
        require(address(ue) == predictedEvaluator, "evaluator address prediction");
    }

    /// @dev With the try/catch, a provider that sends just enough gas makes the evaluator call run out inside `submit`;
    ///      the catch swallows it and `submit` succeeds: the job is Submitted with no end blocks. The design then let
    ///      the provider fix them later, at a moment of its choosing (`sendReads`), so "fixed at submit" didn't hold.
    function test_DP01_designTryCatch_letsStarvedSubmitThroughWithoutEndBlocks() public {
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        _answerSnapshot(jobId, 0, 0);
        _advance();
        bytes memory submitCall = abi.encodeCall(kernel.submit, (jobId, keccak256("done"), bytes("")));

        uint256 starved;
        for (uint256 g = 30_000; g < 900_000; g += 500) {
            uint256 snap = vm.snapshotState();
            vm.prank(provider);
            (bool ok,) = address(kernel).call{gas: g}(submitCall);
            bool fixed_ = ue.evaluationOf(jobId).endFixed;
            vm.revertToState(snap);
            if (ok && !fixed_) {
                starved = g;
                break;
            }
        }
        assertTrue(starved != 0, "no gas level lets submit through without end blocks");

        vm.expectEmit(true, false, false, false, address(hook));
        emit AutoVerifySkipped(jobId);
        vm.prank(provider);
        (bool submitted,) = address(kernel).call{gas: starved}(submitCall);
        assertTrue(submitted, "submit succeeded");
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Submitted));
        assertFalse(ue.evaluationOf(jobId).endFixed, "with no end blocks fixed");
    }
}
