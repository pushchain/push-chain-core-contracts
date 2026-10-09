// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {JobSpec} from "../libraries/JobSpecTypes.sol";
import {ReadConfig} from "./EvaluationTypes.sol";
import {AnswerDecoder} from "./AnswerDecoder.sol";
import {JobSpecRules} from "./JobSpecRules.sol";
import {ReadRequest} from "./ReadRequest.sol";
import {IUniversalCallback} from "../../interfaces/IUniversalCallback.sol";

/// @title UniversalEvaluatorLogic
/// @notice The UniversalEvaluator's stateless parts: checking a spec, pricing its reads, and reading one value out
///         of an answer.
/// @dev - No storage, not upgradeable. Split out for the EIP-170 size limit, as UniversalMarketplaceTerms is for the
///        marketplace. Each evaluator is fixed to one Logic; a rule change is a new Logic and a new evaluator.
///      - `decodeAnswer` is called with a gas cap inside `try`, so a decoder fault becomes "can't tell".
contract UniversalEvaluatorLogic {
    /// @notice Reverts with a `JobSpecErrors` error unless `spec` decodes as a `JobSpec` that can be judged.
    /// @param maxConfirmations The evaluator's ceiling on any read's `minConfirmations`.
    function validateSpec(bytes calldata spec, uint256 maxConfirmations) external pure {
        JobSpecRules.validate(abi.decode(spec, (JobSpec)), maxConfirmations);
    }

    /// @notice What a spec's reads cost at current Read State fees and base fee: the snapshot reads, and one round
    ///         of "after" reads.
    function readsCost(IUniversalCallback readState, ReadConfig calldata cfg, bytes calldata spec)
        external
        view
        returns (uint256 snapshot, uint256 evaluation)
    {
        JobSpec memory s = abi.decode(spec, (JobSpec));
        (bool[] memory need,) = JobSpecRules.snapshotReads(s);
        for (uint256 i; i < s.reads.length; ++i) {
            evaluation += ReadRequest.price(readState, s.reads[i], cfg.callbackGasLimit, cfg.budgetMultiplier);
            if (need[i]) {
                snapshot += ReadRequest.price(readState, s.reads[i], cfg.snapshotCallbackGasLimit, cfg.budgetMultiplier);
            }
        }
    }

    /// @notice The number to compare, from one answer.
    function decodeAnswer(bytes calldata outputs, uint8[] calldata field, bytes calldata res)
        external
        pure
        returns (bool, int256)
    {
        return AnswerDecoder.decode(outputs, field, res);
    }
}
