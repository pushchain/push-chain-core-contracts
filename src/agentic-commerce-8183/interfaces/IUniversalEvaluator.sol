// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IUniversalEvaluator
/// @notice What the UniversalHook calls on the evaluator. The state-changing functions only accept calls from the hook.
interface IUniversalEvaluator {
    /// @notice Store a replacement spec (the provider's, from setBudget). Reverts once the spec is frozen.
    function setSpec(uint256 jobId, bytes calldata spec) external;

    /// @notice The stored replacement spec, or empty if none.
    function currentSpec(uint256 jobId) external view returns (bytes memory);

    /// @notice Freeze this spec and fire the "before" reads from the client's prepaid PC.
    function startSnapshot(uint256 jobId, bytes calldata spec) external;

    /// @notice Fix the end blocks and send the "after" reads from prepaid PC (called from submit). Reverts if the
    ///         end blocks can't be fixed; a failure to send the reads is caught inside.
    function verifyFromSubmit(uint256 jobId) external;
}
