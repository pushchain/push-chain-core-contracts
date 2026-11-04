// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IAGWRenewal
/// @notice The AGW door the UniversalHook uses to run a series' later periods on the wallet's behalf.
/// @dev - Not in the AGW yet: this is the shape the hook expects. The wallet's renewal rule should allow only the
///        hook, and only these calls: `kernel.createJob`, `paymentToken.approve(kernel, …)`, `evaluator.prefund`,
///        `kernel.fund`.
///      - Not an owner call, so the AGW's checkpoint counter does not move.
interface IAGWRenewal {
    /// @notice Calls `target` from the wallet. Reverts with the call's revert data.
    /// @return result The call's return data.
    function executeRenewal(address target, uint256 value, bytes calldata data) external returns (bytes memory result);
}
