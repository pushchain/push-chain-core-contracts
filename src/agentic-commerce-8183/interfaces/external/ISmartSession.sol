// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title ISmartSession
/// @notice Read-only mirror of the SmartSession engine used by Push AGWs.
/// @dev - Source: SmartSession fork `7dc20e4`, `SmartSessionBase.sol:444`.
///      - `PermissionId` is a user-defined `bytes32`; the ABI is plain `bytes32`.
///      - The id comes FIRST here, unlike the engine's other views.
///      - Donut engine: `0x046B2874Fc9F920ad53A317b3cf9d3d1974466f3` (deploy-time input).
interface ISmartSession {
    /// @notice Whether a rules set is live on an account.
    /// @param permissionId The rules set's id (the AGW's `rulesId`; the engine names it `permissionId`).
    /// @param account The wallet.
    /// @return Whether the permission is enabled.
    function isPermissionEnabled(bytes32 permissionId, address account) external view returns (bool);
}
