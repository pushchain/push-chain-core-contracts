// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IUniversalScheduler
/// @notice Push's scheduler: the chain calls `target` with `data` once `executeAt` has passed. The UniversalHook books
///         each period's `renew` and `fundNext` with it.
interface IUniversalScheduler {
    /// @notice Books one call.
    /// @return id The booking's id.
    function schedule(address target, bytes calldata data, uint64 executeAt) external returns (uint256 id);
}
