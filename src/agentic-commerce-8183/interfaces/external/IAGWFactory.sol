// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IAGWFactory
/// @notice Read-only mirror of the Push Agentic Wallet factory.
/// @dev - Source: `push-agentic-wallets@67929f2`, `src/AGWFactory.sol:208`.
///      - Donut proxy: `0x2578041963f692f8b51A137A1c7ddc0c84a8226A` (deploy-time input, never a constant).
interface IAGWFactory {
    /// @notice True only for wallets this factory deployed.
    /// @param account Address to test.
    /// @return Whether it is an AGW.
    function isWallet(address account) external view returns (bool);
}
