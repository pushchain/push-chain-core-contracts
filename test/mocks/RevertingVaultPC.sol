// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @dev Vault that refuses every incoming transfer. Used to prove that an
///      unreceptive vault degrades the protocol fee to an accrual instead of
///      bricking fulfillment and expiry.
contract RevertingVaultPC {
    error VaultRefuses();

    receive() external payable {
        revert VaultRefuses();
    }
}
