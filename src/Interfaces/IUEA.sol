// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalAccountId, UniversalPayload, MigrationPayload} from "../libraries/Types.sol";

/// @title  IUEA (Interface for Universal Executor Account)
/// @notice Interface that all Universal Executor Accounts (UEA) must implement.
/// @dev    A UEA is a smart contract proxy for external chain users on Push Chain.
///         UEA implementation logic varies by external chain type:
///         UEA_EVM for Ethereum, UEA_SVM for Solana.
interface IUEA {
    // =========================
    //    UEA: EVENTS
    // =========================

    /// @notice                  Emitted when a payload is successfully executed.
    /// @param caller            External chain address (UOA) that initiated execution
    /// @param nonce             Nonce of the executed payload
    event PayloadExecuted(bytes caller, uint256 nonce);

    // =========================
    //    UEA_1: VIEW FUNCTIONS
    // =========================

    /// @notice             Returns the version of the UEA.
    /// @return             Version string
    function VERSION() external view returns (string memory);

    /// @notice             Returns the Universal Account information for this UEA.
    /// @return             UniversalAccountId containing chain info and owner key
    function universalAccount()
        external
        view
        returns (UniversalAccountId memory);

    /// @notice             Returns the current nonce.
    /// @return             Current nonce value
    function nonce() external view returns (uint256);

    /// @notice             Verifies a signature for a given payload hash.
    /// @dev                EVM: ECDSA recovery. SVM: Ed25519 via precompile.
    /// @param payloadHash  Hash of the payload that was signed
    /// @param signature    Signature bytes to verify
    /// @return             True if the signature is valid
    function verifyPayloadSignature(
        bytes32 payloadHash,
        bytes memory signature
    ) external view returns (bool);

    /// @notice             Computes the EIP-712 hash for a given payload.
    /// @param payload      The UniversalPayload to hash
    /// @return             EIP-712 compliant hash
    function getPayloadHash(
        UniversalPayload calldata payload
    ) external view returns (bytes32);

    /// @notice             Computes the EIP-712 hash for a given migration payload.
    /// @param payload      The MigrationPayload to hash
    /// @return             EIP-712 compliant hash
    function getMigrationPayloadHash(
        MigrationPayload memory payload
    ) external view returns (bytes32);

    /// @notice             Returns the EIP-712 domain separator.
    /// @return             Domain separator hash
    function domainSeparator() external view returns (bytes32);

    // =========================
    //    UEA_2: EXECUTION
    // =========================

    /// @notice             Executes a cross-chain payload with verification data.
    /// @param payload      The UniversalPayload struct (see Types.sol)
    /// @param verificationData    Signature bytes or tx-hash verification bytes
    function executePayload(
        UniversalPayload calldata payload,
        bytes calldata verificationData
    ) external;

    /// @notice             Executes UEA migration through delegatecall.
    /// @param payload      The MigrationPayload containing migration target and deadline
    /// @param signature    Signature authorizing the migration payload
    function migrateUEA(
        MigrationPayload calldata payload,
        bytes calldata signature
    ) external;

    // =========================
    //    UEA_3: INITIALIZER
    // =========================

    /// @notice                     Initializes the UEA with Universal Account info.
    /// @dev                        Can only be called once during deployment via Factory.
    /// @param universalAccount     UniversalAccountId with chain info and owner key
    function initialize(
        UniversalAccountId memory universalAccount
    ) external;
}
