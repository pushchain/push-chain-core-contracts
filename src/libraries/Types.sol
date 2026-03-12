// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// =========================
//    TYPE DECLARATIONS
// =========================

/// @notice Identity of an external-chain account on Push Chain.
struct UniversalAccountId {
    string chainNamespace;              // Chain namespace (e.g., "eip155" or "solana")
    string chainId;                     // Chain ID of the source chain
    bytes owner;                        // Owner's public key or address in bytes
}

/// @notice Verification mode for UEA payload execution.
enum VerificationType {
    signedVerification,                 // Standard signature verification
    universalTxVerification             // Universal Executor Module (no signature)
}

// =========================
//    STRUCTS
// =========================

/// @notice Payload struct used internally by UEAs for execution.
struct UniversalPayload {
    address to;                         // Target contract address to call
    uint256 value;                      // Native token amount to send
    bytes data;                         // Call data for the function execution
    uint256 gasLimit;                   // Max gas for this tx (caps refund amount)
    uint256 maxFeePerGas;               // Maximum fee per gas unit
    uint256 maxPriorityFeePerGas;       // Maximum priority fee per gas unit
    uint256 nonce;                      // Nonce of the transaction
    uint256 deadline;                   // Timestamp after which payload is invalid
    VerificationType vType;             // Verification type before execution
}

/// @notice (Deprecated) Legacy migration payload — kept for test backward compatibility.
struct MigrationPayload {
    address migration;                  // Migration contract address to call
    uint256 nonce;                      // Nonce of the UEA
    uint256 deadline;                   // Timestamp after which payload is invalid
}

/// @notice Batch call entry for multicall execution.
struct Multicall {
    address to;                         // Target contract address to call
    uint256 value;                      // Native token amount to send
    bytes data;                         // Call data for the function execution
}

// =========================
//    CONSTANTS
// =========================

/// @dev Magic prefix for multicall batch payloads.
bytes4 constant MULTICALL_SELECTOR =
    bytes4(keccak256("UEA_MULTICALL"));

/// @dev Magic prefix for migration request payloads.
bytes4 constant MIGRATION_SELECTOR =
    bytes4(keccak256("UEA_MIGRATION"));

/// @dev EIP-712 typehash for UniversalPayload.
///      keccak256("UniversalPayload(address to,uint256 value,bytes data,uint256 gasLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 nonce,uint256 deadline,uint8 vType)")
bytes32 constant UNIVERSAL_PAYLOAD_TYPEHASH =
    0x1d8b43e5066bd20bfdacf7b8f4790c0309403b18434e3699ce3c5e57502ed8c4;

/// @dev (Deprecated) EIP-712 typehash for MigrationPayload.
///      keccak256("MigrationPayload(address migration,uint256 nonce,uint256 deadline)")
bytes32 constant MIGRATION_PAYLOAD_TYPEHASH =
    0xdf4902934e0ff647f420563d8015e84af8b95595f538c71618622fe3ea2bbb0c;
