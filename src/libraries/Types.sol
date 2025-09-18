// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// User Struct
struct UniversalAccountId {
    string chainNamespace; // Chain namespace identifier of the owner account (e.g., "eip155" or "solana")
    string chainId; // Chain ID of the source chain of the owner of this UEA.
    bytes owner; // Owner's public key or address in bytes format
}

// Signature verification types
enum VerificationType {
    signedVerification,
    universalTxVerification
}

struct UniversalPayload {
    // Core execution parameters
    address to; // Target contract address to call
    uint256 value; // Native token amount to send
    bytes data; // Call data for the function execution
    uint256 gasLimit; // Maximum gas to be used for this tx (caps refund amount)
    uint256 maxFeePerGas; // Maximum fee per gas unit
    uint256 maxPriorityFeePerGas; // Maximum priority fee per gas unit
    uint256 nonce; // Chain ID where this should be executed
    uint256 deadline; // Timestamp after which this payload is invalid
    VerificationType vType; // Type of verification to use before execution (signedVerification or universalTxVerification)
}

// Multicall
struct Multicall {
    address to; // Target contract address to call
    uint256 value; // Native token amount to send
    bytes data; // Call data for the function execution
}

// Hash of keccak256("UniversalPayload(address to,uint256 value,bytes data,uint256 gasLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 nonce,uint256 deadline,uint8 vType)")
bytes32 constant UNIVERSAL_PAYLOAD_TYPEHASH = 0x1d8b43e5066bd20bfdacf7b8f4790c0309403b18434e3699ce3c5e57502ed8c4;
