// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// User Struct
struct UniversalAccountId {
    string chainNamespace;          // Chain namespace identifier of the owner account (e.g., "eip155" or "solana")
    string chainId;                 // Chain ID of the source chain of the owner of this UEA.
    bytes owner;                    // Owner's public key or address in bytes format
}

// UniversalPayload struct used internally by UEAs
// When calling executePayload, callers must encode this struct as: abi.encode(UniversalPayload({...}))
// The encoding layout is: (address, uint256, bytes, uint256, uint256, uint256, uint256, uint256)
struct UniversalPayload {
    address to;                     // Target contract address to call
    uint256 value;                  // Native token amount to send
    bytes data;                     // Call data for the function execution
    uint256 gasLimit;               // Maximum gas to be used for this tx (caps refund amount)
    uint256 maxFeePerGas;           // Maximum fee per gas unit
    uint256 maxPriorityFeePerGas;   // Maximum priority fee per gas unit
    uint256 nonce;                  // Nonce of the Transaction
    uint256 deadline;               // Timestamp after which this payload is invalid
}

struct MigrationPayload {
    address migration;              // Migration contract address to call
    uint256 nonce;                  // nonce of the UEA
    uint256 deadline;               // Timestamp after which this payload is invalid
}

struct Multicall {
    address to;                     // Target contract address to call
    uint256 value;                  // Native token amount to send
    bytes data;                     // Call data for the function execution
}

struct RevertInstructions {
    address fundRecipient;           // where funds go in revert / refund cases
    bytes revertContext;
}

// Magic Prefix for deciding if the payload is a Multicall
bytes4 constant MULTICALL_SELECTOR = bytes4(keccak256("UEA_MULTICALL"));

// Magic Prefix for migration requests
bytes4 constant MIGRATION_SELECTOR = bytes4(keccak256("UEA_MIGRATION"));

// Hash of keccak256("UniversalPayload(address to,uint256 value,bytes data,uint256 gasLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 nonce,uint256 deadline)")
bytes32 constant UNIVERSAL_PAYLOAD_TYPEHASH = 0x102a0b05d0844e7ea580bbdbe2cfe69c4fa4bfac4cf45919f6b24381a1235844;

// Hash of keccak256("MigrationPayload(address migration,uint256 nonce,uint256 deadline)")
bytes32 constant MIGRATION_PAYLOAD_TYPEHASH = 0xdf4902934e0ff647f420563d8015e84af8b95595f538c71618622fe3ea2bbb0c;
