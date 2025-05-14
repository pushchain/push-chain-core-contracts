// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

enum OwnerType {
        EVM,
        NON_EVM
}
    // User Struct 
struct AccountId {
    string namespace;
    string chainId;
    bytes ownerKey; 
    OwnerType ownerType;
}

// TODO: Confirm the final implementation of the cross-chain payload
struct CrossChainPayload {
    // Core execution parameters
    address target;               // Target contract address to call
    uint256 value;                // Native token amount to send
    bytes data;                   // Call data for the function execution
    uint256 gasLimit;             // Maximum gas to be used for this tx (caps refund amount)
    uint256 maxFeePerGas;         // Maximum fee per gas unit
    uint256 maxPriorityFeePerGas; // Maximum priority fee per gas unit
    uint256 nonce;                // Chain ID where this should be executed
    uint256 deadline;             // Timestamp after which this payload is invalid
}

bytes32 constant DOMAIN_SEPARATOR_TYPEHASH = keccak256(
        "EIP712Domain(string version,uint256 chainId,address verifyingContract)"
    );

bytes32 constant PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH = keccak256(
        "CrossChainPayload(address target,uint256 value,bytes data,uint256 gasLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 nonce,uint256 deadline)"
    );