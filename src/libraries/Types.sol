// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

enum VM_TYPE {
    UNREGISTERED, // 0 = default, unregistered state
    EVM,          // 1 = first VM type: EVM
    SVM,          // 2 = second VM type: SVM
    MOVE_VM,      // 3 = third VM type: MOVE
    WASM_VM,      // 4 = fourth VM type: WASM
    CAIRO_VM,     // 5 = fifth VM type: CAIRO
    OTHER_VM      // 6 = sixth VM type: OTHER
}
// User Struct

struct UniversalAccount {
    string CHAIN;
    bytes ownerKey;
}

// TODO: Confirm the final implementation of the cross-chain payload
struct CrossChainPayload {
    // Core execution parameters
    address to; // Target contract address to call
    uint256 value; // Native token amount to send
    bytes data; // Call data for the function execution
    uint256 gasLimit; // Maximum gas to be used for this tx (caps refund amount)
    uint256 maxFeePerGas; // Maximum fee per gas unit
    uint256 maxPriorityFeePerGas; // Maximum priority fee per gas unit
    uint256 nonce; // Chain ID where this should be executed
    uint256 deadline; // Timestamp after which this payload is invalid
}

// Hash of keccak256("EIP712Domain(string version,uint256 chainId,address verifyingContract)")
bytes32 constant DOMAIN_SEPARATOR_TYPEHASH = 0x2aef22f9d7df5f9d21c56d14029233f3fdaa91917727e1eb68e504d27072d6cd;

// Hash of keccak256("CrossChainPayload(address target,uint256 value,bytes data,uint256 gasLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 nonce,uint256 deadline)")
bytes32 constant PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH =  0x023879d5ed9344552f20a12794e69a155bede5080ec43d77c6d1a177ab4aac9f;
