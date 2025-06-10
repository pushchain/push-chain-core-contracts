// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title Errors
 * @dev Library for custom errors used across the UEAFactoryV1 contract and its dependencies
 */
library Errors {
    // Precompile related errors
    error PrecompileCallFailed();

    // Signature related errors
    error InvalidEVMSignature();
    error InvalidSVMSignature();

    // Execution related errors
    error ExecutionFailed();

    // Validation related errors
    error ExpiredDeadline();

    // Account related errors
    error InvalidAccount();
    error AccountAlreadyExists();

    // Owner related errors
    error InvalidOwner();

    // Input validation errors
    error InvalidInputArgs();
}
