// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title Errors
 * @dev Library for custom errors used across the UEAFactoryV1 contract and its dependencies
 */
library UEAErrors {
    // Precompile related errors
    error PrecompileCallFailed();

    // Signature related errors
    error InvalidEVMSignature();
    error InvalidSVMSignature();
    error InvalidTxHash();

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

    // Common Errors
    error InvalidCall();
}

library HandlerErrors {
    error CallerIsNotFungibleModule();
    error InvalidTarget();
    error CantBeIdenticalAddresses();
    error CantBeZeroAddress();
    error ZeroAddress();
    error PoolNotFound();
    error TokenMismatch();
    error SlippageExceeded();
    error DeadlineExpired();
}

library PRC20Errors {
    error CallerIsNotUniversalExecutor();
    error InvalidSender(); // deposit() not from allowed caller
    error GasFeeTransferFailed();
    error ZerogasToken();
    error ZeroGasPrice();
    error LowAllowance();
    error LowBalance();
    error ZeroAddress();
    error ZeroAmount();
}
