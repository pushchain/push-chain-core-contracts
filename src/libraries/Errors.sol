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

library UniversalCoreErrors {
    // Authentication errors
    error CallerIsNotUEModule();
    error CallerIsNotOwner();
    
    // Target validation errors
    error InvalidTarget();
    error AutoSwapNotSupported();
    
    // Address validation errors
    error CantBeIdenticalAddresses();
    error CantBeZeroAddress();
    error ZeroAddress();
    error ZeroAmount();
    
    // Pool related errors
    error PoolNotFound();
    error TokenMismatch();
    
    // Swap related errors
    error SlippageExceeded();
    error DeadlineExpired();
    
    // Default value errors
    error InvalidFeeTier();
    error InvalidSlippageTolerance();
}

library PRC20Errors {
    // Authentication errors
    error CallerIsNotUniversalExecutor();
    error InvalidSender();          // deposit() not from allowed caller
    
    // Transfer related errors
    error GasFeeTransferFailed();
    error LowAllowance();
    error LowBalance();
    
    // Gas related errors
    error ZerogasToken();
    error ZeroGasPrice();
    
    // Input validation errors
    error ZeroAddress();
    error ZeroAmount();
}

library CommonErrors {
    // Common errors
    error ZeroAddress();
    error InvalidInput();
    error Unauthorized();
}