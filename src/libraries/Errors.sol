// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title Errors
 * @dev  Library for custom errors used across all smart contracts
 */

// =========================
//           COMMON ERRORS across all smart contracts
// =========================

library CommonErrors {
    error ZeroAmount();
    error ZeroAddress();
    error InvalidOwner();
    error Unauthorized();
    error InvalidInput();
    error DeadlineExpired();
    error InsufficientBalance();
}

// =========================
//           PRC20-Specific ERRORS
// =========================

library PRC20Errors {
    error LowAllowance();
    error ZeroGasPrice();
    error InvalidSender();
    error GasFeeTransferFailed();
    error CallerIsNotUniversalExecutor();
}

// =========================
//           UNIVERSAL_CORE-Specific ERRORS
// =========================

library UniversalCoreErrors {
    error PoolNotFound();
    error InvalidTarget();
    error InvalidFeeTier();
    error SlippageExceeded();
    error CallerIsNotUEModule();
    error AutoSwapNotSupported();
    error InvalidSlippageTolerance();
}

// =========================
//           UEA-Specific ERRORS
// =========================
library UEAErrors {
    error InvalidCall();
    error InvalidTxHash();
    error InvalidAccount();
    error ExecutionFailed();
    error ExpiredDeadline();
    error InvalidInputArgs();
    error InvalidEVMSignature();
    error InvalidSVMSignature();
    error PrecompileCallFailed();
    error AccountAlreadyExists();
}
