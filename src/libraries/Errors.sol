// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title Errors
 * @dev  Library for custom errors used across all smart contracts
 */

// =========================
//           COMMON ERRORS
// =========================

library CommonErrors {
    error ZeroAmount();
    error ZeroAddress();
    error InvalidOwner();
    error Unauthorized();
    error InvalidInput();
    error DeadlineExpired();
    error InsufficientBalance();
    error TransferFailed();
}

// =========================
//           PRC20-Specific ERRORS
// =========================

library PRC20Errors {
    error LowAllowance();
    error InvalidSender();
    error CallerIsNotUniversalExecutor();
}

// =========================
//           UNIVERSAL_CORE-Specific ERRORS
// =========================

library UniversalCoreErrors {
    error ZeroGasPrice();
    error PoolNotFound();
    error InvalidTarget();
    error InvalidFeeTier();
    error SlippageExceeded();
    error CallerIsNotUEModule();
    error CallerIsNotGatewayPC();
    error AutoSwapNotSupported();
    error InvalidSlippageTolerance();
    error MinPCOutRequired();
    error GasLimitBelowBase(uint256 provided, uint256 minimum);
}

// =========================
//           UEA-Specific ERRORS
// =========================
library UEAErrors {
    error InvalidCall();
    error InvalidTxHash();
    error ExecutionFailed();
    error ExpiredDeadline();
    error InvalidInputArgs();
    error InvalidEVMSignature();
    error InvalidSVMSignature();
    error PrecompileCallFailed();
    error AccountAlreadyExists();
}

library CEAErrors {
    error AlreadyInitialized();
    error ZeroAddress();
    error NotVault();
    error InvalidTarget();
    error InsufficientBalance();
    error PayloadExecuted();
    error InvalidUEA();
    error InvalidInput();
    error ExecutionFailed();
    error InvalidCall();
    error InvalidRecipient();
}
