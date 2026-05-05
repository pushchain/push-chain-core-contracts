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
    error CorePaused();
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
    error MinPCOutRequired();
    error GasLimitBelowBase(uint256 provided, uint256 minimum);
    error ZeroBaseGasLimit();
    error ZeroRescueGasLimit();
    error StaleGasData(uint256 observedAt, uint256 nowTimestamp, uint256 maxAge);
    error PRC20OperationFailed();
}

// =========================
//           WPC-Specific ERRORS
// =========================

library StringUtilsErrors {
    error EmptyString();
    error NonDigitCharacter();
}

library WPCErrors {
    error InsufficientBalance();
    error InsufficientAllowance();
    error TransferFailed();
}

// =========================
//           UEA-Specific ERRORS
// =========================
library UEAErrors {
    error InvalidCall();
    error ExecutionFailed();
    error ExpiredDeadline();
    error InvalidInputArgs();
    error InvalidEVMSignature();
    error InvalidSVMSignature();
    error NonceMismatch(uint256 expected, uint256 provided);
    error PrecompileCallFailed();
    error AccountAlreadyExists();
    error UEAAlreadyRegistered();
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
    error InvalidImplementation();
    error CEAAlreadyDeployed();
}
