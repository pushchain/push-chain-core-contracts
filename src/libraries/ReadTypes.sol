// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalAccountId} from "./Types.sol";

/// @notice Lifecycle of a read request.
/// @dev    `NONE` MUST remain the zero value. Every never-created requestId reads
///         as zero, so a non-zero default would make phantom requests
///         indistinguishable from live ones.
enum RequestStatus {
    NONE,
    PENDING,
    EXECUTED,
    SETTLED,
    EXPIRED
}

struct ReadSpec {
    UniversalAccountId account;
    bytes query;
    uint16 minConfirmations;
    uint64 blockNumber;
    uint64 expiryPushChainHeight;
    uint256 maxFee;
    address revertRecipient;
}

/// @dev Field order is packed deliberately into 4 slots -- do not reorder:
///      slot 0: callbackTarget(20) + callbackSelector(4) + callbackGasLimit(8) = 32
///      slot 1: originalFunder(20) + expiryHeight(8)
///      slot 2: revertRecipient(20)
///      slot 3: callbackBudget(32)
struct PendingRead {
    address callbackTarget;
    bytes4 callbackSelector;
    uint64 callbackGasLimit;
    address originalFunder;
    uint64 expiryHeight;
    address revertRecipient;
    uint256 callbackBudget; // Deposit remaining after the protocol fee was paid at request time.
}

uint16 constant MIN_CONFIRMATIONS_FLOOR = 1;

/// @dev Bounds how much gas a single untrusted callback may consume. Callback
///      execution is gasless at the tx-fee layer, so this is a SECURITY bound
///      against validator DoS, not an economic one -- a request funded at exactly
///      the protocol fee has a zero budget yet still gets up to this much
///      execution without burning anything.
uint64 constant MAX_CALLBACK_GAS_LIMIT = 1_000_000;

bytes32 constant BALLOT_OBSERVATION_TYPE_READ_REQUEST =
    0x3dad9a0dab4bc2ca7e2432bbf434133fe2c77f05558c96d0e819259172a4ce36;
