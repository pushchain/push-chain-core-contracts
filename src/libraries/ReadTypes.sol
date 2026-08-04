// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalAccountId} from "./Types.sol";

struct ReadSpec {
    UniversalAccountId account;
    bytes query;
    uint16 minConfirmations;
    uint64 blockNumber;
    uint64 expiryPushChainHeight;
    uint256 maxFee;
}

struct PendingRead {
    address callbackTarget;
    bytes4 callbackSelector;
    uint64 callbackGasLimit;
    address originalFunder;
    uint256 feesDeposited;
    uint256 protocolFee;
    uint64 expiryHeight;
}

uint16 constant MIN_CONFIRMATIONS_FLOOR = 1;

uint64 constant MAX_CALLBACK_GAS_LIMIT = 1_000_000;

bytes32 constant BALLOT_OBSERVATION_TYPE_READ_REQUEST =
    0x3dad9a0dab4bc2ca7e2432bbf434133fe2c77f05558c96d0e819259172a4ce36;
