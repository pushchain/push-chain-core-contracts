// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ReadSpec} from "../libraries/ReadTypes.sol";

interface IUniversalCallback {
    event ReadRequested(
        uint256 indexed requestId,
        ReadSpec readSpec,
        address indexed callbackTarget,
        address indexed originalFunder,
        uint256 feesDeposited
    );

    event ReadFulfilled(
        uint256 indexed requestId,
        bytes resultData,
        uint64 observedBlockHeight,
        bytes32 observedBlockHash
    );

    event CallbackFailed(uint256 indexed requestId, bytes reason);

    event ProtocolFeeDistributed(
        uint256 indexed requestId,
        address indexed vaultPC,
        uint256 amount
    );

    event FeeRefunded(
        uint256 indexed requestId,
        address indexed recipient,
        uint256 amount
    );

    event RequestExpired(uint256 indexed requestId, address indexed originalFunder);

    event DomainUpdated(string chainNamespace, string chainId, bool supported);

    function requestExternalReadSelf(
        ReadSpec calldata spec,
        bytes4 callbackSelector,
        uint64 callbackGasLimit
    ) external payable returns (uint256 requestId);

    function fulfillExternalCallback(
        uint256 requestId,
        bytes calldata resultData,
        uint64 observedBlockHeight,
        bytes32 observedBlockHash
    ) external;

    function expireExternalRead(uint256 requestId) external;

    function estimateFee(
        string calldata chainNamespace,
        string calldata chainId,
        uint64 callbackGasLimit
    ) external view returns (uint256);

    function isFulfilled(uint256 requestId) external view returns (bool);
}
