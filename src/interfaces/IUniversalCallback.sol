// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ReadSpec, RequestStatus} from "../libraries/ReadTypes.sol";

interface IUniversalCallback {
    /// @notice Emitted when a read is requested. `protocolFee` has ALREADY been
    ///         forwarded to VaultPC by the time this fires; only `callbackBudget`
    ///         remains held by the contract.
    /// @dev    `callbackGasLimit` is not part of `readSpec`, so it is emitted
    ///         separately -- observers need it to reproduce the execution bound.
    event ReadRequested(
        uint256 indexed requestId,
        ReadSpec readSpec,
        address indexed callbackTarget,
        address indexed originalFunder,
        uint64 callbackGasLimit,
        uint256 totalPaid,
        uint256 protocolFee,
        uint256 callbackBudget
    );

    /// @notice Emitted when the callback ran successfully.
    /// @dev    NO money moves at fulfillment. The request sits in EXECUTED until
    ///         the module reports consumed gas.
    event ReadFulfilled(
        uint256 indexed requestId,
        bytes resultData,
        uint64 observedBlockHeight,
        bytes32 observedBlockHash
    );

    /// @notice Emitted when the callback reverted. Financially identical to
    ///         success -- the request still awaits a gas report.
    event CallbackFailed(uint256 indexed requestId, bytes reason);

    /// @notice Emitted when the protocol fee is forwarded to VaultPC at request time.
    event ProtocolFeeDistributed(
        uint256 indexed requestId,
        address indexed vaultPC,
        uint256 amount
    );

    /// @notice Emitted when the module reports gas consumed by a callback.
    /// @param gasReported  Raw amount the module reported
    /// @param burned       Amount after clamping to the request's budget
    /// @param refunded     Unspent budget credited to the revert recipient
    event CallbackGasReported(
        uint256 indexed requestId,
        uint256 gasReported,
        uint256 burned,
        uint256 refunded
    );

    /// @notice Emitted when unattributed native PC is rescued from the contract.
    event NativePCRescued(address indexed to, uint256 amount);

    /// @notice Emitted when unspent callback budget is pushed to the revert
    ///         recipient.
    event RefundSent(
        uint256 indexed requestId,
        address indexed recipient,
        uint256 amount
    );

    /// @notice Emitted when the refund push was rejected by its recipient. The
    ///         request still settles; the PC stays recoverable via rescueNativePC.
    event RefundFailed(
        uint256 indexed requestId,
        address indexed recipient,
        uint256 amount
    );

    /// @notice Emitted when an unexecuted request expires and its full budget is
    ///         refunded. The protocol fee is NOT refunded.
    event RequestExpired(
        uint256 indexed requestId,
        address indexed revertRecipient,
        uint256 refunded
    );

    event DomainUpdated(string chainNamespace, string chainId, bool supported);

    /// @notice                 Request an external chain read.
    /// @dev                    `msg.value` must be at least the protocol fee. Any
    ///                         excess becomes the callback budget, which caps what
    ///                         the module may burn for callback execution.
    /// @param spec             Read parameters, including the revert recipient
    /// @param callbackSelector Selector invoked on the caller with the result
    /// @param callbackGasLimit Execution bound for the callback
    function requestExternalReadSelf(
        ReadSpec calldata spec,
        bytes4 callbackSelector,
        uint64 callbackGasLimit
    ) external payable returns (uint256 requestId);

    /// @notice     Execute the callback with the read result. Moves no money;
    ///             leaves the request in EXECUTED awaiting `reportCallbackGas`.
    function fulfillExternalCallback(
        uint256 requestId,
        bytes calldata resultData,
        uint64 observedBlockHeight,
        bytes32 observedBlockHash
    ) external;

    /// @notice             Report gas consumed by an executed callback and settle.
    /// @dev                Performs NO burn. The caller MUST burn exactly the
    ///                     returned `burned` value -- recomputing it independently
    ///                     bypasses the budget clamp -- and MUST NOT invoke any
    ///                     other function on this contract before doing so.
    /// @param gasBurned    Raw gas cost the module measured
    /// @return burned      `gasBurned` clamped to the request's callback budget
    function reportCallbackGas(uint256 requestId, uint256 gasBurned)
        external
        returns (uint256 burned);

    /// @notice     Expire an unexecuted request and refund its full budget.
    ///             Only valid from PENDING. The protocol fee is not refunded.
    function expireExternalRead(uint256 requestId) external;

    /// @notice     Exact minimum `msg.value` for a request on this domain. Send
    ///             MORE than this -- the excess funds callback execution.
    function estimateFee(string calldata chainNamespace, string calldata chainId)
        external
        view
        returns (uint256);

    /// @notice     True once a request can never execute again (EXECUTED, SETTLED
    ///             or EXPIRED). Note EXECUTED returns true before money has moved.
    function isFulfilled(uint256 requestId) external view returns (bool);

    /// @notice     Precise lifecycle state of a request.
    function statusOf(uint256 requestId) external view returns (RequestStatus);

    /// @notice         Total callback budget held for requests that have not settled.
    ///                 Excludes protocol fees, which leave at request time.
    function totalEscrowed() external view returns (uint256);
}
