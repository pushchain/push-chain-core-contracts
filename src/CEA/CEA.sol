// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ICEA} from "../interfaces/ICEA.sol";
import {CEAErrors} from "../libraries/Errors.sol";
import {IUniversalGateway,
            UniversalTxRequest,
                RevertInstructions} from "../interfaces/IUniversalGateway.sol";
import {Multicall, MULTICALL_SELECTOR} from "../libraries/Types.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title   CEA
 * @notice  Chain Executor Account implementation (v1).
 *
 * @dev
 *  - Intended to be deployed behind a minimal proxy (Clones) by CEAFactory.
 *  - Represents a single UEA on Push Chain on a specific external EVM chain.
 *  - In v1:
 *      * Only Vault may call state-changing functions.
 *      * CEA can:
 *          - execute calls to external protocols using ERC20 balances it holds.
 *          - send tokens back to Vault when requested.
 *      * No direct user / EOA interaction. No signatures. No owner.
 */
contract CEA is ICEA, ReentrancyGuard {
    using SafeERC20 for IERC20;

    //========================
    //           State
    //========================

    /// @inheritdoc ICEA
    address public UEA;
    /// @inheritdoc ICEA
    address public VAULT;
    /// @notice Address of the Universal Gateway contract of the respective chain.
    address public UNIVERSAL_GATEWAY;

    bool private _initialized;

    /// @notice Mapping from txID to bool to check if the tx has been executed
    mapping (bytes32 => bool) public isExecuted;

    //========================
    //        Modifiers
    //========================

    modifier onlyVault() {
        if (msg.sender != VAULT) revert CEAErrors.NotVault();
        _;
    }

    //========================
    //        Views
    //========================

    /// @inheritdoc ICEA
    function isInitialized() external view override returns (bool) {
        return _initialized;
    }

    //========================
    //       Initializer
    //========================

    /// @notice         Initializes this CEA with its UEA identity, Vault and Universal Gateway.
    /// @param _uea     Address of the UEA contract on Push Chain.
    /// @param _vault   Address of the Vault contract on this chain.
    /// @param _universalGateway Address of the Universal Gateway contract of the respective chain.
    function initializeCEA(address _uea, address _vault, address _universalGateway) external {
            if (_initialized) revert CEAErrors.AlreadyInitialized();
        if (_uea == address(0) || 
            _vault == address(0) || 
                _universalGateway == address(0)) revert CEAErrors.ZeroAddress();

        UEA = _uea;
        VAULT     = _vault;
        UNIVERSAL_GATEWAY = _universalGateway;

        _initialized = true;

    }

    //========================
    //      Vault-only ops
    //========================

    /// @notice         Executes a universal transaction.
    /// @dev            Payload can be either:
    ///                 - MULTICALL: payload starts with MULTICALL_SELECTOR + ABI-encoded Multicall[]
    ///                 - SINGLE CALL: raw bytes data for a single call
    ///                 SDK is responsible for crafting correct payload format.
    /// @param txID             Unique transaction identifier (must not be executed before)
    /// @param universalTxID    Universal transaction identifier for cross-chain tracking
    /// @param originCaller     Address of the origin caller (must be UEA)
    /// @param payload          Either multicall or single call payload
    function executeUniversalTx(
        bytes32 txID,
        bytes32 universalTxID,
        address originCaller,
        bytes calldata payload
    ) external payable onlyVault nonReentrant {
        // Top-level validation
        if (isExecuted[txID]) revert CEAErrors.PayloadExecuted();
        if (originCaller != UEA) revert CEAErrors.InvalidUEA();

        isExecuted[txID] = true;

        _handleExecution(txID, universalTxID, originCaller, payload);
    }

    /// @notice         Sends a universal transaction from CEA to its UEA on Push Chain.
    /// @dev            Only callable via self-call through multicall execution (msg.sender == address(this)).
    ///                 For ERC20 tokens, SDK must include approval steps in multicall before this call.
    /// @param token            Token address (address(0) for native)
    /// @param amount           Amount to send
    /// @param payload          Optional payload data to send with the transaction (for execution on UEA)
    /// @param signatureData    Optional signature data to send with the transaction
    function sendUniversalTxToUEA(
        address token,
        uint256 amount,
        bytes calldata payload,
        bytes calldata signatureData
    ) external {
        // Enforce: Only CEA can call this function via self-call
        if (msg.sender != address(this)) revert CEAErrors.NotVault();

        if (amount == 0) revert CEAErrors.InvalidInput();

        UniversalTxRequest memory req = UniversalTxRequest({
            recipient: UEA,
            token: token,
            amount: amount,
            payload: payload,
            revertInstruction: RevertInstructions({
                fundRecipient: UEA,
                revertMsg: ""
            }),
            signatureData: signatureData
        });

        if (token == address(0)) {
            if (address(this).balance < amount) revert CEAErrors.InsufficientBalance();
            IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTx{value: amount}(req);
        } else {
            if (IERC20(token).balanceOf(address(this)) < amount) revert CEAErrors.InsufficientBalance();
            // Note: SDK must have included ERC20 approval in multicall before this call
            IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTx(req);
        }

        emit WithdrawalToUEA(address(this), UEA, token, amount);
    }

    //========================
    //      Internal Helpers
    //========================

    /// @notice         Routes execution based on payload type (MULTICALL vs SINGLE CALL).
    /// @dev            Checks if payload starts with MULTICALL_SELECTOR to determine routing.
    /// @param txID             Transaction identifier for event emission
    /// @param universalTxID    Universal transaction identifier for event emission
    /// @param originCaller     Origin caller for event emission
    /// @param payload          Raw payload bytes (either multicall or single call)
    function _handleExecution(
        bytes32 txID,
        bytes32 universalTxID,
        address originCaller,
        bytes calldata payload
    ) internal {
        if (isMulticall(payload)) {
            // New format: decode and route to multicall handler
            Multicall[] memory calls = decodeCalls(payload);
            _handleMulticall(txID, universalTxID, originCaller, calls);
        } else {
            // Old format: route to backwards-compatible handler
            _handleSingleCall(txID, universalTxID, originCaller, payload);
        }
    }

    /// @notice         Internal handler for multicall execution.
    /// @dev            Validates msg.value matches total call values, then executes each call sequentially.
    ///                 All calls use the same .call execution path (including self-calls).
    ///                 Self-calls must have value == 0 (enforced here).
    ///                 Reverts if any call fails, bubbling revert data if available.
    /// @param txID             Transaction identifier for event emission
    /// @param universalTxID    Universal transaction identifier for event emission
    /// @param originCaller     Origin caller for event emission
    /// @param calls            Decoded Multicall[] array
    function _handleMulticall(
        bytes32 txID,
        bytes32 universalTxID,
        address originCaller,
        Multicall[] memory calls
    ) internal {
        // Validate msg.value matches sum of all call values
        uint256 totalValue = 0;
        for (uint256 i = 0; i < calls.length; i++) {
            totalValue += calls[i].value;
        }
        if (msg.value != totalValue) revert CEAErrors.InvalidAmount();

        // Execute each call in sequence
        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].to == address(0)) revert CEAErrors.InvalidTarget();

            // Enforce: self-calls to CEA must not include value
            if (calls[i].to == address(this) && calls[i].value != 0) {
                revert CEAErrors.InvalidInput();
            }

            (bool success, bytes memory returnData) = calls[i].to.call{value: calls[i].value}(calls[i].data);

            if (!success) revert CEAErrors.ExecutionFailed();

            emit UniversalTxExecuted(txID, universalTxID, originCaller, calls[i].to, calls[i].data);
        }
    }

    /// @notice         Internal handler for single call execution.
    /// @dev            For backwards compatibility, treats payload without MULTICALL_SELECTOR
    ///                 as direct ABI-encoded Multicall[] (old format).
    ///                 This allows existing SDKs to continue working.
    /// @param txID             Transaction identifier for event emission
    /// @param universalTxID    Universal transaction identifier for event emission
    /// @param originCaller     Origin caller for event emission
    /// @param payload          Raw ABI-encoded Multicall[] (old format, no selector prefix)
    function _handleSingleCall(
        bytes32 txID,
        bytes32 universalTxID,
        address originCaller,
        bytes calldata payload
    ) internal {
        // Backwards compatibility: decode as Multicall[] directly (old format)
        Multicall[] memory calls = abi.decode(payload, (Multicall[]));
        _handleMulticall(txID, universalTxID, originCaller, calls);
    }

    //========================
    //      Private Helpers
    //========================

    /// @notice         Checks whether the payload uses the multicall format.
    /// @dev            Determines if payload starts with MULTICALL_SELECTOR.
    /// @param data     Raw payload bytes
    /// @return bool    True if payload starts with MULTICALL_SELECTOR
    function isMulticall(bytes calldata data) private pure returns (bool) {
        if (data.length < 4) return false;
        bytes4 selector = bytes4(data[0:4]);
        return selector == MULTICALL_SELECTOR;
    }

    /// @notice         Decodes multicall payload into Multicall array.
    /// @dev            Strips MULTICALL_SELECTOR prefix and decodes remaining data.
    ///                 Should only be called after isMulticall returns true.
    /// @param data     Raw payload containing MULTICALL_SELECTOR + ABI-encoded Multicall[]
    /// @return         Decoded Multicall array
    function decodeCalls(bytes calldata data) private pure returns (Multicall[] memory) {
        // Strip the first 4 bytes (MULTICALL_SELECTOR) and decode the rest
        bytes calldata strippedData = data[4:];
        return abi.decode(strippedData, (Multicall[]));
    }

    //========================
    //         Receive
    //========================
    /**
     * @notice Allow this CEA to receive native tokens if needed for protocol interactions.
     */
    receive() external payable {}
}