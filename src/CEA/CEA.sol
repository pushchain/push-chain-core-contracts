// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ICEA} from "../interfaces/ICEA.sol";
import {CEAErrors, CommonErrors} from "../libraries/Errors.sol";
import {IUniversalGateway, UniversalTxRequest, RevertInstructions} from "../interfaces/IUniversalGateway.sol";
import {Multicall, MULTICALL_SELECTOR, MIGRATION_SELECTOR} from "../libraries/Types.sol";
import {ICEAFactory} from "../interfaces/ICEAFactory.sol";

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
    /// @notice Reference to the CEA factory for fetching migration contract
    ICEAFactory public factory;

    bool private _initialized;

    /// @notice Mapping from txID to bool to check if the tx has been executed
    mapping(bytes32 => bool) public isExecuted;

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

    /// @notice         Initializes this CEA with its UEA identity, Vault, Universal Gateway and Factory.
    /// @param _uea     Address of the UEA contract on Push Chain.
    /// @param _vault   Address of the Vault contract on this chain.
    /// @param _universalGateway Address of the Universal Gateway contract of the respective chain.
    /// @param _factory Address of the CEA factory contract.
    function initializeCEA(address _uea, address _vault, address _universalGateway, address _factory) external {
        if (_initialized) revert CEAErrors.AlreadyInitialized();
        if (_uea == address(0) || _vault == address(0) || _universalGateway == address(0) || _factory == address(0)) {
            revert CEAErrors.ZeroAddress();
        }

        UEA = _uea;
        VAULT = _vault;
        UNIVERSAL_GATEWAY = _universalGateway;
        factory = ICEAFactory(_factory);

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
    function executeUniversalTx(bytes32 txID, bytes32 universalTxID, address originCaller, bytes calldata payload)
        external
        payable
        onlyVault
        nonReentrant
    {
        // Top-level validation
        if (isExecuted[txID]) revert CEAErrors.PayloadExecuted();
        if (originCaller != UEA) revert CEAErrors.InvalidUEA();

        isExecuted[txID] = true;

        _handleExecution(txID, universalTxID, originCaller, payload);
    }

    /// @notice         Sends funds (and optionally a payload) from CEA to its UEA on Push Chain.
    /// @dev            Only callable via self-call through multicall execution (msg.sender == address(this)).
    ///                 For ERC20 tokens, SDK must include approval steps in multicall before this call.
    ///                 Routes to different gateway functions based on payload:
    ///                 - FUNDS (payload empty)          → sendUniversalTx
    ///                 - FUNDS_AND_PAYLOAD (non-empty)   → sendUniversalTxViaCEA
    /// @param token            Token address (address(0) for native)
    /// @param amount           Amount to send
    /// @param payload          Payload bytes for UEA execution (empty for funds-only)
    function sendUniversalTxToUEA(address token, uint256 amount, bytes calldata payload) external {
        // Enforce: Only CEA can call this function via self-call
        if (msg.sender != address(this)) revert CommonErrors.Unauthorized();

        if (amount == 0) revert CEAErrors.InvalidInput();

        UniversalTxRequest memory req = UniversalTxRequest({
            recipient: UEA,
            token: token,
            amount: amount,
            payload: payload,
            revertInstruction: RevertInstructions({fundRecipient: UEA, revertMsg: ""}),
            signatureData: ""
        });

        if (token == address(0)) {
            if (address(this).balance < amount) revert CEAErrors.InsufficientBalance();
            if (payload.length == 0) {
                IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTx{value: amount}(req);
            } else {
                IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTxViaCEA{value: amount}(req);
            }
        } else {
            if (IERC20(token).balanceOf(address(this)) < amount) revert CEAErrors.InsufficientBalance();
            if (payload.length == 0) {
                IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTx(req);
            } else {
                IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTxViaCEA(req);
            }
        }

        emit UniversalTxToUEA(address(this), UEA, token, amount);
    }

    //========================
    //      Internal Helpers
    //========================

    /// @notice         Routes execution based on payload type (MULTICALL vs SINGLE CALL vs MIGRATION).
    /// @dev            Checks if payload starts with MULTICALL_SELECTOR to determine routing.
    ///                 Detects standalone migration multicalls and routes to _handleMigration().
    /// @param txID             Transaction identifier for event emission
    /// @param universalTxID    Universal transaction identifier for event emission
    /// @param originCaller     Origin caller for event emission
    /// @param payload          Raw payload bytes (either multicall or single call)
    function _handleExecution(bytes32 txID, bytes32 universalTxID, address originCaller, bytes calldata payload)
        internal
    {
        if (isMulticall(payload)) {
            Multicall[] memory calls = decodeCalls(payload);

            // Detect single-element migration multicall
            if (calls.length == 1 && isMigration(calls[0].data)) {
                _handleMigration(calls[0]);
                // Emit event for migration execution
                emit UniversalTxExecuted(txID, universalTxID, originCaller, address(this), calls[0].data);
                return;
            }

            // Normal multicall execution
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
    function _handleMulticall(bytes32 txID, bytes32 universalTxID, address originCaller, Multicall[] memory calls)
        internal
    {
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

            // Prevent migration selector in batched multicalls (must be standalone)
            if (isMigration(calls[i].data)) {
                revert CEAErrors.InvalidCall();
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
    function _handleSingleCall(bytes32 txID, bytes32 universalTxID, address originCaller, bytes calldata payload)
        internal
    {
        // Backwards compatibility: decode as Multicall[] directly (old format)
        Multicall[] memory calls = abi.decode(payload, (Multicall[]));
        _handleMulticall(txID, universalTxID, originCaller, calls);
    }

    /// @notice         Internal handler for migration execution
    /// @dev            Validates migration constraints and delegates to migration contract
    /// @dev            SAFETY CONSTRAINTS:
    ///                 - Must target self (call.to == address(this))
    ///                 - Must have zero value (call.value == 0)
    ///                 - Migration contract must be set in factory
    ///                 - Executed via delegatecall (preserves proxy state)
    /// @param call     The migration Multicall struct
    function _handleMigration(Multicall memory call) internal {
        if (call.to != address(this)) {
            revert CEAErrors.InvalidTarget();
        }
        if (call.value != 0) {
            revert CEAErrors.InvalidInput();
        }

        // Fetch migration contract address from factory
        address migrationContract = factory.CEA_MIGRATION_CONTRACT();

        // CONSTRAINT: Migration contract must be set
        if (migrationContract == address(0)) {
            revert CEAErrors.InvalidCall();
        }

        // Prepare delegatecall to migration contract
        bytes memory migrateCallData = abi.encodeWithSignature("migrateCEA()");

        // Execute migration via delegatecall (writes to proxy storage)
        (bool success, bytes memory returnData) = migrationContract.delegatecall(migrateCallData);

        // Bubble revert data on failure
        if (!success) revert CEAErrors.ExecutionFailed();
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

    /// @notice         Checks whether the call data is a migration request.
    /// @dev            Determines if the data starts with MIGRATION_SELECTOR.
    ///                 Uses bytes memory because it's called on Multicall.data (memory).
    /// @param data     Call data bytes
    /// @return bool    True if data starts with MIGRATION_SELECTOR
    function isMigration(bytes memory data) private pure returns (bool) {
        if (data.length < 4) return false;
        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }
        return selector == MIGRATION_SELECTOR;
    }

    //========================
    //         Receive
    //========================
    /**
     * @notice Allow this CEA to receive native tokens if needed for protocol interactions.
     */
    receive() external payable {}
}
