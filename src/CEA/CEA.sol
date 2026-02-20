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
    address public pushAccount;
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

    /// @notice                  Initializes this CEA with its push account identity, Vault, Universal Gateway and Factory.
    /// @param _pushAccount      Address of the push account (UEA) on Push Chain.
    /// @param _vault            Address of the Vault contract on this chain.
    /// @param _universalGateway Address of the Universal Gateway contract of the respective chain.
    /// @param _factory          Address of the CEA factory contract.
    function initializeCEA(address _pushAccount, address _vault, address _universalGateway, address _factory) external {
        if (_initialized) revert CEAErrors.AlreadyInitialized();
        if (
            _pushAccount == address(0) || _vault == address(0) || _universalGateway == address(0)
                || _factory == address(0)
        ) {
            revert CEAErrors.ZeroAddress();
        }

        pushAccount = _pushAccount;
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
    /// @param txId      Unique transaction identifier (must not be executed before)
    /// @param universalTxId    Universal transaction identifier for cross-chain tracking
    /// @param originCaller     Address of the origin caller (must match pushAccount)
    /// @param payload          Either multicall or single call payload
    function executeUniversalTx(bytes32 txId, bytes32 universalTxId, address originCaller, bytes calldata payload)
        external
        payable
        onlyVault
        nonReentrant
    {
        // Top-level validation
        if (isExecuted[txId]) revert CEAErrors.PayloadExecuted();
        if (originCaller != pushAccount) revert CEAErrors.InvalidUEA();

        isExecuted[txId] = true;

        _handleExecution(txId, universalTxId, originCaller, payload);
    }

    /// @notice         Sends funds (and optionally a payload) from CEA to its UEA on Push Chain.
    /// @dev            Only callable via self-call through multicall execution (msg.sender == address(this)).
    ///                 For ERC20 tokens, SDK must include approval steps in multicall before this call.
    ///                 Always routes through sendUniversalTxViaCEA for both tx types:
    ///                 - FUNDS (payload empty, amount > 0)
    ///                 - FUNDS_AND_PAYLOAD (payload non-empty, amount > 0)
    /// @param token            Token address (address(0) for native)
    /// @param amount           Amount to send
    /// @param payload          Payload bytes for UEA execution (empty for funds-only)
    function sendUniversalTxToUEA(address token, uint256 amount, bytes calldata payload) external {
        if (msg.sender != address(this)) revert CommonErrors.Unauthorized();

        if (amount == 0) revert CEAErrors.InvalidInput();

        UniversalTxRequest memory req = UniversalTxRequest({
            recipient: pushAccount,
            token: token,
            amount: amount,
            payload: payload,
            revertInstruction: RevertInstructions({fundRecipient: pushAccount, revertMsg: ""}),
            signatureData: ""
        });

        if (token == address(0)) {
            if (address(this).balance < amount) revert CEAErrors.InsufficientBalance();
            IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTxViaCEA{value: amount}(req);
        } else {
            if (IERC20(token).balanceOf(address(this)) < amount) revert CEAErrors.InsufficientBalance();
            IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTxViaCEA(req);
        }

        emit UniversalTxToUEA(address(this), pushAccount, token, amount);
    }

    //========================
    //      Internal Helpers
    //========================

    /// @notice         Routes execution based on payload type (MULTICALL vs MIGRATION vs SINGLE CALL).
    /// @dev            Three-way branch matching UEA_EVM pattern:
    ///                 1. isMulticall → decode + _handleMulticall
    ///                 2. isMigration → _handleMigration (top-level, no Multicall wrapper)
    ///                 3. else → _handleSingleCall (backwards compatibility)
    /// @param txId      Transaction identifier for event emission
    /// @param universalTxId    Universal transaction identifier for event emission
    /// @param originCaller     Origin caller for event emission
    /// @param payload          Raw payload bytes
    function _handleExecution(bytes32 txId, bytes32 universalTxId, address originCaller, bytes calldata payload)
        internal
    {
        if (isMulticall(payload)) {
            Multicall[] memory calls = decodeCalls(payload);
            _handleMulticall(txId, universalTxId, originCaller, calls);
        } else if (isMigration(payload)) {
            _handleMigration();
            emit UniversalTxExecuted(txId, universalTxId, originCaller, address(this), payload);
        } else {
            _handleSingleCall(txId, universalTxId, originCaller, payload);
        }
    }

    /// @notice         Internal handler for multicall execution.
    /// @dev            Executes each call sequentially. No strict msg.value == totalValue enforcement;
    ///                 CEA can spend pre-existing balance in addition to Vault-provided msg.value.
    ///                 Self-calls must have value == 0 (enforced here).
    /// @param txId      Transaction identifier for event emission
    /// @param universalTxId    Universal transaction identifier for event emission
    /// @param originCaller     Origin caller for event emission
    /// @param calls            Decoded Multicall[] array
    function _handleMulticall(bytes32 txId, bytes32 universalTxId, address originCaller, Multicall[] memory calls)
        internal
    {
        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].to == address(0)) revert CEAErrors.InvalidTarget();

            // Self-calls to CEA must not include value
            if (calls[i].to == address(this) && calls[i].value != 0) {
                revert CEAErrors.InvalidInput();
            }

            (bool success,) = calls[i].to.call{value: calls[i].value}(calls[i].data);

            if (!success) revert CEAErrors.ExecutionFailed();

            emit UniversalTxExecuted(txId, universalTxId, originCaller, calls[i].to, calls[i].data);
        }
    }

    /// @notice         Internal handler for single call execution.
    /// @dev            For backwards compatibility, treats payload without MULTICALL_SELECTOR
    ///                 as direct ABI-encoded Multicall[] (old format).
    ///                 This allows existing SDKs to continue working.
    /// @param txId      Transaction identifier for event emission
    /// @param universalTxId    Universal transaction identifier for event emission
    /// @param originCaller     Origin caller for event emission
    /// @param payload          Raw ABI-encoded Multicall[] (old format, no selector prefix)
    function _handleSingleCall(bytes32 txId, bytes32 universalTxId, address originCaller, bytes calldata payload)
        internal
    {
        // Backwards compatibility: decode as Multicall[] directly (old format)
        Multicall[] memory calls = abi.decode(payload, (Multicall[]));
        _handleMulticall(txId, universalTxId, originCaller, calls);
    }

    /// @notice         Internal handler for migration execution.
    /// @dev            Fetches migration contract from factory and executes via delegatecall.
    ///                 Migration payload is top-level MIGRATION_SELECTOR (no Multicall wrapper).
    ///                 Migration contract must be set in factory (non-zero address).
    ///                 Rejects msg.value > 0 — migration is a logic upgrade, not a value transfer.
    function _handleMigration() internal {
        if (msg.value != 0) revert CEAErrors.InvalidInput();
        address migrationContract = factory.CEA_MIGRATION_CONTRACT();
        if (migrationContract == address(0)) revert CEAErrors.InvalidCall();

        bytes memory migrateCallData = abi.encodeWithSignature("migrateCEA()");
        (bool success,) = migrationContract.delegatecall(migrateCallData);
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

    /// @notice         Checks whether a top-level payload is a migration request.
    /// @dev            Calldata variant for use in _handleExecution's three-way branch.
    /// @param data     Raw payload bytes (calldata)
    /// @return bool    True if payload starts with MIGRATION_SELECTOR
    function isMigration(bytes calldata data) private pure returns (bool) {
        if (data.length < 4) return false;
        return bytes4(data[0:4]) == MIGRATION_SELECTOR;
    }

    //========================
    //         Receive
    //========================
    /**
     * @notice Allow this CEA to receive native tokens if needed for protocol interactions.
     */
    receive() external payable {}
}
