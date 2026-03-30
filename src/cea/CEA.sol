// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ICEA} from "../interfaces/ICEA.sol";
import {ICEAFactory} from "../interfaces/ICEAFactory.sol";
import {CEAErrors, CommonErrors} from "../libraries/Errors.sol";
import {IUniversalGateway, UniversalTxRequest} from "../interfaces/IUniversalGateway.sol";
import {Multicall, MULTICALL_SELECTOR, MIGRATION_SELECTOR} from "../libraries/Types.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title   CEA
 * @notice  Chain Executor Account implementation (v1).
 * @dev     Deployed behind a minimal proxy (Clones) by CEAFactory.
 *          Represents a single UEA on Push Chain on a specific external EVM chain.
 *          In v1 only the Vault may call state-changing functions.
 */
contract CEA is ICEA, ReentrancyGuard {
    // =========================
    //    CEA: STATE VARIABLES
    // =========================

    /// @inheritdoc ICEA
    address public pushAccount;

    /// @inheritdoc ICEA
    address public VAULT;

    /// @notice Address of the Universal Gateway on this external chain.
    address public UNIVERSAL_GATEWAY;

    /// @notice Reference to the CEA factory for fetching migration contract.
    ICEAFactory public factory;

    bool private _initialized;

    /// @inheritdoc ICEA
    mapping(bytes32 => bool) public isExecuted;

    // =========================
    //    CEA: MODIFIERS
    // =========================

    /// @notice Restricts to the Vault contract.
    modifier onlyVault() {
        if (msg.sender != VAULT) revert CEAErrors.NotVault();
        _;
    }

    // =========================
    //    CEA: INITIALIZER
    // =========================

    /// @inheritdoc ICEA
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

    // =========================
    //    CEA_1: VIEW FUNCTIONS
    // =========================

    /// @inheritdoc ICEA
    function isInitialized() external view override returns (bool) {
        return _initialized;
    }

    // =========================
    //    CEA_2: VAULT OPERATIONS
    // =========================

    /// @inheritdoc ICEA
    function executeUniversalTx(
        bytes32 txId,
        bytes32 universalTxId,
        address originCaller,
        address recipient,
        bytes calldata payload
    ) external payable onlyVault nonReentrant {
        if (isExecuted[txId]) revert CEAErrors.PayloadExecuted();
        if (originCaller != pushAccount) revert CEAErrors.InvalidUEA();

        isExecuted[txId] = true;

        _handleExecution(txId, universalTxId, originCaller, recipient, payload);
    }

    // =========================
    //    CEA_3: SELF-CALL OPERATIONS
    // =========================

    /// @inheritdoc ICEA
    function sendUniversalTxToUEA(address token, uint256 amount, bytes calldata payload, address revertRecipient)
        external
    {
        if (msg.sender != address(this)) {
            revert CommonErrors.Unauthorized();
        }
        if (revertRecipient == address(0)) {
            revert CEAErrors.InvalidInput();
        }

        UniversalTxRequest memory req = UniversalTxRequest({
            recipient: pushAccount,
            token: token,
            amount: amount,
            payload: payload,
            revertRecipient: revertRecipient,
            signatureData: ""
        });

        if (amount > 0) {
            if (token == address(0)) {
                if (address(this).balance < amount) {
                    revert CEAErrors.InsufficientBalance();
                }
                IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTxFromCEA{value: amount}(req);
            } else {
                if (IERC20(token).balanceOf(address(this)) < amount) {
                    revert CEAErrors.InsufficientBalance();
                }
                IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTxFromCEA(req);
            }
        } else {
            IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTxFromCEA(req);
        }

        emit UniversalTxToUEA(address(this), pushAccount, token, amount);
    }

    // =========================
    //    CEA_4: INTERNAL HELPERS
    // =========================

    /// @dev Routes execution based on payload type.
    ///      Three-way branch: MULTICALL, MIGRATION, or SINGLE CALL.
    /// @param txId             Transaction identifier for event emission
    /// @param universalTxId    Universal tx identifier for event emission
    /// @param originCaller     Origin caller for event emission
    /// @param recipient        Target for single-call path (ignored otherwise)
    /// @param payload          Raw payload bytes
    function _handleExecution(
        bytes32 txId,
        bytes32 universalTxId,
        address originCaller,
        address recipient,
        bytes calldata payload
    ) internal {
        if (_isMulticall(payload)) {
            Multicall[] memory calls = _decodeCalls(payload);
            _handleMulticall(txId, universalTxId, originCaller, calls);
        } else if (_isMigration(payload)) {
            _handleMigration();
            emit UniversalTxExecuted(txId, universalTxId, originCaller, address(this), payload);
        } else {
            _handleSingleCall(txId, universalTxId, originCaller, recipient, payload);
        }
    }

    /// @dev Executes each multicall step sequentially.
    ///      Self-calls must have value == 0.
    /// @param txId             Transaction identifier for event emission
    /// @param universalTxId    Universal tx identifier for event emission
    /// @param originCaller     Origin caller for event emission
    /// @param calls            Decoded Multicall[] array
    function _handleMulticall(bytes32 txId, bytes32 universalTxId, address originCaller, Multicall[] memory calls)
        internal
    {
        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].to == address(0)) {
                revert CEAErrors.InvalidTarget();
            }

            if (calls[i].to == address(this) && calls[i].value != 0) {
                revert CEAErrors.InvalidInput();
            }

            (bool success,) = calls[i].to.call{value: calls[i].value}(calls[i].data);

            if (!success) revert CEAErrors.ExecutionFailed();

            emit UniversalTxExecuted(txId, universalTxId, originCaller, calls[i].to, calls[i].data);
        }
    }

    /// @dev Handles single-call execution or funds parking.
    ///      Empty payload = park funds. Non-empty = execute call.
    ///      Self-calls blocked (use multicall path instead).
    /// @param txId             Transaction identifier for event emission
    /// @param universalTxId    Universal tx identifier for event emission
    /// @param originCaller     Origin caller for event emission
    /// @param recipient        Target contract for execution
    /// @param payload          Raw calldata to forward (empty = park funds)
    function _handleSingleCall(
        bytes32 txId,
        bytes32 universalTxId,
        address originCaller,
        address recipient,
        bytes calldata payload
    ) internal {
        if (payload.length == 0) {
            emit UniversalTxExecuted(txId, universalTxId, originCaller, address(this), payload);
            return;
        }

        if (recipient == address(0)) {
            revert CEAErrors.InvalidRecipient();
        }
        if (recipient == address(this)) {
            revert CEAErrors.InvalidRecipient();
        }

        (bool success,) = recipient.call{value: msg.value}(payload);
        if (!success) revert CEAErrors.ExecutionFailed();

        emit UniversalTxExecuted(txId, universalTxId, originCaller, recipient, payload);
    }

    /// @dev Fetches migration contract from factory and delegates.
    ///      Rejects msg.value > 0 — migration is a logic upgrade only.
    function _handleMigration() internal {
        if (msg.value != 0) revert CEAErrors.InvalidInput();
        address migrationContract = factory.CEA_MIGRATION_CONTRACT();
        if (migrationContract == address(0)) {
            revert CEAErrors.InvalidCall();
        }

        bytes memory migrateCallData = abi.encodeWithSignature("migrateCEA()");
        (bool success,) = migrationContract.delegatecall(migrateCallData);
        if (!success) revert CEAErrors.ExecutionFailed();
    }

    // =========================
    //    CEA_5: PRIVATE HELPERS
    // =========================

    /// @dev Checks whether the payload uses the multicall format.
    /// @param data     Raw payload bytes
    /// @return         True if payload starts with MULTICALL_SELECTOR
    function _isMulticall(bytes calldata data) private pure returns (bool) {
        if (data.length < 4) return false;
        return bytes4(data[0:4]) == MULTICALL_SELECTOR;
    }

    /// @dev Decodes multicall payload into Multicall array.
    ///      Strips MULTICALL_SELECTOR prefix and decodes remaining data.
    /// @param data     Raw payload containing selector + ABI-encoded Multicall[]
    /// @return         Decoded Multicall array
    function _decodeCalls(bytes calldata data) private pure returns (Multicall[] memory) {
        bytes calldata strippedData = data[4:];
        return abi.decode(strippedData, (Multicall[]));
    }

    /// @dev Checks whether a top-level payload is a migration request.
    /// @param data     Raw payload bytes
    /// @return         True if payload starts with MIGRATION_SELECTOR
    function _isMigration(bytes calldata data) private pure returns (bool) {
        if (data.length < 4) return false;
        return bytes4(data[0:4]) == MIGRATION_SELECTOR;
    }

    // =========================
    //    CEA: RECEIVE
    // =========================

    /// @notice Allows this CEA to receive native tokens for protocol interactions.
    receive() external payable {}
}
