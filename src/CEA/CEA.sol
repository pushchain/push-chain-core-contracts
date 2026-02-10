// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ICEA} from "../interfaces/ICEA.sol";
import {CEAErrors} from "../libraries/Errors.sol";
import {IUniversalGateway,
            UniversalTxRequest,
                RevertInstructions} from "../interfaces/IUniversalGateway.sol";
import {Multicall} from "../libraries/Types.sol";

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

    /// @notice         Executes a universal transaction using multicall payload.
    /// @dev            All execution is driven by a standardized Multicall[] payload.
    ///                 SDK is responsible for crafting correct multicall steps (including ERC20 approvals).
    /// @param txID             Unique transaction identifier (must not be executed before)
    /// @param universalTxID    Universal transaction identifier for cross-chain tracking
    /// @param originCaller     Address of the origin caller (must be UEA)
    /// @param payload          ABI-encoded Multicall[] containing execution steps
    function executeUniversalTx(
        bytes32 txID,
        bytes32 universalTxID,
        address originCaller,
        bytes calldata payload
    ) external payable onlyVault nonReentrant {
        // Top-level validation
        if (isExecuted[txID]) revert CEAErrors.PayloadExecuted();
        if (originCaller != UEA) revert CEAErrors.InvalidUEA();

        // Validate msg.value matches sum of all call values
        Multicall[] memory calls = decodeMulticall(payload);
        uint256 totalValue = 0;
        for (uint256 i = 0; i < calls.length; i++) {
            totalValue += calls[i].value;
        }
        if (msg.value != totalValue) revert CEAErrors.InvalidAmount();

        isExecuted[txID] = true;

        _handleMulticallDecoded(txID, universalTxID, originCaller, calls);
    }

    /// @notice         Withdraws funds from CEA back to its UEA on Push Chain.
    /// @dev            Only callable via self-call through multicall execution (msg.sender == address(this)).
    ///                 For ERC20 tokens, SDK must include approval steps in multicall before this call.
    /// @param token    Token address (address(0) for native)
    /// @param amount   Amount to withdraw
    function withdrawFundsToUEA(address token, uint256 amount) external {
        // Enforce: Only CEA can call this function via self-call
        if (msg.sender != address(this)) revert CEAErrors.NotVault();

        if (amount == 0) revert CEAErrors.InvalidInput();
        UniversalTxRequest memory req = UniversalTxRequest({
            recipient: UEA,
            token: token,
            amount: amount,
            payload: "",
            revertInstruction: RevertInstructions({
                fundRecipient: UEA,
                revertMsg: ""
            }),
            signatureData: ""
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

    /// @notice         Internal handler for multicall execution.
    /// @dev            Executes each call in the decoded Multicall[] array sequentially.
    ///                 All calls use the same .call execution path (including self-calls).
    ///                 Self-calls must have value == 0 (enforced here).
    ///                 Reverts if any call fails, bubbling revert data if available.
    /// @param txID             Transaction identifier for event emission
    /// @param universalTxID    Universal transaction identifier for event emission
    /// @param originCaller     Origin caller for event emission
    /// @param calls            Decoded Multicall[] array
    function _handleMulticallDecoded(
        bytes32 txID,
        bytes32 universalTxID,
        address originCaller,
        Multicall[] memory calls
    ) internal {

        // Execute each call in sequence
        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].to == address(0)) revert CEAErrors.InvalidTarget();

            // Enforce: self-calls to CEA must not include value
            if (calls[i].to == address(this) && calls[i].value != 0) {
                revert CEAErrors.InvalidInput();
            }

            (bool success, bytes memory returnData) = calls[i].to.call{value: calls[i].value}(calls[i].data);

            if (!success) {
                if (returnData.length > 0) {
                    assembly {
                        let returnDataSize := mload(returnData)
                        revert(add(32, returnData), returnDataSize)
                    }
                } else {
                    revert CEAErrors.ExecutionFailed();
                }
            }

            emit UniversalTxExecuted(txID, universalTxID, originCaller, calls[i].to, calls[i].data);
        }
    }

    /// @notice         Decodes bytes into Multicall array (external helper for try/catch).
    /// @dev            Must be external to use in try/catch pattern for clean error handling.
    /// @param data     ABI-encoded Multicall[] array
    /// @return         Decoded Multicall array
    function decodeMulticall(bytes calldata data) internal pure returns (Multicall[] memory) {
        return abi.decode(data, (Multicall[]));
    }


    //========================
    //         Receive
    //========================

    /**
     * @notice Allow this CEA to receive native tokens if needed for protocol interactions.
     */
    receive() external payable {}
}