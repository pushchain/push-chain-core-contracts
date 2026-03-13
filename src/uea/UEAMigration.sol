// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UEAErrors, CommonErrors} from "../libraries/Errors.sol";

/**
 * @title   UEAMigration
 * @notice  Slot-writer migration singleton for UEAProxy -> new UEA implementation.
 * @dev     Designed to be used via DELEGATECALL only from a UEAProxy contract.
 *          Updates the implementation address stored in UEA_LOGIC_SLOT.
 *          Not upgradeable — a new migration contract is deployed per version.
 *          A single migration contract includes implementations for both EVM and SVM.
 */
contract UEAMigration {
    // =========================
    //    UM: STATE VARIABLES
    // =========================

    /// @notice Address of this migration singleton (used to enforce delegatecall-only).
    address public immutable UEA_MIGRATION_IMPLEMENTATION;

    /// @notice Address of the new UEA_EVM implementation.
    address public immutable UEA_EVM_IMPLEMENTATION;

    /// @notice Address of the new UEA_SVM implementation.
    address public immutable UEA_SVM_IMPLEMENTATION;

    // =========================
    //    UM: CONSTANTS
    // =========================

    /// @dev Storage slot for the implementation address.
    ///      MUST match UEAProxy.UEA_LOGIC_SLOT exactly.
    ///      keccak256("uea.proxy.implementation") - 1
    bytes32 private constant UEA_LOGIC_SLOT =
        0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;

    // =========================
    //    UM: EVENTS
    // =========================

    /// @notice Emitted when the implementation address is updated on the proxy.
    event ImplementationUpdated(address indexed implementation);

    // =========================
    //    UM: MODIFIERS
    // =========================

    /// @notice Ensures the function is only called via DELEGATECALL.
    /// @dev    Under regular CALL, address(this) == UEA_MIGRATION_IMPLEMENTATION.
    ///         Under delegatecall, address(this) is the proxy address.
    modifier onlyDelegateCall() {
        if (address(this) == UEA_MIGRATION_IMPLEMENTATION) {
            revert CommonErrors.Unauthorized();
        }
        _;
    }

    // =========================
    //    UM: CONSTRUCTOR
    // =========================

    /// @param _evmImplementation   Address of the new UEA_EVM implementation
    /// @param _svmImplementation   Address of the new UEA_SVM implementation
    constructor(
        address _evmImplementation,
        address _svmImplementation
    ) {
        UEA_MIGRATION_IMPLEMENTATION = address(this);

        if (
            !hasCode(_evmImplementation)
                || !hasCode(_svmImplementation)
        ) {
            revert UEAErrors.InvalidInputArgs();
        }

        if (_evmImplementation == _svmImplementation) {
            revert UEAErrors.InvalidInputArgs();
        }

        UEA_EVM_IMPLEMENTATION = _evmImplementation;
        UEA_SVM_IMPLEMENTATION = _svmImplementation;
    }

    // =========================
    //    UM_1: MIGRATION
    // =========================

    /// @notice Migrates the UEAProxy to the new UEA_EVM implementation.
    /// @dev    Must be invoked via DELEGATECALL from a UEAProxy instance.
    function migrateUEAEVM() external onlyDelegateCall {
        bytes32 slot = UEA_LOGIC_SLOT;
        address implementation = UEA_EVM_IMPLEMENTATION;

        assembly {
            sstore(slot, implementation)
        }

        emit ImplementationUpdated(implementation);
    }

    /// @notice Migrates the UEAProxy to the new UEA_SVM implementation.
    /// @dev    Must be invoked via DELEGATECALL from a UEAProxy instance.
    function migrateUEASVM() external onlyDelegateCall {
        bytes32 slot = UEA_LOGIC_SLOT;
        address implementation = UEA_SVM_IMPLEMENTATION;

        assembly {
            sstore(slot, implementation)
        }

        emit ImplementationUpdated(implementation);
    }

    // =========================
    //    UM_2: VIEW FUNCTIONS
    // =========================

    /// @notice          Checks whether an address has deployed code.
    /// @param account   Address to check
    /// @return          True if code exists at address
    function hasCode(address account) public view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}
