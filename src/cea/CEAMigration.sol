// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {CEAErrors, CommonErrors} from "../libraries/Errors.sol";

/**
 * @title   CEAMigration
 * @notice  Slot-writer migration singleton for CEAProxy -> new CEA implementation.
 * @dev     Mirrors the UEAMigration pattern: deploy once per version, invoke
 *          ONLY via DELEGATECALL from a CEAProxy instance.
 *          Writes the new implementation address into the proxy's CEA_LOGIC_SLOT.
 *
 *          IMPORTANT: This contract MUST NOT be called directly (regular CALL).
 *          The storage slot constant MUST match CEAProxy's CEA_LOGIC_SLOT exactly.
 */
contract CEAMigration {
    // =========================
    //    CM: STATE VARIABLES
    // =========================

    /// @notice Address of this migration singleton (used to enforce delegatecall-only).
    address public immutable CEA_MIGRATION_IMPLEMENTATION;

    /// @notice Address of the new CEA implementation to migrate proxies to.
    address public immutable CEA_IMPLEMENTATION;

    // =========================
    //    CM: CONSTANTS
    // =========================

    /// @dev Storage slot for the implementation address.
    ///      MUST match CEAProxy.CEA_LOGIC_SLOT exactly.
    ///      bytes32(uint256(keccak256("cea.proxy.implementation")) - 1)
    bytes32 private constant CEA_LOGIC_SLOT = 0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;

    // =========================
    //    CM: EVENTS
    // =========================

    /// @notice Emitted when the implementation address is updated on the proxy.
    event ImplementationUpdated(address indexed implementation);

    // =========================
    //    CM: MODIFIERS
    // =========================

    /// @notice Ensures the function is only called via DELEGATECALL.
    /// @dev    Under regular CALL, address(this) == CEA_MIGRATION_IMPLEMENTATION.
    ///         Under delegatecall, address(this) is the proxy address.
    modifier onlyDelegateCall() {
        if (address(this) == CEA_MIGRATION_IMPLEMENTATION) {
            revert CommonErrors.Unauthorized();
        }
        _;
    }

    // =========================
    //    CM: CONSTRUCTOR
    // =========================

    /// @param _ceaImplementation   Address of the new CEA implementation (e.g., CEA v2)
    constructor(address _ceaImplementation) {
        CEA_MIGRATION_IMPLEMENTATION = address(this);

        if (!hasCode(_ceaImplementation)) {
            revert CEAErrors.InvalidInput();
        }

        CEA_IMPLEMENTATION = _ceaImplementation;
    }

    // =========================
    //    CM_1: MIGRATION
    // =========================

    /// @notice Migrates the calling CEAProxy to the new CEA implementation.
    /// @dev    Must be invoked via DELEGATECALL from a CEAProxy instance.
    ///         Stores CEA_IMPLEMENTATION into CEA_LOGIC_SLOT.
    function migrateCEA() external onlyDelegateCall {
        bytes32 slot = CEA_LOGIC_SLOT;
        address implementation = CEA_IMPLEMENTATION;

        assembly {
            sstore(slot, implementation)
        }

        emit ImplementationUpdated(implementation);
    }

    // =========================
    //    CM_2: VIEW FUNCTIONS
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
