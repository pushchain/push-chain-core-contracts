// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {CEAErrors as Errors, CommonErrors} from "../libraries/Errors.sol";

/**
 * @title   CEAMigration
 * @notice  Slot-writer migration singleton for CEAProxy -> new CEA implementation.
 * @dev
 *  - Mirrors the UEAMigration pattern: DEPLOY ONCE PER VERSION, and invoke ONLY via DELEGATECALL
 *    from a CEAProxy instance.
 *  - Writes the new implementation address into the proxy's implementation slot.
 *
 *  IMPORTANT:
 *  - This contract is NOT meant to be called directly (regular CALL). It must be reached via
 *    delegatecall so that the sstore writes into the proxy storage.
 *  - The storage slot constant MUST match CEAProxy's CEA_LOGIC_SLOT exactly.
 */
contract CEAMigration {
    //========================
    //        Immutables
    //========================

    /// @notice Address of this migration contract singleton, used to enforce delegatecall-only.
    address public immutable CEA_MIGRATION_IMPLEMENTATION;

    /// @notice Address of the new CEA implementation to migrate proxies to.
    address public immutable CEA_IMPLEMENTATION;

    //========================
    //      Proxy Slot
    //========================

    /**
     * @dev Storage slot with the address of the current implementation.
     * MUST match CEAProxy.sol:
     *   bytes32(uint256(keccak256("cea.proxy.implementation")) - 1)
     */
    bytes32 private constant CEA_LOGIC_SLOT =
        0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;

    //========================
    //          Events
    //========================

    /// @notice Emitted when the implementation address is updated on the proxy.
    event ImplementationUpdated(address indexed implementation);

    //========================
    //        Modifiers
    //========================

    /**
     * @notice Modifier to make functions callable via DELEGATECALL only.
     * @dev If called via regular CALL on the singleton, address(this) == CEA_MIGRATION_IMPLEMENTATION.
     *      Under delegatecall, address(this) will be the proxy address, so the check passes.
     */
    modifier onlyDelegateCall() {
        if (address(this) == CEA_MIGRATION_IMPLEMENTATION) {
            revert CommonErrors.Unauthorized();
        }
        _;
    }

    //========================
    //       Constructor
    //========================

    /**
     * @param _ceaImplementation Address of the new CEA implementation (e.g., CEA v2) deployed on this chain.
     */
    constructor(address _ceaImplementation) {
        CEA_MIGRATION_IMPLEMENTATION = address(this);

        if (!hasCode(_ceaImplementation)) {
            revert Errors.InvalidInput(); // align with your Errors library naming if different
        }

        CEA_IMPLEMENTATION = _ceaImplementation;
    }

    //========================
    //       Migration
    //========================

    /**
     * @notice Migrate the calling CEAProxy to the new CEA implementation.
     * @dev Must be invoked via DELEGATECALL from a CEAProxy instance.
     *      Stores `CEA_IMPLEMENTATION` into `CEA_LOGIC_SLOT`.
     */
    function migrateCEA() external onlyDelegateCall {
        bytes32 slot = CEA_LOGIC_SLOT;
        address implementation = CEA_IMPLEMENTATION;

        assembly {
            sstore(slot, implementation)
        }

        emit ImplementationUpdated(implementation);
    }

    //========================
    //          Utils
    //========================

    /**
     * @notice Checks whether an address has deployed code.
     * @param _account The address to check.
     */
    function hasCode(address _account) public view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_account)
        }
        return size > 0;
    }
}