// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UEAErrors, CommonErrors} from "../libraries/Errors.sol";

/**
 * @title UEAMigration
 * @notice This contract facilitates migration of UEA proxy contracts to new implementation versions.
 * @dev This contract is designed to be used via delegatecall only from a UEAProxy contract.
 *      It updates the implementation address stored in the UEA_LOGIC_SLOT of the proxy.
 *      IMPORTANT: This contract will only work with UEAProxy contracts that follow the same
 *      storage layout and implementation slot as defined in UEAProxy.sol.
 * @author Push Chain Team
 */
contract UEAMigration {
    /**
     * @notice Address of this migration contract singleton.
     */
    address public immutable UEA_MIGRATION_IMPLEMENTATION;

    /**
     * @notice Address of the UEA_EVM implementation.
     */
    address public immutable UEA_EVM_IMPLEMENTATION;

    /**
     * @notice Address of the UEA_SVM implementation.
     */
    address public immutable UEA_SVM_IMPLEMENTATION;

    /**
     * @dev Storage slot with the address of the current implementation.
     * This must match the UEA_LOGIC_SLOT in UEAProxy.sol
     * This is the keccak-256 hash of "uea.proxy.implementation" subtracted by 1
     */
    bytes32 private constant UEA_LOGIC_SLOT = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;

    /**
     * @notice Event emitted when the implementation address is updated.
     * @param implementation New implementation address.
     */
    event ImplementationUpdated(address indexed implementation);

    /**
     * @notice Modifier to make a function callable via `DELEGATECALL` only.
     * If the function is called via a regular `CALL`, it will revert.
     */
    modifier onlyDelegateCall() {
        if (address(this) == UEA_MIGRATION_IMPLEMENTATION) {
            revert CommonErrors.Unauthorized();
        }
        _;
    }

    /**
     * @notice UEAMigration constructor.
     * @param _evmImplementation Address of the new UEA_EVM implementation.
     * @param _svmImplementation Address of the new UEA_SVM implementation.
     */
    constructor(address _evmImplementation, address _svmImplementation) {
        UEA_MIGRATION_IMPLEMENTATION = address(this);

        if(!hasCode(_evmImplementation) || !hasCode(_svmImplementation)) {
            revert UEAErrors.InvalidInputArgs();
        }
        
        if (_evmImplementation == _svmImplementation) {
            revert UEAErrors.InvalidInputArgs();
        }

        UEA_EVM_IMPLEMENTATION = _evmImplementation;
        UEA_SVM_IMPLEMENTATION = _svmImplementation;
    }

    /**
     * @notice Migrate the UEAProxy to the new UEA_EVM implementation.
     * @dev This function can only be called via delegatecall from a UEAProxy.
     */
    function migrateUEAEVM() external onlyDelegateCall {
        bytes32 slot = UEA_LOGIC_SLOT;
        address implementation = UEA_EVM_IMPLEMENTATION;

        // Store implementation address directly in storage slot
        assembly {
            sstore(slot, implementation)
        }

        emit ImplementationUpdated(implementation);
    }

    /**
     * @notice Migrate the UEAProxy to the new UEA_SVM implementation.
     * @dev This function can only be called via delegatecall from a UEAProxy.
     */
    function migrateUEASVM() external onlyDelegateCall {
        bytes32 slot = UEA_LOGIC_SLOT;
        address implementation = UEA_SVM_IMPLEMENTATION;

        // Store implementation address directly in storage slot
        assembly {
            sstore(slot, implementation)
        }

        emit ImplementationUpdated(implementation);
    }

    /**
     * @notice Checks whether an address has deployed code.
     * @param _account The address to check.
     * @return bool True if the address has code, false otherwise.
     */
    function hasCode(address _account) public view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_account)
        }
        return size > 0;
    }
}
