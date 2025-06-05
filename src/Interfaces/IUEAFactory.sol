// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalAccount, VM_TYPE} from "../libraries/Types.sol";

/**
 * @title IUEAFactory
 * @dev Interface for the Universal Executor Account Factory
 */
interface IUEAFactory {
    /**
     * @dev Registers a new chain with its VM type
     * @param _chainHash The hash of the chain name to register
     * @param _vmType The VM type for this chain
     */
    function registerNewChain(bytes32 _chainHash, VM_TYPE _vmType) external;

    /**
     * @dev Registers multiple UEA implementations in a batch
     * @param _chainHashes Array of chain hashes
     * @param _uea Array of UEA implementation addresses
     */
    function registerMultipleUEA(bytes32[] memory _chainHashes, address[] memory _uea) external;

    /**
     * @dev Registers a UEA implementation for a specific chain
     * @param _chainHash The hash of the chain name
     * @param _uea The UEA implementation address
     */
    function registerUEA(bytes32 _chainHash, address _uea) external;

    /**
     * @dev Deploys a new UEA for an external chain user
     * @param _id The Universal Account information containing chain and owner key
     * @return The address of the deployed UEA
     */
    function deployUEA(UniversalAccount memory _id) external returns (address);

    /**
     * @dev Returns the UEA implementation address for a given chain
     * @param _chainHash The hash of the chain name
     * @return The UEA implementation address for the chain's VM type
     */
    function getUEA(bytes32 _chainHash) external view returns (address);

    /**
     * @dev Returns the VM type for a given chain hash and whether it's registered
     * @param _chainHash The hash of the chain name
     * @return vmType The VM type (will be UNREGISTERED if not explicitly set)
     * @return isRegistered True if the chain is registered, false otherwise
     */
    function getVMType(bytes32 _chainHash) external view returns (VM_TYPE vmType, bool isRegistered);

    /**
     * @dev Returns the owner key (UOA) for a given UEA address
     * @param _uea The UEA address
     * @return The owner key associated with this UEA
     */
    function getOwnerForUEA(address _uea) external view returns (bytes memory);

    /**
     * @dev Returns the computed UEA address for a given Universal Account ID and deployment status
     * @param _id The Universal Account information
     * @return uea The address of the UEA (computed deterministically)
     * @return isDeployed True if the UEA has already been deployed
     */
    function getUEAForOwner(UniversalAccount memory _id) external view returns (address uea, bool isDeployed);
} 