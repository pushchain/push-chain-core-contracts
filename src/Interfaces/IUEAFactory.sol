// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalAccount} from "../libraries/Types.sol";

/**
 * @title IUEAFactory
 * @dev Interface for the Universal Executor Account Factory
 */
interface IUEAFactory {
    //*** Events ***//
    /// @notice Emitted when a new chain is registered with its VM type
    event ChainRegistered(bytes32 indexed chainHash, bytes32 vmHash);

    /// @notice Emitted when a new UEA is deployed for an external chain owner
    event UEADeployed(address indexed UEA, bytes owner, bytes32 chainHash);

    /// @notice Emitted when a UEA implementation is registered for a specific VM type
    event UEARegistered(bytes32 indexed chainHash, address UEA_Logic, bytes32 vmHash);

    //*** Functions ***//
    /**
     * @dev Registers a new chain with its VM type hash
     * @param _chainHash The hash of the chain name to register
     * @param _vmHash The VM type hash for this chain
     */
    function registerNewChain(bytes32 _chainHash, bytes32 _vmHash) external;

    /**
     * @dev Registers multiple UEA implementations in a batch
     * @param _chainHashes Array of chain hashes
     * @param _vmHashes Array of VM type hashes
     * @param _uea Array of UEA implementation addresses
     */
    function registerMultipleUEA(bytes32[] memory _chainHashes, bytes32[] memory _vmHashes, address[] memory _uea)
        external;

    /**
     * @dev Registers a UEA implementation for a specific VM type hash
     * @param _chainHash The hash of the chain name
     * @param _vmHash The VM type hash
     * @param _uea The UEA implementation address
     */
    function registerUEA(bytes32 _chainHash, bytes32 _vmHash, address _uea) external;

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
     * @dev Returns the VM type hash for a given chain hash and whether it's registered
     * @param _chainHash The hash of the chain name
     * @return vmHash The VM type hash
     * @return isRegistered True if the chain is registered, false otherwise
     */
    function getVMType(bytes32 _chainHash) external view returns (bytes32 vmHash, bool isRegistered);

    /**
     * @dev Returns the owner key (UOA) for a given UEA address
     * @param _uea The UEA address
     * @return account The Universal Account information associated with this UEA
     * @return isNative True if the address is a native EOA, false if it's a UEA
     */
    function getOriginForUEA(address _uea) external view returns (UniversalAccount memory account, bool isNative);

    /**
     * @dev Returns the computed UEA address for a given Universal Account ID and deployment status
     * @param _id The Universal Account information
     * @return uea The address of the UEA (computed deterministically)
     * @return isDeployed True if the UEA has already been deployed
     */
    function getUEAForOrigin(UniversalAccount memory _id) external view returns (address uea, bool isDeployed);
}
