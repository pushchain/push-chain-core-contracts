// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ISmartAccount} from "./Interfaces/ISmartAccount.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {Errors} from "./libraries/Errors.sol";
import {UniversalAccount, VM_TYPE} from "./libraries/Types.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IUEAFactory} from "./Interfaces/IUEAFactory.sol";

/**
 * @title UEAFactoryV1
 * @dev A factory contract for deploying and managing Universal Executor Accounts (UEA) instances.
 *
 *      Key Terms:
 *      - UEA (Universal Executor Account): Smart contract deployed for external chain users
 *        to interact with PUSH chain. Each UEA acts as a proxy for its owner.
 *      - UOA (Universal Owner Address): The address of the external chain owner who
 *        owns a particular UEA. This key is used for signature verification in UEAs.
 *      - VM Types: Different virtual machine environments (EVM, SVM, etc.) that require
 *        specific implementation logic. Each chain is registered with its VM type, and
 *        each VM type is mapped to a corresponding UEA implementation contract address.
 *        This allows the factory to deploy the correct UEA implementation for different
 *        blockchain environments.
 *
 *      The contract uses OZ's Clones library to create deterministic addresses (CREATE2) for UEA instances.
 *      It keeps track of deployed UEAs and their corresponding user keys from external chains.
 *
 * @notice Use this contract to deploy new UEA instances and compute their addresses deterministically.
 */
contract UEAFactoryV1 is Ownable, IUEAFactory {
    using Clones for address;

    /// @notice Maps VM types (as uint256) to their corresponding UEA implementation addresses
    /// @dev VM_TYPE enum values are used as keys in this mapping
    mapping(uint256 => address) public UEA_VM;

    /// @notice Maps owner keys (from external chains) to their deployed UEA contract addresses
    /// @dev Key is the owner's public key from the external chain (as bytes)
    mapping(bytes => address) public UOA_to_UEA;

    /// @notice Maps UEA addresses to their owner keys
    /// @dev Inverse of UOA_to_UEA to allow lookup in both directions
    mapping(address => bytes) private UEA_to_UOA;

    /// @notice Maps chain identifiers to their registered VM types
    /// @dev Key is the keccak256 hash of the chain name/identifier
    mapping(bytes32 => VM_TYPE) public CHAIN_to_VM;

    /// @notice Emitted when a new chain is registered with its VM type
    event ChainRegistered(bytes32 indexed chainHash, uint256 vmType);

    /// @notice Emitted when a new UEA is deployed for an external chain owner
    event UEADeployed(address indexed UEA, bytes ownerKey, bytes32 chainHash);

    /// @notice Emitted when a UEA implementation is registered for a specific VM type
    event UEARegistered(bytes32 indexed chainHash, address UEA_Logic, uint256 vmType);

    constructor() Ownable(msg.sender) {}

    /**
     * @dev Returns the UEA implementation address for a given chain
     * @param _chainHash The hash of the chain name
     * @return The UEA implementation address for the chain's VM type
     */
    function getUEA(bytes32 _chainHash) external view returns (address) {
        return UEA_VM[uint256(CHAIN_to_VM[_chainHash])];
    }

    /**
     * @dev Returns the VM type for a given chain hash and whether it's registered
     * @param _chainHash The hash of the chain name
     * @return vmType The VM type (will be UNREGISTERED if not explicitly set)
     * @return isRegistered True if the chain is registered, false otherwise
     */
    function getVMType(bytes32 _chainHash) public view returns (VM_TYPE vmType, bool isRegistered) {
        vmType = CHAIN_to_VM[_chainHash];
        isRegistered = vmType != VM_TYPE.UNREGISTERED;
        return (vmType, isRegistered);
    }

    /**
     * @dev Registers a new chain with its VM type
     * @param _chainHash The hash of the chain name to register
     * @param _vmType The VM type for this chain
     * @notice Can only be called by the contract owner
     * @notice Will revert if the chain is already registered or if VM type is invalid
     */
    function registerNewChain(bytes32 _chainHash, VM_TYPE _vmType) external onlyOwner {
        // Check that the chainHash is not already registered. If yes, revert.
        VM_TYPE currentVmType = CHAIN_to_VM[_chainHash];
        if (currentVmType != VM_TYPE.UNREGISTERED) {
            revert Errors.InvalidInputArgs();
        }
        // Register the chain with the specified VM type
        CHAIN_to_VM[_chainHash] = _vmType;
        emit ChainRegistered(_chainHash, uint256(_vmType));
    }

    /**
     * @dev Registers multiple UEA implementations in a batch
     * @param _chainHashes Array of chain hashes
     * @param _UEA Array of UEA implementation addresses
     * @notice Can only be called by the contract owner
     * @notice Will revert if arrays are not the same length
     */
    function registerMultipleUEA(bytes32[] memory _chainHashes, address[] memory _UEA) external onlyOwner {
        if (_UEA.length != _chainHashes.length) {
            revert Errors.InvalidInputArgs();
        }

        for (uint256 i = 0; i < _UEA.length; i++) {
            registerUEA(_chainHashes[i], _UEA[i]);
        }
    }

    /**
     * @dev Registers a UEA implementation for a specific chain
     * @param _chainHash The hash of the chain name
     * @param _UEA The UEA implementation address
     * @notice Can only be called by the contract owner
     * @notice Will revert if the UEA address is zero or if the chain is not registered
     */
    function registerUEA(bytes32 _chainHash, address _UEA) public onlyOwner {
        require(_UEA != address(0), "_UEA address cannot be invalid");

        (VM_TYPE vmType, bool isRegistered) = getVMType(_chainHash);
        require(isRegistered, "Chain is not registered");

        UEA_VM[uint256(vmType)] = _UEA;
        emit UEARegistered(_chainHash, _UEA, uint256(vmType));
    }

    /**
     * @dev Deploys a new UEA for an external chain user
     * @param _id The Universal Account information containing chain and owner key
     * @return The address of the deployed UEA
     * @notice Will revert if the account already exists, the chain is not registered,
     *         or if no UEA implementation is available for the chain's VM type
     */
    function deployUEA(UniversalAccount memory _id) external returns (address) {
        if (UOA_to_UEA[_id.ownerKey] != address(0)) {
            revert Errors.AccountAlreadyExists();
        }

        // Get the appropriate UEA Implementation based on VM type
        bytes32 chainHash = keccak256(abi.encode(_id.CHAIN));
        (VM_TYPE vmType, bool isRegistered) = getVMType(chainHash);
        require(isRegistered, "Chain is not registered");

        address _ueaImplementation = UEA_VM[uint256(vmType)];
        require(_ueaImplementation != address(0), "No _ueaImplementation for this VM type");

        bytes32 salt = generateSalt(_id);

        address payable _UEA = payable(_ueaImplementation.cloneDeterministic(salt));
        UOA_to_UEA[_id.ownerKey] = _UEA;
        UEA_to_UOA[_UEA] = _id.ownerKey; // Store the inverse mapping
        ISmartAccount(_UEA).initialize(_id);

        emit UEADeployed(_UEA, _id.ownerKey, chainHash);
        return _UEA;
    }

    /**
     * @dev Computes the address of a UEA before it is deployed
     * @param _id The Universal Account information containing chain and owner key
     * @return The computed address of the UEA
     * @notice Will revert if the chain is not registered or if no UEA implementation
     *         is available for the chain's VM type
     */
    function computeUEA(UniversalAccount memory _id) public view returns (address) {
        bytes32 chainHash = keccak256(abi.encode(_id.CHAIN));
        (VM_TYPE vmType, bool isRegistered) = getVMType(chainHash);
        require(isRegistered, "Chain is not registered");

        address _ueaImplementation = UEA_VM[uint256(vmType)];
        require(_ueaImplementation != address(0), "No _ueaImplementation for this VM type");

        bytes32 salt = generateSalt(_id);
        return _ueaImplementation.predictDeterministicAddress(salt, address(this));
    }

    /**
     * @dev Helper function to check if an address has code deployed
     * @param _addr The address to check
     * @return True if the address has code, false otherwise
     */
    function hasCode(address _addr) public view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }

    /**
     * @dev Returns the UOA (owner key) for a given UEA address
     * @param _uea The UEA address
     * @return The owner key (UOA) associated with this UEA
     */
    function getOwnerForUEA(address _uea) external view returns (bytes memory) {
        return UEA_to_UOA[_uea];
    }

    /**
     * @dev Returns the computed UEA address for a given Universal Account ID and deployment status
     * @param _id The Universal Account information
     * @return uea The address of the UEA (computed deterministically)
     * @return isDeployed True if the UEA has already been deployed
     */
    function getUEAForOwner(UniversalAccount memory _id) external view returns (address uea, bool isDeployed) {
        // Check if we already have a mapping
        uea = UOA_to_UEA[_id.ownerKey];

        if (uea != address(0)) {
            // We have a mapping, but check if it's actually deployed
            isDeployed = hasCode(uea);
            return (uea, isDeployed);
        }

        // No mapping exists, compute the address
        uea = computeUEA(_id);
        isDeployed = hasCode(uea);

        return (uea, isDeployed);
    }

    /**
     * @dev Generates a unique salt for CREATE2 deployment based on Universal Account info
     * @param _id The Universal Account information
     * @return A unique salt derived from the account information
     */
    function generateSalt(UniversalAccount memory _id) public pure returns (bytes32) {
        return keccak256(abi.encode(_id));
    }
}
