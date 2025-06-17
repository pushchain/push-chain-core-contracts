// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUEA} from "./Interfaces/IUEA.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {Errors} from "./libraries/Errors.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {IUEAFactory} from "./Interfaces/IUEAFactory.sol";
import {UniversalAccount} from "./libraries/Types.sol";

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
 *        specific implementation logic. Each chain is registered with its VM type hash, and
 *        each VM type hash is mapped to a corresponding UEA implementation contract address.
 *        This allows the factory to deploy the correct UEA implementation for different
 *        blockchain environments.
 *      - Chain identifiers: These follow the CAIP-2 standard (e.g., "eip155:1" for Ethereum mainnet).
 *        These standardized chain IDs are used to identify which blockchain an account belongs to.
 *        The full identifier is hashed to produce a chainHash value for internal usage.
 *
 *      The contract uses OZ's Clones library to create deterministic addresses (CREATE2) for UEA instances.
 *      It keeps track of deployed UEAs and their corresponding user keys from external chains.
 *
 * @notice Use this contract to deploy new UEA instances and compute their addresses deterministically.
 */
contract UEAFactoryV1 is Initializable, OwnableUpgradeable, IUEAFactory {
    using Clones for address;

    /// @notice Maps VM type hashes to their corresponding UEA implementation addresses
    mapping(bytes32 => address) public UEA_VM;

    /// @notice Maps UniversalAccount(hash) to their deployed UEA contract addresses
    mapping(bytes32 => address) public UOA_to_UEA;

    /// @notice Maps UEA addresses to their Universal Account information
    mapping(address => UniversalAccount) private UEA_to_UOA;

    /// @notice Maps chain identifiers to their registered VM type hashes
    mapping(bytes32 => bytes32) public CHAIN_to_VM;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract setting the provided address as the initial owner.
     * @param initialOwner The initial owner of the contract
     */
    function initialize(address initialOwner) public initializer {
        __Ownable_init(initialOwner);
    }

    /**
     * @dev Returns the UEA implementation address for a given chain
     * @param _chainHash The hash of the chain identifier (e.g., keccak256(abi.encode("eip155:1")))
     * @return The UEA implementation address for the chain's VM type
     */
    function getUEA(bytes32 _chainHash) external view returns (address) {
        bytes32 vmHash = CHAIN_to_VM[_chainHash];
        return UEA_VM[vmHash];
    }

    /**
     * @dev Returns the VM type hash for a given chain hash and whether it's registered
     * @param _chainHash The hash of the chain identifier (e.g., keccak256(abi.encode("eip155:1")))
     * @return vmHash The VM type hash
     * @return isRegistered True if the chain is registered, false otherwise
     */
    function getVMType(bytes32 _chainHash) public view returns (bytes32 vmHash, bool isRegistered) {
        vmHash = CHAIN_to_VM[_chainHash];
        isRegistered = vmHash != bytes32(0);
        return (vmHash, isRegistered);
    }

    /**
     * @dev Registers a new chain with its VM type hash
     * @param _chainHash The hash of the chain identifier to register (e.g., keccak256(abi.encode("eip155:1")))
     * @param _vmHash The VM type hash for this chain
     * @notice Can only be called by the contract owner
     * @notice Will revert if the chain is already registered or if VM type is invalid
     */
    function registerNewChain(bytes32 _chainHash, bytes32 _vmHash) external onlyOwner {
        // Check that the chainHash is not already registered. If yes, revert.
        (, bool isRegistered) = getVMType(_chainHash);
        if (isRegistered) {
            revert Errors.InvalidInputArgs();
        }

        CHAIN_to_VM[_chainHash] = _vmHash;
        emit ChainRegistered(_chainHash, _vmHash);
    }

    /**
     * @dev Registers multiple UEA implementations in a batch
     * @param _chainHashes Array of chain hashes
     * @param _vmHashes Array of VM type hashes
     * @param _UEA Array of UEA implementation addresses
     * @notice Can only be called by the contract owner
     * @notice Will revert if arrays are not the same length
     */
    function registerMultipleUEA(bytes32[] memory _chainHashes, bytes32[] memory _vmHashes, address[] memory _UEA)
        external
        onlyOwner
    {
        if (_UEA.length != _vmHashes.length || _UEA.length != _chainHashes.length) {
            revert Errors.InvalidInputArgs();
        }

        for (uint256 i = 0; i < _UEA.length; i++) {
            registerUEA(_chainHashes[i], _vmHashes[i], _UEA[i]);
        }
    }

    /**
     * @dev Registers a UEA implementation for a specific VM type hash
     * @param _chainHash The hash of the chain identifier (e.g., keccak256(abi.encode("eip155:1")))
     * @param _vmHash The VM type hash for this chain
     * @param _UEA The UEA implementation address
     * @notice Can only be called by the contract owner
     * @notice Will revert if the UEA address is zero or if vmHash doesn't match the chain's registered vmHash
     */
    function registerUEA(bytes32 _chainHash, bytes32 _vmHash, address _UEA) public onlyOwner {
        if (_UEA == address(0)) {
            revert Errors.InvalidInputArgs();
        }

        // Get the vmHash registered for this chain and verify it matches the provided vmHash
        (bytes32 registeredVmHash, bool isRegistered) = getVMType(_chainHash);
        if (!isRegistered || registeredVmHash != _vmHash) {
            revert Errors.InvalidInputArgs();
        }

        UEA_VM[_vmHash] = _UEA;
        emit UEARegistered(_chainHash, _UEA, _vmHash);
    }

    /**
     * @dev Deploys a new UEA for an external chain user
     * @param _id The Universal Account information containing chain (e.g., "ETHEREUM") and owner key
     * @return The address of the deployed UEA
     * @notice Will revert if the account already exists, the chain is not registered,
     *         or if no UEA implementation is available for the chain's VM type
     */
    function deployUEA(UniversalAccount memory _id) external returns (address) {
        bytes32 salt = generateSalt(_id);
        if (UOA_to_UEA[salt] != address(0)) {
            revert Errors.AccountAlreadyExists();
        }

        // Get the appropriate UEA Implementation based on VM type
        bytes32 chainHash = keccak256(abi.encode(_id.chain));
        (bytes32 vmHash, bool isRegistered) = getVMType(chainHash);
        if (!isRegistered) {
            revert Errors.InvalidInputArgs();
        }

        address _ueaImplementation = UEA_VM[vmHash];
        if (_ueaImplementation == address(0)) {
            revert Errors.InvalidInputArgs();
        }

        address _UEA = _ueaImplementation.cloneDeterministic(salt);
        UOA_to_UEA[salt] = _UEA;
        UEA_to_UOA[_UEA] = _id; // Store the inverse mapping
        IUEA(_UEA).initialize(_id);

        emit UEADeployed(_UEA, _id.owner, chainHash);
        return _UEA;
    }

    /**
     * @dev Computes the address of a UEA before it is deployed
     * @param _id The Universal Account information containing chain identifier (e.g., "eip155:1") and owner key
     * @return The computed address of the UEA
     * @notice Will revert if the chain is not registered or if no UEA implementation
     *         is available for the chain's VM type
     */
    function computeUEA(UniversalAccount memory _id) public view returns (address) {
        bytes32 chainHash = keccak256(abi.encode(_id.chain));
        (bytes32 vmHash, bool isRegistered) = getVMType(chainHash);
        if (!isRegistered) {
            revert Errors.InvalidInputArgs();
        }

        address _ueaImplementation = UEA_VM[vmHash];
        if (_ueaImplementation == address(0)) {
            revert Errors.InvalidInputArgs();
        }

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

    /// @inheritdoc IUEAFactory
    function getOriginForUEA(address _uea) external view returns (UniversalAccount memory account, bool isNative) {
        account = UEA_to_UOA[_uea];
        
        // If the address has no associated Universal Account (owner.length == 0), 
        // then it's likely a native EOA account on PUSH Chain
        if (account.owner.length == 0) {
            isNative = true;
            // We don't need to set any values for native accounts
        } else {
            // This is a UEA with a valid Universal Account
            isNative = false;
        }
        
        return (account, isNative);
    }

    /// @inheritdoc IUEAFactory
    function getUEAForOrigin(UniversalAccount memory _id) external view returns (address uea, bool isDeployed) {
        // Generate salt from the UniversalAccount struct
        bytes32 salt = generateSalt(_id);

        // Check if we already have a mapping
        uea = UOA_to_UEA[salt];

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
