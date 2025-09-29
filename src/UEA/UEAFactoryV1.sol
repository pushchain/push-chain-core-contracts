// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUEA} from "../interfaces/IUEA.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {UEAErrors as Errors} from "../libraries/Errors.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {IUEAFactory} from "../interfaces/IUEAFactory.sol";
import {UniversalAccountId} from "../libraries/Types.sol";
import {UEAProxy} from "./UEAProxy.sol";

/**
 * @title UEAFactoryV1
 * @dev A factory contract for deploying and managing Universal Executor Accounts (UEA) instances.
 *
 *      - UEA (Universal Executor Account) : Smart contract deployed for external chain users to interact with PUSH chain.
 *                                           Each UEA acts as a proxy for its owner.
 *      - UOA (Universal Owner Address)   : The address of the external chain owner who owns a particular UEA.
 *                                          This key is used for signature verification in UEAs.
 *      - VM Types                        : Different virtual machine environments (EVM, SVM, etc.) require specific implementation logic.
 *                                          Each chain is registered with a VM_TYPE_HASH, and each VM_TYPE_HASH is mapped to a corresponding UEA.
 *                                          This allows the factory to deploy the correct UEA implementation for different blockchain environments.
 *      - Chain identifiers               : These follow the CAIP-2 standard (e.g., "eip155:1" for Ethereum mainnet).
 *                                          The UniversalAccountId struct uses the chainNamespace and chainId for chain identification.
 *                                          The full identifier is hashed to produce a chainHash value for internal usage.
 *                                          Note: chainHash = keccak256(abi.encode(_id.chainNamespace, _id.chainId))
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

    /// @notice Maps UniversalAccountId(hash) to their deployed UEA contract addresses
    mapping(bytes32 => address) public UOA_to_UEA;

    /// @notice Maps UEA addresses to their Universal Account information
    mapping(address => UniversalAccountId) private UEA_to_UOA;

    /// @notice Maps chain identifiers to their registered VM type hashes
    mapping(bytes32 => bytes32) public CHAIN_to_VM;
    /// @notice The implementation of UEAProxy that will be cloned for each user
    address public UEA_PROXY_IMPLEMENTATION;

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
     * @dev Sets the UEAProxy implementation address
     * @param _UEA_PROXY_IMPLEMENTATION The new UEAProxy implementation address
     * @notice Can only be called by the contract owner
     * @notice Will revert if the address is zero
     */
    function setUEAProxyImplementation(address _UEA_PROXY_IMPLEMENTATION) external onlyOwner {
        if (_UEA_PROXY_IMPLEMENTATION == address(0)) {
            revert Errors.InvalidInputArgs();
        }
        UEA_PROXY_IMPLEMENTATION = _UEA_PROXY_IMPLEMENTATION;
    }

    /**
     * @inheritdoc IUEAFactory
     */
    function getUEA(bytes32 _chainHash) external view returns (address) {
        bytes32 vmHash = CHAIN_to_VM[_chainHash];
        return UEA_VM[vmHash];
    }

    /**
     * @inheritdoc IUEAFactory
     */
    function getVMType(bytes32 _chainHash) public view returns (bytes32 vmHash, bool isRegistered) {
        vmHash = CHAIN_to_VM[_chainHash];
        isRegistered = vmHash != bytes32(0);
        return (vmHash, isRegistered);
    }

    /**
     * @inheritdoc IUEAFactory
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
     * @inheritdoc IUEAFactory
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
     * @inheritdoc IUEAFactory
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
     * @inheritdoc IUEAFactory
     */
    function deployUEA(UniversalAccountId memory _id) external returns (address) {
        if (UEA_PROXY_IMPLEMENTATION == address(0)) {
            revert Errors.InvalidInputArgs();
        }

        bytes32 salt = generateSalt(_id);

        // Get the appropriate UEA Implementation based on VM type
        bytes32 chainHash = keccak256(abi.encode(_id.chainNamespace, _id.chainId));
        (bytes32 vmHash, bool isRegistered) = getVMType(chainHash);
        if (!isRegistered) {
            revert Errors.InvalidInputArgs();
        }

        address _ueaImplementation = UEA_VM[vmHash];
        if (_ueaImplementation == address(0)) {
            revert Errors.InvalidInputArgs();
        }

        // Deploy the UEAProxy using CREATE2 via cloneDeterministic
        address payable _UEAProxy = payable(UEA_PROXY_IMPLEMENTATION.cloneDeterministic(salt));

        // Initialize the proxy with the implementation address
        UEAProxy(_UEAProxy).initializeUEA(_ueaImplementation);

        // Initialize the UEA implementation through the proxy
        IUEA(_UEAProxy).initialize(_id);

        // Store mappings
        UOA_to_UEA[salt] = _UEAProxy;
        UEA_to_UOA[_UEAProxy] = _id;

        emit UEADeployed(_UEAProxy, _id.owner, _id.chainId, chainHash);
        return _UEAProxy;
    }

    /**
     * @inheritdoc IUEAFactory
     */
    function computeUEA(UniversalAccountId memory _id) public view returns (address) {
        if (UEA_PROXY_IMPLEMENTATION == address(0)) {
            revert Errors.InvalidInputArgs();
        }

        bytes32 chainHash = keccak256(abi.encode(_id.chainNamespace, _id.chainId));
        (, bool isRegistered) = getVMType(chainHash);
        if (!isRegistered) {
            revert Errors.InvalidInputArgs();
        }

        bytes32 salt = generateSalt(_id);
        return UEA_PROXY_IMPLEMENTATION.predictDeterministicAddress(salt, address(this));
    }

    /// @inheritdoc IUEAFactory
    function getOriginForUEA(address addr) external view returns (UniversalAccountId memory account, bool isUEA) {
        account = UEA_to_UOA[addr];

        // If the address has an associated Universal Account (owner.length > 0),
        // then it is a UEA contract - isUEA = true
        if (account.owner.length > 0) {
            isUEA = true;
        } else {
            // If Account is NOT UEA, then it is a native EOA account on PUSH Chain
            // So we need to set the chainNamespace to eip155 and chainId to 42101
            // and the owner to the address of the EOA
            account =
                UniversalAccountId({chainNamespace: "eip155", chainId: "42101", owner: bytes(abi.encodePacked(addr))});
        }

        return (account, isUEA);
    }
    /// @inheritdoc IUEAFactory

    function getUEAForOrigin(UniversalAccountId memory _id) external view returns (address uea, bool isDeployed) {
        bytes32 salt = generateSalt(_id);

        uea = UOA_to_UEA[salt];

        if (uea != address(0)) {
            isDeployed = hasCode(uea);
            return (uea, isDeployed);
        }

        uea = computeUEA(_id);
        isDeployed = hasCode(uea);

        return (uea, isDeployed);
    }


    //========================
    //           Helpers
    //========================

    /**
     * @dev         Helper function to check if an address has code deployed
     * @param _addr address to check
     * @return bool True if the address has code, false otherwise
     */
    function hasCode(address _addr) public view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }

    /**
     * @dev             Generates a unique salt for CREATE2 deployment based on Universal Account info
     * @param _id       Universal Account information
     * @return bytes32  a unique salt derived from the account information
     */
    function generateSalt(UniversalAccountId memory _id) public pure returns (bytes32) {
        return keccak256(abi.encode(_id));
    }
}
