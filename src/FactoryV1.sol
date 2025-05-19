// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SmartAccountV1} from "./smartAccounts/SmartAccountV1.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {Errors} from "./libraries/Errors.sol";
import {AccountId, VM_TYPE} from "./libraries/Types.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title FactoryV1
 * @dev A factory contract for deploying and managing SmartAccount instances using the minimal proxy pattern.
 *      The contract OZ's Clones library to create deterministic addresses ( CREATE2 ) for smart accounts.
 *      The contract also keeps track of the deployed smart accounts and their corresponding user keys.
 * @notice Use this contract to deploy new SmartAccountV1 instances and compute their addresses deterministically.
 */
contract FactoryV1 is Ownable {
    using Clones for address;

    // Map VM types to their corresponding implementations
    mapping(uint256 => address) public accountImplmentationForVM;
    mapping(bytes => address) public userAccounts;

    event SmartAccountDeployed(address indexed smartAccount, bytes ownerKey, AccountId id);
    event ImplementationRegistered(uint256 indexed vmType, address implementation);

    /**
     * @dev Constructor to register multiple implementations for different VM types.
     * @param _implementations Array of implementation addresses
     * @param _vmTypes Array of VM types corresponding to each implementation
     */
    constructor(address[] memory _implementations, uint256[] memory _vmTypes) Ownable(msg.sender) {
        if (_implementations.length != _vmTypes.length) {
            revert Errors.InvalidInputArgs();
        }

        // Register all implementations
        for (uint256 i = 0; i < _implementations.length; i++) {
            registerImplementation(_vmTypes[i], _implementations[i]);
        }
    }

    /**
     * @dev Returns the implementation address for backward compatibility
     */
    function getImplementation(VM_TYPE _vmType) external view returns (address) {
        return accountImplmentationForVM[uint256(_vmType)];
    }

    /**
     * @dev Registers multiple implementations for different VM types.
     * @param _vmTypes Array of VM types
     * @param _implementations Array of implementation addresses
     */
    function registerMultipleImplementations(uint256[] memory _vmTypes, address[] memory _implementations)
        external
        onlyOwner
    {
        if (_implementations.length != _vmTypes.length) {
            revert Errors.InvalidInputArgs();
        }

        for (uint256 i = 0; i < _implementations.length; i++) {
            registerImplementation(_vmTypes[i], _implementations[i]);
        }
    }

    /**
     * @dev Registers a new implementation for a specific VM type.
     * @param _vmType The VM type enum value.
     * @param _implementation The address of the implementation contract.
     */
    function registerImplementation(uint256 _vmType, address _implementation) public onlyOwner {
        require(_implementation != address(0), "Implementation cannot be zero address");
        accountImplmentationForVM[_vmType] = _implementation;
        emit ImplementationRegistered(_vmType, _implementation);
    }

    /**
     * @dev Deploys a new SmartAccount instance with the given user key and VM type.
     * @param _id AccountId struct containing all details
     */
    function deploySmartAccount(AccountId memory _id) external returns (address) {
        if (userAccounts[_id.ownerKey] != address(0)) {
            revert Errors.AccountAlreadyExists();
        }

        if (uint256(_id.vmType) >= uint256(VM_TYPE.OTHER_VM) + 1) {
            revert Errors.InvalidInputArgs();
        }

        // Get the appropriate implementation based on VM type
        address implementation = accountImplmentationForVM[uint256(_id.vmType)];
        require(implementation != address(0), "No implementation for this VM type");

        bytes32 salt = keccak256(abi.encode(_id.ownerKey));

        address payable smartAccount = payable(implementation.cloneDeterministic(salt));
        userAccounts[_id.ownerKey] = smartAccount;
        SmartAccountV1(smartAccount).initialize(_id);

        emit SmartAccountDeployed(smartAccount, _id.ownerKey, _id);
        return smartAccount;
    }

    /**
     * @dev Computes the deterministic address of a SmartAccountV1 instance based on the user key and VM type.
     * @param _id AccountId struct containing all details
     * @return smartAccount The computed address of the SmartAccountV1 instance.
     */
    function computeSmartAccountAddress(AccountId memory _id) external view returns (address) {
        if (uint256(_id.vmType) >= uint256(VM_TYPE.OTHER_VM) + 1) {
            revert Errors.InvalidInputArgs();
        }

        address implementation = accountImplmentationForVM[uint256(_id.vmType)];
        require(implementation != address(0), "No implementation for this VM type");

        bytes32 salt = keccak256(abi.encode(_id.ownerKey));
        return implementation.predictDeterministicAddress(salt, address(this));
    }
}
