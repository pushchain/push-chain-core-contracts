// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { SmartAccountV1 } from "./SmartAccountV1.sol";
import { Clones } from "@openzeppelin/contracts/proxy/Clones.sol";


/**
 * @title FactoryV1
 * @dev A factory contract for deploying and managing SmartAccount instances using the minimal proxy pattern.
 *      The contract OZ's Clones library to create deterministic addresses ( CREATE2 ) for smart accounts.
 *      The contract also keeps track of the deployed smart accounts and their corresponding user keys.
 * @notice Use this contract to deploy new SmartAccountV1 instances and compute their addresses deterministically.
 */
contract FactoryV1 {
    using Clones for address;

    address public smartAccountImplementation;
    mapping(bytes => address) public userAccounts;

    event SmartAccountDeployed(address indexed smartAccount, bytes userKey);

    /**
     * @dev Constructor to set the implementation address for SmartAccountV1.
     * @param _smartAccountImplementation The address of the SmartAccountV1 implementation contract.
     */
    constructor(address _smartAccountImplementation) {
        smartAccountImplementation = _smartAccountImplementation;
    }

    /**
     * @dev Deploys a new SmartAccountV1 instance with the given user key and owner type.
     * @param userKey The unique key for the user, used to compute the deterministic address.
     * @param ownerType The type of owner (EVM or NON_EVM) for the SmartAccount.
     * @param verifierPrecompile The address of the verifier precompile contract.
     * @return smartAccount The address of the newly deployed SmartAccountV1 instance.
     */
    function deploySmartAccount(
        bytes memory userKey,
        SmartAccountV1.OwnerType ownerType,
        address verifierPrecompile
    ) external returns(address) {
        require(userAccounts[userKey] == address(0), "Account already exists");

        bytes32 salt = keccak256(userKey);

        address smartAccount = smartAccountImplementation.cloneDeterministic(salt);
        userAccounts[userKey] = smartAccount;
        SmartAccountV1(smartAccount).initialize(userKey, ownerType, verifierPrecompile);

        emit SmartAccountDeployed(smartAccount, userKey);
        return smartAccount;
    }

    /**
     * @dev Computes the deterministic address of a SmartAccountV1 instance based on the user key.
     * @param userKey The unique key for the user, used to compute the deterministic address.
     * @return smartAccount The computed address of the SmartAccountV1 instance.
     */
    function computeSmartAccountAddress(
        bytes memory userKey
    ) external view returns (address) {
        bytes32 salt = keccak256(userKey);
        return smartAccountImplementation.predictDeterministicAddress(salt, address(this));
    }
}