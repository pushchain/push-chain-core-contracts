// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ICEAFactory} from "../interfaces/ICEAFactory.sol";
import {ICEA} from "../interfaces/ICEA.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ICEAProxy} from "../interfaces/ICEAProxy.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/**
 * @title   CEAFactory
 * @notice  Factory for Chain Executor Accounts (CEAs) on external chains.
 *
 * @dev
 *  - This contract is deployed on an external chain (e.g., Base, Ethereum mainnet, etc.).
 *  - It deploys minimal proxy CEAs via CREATE2 using a shared CEA proxy implementation.
 *  - It maintains a 1:1 mapping between UEA (on Push) and CEA (on this chain) in v1.
 *  - Only the external chain Vault is allowed to deploy CEAs and drive their execution.
 *
 *  New (v1.1) design:
 *  - CEAFactory now tracks:
 *      * CEA_PROXY_IMPLEMENTATION  : template proxy (CEAProxy) to be cloned.
 *      * CEA_IMPLEMENTATION        : shared CEA logic contract (delegated to by proxies).
 *      * UNIVERSAL_GATEWAY         : UniversalGateway on this external chain.
 *  - deployCEA flow:
 *      * cloneDeterministic(CEA_PROXY_IMPLEMENTATION)
 *      * CEAProxy(cea).initializeCEAProxy(CEA_IMPLEMENTATION)
 *      * ICEA(cea).initializeCEA(pushAccount, VAULT, UNIVERSAL_GATEWAY)
 */
contract CEAFactory is Initializable, OwnableUpgradeable, ICEAFactory {
    using Clones for address;

    //========================
    //           State
    //========================

    /// @inheritdoc ICEAFactory
    address public VAULT;

    /// @notice Address of the Universal Gateway on this external chain.
    address public UNIVERSAL_GATEWAY;

    /// @notice CEA proxy implementation (CEAProxy) that will be cloned for each CEA.
    address public CEA_PROXY_IMPLEMENTATION;

    /// @notice CEA logic implementation that all CEA proxies delegate to.
    address public CEA_IMPLEMENTATION;

    /// @notice Address of the CEA migration contract
    address public CEA_MIGRATION_CONTRACT;

    /// @notice Mapping from push account (UEA on Push Chain) -> CEA on this chain.
    mapping(address => address) public pushAccountToCEA;

    /// @notice Mapping from CEA on this chain -> push account (UEA on Push Chain).
    mapping(address => address) public ceaToPushAccount;

    //========================
    //          Errors
    //========================

    error ZeroAddress();
    error NotVault();
    error InvalidImplementation();
    error CEAAlreadyDeployed();

    //========================
    //        Events
    //========================

    /// @notice Emitted when the CEA migration contract is updated
    event CEAMigrationContractUpdated(address indexed oldContract, address indexed newContract);

    //========================
    //        Modifiers
    //========================

    modifier onlyVault() {
        if (msg.sender != VAULT) revert NotVault();
        _;
    }

    //========================
    //        Initializer
    //========================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the CEAFactory with owner, VAULT, UG, and proxy/logic implementations.
     *
     * @param initialOwner             Owner of the factory (governance).
     * @param initialVault             Vault address on this chain (sole deployer/driver of CEAs).
     * @param ceaProxyImplementation   CEA proxy implementation to clone for each CEA (CEAProxy).
     * @param ceaImplementation        CEA logic implementation (CEA) to be set on each proxy.
     * @param universalGateway         Universal Gateway contract on this chain.
     */
    function initialize(
        address initialOwner,
        address initialVault,
        address ceaProxyImplementation,
        address ceaImplementation,
        address universalGateway
    ) external initializer {
        if (
            initialOwner == address(0) || initialVault == address(0) || ceaProxyImplementation == address(0)
                || ceaImplementation == address(0) || universalGateway == address(0)
        ) {
            revert ZeroAddress();
        }

        __Ownable_init(initialOwner);

        VAULT = initialVault;
        CEA_PROXY_IMPLEMENTATION = ceaProxyImplementation;
        CEA_IMPLEMENTATION = ceaImplementation;
        UNIVERSAL_GATEWAY = universalGateway;
    }

    //========================
    //     Admin / governance
    //========================

    /// @notice Sets the VAULT address.
    /// @param newVault The new VAULT address.
    function setVault(address newVault) external onlyOwner {
        if (newVault == address(0)) revert ZeroAddress();
        address old = VAULT;
        VAULT = newVault;
        emit VaultUpdated(old, newVault);
    }

    /// @notice Sets the CEA proxy implementation (CEAProxy template).
    /// @param newImplementation The new CEA proxy implementation address.
    function setCEAProxyImplementation(address newImplementation) external onlyOwner {
        if (newImplementation == address(0)) revert ZeroAddress();
        address old = CEA_PROXY_IMPLEMENTATION;
        CEA_PROXY_IMPLEMENTATION = newImplementation;
        emit CEAProxyImplementationUpdated(old, newImplementation);
    }

    /// @notice Sets the CEA logic implementation.
    /// @param newImplementation The new CEA logic implementation (CEA) address.
    function setCEAImplementation(address newImplementation) external onlyOwner {
        if (newImplementation == address(0)) revert ZeroAddress();
        address old = CEA_IMPLEMENTATION;
        CEA_IMPLEMENTATION = newImplementation;
        emit CEAImplementationUpdated(old, newImplementation);
    }

    /// @notice Sets the Universal Gateway address for this chain.
    /// @param newUG The new Universal Gateway address.
    function setUniversalGateway(address newUG) external onlyOwner {
        if (newUG == address(0)) revert ZeroAddress();
        address old = UNIVERSAL_GATEWAY;
        UNIVERSAL_GATEWAY = newUG;
        emit UniversalGatewayUpdated(old, newUG);
    }

    /// @notice Sets the CEA migration contract address
    /// @dev    Only callable by owner (governance)
    /// @param  newMigrationContract Address of the CEA migration contract
    function setCEAMigrationContract(address newMigrationContract) external onlyOwner {
        if (newMigrationContract == address(0)) revert ZeroAddress();
        address old = CEA_MIGRATION_CONTRACT;
        CEA_MIGRATION_CONTRACT = newMigrationContract;
        emit CEAMigrationContractUpdated(old, newMigrationContract);
    }

    //========================
    //        View helpers
    //========================

    /// @inheritdoc ICEAFactory
    function getCEAForPushAccount(address pushAccount) external view override returns (address cea, bool isDeployed) {
        address mapped = pushAccountToCEA[pushAccount];

        if (mapped != address(0)) {
            cea = mapped;
        } else {
            cea = _computeCEAInternal(pushAccount);
        }

        isDeployed = _hasCode(cea);
    }

    /// @inheritdoc ICEAFactory
    function computeCEA(address pushAccount) external view override returns (address cea) {
        return _computeCEAInternal(pushAccount);
    }

    /// @inheritdoc ICEAFactory
    function isCEA(address addr) external view override returns (bool isCea) {
        return ceaToPushAccount[addr] != address(0);
    }

    /// @inheritdoc ICEAFactory
    function getPushAccountForCEA(address cea) external view override returns (address pushAccount) {
        return ceaToPushAccount[cea];
    }

    //========================
    //      Core function
    //========================

    /// @inheritdoc ICEAFactory
    function deployCEA(address pushAccount) external override onlyVault returns (address cea) {
        if (pushAccount == address(0)) revert ZeroAddress();
        if (CEA_PROXY_IMPLEMENTATION == address(0) || CEA_IMPLEMENTATION == address(0)) {
            revert InvalidImplementation();
        }
        if (UNIVERSAL_GATEWAY == address(0)) {
            revert InvalidImplementation();
        }

        // If a mapping already exists and code is present, treat as already deployed.
        address existing = pushAccountToCEA[pushAccount];
        if (existing != address(0) && _hasCode(existing)) {
            revert CEAAlreadyDeployed();
        }

        bytes32 salt = _generateSalt(pushAccount);

        // 1. Clone the CEAProxy (template)
        cea = CEA_PROXY_IMPLEMENTATION.cloneDeterministic(salt);

        // 2. Initialize the proxy with the CEA logic implementation
        ICEAProxy(cea).initializeCEAProxy(CEA_IMPLEMENTATION);

        // 3. Initialize the CEA logic through the proxy (pass factory address)
        ICEA(cea).initializeCEA(pushAccount, VAULT, UNIVERSAL_GATEWAY, address(this));

        // 4. Store mappings
        pushAccountToCEA[pushAccount] = cea;
        ceaToPushAccount[cea] = pushAccount;

        emit CEADeployed(pushAccount, cea);
    }

    //========================
    //          Internals
    //========================

    function _computeCEAInternal(address pushAccount) internal view returns (address) {
        if (CEA_PROXY_IMPLEMENTATION == address(0)) revert InvalidImplementation();
        bytes32 salt = _generateSalt(pushAccount);
        return CEA_PROXY_IMPLEMENTATION.predictDeterministicAddress(salt, address(this));
    }

    function _generateSalt(address pushAccount) internal pure returns (bytes32) {
        // v1: 1 CEA per (UEA, chain). Factory address + chainId differentiate across chains.
        return keccak256(abi.encode(pushAccount));
    }

    function _hasCode(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }
}
