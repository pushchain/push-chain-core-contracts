// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ICEAFactory} from "../interfaces/ICEAFactory.sol";
import {ICEA} from "../interfaces/ICEA.sol";
import {ICEAProxy} from "../interfaces/ICEAProxy.sol";
import {CEAErrors} from "../libraries/Errors.sol";

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/**
 * @title   CEAFactory
 * @notice  Factory for Chain Executor Accounts (CEAs) on external chains.
 * @dev     Deploys minimal proxy CEAs via CREATE2 using a shared CEA proxy
 *          implementation. Maintains a 1:1 mapping between UEA (on Push) and
 *          CEA (on this chain).
 *
 *          Access control uses OpenZeppelin AccessControl:
 *          - DEFAULT_ADMIN_ROLE: governance — can update all config and grant roles.
 *          - PAUSER_ROLE:        guardian hot-wallet — can pause/unpause only.
 */
contract CEAFactory is Initializable, AccessControlUpgradeable, PausableUpgradeable, ICEAFactory {
    using Clones for address;

    // =========================
    //    CF: ROLES
    // =========================

    /// @notice Role that can pause and unpause CEA deployments.
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // =========================
    //    CF: STATE VARIABLES
    // =========================

    /// @inheritdoc ICEAFactory
    address public VAULT;

    /// @notice Address of the Universal Gateway on this external chain.
    address public UNIVERSAL_GATEWAY;

    /// @notice CEA proxy implementation (CEAProxy) that will be cloned for each CEA.
    address public CEA_PROXY_IMPLEMENTATION;

    /// @notice CEA logic implementation that all CEA proxies delegate to.
    address public CEA_IMPLEMENTATION;

    /// @notice Address of the CEA migration contract.
    address public CEA_MIGRATION_CONTRACT;

    /// @notice Mapping from push account (UEA on Push Chain) to CEA on this chain.
    mapping(address => address) public pushAccountToCEA;

    /// @notice Mapping from CEA on this chain to push account (UEA on Push Chain).
    mapping(address => address) public ceaToPushAccount;

    // =========================
    //    CF: MODIFIERS
    // =========================

    /// @notice Restricts to the Vault contract.
    modifier onlyVault() {
        if (msg.sender != VAULT) revert CEAErrors.NotVault();
        _;
    }

    // =========================
    //    CF: CONSTRUCTOR
    // =========================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev                              Initializer for the upgradeable CEAFactory.
    /// @param initialAdmin               Owner of the factory (governance) — granted DEFAULT_ADMIN_ROLE
    /// @param initialPauser              Address granted the PAUSER_ROLE
    /// @param initialVault               Vault address on this chain
    /// @param ceaProxyImplementation     CEA proxy implementation to clone (CEAProxy)
    /// @param ceaImplementation          CEA logic implementation (CEA)
    /// @param universalGateway           Universal Gateway on this chain
    function initialize(
        address initialAdmin,
        address initialPauser,
        address initialVault,
        address ceaProxyImplementation,
        address ceaImplementation,
        address universalGateway
    ) external initializer {
        if (
            initialAdmin == address(0)
                || initialPauser == address(0)
                || initialVault == address(0)
                || ceaProxyImplementation == address(0)
                || ceaImplementation == address(0)
                || universalGateway == address(0)
        ) {
            revert CEAErrors.ZeroAddress();
        }

        __AccessControl_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(PAUSER_ROLE, initialPauser);
        emit PauserRoleGranted(initialPauser);

        VAULT = initialVault;
        CEA_PROXY_IMPLEMENTATION = ceaProxyImplementation;
        CEA_IMPLEMENTATION = ceaImplementation;
        UNIVERSAL_GATEWAY = universalGateway;
    }

    // =========================
    //    CF_1: VIEW FUNCTIONS
    // =========================

    /// @inheritdoc ICEAFactory
    function getCEAForPushAccount(
        address pushAccount
    ) external view override returns (address cea, bool isDeployed) {
        address mapped = pushAccountToCEA[pushAccount];

        if (mapped != address(0)) {
            cea = mapped;
        } else {
            cea = _computeCEAInternal(pushAccount);
        }

        isDeployed = _hasCode(cea);
    }

    /// @inheritdoc ICEAFactory
    function computeCEA(
        address pushAccount
    ) external view override returns (address cea) {
        return _computeCEAInternal(pushAccount);
    }

    /// @inheritdoc ICEAFactory
    function isCEA(
        address addr
    ) external view override returns (bool isCea) {
        return ceaToPushAccount[addr] != address(0);
    }

    /// @inheritdoc ICEAFactory
    function getPushAccountForCEA(
        address cea
    ) external view override returns (address pushAccount) {
        return ceaToPushAccount[cea];
    }

    // =========================
    //    CF_2: VAULT OPERATIONS
    // =========================

    /// @inheritdoc ICEAFactory
    function deployCEA(
        address pushAccount
    ) external override onlyVault whenNotPaused returns (address cea) {
        if (pushAccount == address(0)) revert CEAErrors.ZeroAddress();
        if (
            CEA_PROXY_IMPLEMENTATION == address(0)
                || CEA_IMPLEMENTATION == address(0)
        ) {
            revert CEAErrors.InvalidImplementation();
        }
        if (UNIVERSAL_GATEWAY == address(0)) {
            revert CEAErrors.InvalidImplementation();
        }

        address existing = pushAccountToCEA[pushAccount];
        if (existing != address(0) && _hasCode(existing)) {
            revert CEAErrors.CEAAlreadyDeployed();
        }

        bytes32 salt = _generateSalt(pushAccount);

        cea = CEA_PROXY_IMPLEMENTATION.cloneDeterministic(salt);

        ICEAProxy(cea).initializeCEAProxy(CEA_IMPLEMENTATION);

        ICEA(cea).initializeCEA(
            pushAccount, VAULT, UNIVERSAL_GATEWAY, address(this)
        );

        pushAccountToCEA[pushAccount] = cea;
        ceaToPushAccount[cea] = pushAccount;

        emit CEADeployed(pushAccount, cea);
    }

    // =========================
    //    CF_3: ADMIN ACTIONS
    // =========================

    /// @notice          Pause CEA deployments. Only callable by PAUSER_ROLE.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice          Unpause CEA deployments. Only callable by PAUSER_ROLE.
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice              Grant PAUSER_ROLE to a new address. Only callable by DEFAULT_ADMIN_ROLE.
    /// @param newPauser     Address to grant pauser role to
    function setPauserRole(address newPauser) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newPauser == address(0)) revert CEAErrors.ZeroAddress();
        _grantRole(PAUSER_ROLE, newPauser);
        emit PauserRoleGranted(newPauser);
    }

    /// @notice              Sets the Vault address. Only callable by DEFAULT_ADMIN_ROLE.
    /// @param newVault      New Vault address
    function setVault(address newVault) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newVault == address(0)) revert CEAErrors.ZeroAddress();
        address old = VAULT;
        VAULT = newVault;
        emit VaultUpdated(old, newVault);
    }

    /// @notice                    Sets the CEA proxy implementation (CEAProxy template).
    /// @param newImplementation   New CEA proxy implementation address
    function setCEAProxyImplementation(
        address newImplementation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newImplementation == address(0)) revert CEAErrors.ZeroAddress();
        address old = CEA_PROXY_IMPLEMENTATION;
        CEA_PROXY_IMPLEMENTATION = newImplementation;
        emit CEAProxyImplementationUpdated(old, newImplementation);
    }

    /// @notice                    Sets the CEA logic implementation.
    /// @param newImplementation   New CEA logic implementation address
    function setCEAImplementation(
        address newImplementation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newImplementation == address(0)) revert CEAErrors.ZeroAddress();
        address old = CEA_IMPLEMENTATION;
        CEA_IMPLEMENTATION = newImplementation;
        emit CEAImplementationUpdated(old, newImplementation);
    }

    /// @notice          Sets the Universal Gateway address. Only callable by DEFAULT_ADMIN_ROLE.
    /// @param newUG     New Universal Gateway address
    function setUniversalGateway(
        address newUG
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newUG == address(0)) revert CEAErrors.ZeroAddress();
        address old = UNIVERSAL_GATEWAY;
        UNIVERSAL_GATEWAY = newUG;
        emit UniversalGatewayUpdated(old, newUG);
    }

    /// @notice                       Sets the CEA migration contract address.
    /// @param newMigrationContract   Address of the new migration contract
    function setCEAMigrationContract(
        address newMigrationContract
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newMigrationContract == address(0)) revert CEAErrors.ZeroAddress();
        address old = CEA_MIGRATION_CONTRACT;
        CEA_MIGRATION_CONTRACT = newMigrationContract;
        emit CEAMigrationContractUpdated(old, newMigrationContract);
    }

    // =========================
    //    CF_4: INTERNAL HELPERS
    // =========================

    /// @dev Computes the deterministic CEA address for a push account.
    /// @param pushAccount   UEA address on Push Chain
    /// @return              Predicted CEA clone address
    function _computeCEAInternal(
        address pushAccount
    ) internal view returns (address) {
        if (CEA_PROXY_IMPLEMENTATION == address(0)) {
            revert CEAErrors.InvalidImplementation();
        }
        bytes32 salt = _generateSalt(pushAccount);
        return CEA_PROXY_IMPLEMENTATION
            .predictDeterministicAddress(salt, address(this));
    }

    /// @dev Generates CREATE2 salt from push account.
    /// @param pushAccount   UEA address on Push Chain
    /// @return              Salt for deterministic deployment
    function _generateSalt(
        address pushAccount
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(pushAccount));
    }

    /// @dev Checks whether an address has deployed code.
    /// @param addr   Address to check
    /// @return       True if code exists at address
    function _hasCode(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }
}
