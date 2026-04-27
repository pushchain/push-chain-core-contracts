// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ICEAFactory} from "../interfaces/ICEAFactory.sol";
import {ICEA} from "../interfaces/ICEA.sol";
import {ICEAProxy} from "../interfaces/ICEAProxy.sol";
import {CEAErrors} from "../libraries/Errors.sol";

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {
    AccessControlDefaultAdminRulesUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/**
 * @title   CEAFactory
 * @notice  Factory for Chain Executor Accounts (CEAs) on external chains.
 * @dev     Deploys minimal proxy CEAs via CREATE2 using a shared CEA proxy
 *          implementation. Maintains a 1:1 mapping between UEA (on Push) and
 *          CEA (on this chain).
 *
 *          Access control: AccessControlDefaultAdminRulesUpgradeable (2-day delay).
 *          Roles: DEFAULT_ADMIN_ROLE (root), ROLE_MANAGER_ROLE (grants operational roles),
 *          CEA_ADMIN_ROLE (implementation config), OPERATOR_ROLE (address setters + unpause),
 *          PAUSER_ROLE (pause only).
 */
contract CEAFactory is Initializable, AccessControlDefaultAdminRulesUpgradeable, PausableUpgradeable, ICEAFactory {
    using Clones for address;

    // =========================
    //    CF: ROLES
    // =========================

    bytes32 public constant ROLE_MANAGER_ROLE = keccak256("ROLE_MANAGER_ROLE");
    bytes32 public constant CEA_ADMIN_ROLE = keccak256("CEA_ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
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
    /// @param _admin                     Admin address — granted DEFAULT_ADMIN_ROLE + all operational roles
    /// @param _pauser                    Address granted the PAUSER_ROLE
    /// @param _vault                     Vault address on this chain
    /// @param _ceaProxyImplementation    CEA proxy implementation to clone (CEAProxy)
    /// @param _ceaImplementation         CEA logic implementation (CEA)
    /// @param _universalGateway          Universal Gateway on this chain
    function initialize(
        address _admin,
        address _pauser,
        address _vault,
        address _ceaProxyImplementation,
        address _ceaImplementation,
        address _universalGateway
    ) external initializer {
        if (
            _admin == address(0) || _pauser == address(0) || _vault == address(0)
                || _ceaProxyImplementation == address(0) || _ceaImplementation == address(0)
                || _universalGateway == address(0)
        ) {
            revert CEAErrors.ZeroAddress();
        }

        __AccessControlDefaultAdminRules_init(1 days, _admin);
        __Pausable_init();

        _setRoleAdmin(CEA_ADMIN_ROLE, ROLE_MANAGER_ROLE);
        _setRoleAdmin(OPERATOR_ROLE, ROLE_MANAGER_ROLE);
        _setRoleAdmin(PAUSER_ROLE, ROLE_MANAGER_ROLE);

        _grantRole(ROLE_MANAGER_ROLE, _admin);
        _grantRole(CEA_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _pauser);

        VAULT = _vault;
        CEA_PROXY_IMPLEMENTATION = _ceaProxyImplementation;
        CEA_IMPLEMENTATION = _ceaImplementation;
        UNIVERSAL_GATEWAY = _universalGateway;
    }

    // =========================
    //    CF_1: VIEW FUNCTIONS
    // =========================

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

    // =========================
    //    CF_2: VAULT OPERATIONS
    // =========================

    /// @inheritdoc ICEAFactory
    function deployCEA(address pushAccount) external override onlyVault whenNotPaused returns (address cea) {
        if (pushAccount == address(0)) revert CEAErrors.ZeroAddress();
        if (CEA_PROXY_IMPLEMENTATION == address(0) || CEA_IMPLEMENTATION == address(0)) {
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

        ICEA(cea).initializeCEA(pushAccount, address(this));

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

    /// @notice          Unpause CEA deployments. Only callable by OPERATOR_ROLE.
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /// @notice              Updates the Vault address. Only callable by OPERATOR_ROLE.
    /// @param newVault      New Vault address
    function updateVault(address newVault) external onlyRole(OPERATOR_ROLE) {
        if (newVault == address(0)) revert CEAErrors.ZeroAddress();
        address old = VAULT;
        VAULT = newVault;
        emit VaultUpdated(old, newVault);
    }

    /// @notice                    Sets the CEA proxy implementation (CEAProxy template). Only callable by CEA_ADMIN_ROLE.
    /// @param newImplementation   New CEA proxy implementation address
    function setCEAProxyImplementation(address newImplementation) external onlyRole(CEA_ADMIN_ROLE) {
        if (newImplementation == address(0)) revert CEAErrors.ZeroAddress();
        address old = CEA_PROXY_IMPLEMENTATION;
        CEA_PROXY_IMPLEMENTATION = newImplementation;
        emit CEAProxyImplementationUpdated(old, newImplementation);
    }

    /// @notice                    Sets the CEA logic implementation. Only callable by CEA_ADMIN_ROLE.
    /// @param newImplementation   New CEA logic implementation address
    function setCEAImplementation(address newImplementation) external onlyRole(CEA_ADMIN_ROLE) {
        if (newImplementation == address(0)) revert CEAErrors.ZeroAddress();
        address old = CEA_IMPLEMENTATION;
        CEA_IMPLEMENTATION = newImplementation;
        emit CEAImplementationUpdated(old, newImplementation);
    }

    /// @notice          Updates the Universal Gateway address. Only callable by OPERATOR_ROLE.
    /// @param newUG     New Universal Gateway address
    function updateUniversalGateway(address newUG) external onlyRole(OPERATOR_ROLE) {
        if (newUG == address(0)) revert CEAErrors.ZeroAddress();
        address old = UNIVERSAL_GATEWAY;
        UNIVERSAL_GATEWAY = newUG;
        emit UniversalGatewayUpdated(old, newUG);
    }

    /// @notice                       Sets the CEA migration contract address. Only callable by CEA_ADMIN_ROLE.
    /// @param newMigrationContract   Address of the new migration contract
    function updateCEAMigrationContract(address newMigrationContract) external onlyRole(CEA_ADMIN_ROLE) {
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
    function _computeCEAInternal(address pushAccount) internal view returns (address) {
        if (CEA_PROXY_IMPLEMENTATION == address(0)) {
            revert CEAErrors.InvalidImplementation();
        }
        bytes32 salt = _generateSalt(pushAccount);
        return CEA_PROXY_IMPLEMENTATION.predictDeterministicAddress(salt, address(this));
    }

    /// @dev Generates CREATE2 salt from push account.
    /// @param pushAccount   UEA address on Push Chain
    /// @return              Salt for deterministic deployment
    function _generateSalt(address pushAccount) internal pure returns (bytes32) {
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
