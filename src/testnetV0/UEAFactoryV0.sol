// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUEA} from "../interfaces/IUEA.sol";
import {IUEAFactory} from "../interfaces/IUEAFactory.sol";
import {UEAErrors} from "../libraries/Errors.sol";
import {UniversalAccountId} from "../libraries/Types.sol";
import {UEAProxy} from "../uea/UEAProxy.sol";

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlDefaultAdminRulesUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/**
 * @title   UEAFactoryV0  (TESTNET ONLY — DO NOT DEPLOY TO MAINNET)
 * @notice  Testnet version of UEAFactory, preserved as-is from the live deployment
 *          on Push Chain Donut Testnet.
 *
 *          Access control: AccessControlDefaultAdminRulesUpgradeable (1-day delay).
 *          Roles: DEFAULT_ADMIN_ROLE (root), ROLE_MANAGER_ROLE (grants operational roles),
 *          UEA_ADMIN_ROLE (implementation + chain config), OPERATOR_ROLE (unpause),
 *          PAUSER_ROLE (pause only).
 */
contract UEAFactoryV0 is Initializable, AccessControlDefaultAdminRulesUpgradeable, PausableUpgradeable, IUEAFactory {
    using Clones for address;

    // =========================
    //    UF: ROLES
    // =========================

    bytes32 public constant ROLE_MANAGER_ROLE = keccak256("ROLE_MANAGER_ROLE");
    bytes32 public constant UEA_ADMIN_ROLE = keccak256("UEA_ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // =========================
    //    UF: STATE VARIABLES
    // =========================

    /// @dev DEAD SLOT — preserved for storage layout compatibility. Do not use.
    mapping(bytes32 => address) public roles;

    /// @notice Maps VM type hashes to their UEA implementation addresses.
    mapping(bytes32 => address) public UEA_VM;

    /// @notice Maps UniversalAccountId hash to deployed UEA addresses.
    mapping(bytes32 => address) public UOA_to_UEA;

    /// @notice Maps UEA addresses to their Universal Account information.
    mapping(address => UniversalAccountId) private UEA_to_UOA;

    /// @notice Maps chain identifier hashes to their VM type hashes.
    mapping(bytes32 => bytes32) public CHAIN_to_VM;

    /// @notice The UEAProxy implementation that will be cloned for each user.
    address public UEA_PROXY_IMPLEMENTATION;

    /// @notice The current UEA migration contract address.
    address public UEA_MIGRATION_CONTRACT;

    /// @notice Push Chain numeric identifier used in the `getOriginForUEA` synthetic fallback.
    string public pushChainId;

    // =========================
    //    UF: CONSTRUCTOR
    // =========================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // =========================
    //    UF: INITIALIZER
    // =========================

    /// @dev                     Initializer for the upgradeable UEAFactoryV0.
    /// @param initialOwner      Initial owner of the contract
    /// @param initialPauser     Address granted the PAUSER_ROLE
    function initialize(address initialOwner, address initialPauser) public initializer {
        if (initialOwner == address(0) || initialPauser == address(0)) revert UEAErrors.InvalidInputArgs();
        __Pausable_init();
        roles[PAUSER_ROLE] = initialPauser;
    }

    /// @dev                     Reinitializer to migrate from OwnableUpgradeable to RBAC.
    /// @param _admin            Admin address — granted DEFAULT_ADMIN_ROLE + all operational roles
    /// @param _pauser           Address granted the PAUSER_ROLE
    function initializeV2(address _admin, address _pauser) public reinitializer(2) {
        if (_admin == address(0) || _pauser == address(0)) revert UEAErrors.InvalidInputArgs();

        __AccessControlDefaultAdminRules_init(1 days, _admin);

        _setRoleAdmin(UEA_ADMIN_ROLE, ROLE_MANAGER_ROLE);
        _setRoleAdmin(OPERATOR_ROLE, ROLE_MANAGER_ROLE);
        _setRoleAdmin(PAUSER_ROLE, ROLE_MANAGER_ROLE);

        _grantRole(ROLE_MANAGER_ROLE, _admin);
        _grantRole(UEA_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _pauser);
    }

    // =========================
    //    UF_1: VIEW FUNCTIONS
    // =========================

    /// @notice             Returns the UEA version string for a given VM type.
    /// @param vmHash       VM type hash
    /// @return             Version string from the implementation
    function UEA_VERSION(bytes32 vmHash) public view returns (string memory) {
        address implementation = UEA_VM[vmHash];
        if (implementation == address(0)) {
            revert UEAErrors.InvalidInputArgs();
        }
        return IUEA(implementation).VERSION();
    }

    /// @inheritdoc IUEAFactory
    function getUEA(bytes32 _chainHash) external view returns (address) {
        bytes32 vmHash = CHAIN_to_VM[_chainHash];
        return UEA_VM[vmHash];
    }

    /// @inheritdoc IUEAFactory
    function getVMType(bytes32 _chainHash) public view returns (bytes32 vmHash, bool isRegistered) {
        vmHash = CHAIN_to_VM[_chainHash];
        isRegistered = vmHash != bytes32(0);
        return (vmHash, isRegistered);
    }

    /// @inheritdoc IUEAFactory
    function computeUEA(UniversalAccountId memory _id) public view returns (address) {
        if (UEA_PROXY_IMPLEMENTATION == address(0)) {
            revert UEAErrors.InvalidInputArgs();
        }

        bytes32 chainHash = keccak256(abi.encode(_id.chainNamespace, _id.chainId));
        (, bool isRegistered) = getVMType(chainHash);
        if (!isRegistered) {
            revert UEAErrors.InvalidInputArgs();
        }

        bytes32 salt = generateSalt(_id);
        return UEA_PROXY_IMPLEMENTATION.predictDeterministicAddress(salt, address(this));
    }

    /// @inheritdoc IUEAFactory
    /// @dev When `isUEA` is false, `account` is a synthetic fallback built from
    ///      `"eip155"` + `pushChainId` + `addr` — NOT a registered origin.
    ///      Callers MUST check `isUEA` before trusting `account`.
    function getOriginForUEA(address addr) external view returns (UniversalAccountId memory account, bool isUEA) {
        account = UEA_to_UOA[addr];

        if (account.owner.length > 0) {
            isUEA = true;
        } else {
            account =
                UniversalAccountId({chainNamespace: "eip155", chainId: pushChainId, owner: bytes(abi.encodePacked(addr))});
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

    // =========================
    //    UF_2: DEPLOYMENT
    // =========================

    /// @inheritdoc IUEAFactory
    function deployUEA(UniversalAccountId memory _id) external whenNotPaused returns (address) {
        if (UEA_PROXY_IMPLEMENTATION == address(0)) {
            revert UEAErrors.InvalidInputArgs();
        }

        bytes32 salt = generateSalt(_id);

        bytes32 chainHash = keccak256(abi.encode(_id.chainNamespace, _id.chainId));
        (bytes32 vmHash, bool isRegistered) = getVMType(chainHash);
        if (!isRegistered) {
            revert UEAErrors.InvalidInputArgs();
        }

        address ueaImplementation = UEA_VM[vmHash];
        if (ueaImplementation == address(0)) {
            revert UEAErrors.InvalidInputArgs();
        }

        address payable ueaProxy = payable(UEA_PROXY_IMPLEMENTATION.cloneDeterministic(salt));

        UEAProxy(ueaProxy).initializeUEA(ueaImplementation);

        IUEA(ueaProxy).initialize(_id, address(this));

        UOA_to_UEA[salt] = ueaProxy;
        UEA_to_UOA[ueaProxy] = _id;

        emit UEADeployed(ueaProxy, _id.owner, _id.chainId, chainHash);
        return ueaProxy;
    }

    // =========================
    //    UF_3: ADMIN ACTIONS
    // =========================

    /// @notice          Pause UEA deployments. Only callable by PAUSER_ROLE.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice          Unpause UEA deployments. Only callable by OPERATOR_ROLE.
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /// @notice                             Sets the UEAProxy implementation address. Only callable by UEA_ADMIN_ROLE.
    /// @param ueaProxyImplementation       New UEAProxy implementation address
    function updateUEAProxyImplementation(address ueaProxyImplementation) external onlyRole(UEA_ADMIN_ROLE) {
        if (ueaProxyImplementation == address(0)) {
            revert UEAErrors.InvalidInputArgs();
        }
        UEA_PROXY_IMPLEMENTATION = ueaProxyImplementation;
    }

    /// @notice                         Sets the UEA migration contract address. Only callable by UEA_ADMIN_ROLE.
    /// @param ueaMigrationContract     New migration contract address
    function updateUEAMigrationContract(address ueaMigrationContract) external onlyRole(UEA_ADMIN_ROLE) {
        if (ueaMigrationContract == address(0)) {
            revert UEAErrors.InvalidInputArgs();
        }
        UEA_MIGRATION_CONTRACT = ueaMigrationContract;
    }

    /// @notice Update `pushChainId`. Reverts on empty string. Only callable by UEA_ADMIN_ROLE.
    function updatePushChainId(string memory _pushChainId) external onlyRole(UEA_ADMIN_ROLE) {
        if (bytes(_pushChainId).length == 0) revert UEAErrors.InvalidInputArgs();
        pushChainId = _pushChainId;
    }

    /// @inheritdoc IUEAFactory
    function registerNewChain(bytes32 _chainHash, bytes32 _vmHash) external onlyRole(UEA_ADMIN_ROLE) {
        (, bool isRegistered) = getVMType(_chainHash);
        if (isRegistered) {
            revert UEAErrors.InvalidInputArgs();
        }

        CHAIN_to_VM[_chainHash] = _vmHash;
        emit ChainRegistered(_chainHash, _vmHash);
    }

    /// @inheritdoc IUEAFactory
    function registerMultipleUEA(bytes32[] memory _chainHashes, bytes32[] memory _vmHashes, address[] memory _UEA)
        external
        onlyRole(UEA_ADMIN_ROLE)
    {
        if (_UEA.length != _vmHashes.length || _UEA.length != _chainHashes.length) {
            revert UEAErrors.InvalidInputArgs();
        }

        for (uint256 i = 0; i < _UEA.length; i++) {
            _registerUEA(_chainHashes[i], _vmHashes[i], _UEA[i]);
        }
    }

    /// @inheritdoc IUEAFactory
    function registerUEA(bytes32 _chainHash, bytes32 _vmHash, address _UEA) public onlyRole(UEA_ADMIN_ROLE) {
        _registerUEA(_chainHash, _vmHash, _UEA);
    }

    /// @dev Internal registration logic with overwrite protection.
    function _registerUEA(bytes32 _chainHash, bytes32 _vmHash, address _UEA) internal {
        if (_UEA == address(0)) {
            revert UEAErrors.InvalidInputArgs();
        }

        (bytes32 registeredVmHash, bool isRegistered) = getVMType(_chainHash);
        if (!isRegistered || registeredVmHash != _vmHash) {
            revert UEAErrors.InvalidInputArgs();
        }

        if (UEA_VM[_vmHash] != address(0)) {
            revert UEAErrors.UEAAlreadyRegistered();
        }

        UEA_VM[_vmHash] = _UEA;
        emit UEARegistered(_chainHash, _UEA, _vmHash);
    }

    /// @notice                  Replace the registered UEA implementation for a VM hash.
    /// @param _vmHash           VM hash whose implementation is being updated
    /// @param _newUEA           New UEA implementation address (must be non-zero)
    function updateUEAImplementation(bytes32 _vmHash, address _newUEA) external onlyRole(UEA_ADMIN_ROLE) {
        if (_newUEA == address(0)) {
            revert UEAErrors.InvalidInputArgs();
        }
        address previous = UEA_VM[_vmHash];
        if (previous == address(0)) {
            revert UEAErrors.InvalidInputArgs();
        }

        UEA_VM[_vmHash] = _newUEA;
        emit UEAImplementationUpdated(_vmHash, previous, _newUEA);
    }

    // =========================
    //    UF_4: PUBLIC HELPERS
    // =========================

    /// @notice          Checks whether an address has deployed code.
    /// @param addr      Address to check
    /// @return          True if code exists at address
    function hasCode(address addr) public view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }

    /// @notice          Generates a unique CREATE2 salt from Universal Account info.
    /// @param _id       Universal Account information
    /// @return          Unique salt derived from the account information
    function generateSalt(UniversalAccountId memory _id) public pure returns (bytes32) {
        return keccak256(abi.encode(_id));
    }
}
