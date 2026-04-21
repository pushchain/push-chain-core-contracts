// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalAccountId} from "../libraries/Types.sol";

/// @title  IUEAFactory
/// @notice Interface for the Universal Executor Account Factory.
/// @dev    Deploys deterministic UEA instances via CREATE2 and maintains
///         mappings between external chain identities and UEA addresses.
interface IUEAFactory {
    // =========================
    //    UF: EVENTS
    // =========================

    /// @notice                  Emitted when a new chain is registered.
    /// @param chainHash         Hash of the chain identifier
    /// @param vmHash            VM type hash for this chain
    event ChainRegistered(bytes32 indexed chainHash, bytes32 vmHash);

    /// @notice                  Emitted when a new UEA is deployed.
    /// @param uea               Address of the deployed UEA
    /// @param owner             Owner key from the external chain
    /// @param sourceChainId     Source chain identifier
    /// @param chainHash         Hash of the chain identifier
    event UEADeployed(address indexed uea, bytes owner, string sourceChainId, bytes32 chainHash);

    /// @notice                  Emitted when a UEA implementation is registered.
    /// @param chainHash         Hash of the chain identifier
    /// @param ueaLogic          UEA implementation address
    /// @param vmHash            VM type hash
    event UEARegistered(bytes32 indexed chainHash, address ueaLogic, bytes32 vmHash);

    /// @notice                  Emitted when an existing UEA implementation is replaced.
    /// @param vmHash            VM hash whose implementation is being updated
    /// @param previousUEA       Previous UEA implementation address
    /// @param newUEA            New UEA implementation address
    event UEAImplementationUpdated(bytes32 indexed vmHash, address previousUEA, address newUEA);

    /// @notice                  Emitted when the PAUSER_ROLE is granted to a new address.
    /// @param pauser            Address that was granted the pauser role
    event PauserRoleGranted(address indexed pauser);

    // =========================
    //    UF_1: VIEW FUNCTIONS
    // =========================

    /// @notice             Returns the UEA implementation address for a given chain.
    /// @param chainHash    Hash of the chain identifier
    /// @return             UEA implementation address
    function getUEA(bytes32 chainHash) external view returns (address);

    /// @notice             Returns the VM type hash for a given chain.
    /// @param chainHash    Hash of the chain identifier
    /// @return vmHash      VM type hash
    /// @return isRegistered True if the chain is registered
    function getVMType(bytes32 chainHash) external view returns (bytes32 vmHash, bool isRegistered);

    /// @notice             Returns origin info for any address on Push Chain.
    /// @dev                If addr is a UEA, returns its external identity.
    ///                     If addr is a native EOA, returns a default identity.
    /// @param addr         Address to look up
    /// @return account     UniversalAccountId for the address
    /// @return isUEA       True if the address is a deployed UEA
    function getOriginForUEA(address addr) external view returns (UniversalAccountId memory account, bool isUEA);

    /// @notice             Returns the UEA address and deployment status for an identity.
    /// @param id           Universal Account information
    /// @return uea         UEA address (deployed or predicted)
    /// @return isDeployed  True if the UEA has been deployed
    function getUEAForOrigin(UniversalAccountId memory id) external view returns (address uea, bool isDeployed);

    /// @notice             Computes the deterministic UEA address before deployment.
    /// @param id           Universal Account information
    /// @return             Predicted UEA proxy address
    function computeUEA(UniversalAccountId memory id) external view returns (address);

    /// @notice             Returns the current UEA migration contract address.
    /// @return             Migration contract address
    function UEA_MIGRATION_CONTRACT() external view returns (address);

    // =========================
    //    UF_2: DEPLOYMENT
    // =========================

    /// @notice             Deploys a new UEA for an external chain user.
    /// @param id           Universal Account information
    /// @return             Address of the deployed UEA
    function deployUEA(UniversalAccountId memory id) external returns (address);

    // =========================
    //    UF_3: ADMIN ACTIONS
    // =========================

    /// @notice             Registers a new chain with its VM type.
    /// @param chainHash    Hash of the chain identifier
    /// @param vmHash       VM type hash for this chain
    function registerNewChain(bytes32 chainHash, bytes32 vmHash) external;

    /// @notice             Registers multiple UEA implementations in a batch.
    /// @param chainHashes  Array of chain hashes
    /// @param vmHashes     Array of VM type hashes
    /// @param uea          Array of UEA implementation addresses
    function registerMultipleUEA(bytes32[] memory chainHashes, bytes32[] memory vmHashes, address[] memory uea) external;

    /// @notice             Registers a UEA implementation for a specific VM type.
    /// @param chainHash    Hash of the chain identifier
    /// @param vmHash       VM type hash
    /// @param uea          UEA implementation address
    function registerUEA(bytes32 chainHash, bytes32 vmHash, address uea) external;
}
