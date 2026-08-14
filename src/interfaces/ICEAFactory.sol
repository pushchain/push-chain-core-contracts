// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  ICEAFactory
/// @notice Interface for the Chain Executor Account Factory on external EVM chains.
/// @dev    Each CEA is a smart contract account on the external chain representing
///         a single UEA on Push Chain. There MUST be at most one CEA per
///         (UEA, external chain) pair.
interface ICEAFactory {
    // =========================
    //    CF: EVENTS
    // =========================

    /// @notice                  Emitted when a new CEA is deployed.
    /// @param pushAccount       UEA address on Push Chain
    /// @param cea               Deployed CEA address on the external chain
    event CEADeployed(address indexed pushAccount, address indexed cea);

    /// @notice                  Emitted when the Universal Gateway is updated.
    /// @param oldGateway        Previous Universal Gateway address
    /// @param newGateway        New Universal Gateway address
    event UniversalGatewayUpdated(address indexed oldGateway, address indexed newGateway);

    /// @notice                  Emitted when the Vault address is updated.
    /// @param oldVault          Previous Vault address
    /// @param newVault          New Vault address
    event VaultUpdated(address indexed oldVault, address indexed newVault);

    /// @notice                  Emitted when the CEA proxy implementation is updated.
    /// @param oldImpl           Previous proxy implementation address
    /// @param newImpl           New proxy implementation address
    event CEAProxyImplementationUpdated(address indexed oldImpl, address indexed newImpl);

    /// @notice                  Emitted when the CEA logic implementation is updated.
    /// @param oldImpl           Previous logic implementation address
    /// @param newImpl           New logic implementation address
    event CEAImplementationUpdated(address indexed oldImpl, address indexed newImpl);

    /// @notice                  Emitted when the CEA migration contract is updated.
    /// @param oldContract       Previous migration contract address
    /// @param newContract       New migration contract address
    event CEAMigrationContractUpdated(address indexed oldContract, address indexed newContract);

    // =========================
    //    CF_1: VIEW FUNCTIONS
    // =========================

    /// @notice             Returns the current Vault address.
    /// @return             Vault address
    function VAULT() external view returns (address);

    /// @notice             Returns the current Universal Gateway address.
    /// @return             Universal Gateway address
    function UNIVERSAL_GATEWAY() external view returns (address);

    /// @notice             Returns the CEA proxy implementation used for clones.
    /// @return             CEA proxy implementation address
    function CEA_PROXY_IMPLEMENTATION() external view returns (address);

    /// @notice             Returns the CEA migration contract address.
    /// @return             Migration contract address (address(0) if not set)
    function CEA_MIGRATION_CONTRACT() external view returns (address);

    /// @notice             Returns the CEA address and deployment status for a push account.
    /// @param pushAccount  UEA address on Push Chain
    /// @return cea         CEA address (deployed or predicted via CREATE2)
    /// @return isDeployed  True if the CEA has code deployed
    function getCEAForPushAccount(address pushAccount) external view returns (address cea, bool isDeployed);

    /// @notice             Returns the push account for a given CEA.
    /// @param cea          CEA address
    /// @return pushAccount UEA address on Push Chain
    function getPushAccountForCEA(address cea) external view returns (address pushAccount);

    /// @notice             Computes the deterministic CEA address for a push account.
    /// @param pushAccount  UEA address on Push Chain
    /// @return cea         Predicted CEA clone address
    function computeCEA(address pushAccount) external view returns (address cea);

    /// @notice             Returns whether a given address is recognized as a CEA.
    /// @param addr         Address to check
    /// @return isCea       True if the address is a CEA managed by this factory
    function isCEA(address addr) external view returns (bool isCea);

    // =========================
    //    CF_2: VAULT OPERATIONS
    // =========================

    /// @notice             Deploys a new CEA for the given UEA on Push Chain.
    /// @dev                Only callable by the Vault contract.
    /// @param pushAccount  UEA address on Push Chain
    /// @return cea         Deployed CEA address on the external chain
    function deployCEA(address pushAccount) external returns (address cea);
}
