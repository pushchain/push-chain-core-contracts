// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title   ICEAFactory
 * @notice  Interface for the Chain Executor Account Factory on external EVM chains.
 *
 * @dev
 *  - Each CEA (Chain Executor Account) is a smart contract account on the
 *    external chain that represents a single UEA on Push Chain.
 *  - There MUST be at most one CEA per (UEA, external chain) pair.
 *  - The factory is responsible for:
 *      * Deterministic CREATE2 deployment of CEAs.
 *      * Maintaining the mapping UEA <-> CEA.
 *      * Exposing pure/read-only helpers to compute and query CEA addresses.
 *
 *  - Deployment is restricted to the external chain Vault contract.
 *    (Vault is the only allowed caller of deployCEA in v1 of CEAs.)
 */
interface ICEAFactory {
    //========================
    //           Events
    //========================

    /**
     * @notice           Emitted when a new CEA is deployed for a given UEA on Push Chain.
     * @param _uea       Address of the UEA on Push Chain that this CEA represents.
     * @param cea        Address of the deployed CEA on the external chain.
     */
    event CEADeployed(address indexed _uea, address indexed cea);

    /**
     * @notice           Emitted when the Vault address is updated.
     * @param oldVault   Previous Vault address.
     * @param newVault   New Vault address.
     */
    event VaultUpdated(address indexed oldVault, address indexed newVault);

    /**
     * @notice          Emitted when the CEA proxy implementation is updated.
     * @param oldImpl   Previous proxy implementation address.
     * @param newImpl   New proxy implementation address.
     */
    event CEAProxyImplementationUpdated(address indexed oldImpl, address indexed newImpl);

    event CEAImplementationUpdated(address indexed oldImpl, address indexed newImpl);

    //========================
    //        View helpers
    //========================

    /**
     * @notice Returns the current Vault address that is allowed to deploy and drive CEAs.
     */
    function VAULT() external view returns (address);

    /**
     * @notice Returns the current CEA proxy implementation used for clones.
     */
    function CEA_PROXY_IMPLEMENTATION() external view returns (address);

    /**
     * @notice Returns the CEA address and deployment status for a given UEA on Push Chain.
     *
     * @dev
     *  - If the CEA has been deployed, returns (cea, true).
     *  - If the CEA has not been deployed, returns (predictedAddress, false).
     *
     * @param _uea       Address of the UEA contract on Push Chain.
     * @return cea       Address of the CEA (deployed or predicted via CREATE2).
     * @return isDeployed True if the CEA has code deployed at that address.
     */
    function getCEAForUEA(address _uea) external view returns (address cea, bool isDeployed);
    /**
     * @notice            Returns the UEA address on Push Chain that a given CEA represents.
     *
     * @param _cea       Address of a CEA.
     * @return _uea      Address of the UEA on Push Chain.
     */
    function getUEAForCEA(address _cea) external view returns (address _uea);

    /**
     * @notice          Computes the deterministic CEA address for a given UEA on Push Chain.
     *
     * @param _uea       Address of the UEA contract on Push Chain.
     * @return cea       Predicted address of the CEA clone.
     */
    function computeCEA(address _uea) external view returns (address cea);

    /**
     * @notice Returns whether a given address is recognized as a CEA.
     *
     * @param addr       Address to check.
     * @return isCea     True if the address is a CEA managed by this factory.
     */
    function isCEA(address addr) external view returns (bool isCea);

    //========================
    //      Core function
    //========================

    /**
     * @notice Deploys a new CEA for the given UEA on Push Chain, if not already deployed.
     *
     * @dev
     *  - Only callable by the Vault contract.
     *  - If a CEA already exists and has code, SHOULD revert to avoid ambiguity.
     *  - If the mapping exists but the code at the address is missing (e.g. selfdestruct),
     *    the factory MAY re-deploy at the same address using the same salt.
     *
     * @param _uea  Address of the UEA on Push Chain.
     * @return cea       Address of the deployed CEA on the external chain.
     */
    function deployCEA(address _uea) external returns (address cea);
}