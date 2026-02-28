// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title   ICEA (Interface for Chain Executor Account)
 * @notice  CEA is the per-user smart account on an external chain that represents a UEA on Push Chain.
 *
 * @dev
 *  - There is at most one CEA per (UEA, external chain) in v1.
 *  - CEAs are NOT user-owned wallets in v1. They are system-controlled accounts:
 *      * Only the external-chain Vault may call state-changing functions.
 *      * CEAs hold user positions and balances on external chains.
 *  - CEAs preserve the identity of a UEA on the external chains.
 *  - Any action requested by UEA ( from Push Chain ) is executed by the CEA on the external chain.
 *
 */
interface ICEA {
    //========================
    //           Events
    //========================

    /// @notice                     Universal tx execution event emitted for each multicall step.
    /// @param txId                 Unique transaction identifier
    /// @param universalTxId        Unique transaction identifier on Universal Gateway
    /// @param originCaller         Original caller/user on source chain (Push Chain)
    /// @param target               Target contract address for this call step
    /// @param data                 Calldata executed on target contract
    event UniversalTxExecuted(
        bytes32 indexed txId, bytes32 indexed universalTxId, address indexed originCaller, address target, bytes data
    );

    /// @notice                     Emitted when a universal tx is sent from CEA to UEA on Push Chain.
    /// @param _cea                 Address of the CEA sending the tx
    /// @param pushAccount          Address of the push account (UEA on Push Chain) that this CEA represents.
    /// @param token                Token address being sent
    /// @param amount               Amount of token being sent
    event UniversalTxToUEA(address indexed _cea, address indexed pushAccount, address indexed token, uint256 amount);
    //========================
    //           Views
    //========================

    /**
     * @notice Returns the push account (UEA on Push Chain) that this CEA represents.
     */
    function pushAccount() external view returns (address);

    /**
     * @notice Returns the Vault on this chain that is allowed to drive this CEA.
     */
    function VAULT() external view returns (address);

    /**
     * @notice Returns true if this CEA has been initialized.
     */
    function isInitialized() external view returns (bool);

    function initializeCEA(address _pushAccount, address _vault, address _universalGateway, address _factory) external;

    //========================
    //      Vault-only ops
    //========================

    /**
     * @notice Executes a universal transaction using standardized multicall payload.
     *
     * @dev
     *  - Only callable by Vault.
     *  - All execution is driven by a Multicall[] payload (similar to UEA multicall).
     *  - SDK is responsible for crafting correct multicall steps, including:
     *      * ERC20 approvals before calls that need token spending
     *      * ERC20 approval resets after operations (if needed)
     *  - CEA no longer performs automatic approval/reset logic.
     *  - This ensures flexible, composable execution paths.
     *
     * @param txId              Transaction ID (must not be executed before)
     * @param universalTxId     Unique transaction identifier on Universal Gateway
     * @param originCaller      Push account (UEA on Push Chain) that this CEA represents (verified)
     * @param recipient         Target contract for single-call execution. Ignored for multicall/migration payloads.
     * @param payload           ABI-encoded Multicall[] containing execution steps
     */
    function executeUniversalTx(
        bytes32 txId,
        bytes32 universalTxId,
        address originCaller,
        address recipient,
        bytes calldata payload
    ) external payable;
}
