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

    /// @notice                     Universal tx execution event that is executed on External Chains.
    /// @param txID                 Unique transaction identifier
    /// @param originCaller         Original caller/user on source chain ( Push Chain)
    /// @param target               Target contract address to execute call
    /// @param token                Token address being sent
    /// @param amount               Amount of token being sent
    /// @param data                 Calldata to be executed on target contract on external chain
    event UniversalTxExecuted(
        bytes32 indexed txID,
        address indexed originCaller,
        address indexed target,
        address token,
        uint256 amount,
        bytes data
    );

    /**
     * @notice Emitted once when this CEA is initialized for a UEA + Vault.
     * @param uea  UEA on Push Chain that this CEA represents.
     * @param vault      Vault on this chain that is allowed to drive this CEA.
     * @param universalGateway Address of the Universal Gateway contract of the respective chain.
     */
    event CEAInitialized(address indexed uea, address indexed vault, address indexed universalGateway);

    /// @notice                     Emitted when funds are withdrawn to the UEA on Push Chain.
    /// @param _cea                Address of the CEA that is withdrawing funds
    /// @param _uea                Address of the UEA on Push Chain that this CEA represents.
    /// @param token                Token address being withdrawn
    /// @param amount               Amount of token being withdrawn
    event WithdrawalToUEA(address indexed _cea, address indexed _uea, address indexed token, uint256 amount);
    //========================
    //           Views
    //========================

    /**
     * @notice Returns the UEA on Push Chain that this CEA represents.
     */
    function UEA() external view returns (address);

    /**
     * @notice Returns the Vault on this chain that is allowed to drive this CEA.
     */
    function VAULT() external view returns (address);

    /**
     * @notice Returns true if this CEA has been initialized.
     */
    function isInitialized() external view returns (bool);

    function initializeCEA(address _uea, address _vault, address _universalGateway) external;

    //========================
    //      Vault-only ops
    //========================

    /**
     * @notice Executes a call against an external target on behalf of the UEA,
     *         using tokens that are already held by this CEA.
     *
     * @dev
     *  - Only callable by Vault.
     *  - Typical usage pattern:
     *      1. Vault transfers `amount` of `token` into this CEA.
     *      2. Vault calls executeUniversalTx(txID, uea, token, target, amount, payload).
     *      3. CEA safe-approves `target` for `amount` and then calls `target` with `data`.
     *  - This ensures the external protocol sees `msg.sender == CEA`, not Vault.
     *
     * @param txID    Transaction ID of the UniversalTx to execute.
     * @param uea     UEA on Push Chain that this CEA represents.
     * @param token   ERC20 token to be used for the operation (address(0) if purely native / no-ERC20 op).
     * @param target  Target protocol contract to call.
     * @param amount  Amount of `token` to make available to `target` (used for allowance).
     * @param payload Calldata to forward to `target`.
     */
    function executeUniversalTx(
        bytes32 txID,
        address uea,
        address token,
        address target, 
        uint256 amount,
        bytes calldata payload
    ) external;

    /**
     * @notice Executes a call against an external target on behalf of the UEA,
     *         using native tokens that are already held by this CEA.
     *
     * @dev
     *  - Only callable by Vault.
     *  - Typical usage pattern:
     *      1. Vault transfers `amount` of native tokens into this CEA.
     *      2. Vault calls executeUniversalTx(txID, uea, target, amount, payload).
     *      3. CEA calls `target` with `payload` and `amount` of native tokens.
     */
    function executeUniversalTx(
        bytes32 txID,
        address uea,
        address target,
        uint256 amount,
        bytes calldata payload
    ) external payable;
}