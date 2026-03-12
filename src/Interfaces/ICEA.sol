// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  ICEA (Interface for Chain Executor Account)
/// @notice CEA is the per-user smart account on an external chain that
///         represents a UEA on Push Chain.
/// @dev    There is at most one CEA per (UEA, external chain) in v1.
///         CEAs are NOT user-owned wallets in v1 — they are system-controlled
///         accounts driven exclusively by the external-chain Vault.
interface ICEA {
    // =========================
    //    CEA: EVENTS
    // =========================

    /// @notice                  Emitted for each execution step (multicall or single call).
    /// @param txId              Unique transaction identifier
    /// @param universalTxId     Universal transaction identifier on Universal Gateway
    /// @param originCaller      Original caller on source chain (Push Chain)
    /// @param target            Target contract address for this call step
    /// @param data              Calldata executed on target contract
    event UniversalTxExecuted(
        bytes32 indexed txId,
        bytes32 indexed universalTxId,
        address indexed originCaller,
        address target,
        bytes data
    );

    /// @notice                  Emitted when funds are sent from CEA to its UEA on Push Chain.
    /// @param cea               Address of the CEA sending the tx
    /// @param pushAccount       Address of the UEA on Push Chain
    /// @param token             Token address being sent
    /// @param amount            Amount of token being sent
    event UniversalTxToUEA(
        address indexed cea,
        address indexed pushAccount,
        address indexed token,
        uint256 amount
    );

    // =========================
    //    CEA_1: VIEW FUNCTIONS
    // =========================

    /// @notice             Returns the push account (UEA on Push Chain) this CEA represents.
    /// @return             Push account address
    function pushAccount() external view returns (address);

    /// @notice             Returns the Vault on this chain that drives this CEA.
    /// @return             Vault address
    function VAULT() external view returns (address);

    /// @notice             Returns true if this CEA has been initialized.
    /// @return             Initialization status
    function isInitialized() external view returns (bool);

    /// @notice             Returns whether a given txId has been executed.
    /// @param txId         Transaction identifier to check
    /// @return             True if already executed
    function isExecuted(bytes32 txId) external view returns (bool);

    // =========================
    //    CEA_2: VAULT OPERATIONS
    // =========================

    /// @notice             Executes a universal transaction.
    /// @dev                Payload can be MULTICALL, MIGRATION, or SINGLE CALL format.
    ///                     Only callable by Vault. SDK crafts correct payload format.
    /// @param txId         Unique transaction identifier (must not be executed before)
    /// @param universalTxId  Universal transaction identifier for cross-chain tracking
    /// @param originCaller Origin caller address (must match pushAccount)
    /// @param recipient    Target contract for single-call. Ignored for multicall/migration.
    /// @param payload      Multicall, migration, or single call payload
    function executeUniversalTx(
        bytes32 txId,
        bytes32 universalTxId,
        address originCaller,
        address recipient,
        bytes calldata payload
    ) external payable;

    // =========================
    //    CEA_3: SELF-CALL OPERATIONS
    // =========================

    /// @notice             Sends funds (and optionally a payload) from CEA to its UEA.
    /// @dev                Only callable via self-call through multicall execution.
    /// @param token        Token address (address(0) for native)
    /// @param amount       Amount to send
    /// @param payload      Payload bytes for UEA execution (empty for funds-only)
    function sendUniversalTxToUEA(
        address token,
        uint256 amount,
        bytes calldata payload
    ) external;

    // =========================
    //    CEA_4: INITIALIZER
    // =========================

    /// @notice                     Initializes this CEA with its identity and references.
    /// @param _pushAccount         Address of the UEA on Push Chain
    /// @param _vault               Address of the Vault on this chain
    /// @param _universalGateway    Address of the Universal Gateway
    /// @param _factory             Address of the CEA factory
    function initializeCEA(
        address _pushAccount,
        address _vault,
        address _universalGateway,
        address _factory
    ) external;
}
