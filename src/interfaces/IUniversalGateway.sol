// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice Universal transaction request for cross-chain operations.
struct UniversalTxRequest {
    address recipient;                  // address(0) => credit to UEA on Push
    address token;                      // address(0) => native path (gas-only)
    uint256 amount;                     // Native amount or ERC20 amount
    bytes payload;                      // Call data / memo (UNIVERSAL PAYLOAD)
    address revertRecipient;            // Receives funds if the tx reverts
    bytes signatureData;                // Signature data for further verification
}

/// @title  IUniversalGateway
/// @notice Interface for the Universal Gateway on external chains.
/// @dev    Routes cross-chain transactions between Push Chain and external chains.
interface IUniversalGateway {
    /// @notice             Sends a universal transaction from a user (EOA or contract).
    /// @param req          Universal transaction request
    function sendUniversalTx(
        UniversalTxRequest calldata req
    ) external payable;

    /// @notice             Sends a universal transaction from a CEA back to its UEA.
    /// @param req          Universal transaction request
    function sendUniversalTxFromCEA(
        UniversalTxRequest calldata req
    ) external payable;
}
