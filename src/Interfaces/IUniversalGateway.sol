// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice         Universal transaction request for native token as GAS
struct UniversalTxRequest {
    address recipient; // address(0) => credit to UEA on Push
    address token; // address(0) => native path (gas-only)
    uint256 amount; // native amount or ERC20 amount
    bytes payload; // call data / memo = UNIVERSAL PAYLOAD
    address revertRecipient; // address to receive funds in case of revert
    bytes signatureData; // signature data for further verification
}

interface IUniversalGateway {
    function sendUniversalTx(UniversalTxRequest calldata req) external payable;

    function sendUniversalTxFromCEA(UniversalTxRequest calldata req) external payable;
}
