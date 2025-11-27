// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;


struct RevertInstructions {
    ///             where funds go in revert / refund cases
    address fundRecipient;
    ///             arbitrary message for relayers/UEA
    bytes revertMsg;
}

/// @notice         Universal transaction request for native token as GAS
struct UniversalTxRequest {
    address recipient;                      // address(0) => credit to UEA on Push
    address token;                          // address(0) => native path (gas-only)
    uint256 amount;                         // native amount or ERC20 amount
    bytes   payload;                        // call data / memo = UNIVERSAL PAYLOAD
    RevertInstructions revertInstruction;   // revert instructions
    bytes   signatureData;                  // signature data for further verification
}
interface IUniversalGateway {

    function sendUniversalTx(UniversalTxRequest calldata req) external payable;

}