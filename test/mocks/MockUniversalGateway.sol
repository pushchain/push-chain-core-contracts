// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../../src/interfaces/IUniversalGateway.sol";

/**
 * @dev Mock Universal Gateway contract for testing
 */
contract MockUniversalGateway is IUniversalGateway {
    // Storage to track calls for verification
    uint256 public callCount;
    uint256 public lastValue;
    
    // Store individual fields for easier access
    address public lastRecipient;
    address public lastToken;
    uint256 public lastAmount;
    bytes public lastPayload;
    address public lastFundRecipient;
    bytes public lastRevertMsg;
    bytes public lastSignatureData;

    function sendUniversalTx(UniversalTxRequest calldata req) external payable {
        lastRecipient = req.recipient;
        lastToken = req.token;
        lastAmount = req.amount;
        lastPayload = req.payload;
        lastFundRecipient = req.revertInstruction.fundRecipient;
        lastRevertMsg = req.revertInstruction.revertMsg;
        lastSignatureData = req.signatureData;
        lastValue = msg.value;
        callCount++;
    }
    
    // Helper to get full request struct (for event verification)
    function getLastRequest() external view returns (UniversalTxRequest memory) {
        return UniversalTxRequest({
            recipient: lastRecipient,
            token: lastToken,
            amount: lastAmount,
            payload: lastPayload,
            revertInstruction: RevertInstructions({
                fundRecipient: lastFundRecipient,
                revertMsg: lastRevertMsg
            }),
            signatureData: lastSignatureData
        });
    }
}

