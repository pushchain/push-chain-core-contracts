// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @dev Interface for contracts that can receive cross-chain calls
 */
interface IUniversalContract {
    /**
     * @dev Called when a cross-chain message is received
     * @param context The context of the cross-chain call
     * @param prc20 The address of the PRC20 token
     * @param amount The amount of tokens received
     * @param message The message data
     */
    function onCrossChainCall(pContext calldata context, address prc20, uint256 amount, bytes calldata message)
        external;
}

/**
 * @dev Context for cross-chain calls
 */
struct pContext {
    uint256 srcChainId;
    bytes srcAddress;
    uint256 nonce;
}
