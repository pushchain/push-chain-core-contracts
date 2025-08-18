// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @dev Interface for PRC20 tokens
 */
interface IPRC20 {
    /**
     * @dev Deposits tokens to a specified address
     * @param to The address to deposit tokens to
     * @param amount The amount of tokens to deposit
     */
    function deposit(address to, uint256 amount) external;
}