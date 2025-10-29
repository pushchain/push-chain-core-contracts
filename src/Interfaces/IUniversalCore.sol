// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IUniversalCore
/// @notice Interface for the UniversalCore contract.
/// @dev Defines functions for UniversalCore contract callable by fungible module.
interface IUniversalCore {
    // =========================
    //           Universal Core Events
    // =========================    
    event SetGasPrice(string chainId, uint256 price);
    event SetGasToken(string chainId, address prc20);
    event SetDefaultDeadlineMins(uint256 minutesValue);
    event SetSupportedToken(address indexed prc20, bool supported);
    event SetGasPCPool(string chainId, address pool, uint24 fee);   
    event DepositPRC20WithAutoSwap(address prc20, uint256 amountIn, address pcToken, uint256 amountOut, uint24 fee, address target);
    // =========================
    //           Universal Core Functions
    // =========================  

    /**
     * @notice Check if a PRC20 token is supported
     * @param prc20 PRC20 token address
     * @return supported Whether the token is supported
     */
    function isSupportedToken(address prc20) external view returns (bool supported);
    /**
     * @notice Deposits PRC20 tokens to the provided target address.
     * @dev    Can only be called by the Universal Executor Module.
     *         For any inbound transactions of moving supported tokens from external chains to Push Chain,
     *         the Universal Executor Module uses this function to deposit the tokens to the target address.
     *         The target address can be any address of the user's choice.
     * @param prc20 PRC20 address for deposit
     * @param amount Amount to deposit
     * @param target Address to deposit tokens to
     */
    function depositPRC20Token(address prc20, uint256 amount, address target) external;

    /**
     * @notice Deposits PRC20 tokens and automatically swaps them to native PC before sending to target.
     * @dev    Can only be called by the Universal Executor Module.
     *         Can only be called if the PRC20 token is in the auto-swap supported list. ( eg pETH, pSOL, pUSDC etc.)
     *         If no pool exists, reverts with appropriate error. Although all auto-swap supported tokens are expected to have a pool.
     *         Default values are used when parameters are set to 0. ( fee = defaultFeeTier[prc20], minPCOut = calculateMinOutput(expectedOutput, prc20), deadline = block.timestamp + (defaultDeadlineMins * 1 minutes) )
     *         target address always receive the swapped native PC tokens.
     *         The function is called directly by the Universal Executor Module and is also gasless.
     * @param prc20 PRC20 address for deposit and swap
     * @param amount Amount to deposit and swap
     * @param target Address to receive the swapped native PC tokens
     * @param fee Uniswap V3 fee tier for the pool (0 = use default)
     * @param minPCOut Minimum amount of native PC expected from the swap (0 = calculate from slippage tolerance)
     * @param deadline Timestamp after which the transaction will revert (0 = use default)
     */
    function depositPRC20WithAutoSwap(
        address prc20,
        uint256 amount,
        address target,
        uint24 fee,
        uint256 minPCOut,
        uint256 deadline
    ) external;


    // =========================
    //           Getter Functions
    // =========================

    /**
     * @notice Get gas token PRC20 address for a chain
     * @param chainId Chain ID
     * @return gasToken Gas token address
     */
    function gasTokenPRC20ByChainId(string memory chainId) external view returns (address gasToken);

    /**
     * @notice Get gas price for a chain
     * @param chainId Chain ID
     * @return price Gas price
     */
    function gasPriceByChainId(string memory chainId) external view returns (uint256 price);

    /**
     * @notice Get base gas limit for a chain
     * @return baseGasLimit Base gas limit
     */
    function BASE_GAS_LIMIT() external view returns (uint256 baseGasLimit);

    /**
     * @notice Get gas fee for a PRC20 token.
     * @dev    Uses BASE_GAS_LIMIT for the gas limit used in the fee computation.
     * @param _prc20 PRC20 address
     * @return gasToken Gas token address
     * @return gasFee Gas fee
     */
    function withdrawGasFee(address _prc20) external view returns (address gasToken, uint256 gasFee);

    /**
     * @notice Get gas fee for a PRC20 token with a custom gas limit
     * @dev    Uses the provided gas limit for the fee computation.
     * @param _prc20 PRC20 address
     * @param gasLimit Gas limit
     * @return gasToken Gas token address
     * @return gasFee Gas fee
     */
    function withdrawGasFeeWithGasLimit(address _prc20, uint256 gasLimit) external view returns (address gasToken, uint256 gasFee);
}