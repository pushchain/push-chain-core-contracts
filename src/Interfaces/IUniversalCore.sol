// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IUniversalCore
/// @notice Interface for the UniversalCore contract.
/// @dev Defines functions for UniversalCore contract callable by fungible module.
interface IUniversalCore {
    // =========================
    //           Universal Core Events
    // =========================    
    event SetWPC(address wpc);
    event SetGasPrice(string chainId, uint256 price);
    event SetGasToken(string chainId, address prc20);
    event SetDefaultDeadlineMins(uint256 minutesValue);
    event SetAutoSwapSupported(address token, bool supported);
    event SetGasPCPool(string chainId, address pool, uint24 fee);   
    event SetDefaultFeeTier(address indexed token, uint24 feeTier);
    event SetSlippageTolerance(address indexed token, uint256 tolerance);
    event SetUniswapV3Addresses(address factory, address swapRouter, address quoter);
    event DepositPRC20WithAutoSwap(address prc20, uint256 amountIn, address pcToken, uint256 amountOut, uint24 fee, address target);

    // =========================
    //           Universal Core Functions
    // =========================  

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

    /**
     * @dev Set the gas PC pool for a chain
     * @param chainID Chain ID
     * @param gasToken Gas coin address
     * @param fee Uniswap V3 fee tier
     */
    function setGasPCPool(string memory chainID, address gasToken, uint24 fee) external;

    /**
     * @dev Fungible module updates the gas price oracle periodically.
     * @param chainID Chain ID
     * @param price New gas price
     */
    function setGasPrice(string memory chainID, uint256 price) external;

    /**
     * @dev Setter for gasTokenPRC20ByChainId map.
     * @param chainID Chain ID
     * @param prc20 PRC20 address
     */
    function setGasTokenPRC20(string memory chainID, address prc20) external;

    /**
     * @notice Set auto-swap support for a token
     * @param token Token address
     * @param supported Whether the token supports auto-swap
     */
    function setAutoSwapSupported(address token, bool supported) external;

    /**
     * @dev Setter for wrapped PC address.
     * @param addr WPC new address
     */
    function setWPCContractAddress(address addr) external;

    /**
     * @dev Setter for uniswap V3 addresses.
     * @param factory Uniswap V3 Factory address
     * @param swapRouter Uniswap V3 SwapRouter address
     * @param quoter Uniswap V3 Quoter address
     */
    function setUniswapV3Addresses(address factory, address swapRouter, address quoter) external;

    /**
     * @notice Set default fee tier for a token
     * @param token Token address
     * @param feeTier Fee tier (500, 3000, 10000)
     */
    function setDefaultFeeTier(address token, uint24 feeTier) external;

    /**
     * @notice Set slippage tolerance for a token
     * @param token Token address
     * @param tolerance Slippage tolerance in basis points (e.g., 300 = 3%)
     */
    function setSlippageTolerance(address token, uint256 tolerance) external;

    /**
     * @notice Set default deadline in minutes
     * @param minutesValue Default deadline in minutes
     */
    function setDefaultDeadlineMins(uint256 minutesValue) external;

    /**
     * @notice Pause the contract - stops all deposit functions
     * @dev Can only be called by the owner
     */
    function pause() external;

    /**
     * @notice Unpause the contract - resumes all deposit functions
     * @dev Can only be called by the owner
     */
    function unpause() external;

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
}