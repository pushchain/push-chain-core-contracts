// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @dev Interface for Uniswap V3 Factory
 */
interface IUniswapV3Factory {
    /**
     * @dev Returns the pool address for a given pair of tokens and fee
     * @param tokenA The first token of the pair
     * @param tokenB The second token of the pair
     * @param fee The fee tier
     * @return pool The address of the pool
     */
    function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address pool);
}

/**
 * @dev Interface for Uniswap V3 SwapRouter
 */
interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    /**
     * @dev Swaps `amountIn` of one token for as much as possible of another token
     * @param params The parameters necessary for the swap
     * @return amountOut The amount of the received token
     */
    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}

/**
 * @dev Interface for Uniswap V3 QuoterV2 (replaces old Quoter)
 */
interface IQuoterV2 {
    struct QuoteExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint24 fee;
        uint160 sqrtPriceLimitX96;
    }

    /**
     * @dev Returns the amount out received for a given exact input swap without executing the swap
     * @param params The quote parameters
     * @return amountOut The amount of tokenOut received
     * @return sqrtPriceX96After The sqrt price after the swap
     * @return initializedTicksCrossed The number of initialized ticks crossed
     * @return gasEstimate The estimated gas for the swap
     */
    function quoteExactInputSingle(QuoteExactInputSingleParams memory params)
        external
        view
        returns (uint256 amountOut, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate);
}
