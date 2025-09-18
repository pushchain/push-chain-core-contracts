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
 * @dev Interface for Uniswap V3 Quoter
 */
interface IQuoter {
    /**
     * @dev Returns the amount out received for a given exact input swap without executing the swap
     * @param tokenIn The token being swapped in
     * @param tokenOut The token being swapped out
     * @param fee The fee tier of the pool
     * @param amountIn The amount of tokenIn to swap
     * @param sqrtPriceLimitX96 The price limit of the pool that cannot be exceeded by the swap
     * @return amountOut The amount of tokenOut received
     */
    function quoteExactInputSingle(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        uint256 amountIn,
        uint160 sqrtPriceLimitX96
    ) external view returns (uint256 amountOut);
}
