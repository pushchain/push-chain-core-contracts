// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../../src/interfaces/IUniswapV3.sol";

contract MockUniswapV3Router {
    function exactInputSingle(ISwapRouter.ExactInputSingleParams calldata params) external returns (uint256) {
        // Mock implementation - return 90% of input as output
        return params.amountIn * 90 / 100;
    }
}
