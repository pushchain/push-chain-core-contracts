// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../../src/interfaces/IUniswapV3.sol";
import "../mocks/MockPRC20.sol";

interface IERC20Transfer {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract MockUniswapV3Router {
    function exactInputSingle(ISwapRouter.ExactInputSingleParams calldata params) external returns (uint256) {
        uint256 amountOut = params.amountIn * 90 / 100;
        IERC20Transfer(params.tokenIn).transferFrom(msg.sender, address(this), params.amountIn);
        MockPRC20(params.tokenOut).deposit(params.recipient, amountOut);
        return amountOut;
    }
}
