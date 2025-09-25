// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../../src/interfaces/IUniswapV3.sol";

contract MockUniswapV3Quoter {
    function quoteExactInputSingle(address, address, uint24, uint256 amountIn, uint160)
        external
        pure
        returns (uint256)
    {
        // Mock implementation - return 90% of input as output
        return amountIn * 90 / 100;
    }
}
