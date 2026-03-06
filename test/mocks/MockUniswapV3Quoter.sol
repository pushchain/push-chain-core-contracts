// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../../src/interfaces/IUniswapV3.sol";

contract MockUniswapV3Quoter {
    function quoteExactInputSingle(address, address, uint24, uint256 amountIn, uint160)
        external
        pure
        returns (uint256)
    {
        return amountIn * 90 / 100;
    }

    function quoteExactInputSingle(IQuoterV2.QuoteExactInputSingleParams memory params)
        external
        pure
        returns (uint256, uint160, uint32, uint256)
    {
        return (params.amountIn * 90 / 100, 0, 0, 0);
    }
}
