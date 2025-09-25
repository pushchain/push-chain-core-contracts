// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract MockUniswapV3Factory {
    mapping(address => mapping(address => mapping(uint24 => address))) public pools;

    function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address) {
        return pools[tokenA][tokenB][fee];
    }

    function setPool(address tokenA, address tokenB, uint24 fee, address pool) external {
        pools[tokenA][tokenB][fee] = pool;
    }
}
