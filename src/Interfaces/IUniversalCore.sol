// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IUniversalCore
/// @notice Interface for the UniversalCore contract.
/// @dev Defines functions for UniversalCore contract callable by fungible module.
interface IUniversalCore {
    // Constants
    function UNIVERSAL_EXECUTOR_MODULE() external view returns (address);

    // Immutables
    function uniswapV3FactoryAddress() external view returns (address);
    function uniswapV3SwapRouterAddress() external view returns (address);
    function uniswapV3QuoterAddress() external view returns (address);

    // State variables
    function wPCContractAddress() external view returns (address);
    function gasPriceByChainId(string memory chainID) external view returns (uint256);
    function gasTokenPRC20ByChainId(string memory chainID) external view returns (address);
    function gasPCPoolByChainId(string memory chainID) external view returns (address);

    // Events
    event SetGasPrice(string chainId, uint256 price);
    event SetGasToken(string chainId, address prc20);
    event SetGasPCPool(string chainId, address pool, uint24 fee);
    event SetWPC(address wpc);
    event SetUniswapV3Addresses(address factory, address swapRouter, address quoter);
    event SetAutoSwapSupported(address token, bool supported);
    event SetDefaultFeeTier(address indexed token, uint24 feeTier);
    event SetSlippageTolerance(address indexed token, uint256 tolerance);
    event SetDefaultDeadlineMins(uint256 minutesValue);
    event DepositPRC20WithAutoSwap(
        address prc20, uint256 amountIn, address pcToken, uint256 amountOut, uint24 fee, address target
    );
}
