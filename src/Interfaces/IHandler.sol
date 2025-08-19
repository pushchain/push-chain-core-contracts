// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./IUniversalContract.sol";

/// @title IHandler
/// @notice Interface for the Handler contract.
/// @dev Defines functions for handler contract callable by fungible module.
interface IHandler {
    // Constants
    function UNIVERSAL_EXECUTOR_MODULE() external view returns (address);

    // Immutables
    function uniswapV3FactoryAddress() external view returns (address);
    function uniswapV3SwapRouterAddress() external view returns (address);
    function uniswapV3QuoterAddress() external view returns (address);

    // State variables
    function wPCContractAddress() external view returns (address);
    function gasPriceByChainId(uint256 chainID) external view returns (uint256);
    function gasTokenPRC20ByChainId(uint256 chainID) external view returns (address);
    function gasPCPoolByChainId(uint256 chainID) external view returns (address);

    // Events
    event SystemContractDeployed();
    event SetGasPrice(uint256 chainId, uint256 price);
    event SetGasToken(uint256 chainId, address prc20);
    event SetGasPCPool(uint256 chainId, address pool, uint24 fee);
    event SetWPC(address wpc);
    event GasFundedWithGasToken(
        bytes32 payloadId, uint256 dstChainId, address gasToken, uint256 amount, address from, address to
    );
    event GasFundedViaSwap(
        bytes32 payloadId,
        uint256 dstChainId,
        address tokenIn,
        uint256 amountIn,
        address gasToken,
        uint256 amountOut,
        uint24 fee,
        address from,
        address to
    );
}
