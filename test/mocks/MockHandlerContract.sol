// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../../src/interfaces/IHandler.sol";

/**
 * @title MockHandlerContract
 * @notice Mock implementation of the Handler contract for testing PRC20
 */
contract MockHandlerContract is IHandler {
    address public immutable UNIVERSAL_EXECUTOR_MODULE;
    address private _uniswapV3FactoryAddress;
    address private _uniswapV3SwapRouterAddress;
    address private _uniswapV3QuoterAddress;
    address private _wPCContractAddress;

    mapping(uint256 => uint256) private _gasPriceByChainId;
    mapping(uint256 => address) private _gasTokenPRC20ByChainId;
    mapping(uint256 => address) private _gasPCPoolByChainId;

    constructor(address universalExecutorModule) {
        UNIVERSAL_EXECUTOR_MODULE = universalExecutorModule;
    }

    // State setters
    function setGasPrice(uint256 chainId, uint256 price) external {
        _gasPriceByChainId[chainId] = price;
        emit SetGasPrice(chainId, price);
    }

    function setGasTokenPRC20(uint256 chainId, address token) external {
        _gasTokenPRC20ByChainId[chainId] = token;
        emit SetGasToken(chainId, token);
    }

    function setGasPCPool(uint256 chainId, address pool, uint24 fee) external {
        _gasPCPoolByChainId[chainId] = pool;
        emit SetGasPCPool(chainId, pool, fee);
    }

    function setWPCContractAddress(address wpc) external {
        _wPCContractAddress = wpc;
        emit SetWPC(wpc);
    }

    function setUniswapAddresses(
        address factory,
        address router,
        address quoter
    ) external {
        _uniswapV3FactoryAddress = factory;
        _uniswapV3SwapRouterAddress = router;
        _uniswapV3QuoterAddress = quoter;
    }

    // View functions
    function uniswapV3FactoryAddress() external view returns (address) {
        return _uniswapV3FactoryAddress;
    }

    function uniswapV3SwapRouterAddress() external view returns (address) {
        return _uniswapV3SwapRouterAddress;
    }

    function uniswapV3QuoterAddress() external view returns (address) {
        return _uniswapV3QuoterAddress;
    }

    function wPCContractAddress() external view returns (address) {
        return _wPCContractAddress;
    }

    function gasPriceByChainId(uint256 chainId) external view returns (uint256) {
        return _gasPriceByChainId[chainId];
    }

    function gasTokenPRC20ByChainId(uint256 chainId) external view returns (address) {
        return _gasTokenPRC20ByChainId[chainId];
    }

    function gasPCPoolByChainId(uint256 chainId) external view returns (address) {
        return _gasPCPoolByChainId[chainId];
    }
}
