// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ISwapRouter, IWETH, AggregatorV3Interface} from "../Interfaces/AMMInterfaces.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";


contract PushLocker is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable
{
    using SafeERC20 for IERC20;
    event FundsAdded(
        address indexed user,
        uint256 ethAmount,
        uint256 usdtAmount
    );
    event TokenRecovered(address indexed admin, uint256 amount);

    address public WETH;
    address public USDT;
    address public UNISWAP_ROUTER;
    AggregatorV3Interface public ethUsdPriceFeed;

    uint24 constant POOL_FEE = 500; // 0.05%

    function initialize(
        address _admin,
        address _weth,
        address _usdt,
        address _router,
        address _priceFeed
    ) external initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        WETH = _weth;
        USDT = _usdt;
        UNISWAP_ROUTER = _router;
        ethUsdPriceFeed = AggregatorV3Interface(_priceFeed);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function addFunds() external payable {
        require(msg.value > 0, "No ETH sent");

        // Wrap ETH to WETH
        IWETH(WETH).deposit{value: msg.value}();
        IWETH(WETH).approve(UNISWAP_ROUTER, msg.value);

        // Get current ETH/USD price from Chainlink
        (, int256 price, , , ) = ethUsdPriceFeed.latestRoundData(); // price is 8 decimals
        require(price > 0, "Invalid oracle price");

        uint256 ethInUsd = (uint256(price) * msg.value) / 1e8;

        // Expect similar USDT amount (1:1 with USD), allow 0.5% slippage
        uint256 minOut = (ethInUsd * 995) / 1000;

        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter
            .ExactInputSingleParams({
                tokenIn: WETH,
                tokenOut: USDT,
                fee: POOL_FEE,
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: msg.value,
                amountOutMinimum: minOut / 1e12, // Adjust to USDT decimals (6)
                sqrtPriceLimitX96: 0
            });

        uint256 usdtReceived = ISwapRouter(UNISWAP_ROUTER).exactInputSingle(
            params
        );
    // IERC20(USDT).transfer(0x6CA6d1e2D5347Bfab1d91e883F1915560e09129D, usdtReceived);

        emit FundsAdded(msg.sender, msg.value, usdtReceived);
    }

function recoverToken(address _recipient, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
    uint256 balance = IERC20(USDT).balanceOf(address(this));
    require(balance >= amount, "Insufficient balance");

    IERC20(USDT).safeTransfer(_recipient, amount);

    emit TokenRecovered(_recipient, amount);
}

}
