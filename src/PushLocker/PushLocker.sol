// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ISwapRouter, IWETH, AggregatorV3Interface} from "../Interfaces/AMMInterfaces.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

contract PushLocker is Initializable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    event FundsAdded(address indexed user, uint256 usdtAmount, bytes32 transactionHash);
    event TokenRecovered(address indexed admin, uint256 amount);

    address public WETH;
    address public USDT;
    address public UNISWAP_ROUTER;
    AggregatorV3Interface public ethUsdPriceFeed;

    uint24 constant POOL_FEE = 500; // 0.05%

    function initialize(address _admin, address _weth, address _usdt, address _router, address _priceFeed)
        external
        initializer
    {
        __ReentrancyGuard_init();
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        WETH = _weth;
        USDT = _usdt;
        UNISWAP_ROUTER = _router;
        ethUsdPriceFeed = AggregatorV3Interface(_priceFeed);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function addFunds(bytes32 _transactionHash) external payable nonReentrant {
        require(msg.value > 0, "No ETH sent");

        // Wrap ETH to WETH
        IWETH(WETH).deposit{value: msg.value}();
        uint256 WethBalance = IERC20(WETH).balanceOf(address(this));
        IWETH(WETH).approve(UNISWAP_ROUTER, WethBalance);

        // Get current ETH/USD price from Chainlink
        uint256 price = getEthUsdPrice();

        uint256 ethInUsd = (uint256(price) * WethBalance) / 1e8;

        // Expect similar USDT amount (1:1 with USD), allow 0.5% slippage
        uint256 minOut = (ethInUsd * 995) / 1000;

        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: WETH,
            tokenOut: USDT,
            fee: POOL_FEE,
            recipient: address(this),
            deadline: block.timestamp, //not for sepolia
            amountIn: WethBalance,
            amountOutMinimum: minOut / 1e12, // Adjust to USDT decimals (6) && not for sepolia
            sqrtPriceLimitX96: 0
        });

        uint256 usdtReceived = ISwapRouter(UNISWAP_ROUTER).exactInputSingle(params);

        emit FundsAdded(msg.sender, usdtReceived, _transactionHash);
    }

    function recoverToken(address _recipient, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20(USDT).safeTransfer(_recipient, amount);

        emit TokenRecovered(_recipient, amount);
    }

    function getEthUsdPrice() public view returns (uint256) {
        (, int256 price,,,) = ethUsdPriceFeed.latestRoundData();

        require(price > 0, "Invalid price");
        return uint256(price); // 8 decimals
    }
}
