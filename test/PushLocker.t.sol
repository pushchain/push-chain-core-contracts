// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/PushLocker/PushLocker.sol";
import "forge-std/console2.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract PushLockerTest is Test {
    PushLocker locker;
    address user = makeAddr("user");
    address admin = makeAddr("admin");
    address recipient = makeAddr("recipient");
    bytes32 transactionHash = keccak256("transactionHash");

    // address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    // address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    // address constant ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
    // address constant FEED = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;

    //TESTNET SEPOLIA ADDRESS

    address constant WETH = 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14;
    address constant USDT = 0x7169D38820dfd117C3FA1f22a697dBA58d90BA06;
    address constant ROUTER = 0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E;
    address constant FEED = 0x694AA1769357215DE4FAC081bf1f309aDC325306;

    function setUp() public {
        // vm.createSelectFork(vm.envString("MAINNET_RPC_URL"));
        vm.createSelectFork(vm.envString("SEPOLIA_RPC_URL"));

        address deployedAddress = Upgrades.deployUUPSProxy(
            "PushLocker.sol", abi.encodeCall(PushLocker.initialize, (admin, WETH, USDT, ROUTER, FEED))
        );
        locker = PushLocker(deployedAddress);
        console2.logBytes32(locker.getRoleAdmin(0x00));
        vm.deal(user, 100 ether);
    }

    function test_AddFunds_ConvertsETHtoUSDT() public {
        vm.startPrank(user);
        uint256 initialUSDTBalance = IERC20(USDT).balanceOf(address(locker));

        locker.addFunds{value: 1 ether}(transactionHash);

        uint256 finalUSDTBalance = IERC20(USDT).balanceOf(address(locker));
        assertGt(finalUSDTBalance, initialUSDTBalance, "USDT not received");

        vm.stopPrank();
    }

    function test_RecoverToken_ByAdmin() public {
        // Send some ETH and convert to USDT
        vm.startPrank(user);
        locker.addFunds{value: 1 ether}(transactionHash);
        vm.stopPrank();

        uint256 lockerUSDTBalance = IERC20(USDT).balanceOf(address(locker));
        assertGt(lockerUSDTBalance, 0);

        vm.startPrank(admin);
        vm.expectEmit(true, true, false, true);
        emit TokenRecovered(recipient, lockerUSDTBalance);
        locker.recoverToken(recipient, lockerUSDTBalance);
        vm.stopPrank();

        assertEq(IERC20(USDT).balanceOf(recipient), lockerUSDTBalance);
    }

    function test_RecoverToken_NotAdminShouldRevert() public {
        vm.expectRevert();
        vm.prank(user);
        locker.recoverToken(recipient, 1e6); // Try to recover 1 USDT
    }

    function test_Upgradeability() public {
        //@dev: This is a workaround for the upgradeability test. In a real scenario, the admin can upgrade.
        vm.prank(admin);
        locker.grantRole(0x00, address(this));

        Upgrades.upgradeProxy(address(locker), "PushLockerV2.sol", "");

        // Just assert that it’s still functional after upgrade
        vm.prank(user);
        locker.addFunds{value: 0.5 ether}(transactionHash);
    }

    event FundsAdded(address indexed user, uint256 ethAmount, uint256 usdtAmount);
    event TokenRecovered(address indexed admin, uint256 amount);
}
