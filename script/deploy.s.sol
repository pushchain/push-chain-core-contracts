// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/PushLocker/PushLocker.sol";
import {FactoryV1} from "../src/SmartAccount/FactoryV1.sol";
import {SmartAccountV1} from "../src/SmartAccount/SmartAccountV1.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract DeployLocker is Script {
    address public constant ADMIN = 0xEbf0Cfc34E07ED03c05615394E2292b387B63F12; // Replace with the actual admin address
    
    //TODO These are mainnet address.
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
    address constant FEED = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;

    function run() external {
        vm.startBroadcast();

        SmartAccountV1 _smartAccount = new SmartAccountV1();
        FactoryV1 _factory = new FactoryV1(address(_smartAccount));

        console.log(
            "FactoryV1 deployed at address:",
            address(_factory),
            "SmartAccountV1 deployed at address:",
            address(_smartAccount)
        );

        address pushLocker = Upgrades.deployUUPSProxy(
            "PushLocker.sol",
            abi.encodeCall(
                PushLocker.initialize,
                (ADMIN, WETH, USDT, ROUTER, FEED) // Initialize with admin and other parameters
            )
        );

        console.log(
            "PushLocker deployed to proxy address:",
            address(pushLocker)
        );

        vm.stopBroadcast();
    }
}

/**
 * export ETHERSCAN_API_KEY=ZGBAFYMRDEYN1RHHJFH71JWJPVWX2QDKDK  
  forge verify-contract 0x7A3AbCA9aABf881627011A7e0D3Ad11628d85C28 src/SmartAccount/FactoryV1.sol:FactoryV1 --chain-id 11155111 --watch
  forge verify-contract 0x10cB82cb3Fa3cf01855cF90AbF61855Cfe92d937 src/SmartAccount/SmartAccountV1:SmartAccountV1 --chain-id 11155111 --watch
  forge verify-contract 0xeC1cE626D8138E645F2f8B5279f74B2C6805c1c1 src/PushLocker/PushLocker.sol:PushLocker --chain-id 11155111 --watch
 * 
 * 
 */
