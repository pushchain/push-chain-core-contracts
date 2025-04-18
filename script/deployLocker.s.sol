// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/PushLocker/PushLocker.sol";
import {FactoryV1} from "../src/SmartAccount/FactoryV1.sol";
import {SmartAccountV1} from "../src/SmartAccount/SmartAccountV1.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract DeployLocker is Script {
    address public constant ADMIN = 0xEbf0Cfc34E07ED03c05615394E2292b387B63F12; // Replace with the actual admin address
    address _weth;
    address _usdt;
    address _router;
    address _priceFeed;

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
                (ADMIN, _weth, _usdt, _router, _priceFeed)
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
