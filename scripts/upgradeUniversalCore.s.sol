// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UniversalCore} from "../src/UniversalCore.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy, ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract UpgradeUniversalCoreScript is Script {
    function run() external {
        vm.startBroadcast(0xa96CaA79eb2312DbEb0B8E93c1Ce84C98b67bF11); // proxyAdminOwner

        // 1. Deploy new implementation
        UniversalCore newImplementation = new UniversalCore();
        console.log("New UniversalCore deployed at:", address(newImplementation));

        // 2. Connect to deployed ProxyAdmin
        ProxyAdmin proxyAdmin = ProxyAdmin(0xf2000000000000000000000000000000000000c0);

        // 3. Upgrade the proxy
        ITransparentUpgradeableProxy proxy = ITransparentUpgradeableProxy(payable(0x00000000000000000000000000000000000000C0));

        proxyAdmin.upgradeAndCall(proxy, address(newImplementation), "");
        console.log("Proxy upgraded successfully");

        vm.stopBroadcast();
    }
}
