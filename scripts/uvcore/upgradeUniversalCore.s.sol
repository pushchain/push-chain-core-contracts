// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UniversalCore} from "../../src/UniversalCore.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy, ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title UpgradeUniversalCoreScript
 * @notice Upgrade script for UniversalCore on Push Chain
 *
 * @dev Upgrades UniversalCore implementation through ProxyAdmin
 *
 * CONFIGURATION:
 *  Update the state variables below with your upgrade parameters.
 *  Environment variables needed: PRIVATE_KEY, RPC_URL, ETHERSCAN_API_KEY
 */
contract UpgradeUniversalCoreScript is Script {
    // ============================================================================
    // UPGRADE PARAMETERS - Pre-Upgrade Checklist 
    // ============================================================================

    // Address of the ProxyAdmin contract (manages upgrades)
    address public PROXY_ADMIN_ADDRESS = 0xf2000000000000000000000000000000000000c0;

    // Address of the UniversalCore proxy to upgrade
    address public UNIVERSAL_CORE_PROXY_ADDRESS = 0x00000000000000000000000000000000000000C0;

    function run() external {
        vm.startBroadcast();

        console.log("=== UniversalCore Upgrade Configuration ===");
        console.log("Proxy Admin:", PROXY_ADMIN_ADDRESS);
        console.log("UniversalCore Proxy:", UNIVERSAL_CORE_PROXY_ADDRESS);

        // 1. Deploy new implementation
        UniversalCore newImplementation = new UniversalCore();
        console.log("New UniversalCore implementation deployed at:", address(newImplementation));

        // 2. Connect to deployed ProxyAdmin
        ProxyAdmin proxyAdmin = ProxyAdmin(PROXY_ADMIN_ADDRESS);

        // 3. Upgrade the proxy
        ITransparentUpgradeableProxy proxy = ITransparentUpgradeableProxy(payable(UNIVERSAL_CORE_PROXY_ADDRESS));

        proxyAdmin.upgradeAndCall(proxy, address(newImplementation), "");
        console.log("Proxy upgraded successfully");
        console.log("\n=== Upgrade Complete ===");

        vm.stopBroadcast();
    }
}
