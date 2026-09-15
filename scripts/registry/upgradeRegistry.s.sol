// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UniversalReadRegistry} from "../../src/UniversalReadRegistry.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {
    TransparentUpgradeableProxy,
    ITransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title UpgradeRegistryScript
 * @notice Upgrade script for UniversalReadRegistry on Push Chain
 *
 * @dev Deploys a new implementation and upgrades the proxy through ProxyAdmin.
 *      The new implementation MUST be deployed with the same UniversalCallback
 *      address — pending callbacks auth against the immutable baked into bytecode.
 *
 * CONFIGURATION:
 *  Update the state variables below with your upgrade parameters.
 *  Environment variables needed: PRIVATE_KEY, RPC_URL, ETHERSCAN_API_KEY
 */
contract UpgradeRegistryScript is Script {
    // ============================================================================
    // UPGRADE PARAMETERS - Pre-Upgrade Checklist
    // ============================================================================

    // ProxyAdmin address (created by TransparentUpgradeableProxy on first deploy)
    address public PROXY_ADMIN_ADDRESS = address(0);

    // UniversalReadRegistry proxy address
    address public REGISTRY_PROXY_ADDRESS = address(0);

    // UniversalCallback proxy address (MUST match the original deployment)
    address public UNIVERSAL_CALLBACK_ADDRESS = address(0);

    function run() external {
        require(PROXY_ADMIN_ADDRESS != address(0), "Set PROXY_ADMIN_ADDRESS");
        require(REGISTRY_PROXY_ADDRESS != address(0), "Set REGISTRY_PROXY_ADDRESS");
        require(UNIVERSAL_CALLBACK_ADDRESS != address(0), "Set UNIVERSAL_CALLBACK_ADDRESS");

        vm.startBroadcast();

        console.log("=== UniversalReadRegistry Upgrade ===");
        console.log("Proxy Admin:", PROXY_ADMIN_ADDRESS);
        console.log("Registry Proxy:", REGISTRY_PROXY_ADDRESS);
        console.log("UniversalCallback:", UNIVERSAL_CALLBACK_ADDRESS);

        // 1. Deploy new implementation
        UniversalReadRegistry newImpl = new UniversalReadRegistry(UNIVERSAL_CALLBACK_ADDRESS);
        console.log("New implementation deployed at:", address(newImpl));

        // 2. Upgrade proxy
        ProxyAdmin proxyAdmin = ProxyAdmin(PROXY_ADMIN_ADDRESS);
        ITransparentUpgradeableProxy proxy = ITransparentUpgradeableProxy(payable(REGISTRY_PROXY_ADDRESS));

        proxyAdmin.upgradeAndCall(proxy, address(newImpl), "");
        console.log("Proxy upgraded successfully");

        console.log("\n=== Upgrade Complete ===");

        vm.stopBroadcast();
    }
}
