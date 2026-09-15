// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UniversalReadRegistry} from "../../src/UniversalReadRegistry.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title DeployRegistryScript
 * @notice Deployment script for UniversalReadRegistry on Push Chain
 *
 * @dev Deploys:
 *  1. UniversalReadRegistry implementation (immutable UNIVERSAL_CALLBACK set here)
 *  2. TransparentUpgradeableProxy (auto-creates ProxyAdmin owned by OWNER_ADDRESS)
 *
 * CONFIGURATION:
 *  Update the state variables below with your deployment parameters.
 *  Environment variables needed: PRIVATE_KEY, RPC_URL, ETHERSCAN_API_KEY
 */
contract DeployRegistryScript is Script {
    // ============================================================================
    // DEPLOYMENT PARAMETERS - Pre-Deployment Checklist
    // ============================================================================

    // Owner of the ProxyAdmin (can upgrade the registry proxy)
    address public OWNER_ADDRESS = 0xa96CaA79eb2312DbEb0B8E93c1Ce84C98b67bF11;

    // UniversalCallback proxy address on Push Chain
    address public UNIVERSAL_CALLBACK_ADDRESS = address(0);

    function run() external {
        require(UNIVERSAL_CALLBACK_ADDRESS != address(0), "Set UNIVERSAL_CALLBACK_ADDRESS");

        vm.startBroadcast();

        console.log("=== UniversalReadRegistry Deployment ===");
        console.log("Owner:", OWNER_ADDRESS);
        console.log("UniversalCallback:", UNIVERSAL_CALLBACK_ADDRESS);

        // 1. Deploy implementation
        UniversalReadRegistry impl = new UniversalReadRegistry(UNIVERSAL_CALLBACK_ADDRESS);
        console.log("Implementation deployed at:", address(impl));

        // 2. Deploy proxy (OZ v5: initialOwner becomes ProxyAdmin owner)
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            OWNER_ADDRESS,
            abi.encodeWithSelector(UniversalReadRegistry.initialize.selector)
        );
        console.log("Proxy deployed at:", address(proxy));

        console.log("\n=== Deployment Complete ===");
        console.log("Registry address (use this):", address(proxy));

        vm.stopBroadcast();
    }
}
