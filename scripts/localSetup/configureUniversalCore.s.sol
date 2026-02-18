// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UniversalCoreV0} from "../../src/UniversalCoreV0.sol";

contract ConfigureUniversalCoreScript is Script {
    // UniversalCore contract address
    address constant UNIVERSAL_CORE = 0x00000000000000000000000000000000000000C0;
    
    // Fee tiers: 500 (0.05%), 3000 (0.3%), 10000 (1%)
    uint24 constant FEE_TIER_LOW = 500;
    uint24 constant FEE_TIER_MEDIUM = 3000;
    uint24 constant FEE_TIER_HIGH = 10000;

    function run() external {
        address uniswapV3Factory = vm.envAddress("UNISWAP_V3_FACTORY");
        address uniswapV3Router = vm.envAddress("UNISWAP_V3_ROUTER");
        address uniswapV3Quoter = vm.envAddress("UNISWAP_V3_QUOTER");
        address wpc = vm.envAddress("WPC");
        address token1 = vm.envAddress("TOKEN1"); // WETH token

        vm.startBroadcast();

        UniversalCoreV0 core = UniversalCoreV0(payable(UNIVERSAL_CORE));

        // 1. Set Uniswap V3 addresses
        console.log("Setting Uniswap V3 addresses...");
        core.setUniswapV3Addresses(
            uniswapV3Factory,
            uniswapV3Router,
            uniswapV3Quoter
        );
        console.log("  Factory:", uniswapV3Factory);
        console.log("  Router:", uniswapV3Router);
        console.log("  Quoter:", uniswapV3Quoter);

        // 2. Set WPC contract address
        console.log("\nSetting WPC contract address...");
        core.setWPCContractAddress(wpc);
        console.log("  WPC:", wpc);

        // 3. Set auto-swap support for tokens
        console.log("\nConfiguring auto-swap support...");
        core.setAutoSwapSupported(token1, true);
        console.log("  Token 1 auto-swap enabled:", token1);

        // 4. Set default fee tiers for tokens
        console.log("\nSetting default fee tiers...");
        core.setDefaultFeeTier(token1, FEE_TIER_LOW);  // 0.05%
        console.log("  Token 1 fee tier set to:", FEE_TIER_LOW);

        console.log("\nUniversalCore configuration complete!");

        vm.stopBroadcast();
    }
}
