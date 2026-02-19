// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UniversalCoreV0} from "../../src/UniversalCoreV0.sol";

contract SetupTokenForAutoSwapScript is Script {
	// Fee tiers: 500 (0.05%), 3000 (0.3%), 10000 (1%)
	uint24 constant FEE_TIER_LOW = 500;

	function run() external {
		address universalCore = 0x00000000000000000000000000000000000000C0;
		address token1 = vm.envAddress("TOKEN1"); // USDT token
		address token2 = vm.envAddress("TOKEN2");

		vm.startBroadcast();

		UniversalCoreV0 core = UniversalCoreV0(payable(universalCore));

		// 1. Set auto-swap support for tokens
		console.log("Configuring auto-swap support...");
		core.setAutoSwapSupported(token1, true);
		console.log("  Token 1 auto-swap enabled:", token1);
		core.setAutoSwapSupported(token2, true);
		console.log("  Token 2 auto-swap enabled:", token2);

		// 2. Set default fee tier for tokens
		console.log("\nSetting default fee tiers...");
		core.setDefaultFeeTier(token1, FEE_TIER_LOW); // 0.05%
		console.log("  Token 1 fee tier set to:", FEE_TIER_LOW);
		core.setDefaultFeeTier(token2, FEE_TIER_LOW); // 0.05%
		console.log("  Token 2 fee tier set to:", FEE_TIER_LOW);

		console.log("\nUniversalCore token setup complete!");

		vm.stopBroadcast();
	}
}
