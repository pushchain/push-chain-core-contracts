// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UniversalCoreV0} from "../../src/UniversalCoreV0.sol";

contract SetupTokenForAutoSwapScript is Script {
	// Fee tiers: 500 (0.05%), 3000 (0.3%), 10000 (1%)
	uint24 constant FEE_TIER_LOW = 500;

	function run() external {
		address universalCore = 0x00000000000000000000000000000000000000C0;

		vm.startBroadcast();

		UniversalCoreV0 core = UniversalCoreV0(payable(universalCore));

		// 1. Configure auto-swap + default fee tiers for TOKEN1..TOKENn
		console.log("Configuring tokens from .env...");
		uint256 tokenCount;
		for (uint256 index = 1; ; index++) {
			string memory tokenKey = string.concat("TOKEN", vm.toString(index));
			address token = vm.envOr(tokenKey, address(0));

			if (token == address(0)) {
				break;
			}

			core.setAutoSwapSupported(token, true);
			console.log("  Token auto-swap enabled:", token);

			core.setDefaultFeeTier(token, FEE_TIER_LOW); // 0.05%
			console.log("  Token fee tier set to:", FEE_TIER_LOW);

			tokenCount++;
		}

		require(tokenCount > 0, "No TOKEN{i} found in .env");
		console.log("  Total tokens configured:", tokenCount);

		console.log("\nUniversalCore token setup complete!");

		vm.stopBroadcast();
	}
}
