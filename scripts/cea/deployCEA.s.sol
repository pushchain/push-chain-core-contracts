// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CEA} from "../../src/cea/CEA.sol";

/**
 * @title DeployCEAScript
 * @notice Deployment script for the CEA implementation contract on external EVM chains.
 *
 * @dev Deploys only the CEA logic contract (no factory, proxy, or admin).
 *      Useful when upgrading the CEA implementation on an existing CEAFactory.
 *
 *      After deployment, call `CEAFactory.setCEAImplementation(newCEAImpl)`
 *      on the factory to point clones at the new implementation.
 *
 * CONFIGURATION:
 *  Environment variables needed: KEY, RPC_URL, ETHERSCAN_API_KEY
 */
contract DeployCEAScript is Script {
    function run() external {
        // Get chain ID and deployer info
        uint256 chainId = block.chainid;
        uint256 deployerKey = uint256(vm.envBytes32("KEY"));
        address deployer = vm.addr(deployerKey);

        console.log("=== CEA Implementation Deployment ===");
        console.log("Chain ID:", chainId);
        console.log("Deployer:", deployer);
        console.log("");

        vm.startBroadcast(deployerKey);

        // Deploy CEA implementation (logic contract)
        CEA ceaImplementation = new CEA();
        console.log("[1/1] CEA Implementation:", address(ceaImplementation));

        vm.stopBroadcast();

        // Post-deployment output
        console.log("\n=== Post-Deployment Info ===");
        console.log("CEA Implementation:", address(ceaImplementation));
        console.log("");

        // Generate JSON output for deployment tracking
        string memory json = string(
            abi.encodePacked(
                "{\n",
                '  "chainId": ',
                vm.toString(chainId),
                ",\n",
                '  "deployer": "',
                vm.toString(deployer),
                '",\n',
                '  "ceaImplementation": "',
                vm.toString(address(ceaImplementation)),
                '"\n',
                "}"
            )
        );
        console.log("\n=== Deployment Addresses (JSON) ===");
        console.log(json);

        // Write to file
        string memory filename = string(abi.encodePacked("deployments/cea-impl-", vm.toString(chainId), ".json"));
        vm.writeFile(filename, json);
        console.log("\nDeployment saved to:", filename);

        console.log("\n=== Deployment Complete ===");
        console.log(
            "NEXT STEP: Call CEAFactory.setCEAImplementation(",
            address(ceaImplementation),
            ") on the factory proxy to activate this implementation."
        );
    }
}

/*
 * ============================================================================
 * DEPLOYMENT COMMAND
 * ============================================================================
 *
 * Deploy to any EVM chain:
 *
 * forge script scripts/cea/deployCEA.s.sol:DeployCEAScript \
 *   --rpc-url $RPC_URL \
 *   --private-key $KEY \
 *   --broadcast \
 *   -vvvv
 *
 * ============================================================================
 * VERIFICATION COMMAND
 * ============================================================================
 *
 * forge verify-contract \
 *   <CEA_IMPLEMENTATION_ADDRESS> \
 *   src/cea/CEA.sol:CEA \
 *   --chain-id <CHAIN_ID> \
 *   --etherscan-api-key $ETHERSCAN_API_KEY
 *
 * ============================================================================
 * POST-DEPLOYMENT
 * ============================================================================
 *
 * Update the factory to use the new implementation:
 *
 * cast send <CEA_FACTORY_PROXY_ADDRESS> \
 *   "setCEAImplementation(address)" <CEA_IMPLEMENTATION_ADDRESS> \
 *   --rpc-url $RPC_URL \
 *   --private-key $KEY
 */
