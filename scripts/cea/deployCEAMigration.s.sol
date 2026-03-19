// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CEA_V2} from "../../src/cea/CEA_V2.sol";
import {CEAMigration} from "../../src/cea/CEAMigration.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";

/**
 * @title DeployCEAMigrationScript
 * @notice Deploys CEA_V2 + CEAMigration and sets it in the CEAFactory.
 *
 * @dev Steps:
 *  1. Deploy CEA_V2 (new implementation)
 *  2. Deploy CEAMigration(ceaV2Address)
 *  3. Call CEAFactory.setCEAMigrationContract(migrationAddress)
 *
 * CONFIGURATION:
 *  Environment variables needed: KEY, RPC_URL
 */
contract DeployCEAMigrationScript is Script {
    // ============================================================================
    // DEPLOYMENT PARAMETERS
    // ============================================================================

    address public CEA_FACTORY_PROXY = 0xe2182dae2dc11cBF6AA6c8B1a7f9c8315A6B0719;

    function run() external {
        uint256 chainId = block.chainid;
        uint256 deployerKey = uint256(vm.envBytes32("KEY"));
        address deployer = vm.addr(deployerKey);

        console.log("=== CEA Migration Deployment ===");
        console.log("Chain ID:", chainId);
        console.log("Deployer:", deployer);
        console.log("CEAFactory Proxy:", CEA_FACTORY_PROXY);
        console.log("");

        vm.startBroadcast(deployerKey);

        // 1. Deploy CEA_V2
        CEA_V2 ceaV2 = new CEA_V2();
        console.log("[1/3] CEA_V2:", address(ceaV2));

        // 2. Deploy CEAMigration
        CEAMigration migration = new CEAMigration(address(ceaV2));
        console.log("[2/3] CEAMigration:", address(migration));

        // 3. Set migration contract in factory
        CEAFactory factory = CEAFactory(CEA_FACTORY_PROXY);
        factory.setCEAMigrationContract(address(migration));
        console.log("[3/3] setCEAMigrationContract called");

        vm.stopBroadcast();

        // Post-deployment verification
        console.log("\n=== Post-Deployment Verification ===");

        address verifiedMigration = factory.CEA_MIGRATION_CONTRACT();
        address verifiedImpl = migration.CEA_IMPLEMENTATION();

        console.log(
            "CEA_MIGRATION_CONTRACT:",
            verifiedMigration,
            verifiedMigration == address(migration) ? "[OK]" : "[MISMATCH]"
        );
        console.log(
            "CEA_IMPLEMENTATION:", verifiedImpl, verifiedImpl == address(ceaV2) ? "[OK]" : "[MISMATCH]"
        );

        require(verifiedMigration == address(migration), "Migration contract mismatch");
        require(verifiedImpl == address(ceaV2), "CEA implementation mismatch");

        // JSON output
        string memory json = string(
            abi.encodePacked(
                "{\n",
                '  "chainId": ',
                vm.toString(chainId),
                ",\n",
                '  "deployer": "',
                vm.toString(deployer),
                '",\n',
                '  "ceaV2": "',
                vm.toString(address(ceaV2)),
                '",\n',
                '  "ceaMigration": "',
                vm.toString(address(migration)),
                '",\n',
                '  "ceaFactoryProxy": "',
                vm.toString(CEA_FACTORY_PROXY),
                '"\n',
                "}"
            )
        );
        console.log("\n=== Deployment Addresses (JSON) ===");
        console.log(json);

        string memory filename =
            string(abi.encodePacked("deployments/", vm.toString(chainId), "_cea_migration.json"));
        vm.writeFile(filename, json);
        console.log("\nDeployment saved to:", filename);

        console.log("\n=== Deployment Complete ===");
    }
}

/*
 * ============================================================================
 * DEPLOYMENT COMMAND
 * ============================================================================
 *
 * forge script scripts/cea/deployCEAMigration.s.sol:DeployCEAMigrationScript \
 *   --rpc-url $BSC_TESTNET_RPC_URL \
 *   --private-key $KEY \
 *   --broadcast \
 *   -vvvv
 *
 * ============================================================================
 * VERIFICATION COMMANDS
 * ============================================================================
 *
 * 1. Verify CEA_V2:
 * forge verify-contract <CEA_V2_ADDRESS> src/cea/CEA_V2.sol:CEA_V2 \
 *   --chain-id 97 --etherscan-api-key $BSCSCAN_API_KEY
 *
 * 2. Verify CEAMigration:
 * forge verify-contract <MIGRATION_ADDRESS> src/cea/CEAMigration.sol:CEAMigration \
 *   --chain-id 97 --etherscan-api-key $BSCSCAN_API_KEY \
 *   --constructor-args $(cast abi-encode "constructor(address)" <CEA_V2_ADDRESS>)
 */
