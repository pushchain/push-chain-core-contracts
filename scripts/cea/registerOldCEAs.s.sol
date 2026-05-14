// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";

/**
 * @title RegisterOldCEAsScript
 * @notice Reads a JSON file of old CEA↔pushAccount pairs and registers
 *         them on the new CEAFactory via registerExistingCEAs().
 *
 * PREREQUISITES:
 *  1. Run fetchOldCEAs.sh to generate migrations/<chainId>_old_ceas.json
 *  2. Review the JSON file to verify correctness
 *  3. Set NEW_CEA_FACTORY below to the new factory proxy address
 *
 * USAGE:
 *  source .env && KEY=$KEY_ETH forge script \
 *    scripts/cea/registerOldCEAs.s.sol:RegisterOldCEAsScript \
 *    --rpc-url "$SEPOLIA_RPC_URL" \
 *    --broadcast -vvvv
 *
 * CONFIGURATION:
 *  Update the state variables below per chain.
 *  Environment variables needed: KEY
 */
contract RegisterOldCEAsScript is Script {
    // ============================================================================
    // CONFIGURATION — update per chain
    // ============================================================================

    // New CEAFactory proxy address (from fresh deployment)
    address public NEW_CEA_FACTORY = address(0);

    // Max CEAs per transaction to stay within block gas limit
    uint256 public constant BATCH_SIZE = 50;

    function run() external {
        uint256 chainId = block.chainid;
        uint256 deployerKey = uint256(vm.envBytes32("KEY"));
        address deployer = vm.addr(deployerKey);

        require(
            NEW_CEA_FACTORY != address(0),
            "Set NEW_CEA_FACTORY before running"
        );

        string memory jsonPath = string(
            abi.encodePacked(
                "migrations/",
                vm.toString(chainId),
                "_old_ceas.json"
            )
        );

        console.log("=== Register Old CEAs ===");
        console.log("Chain ID:", chainId);
        console.log("Deployer:", deployer);
        console.log("New CEAFactory:", NEW_CEA_FACTORY);
        console.log("JSON file:", jsonPath);

        string memory json = vm.readFile(jsonPath);

        uint256 totalPairs = abi.decode(
            vm.parseJson(json, ".uniquePairs"),
            (uint256)
        );
        console.log("Total pairs to register:", totalPairs);

        if (totalPairs == 0) {
            console.log("No pairs to register. Exiting.");
            return;
        }

        address[] memory pushAccounts = abi.decode(
            vm.parseJson(json, ".pairs[*].pushAccount"),
            (address[])
        );
        address[] memory ceaAddresses = abi.decode(
            vm.parseJson(json, ".pairs[*].cea"),
            (address[])
        );

        require(
            pushAccounts.length == ceaAddresses.length,
            "Array length mismatch in JSON"
        );
        require(
            pushAccounts.length == totalPairs,
            "Pair count mismatch"
        );

        CEAFactory factory = CEAFactory(NEW_CEA_FACTORY);

        // Verify deployer has CEA_ADMIN_ROLE
        bytes32 ceaAdminRole = factory.CEA_ADMIN_ROLE();
        require(
            factory.hasRole(ceaAdminRole, deployer),
            "Deployer missing CEA_ADMIN_ROLE"
        );

        console.log("");
        console.log("=== Pre-Registration Checks ===");

        // Verify first and last pair are not already registered
        (address existingFirst,) = factory.getCEAForPushAccount(
            pushAccounts[0]
        );
        console.log(
            "First pushAccount existing CEA:",
            existingFirst
        );

        uint256 totalBatches = (totalPairs + BATCH_SIZE - 1)
            / BATCH_SIZE;
        console.log(
            "Batches:",
            totalBatches,
            "(batch size:",
            BATCH_SIZE,
            ")"
        );

        vm.startBroadcast(deployerKey);

        for (uint256 b = 0; b < totalBatches; b++) {
            uint256 start = b * BATCH_SIZE;
            uint256 end = start + BATCH_SIZE;
            if (end > totalPairs) end = totalPairs;
            uint256 batchLen = end - start;

            address[] memory batchPush = new address[](batchLen);
            address[] memory batchCea = new address[](batchLen);

            for (uint256 i = 0; i < batchLen; i++) {
                batchPush[i] = pushAccounts[start + i];
                batchCea[i] = ceaAddresses[start + i];
            }

            factory.registerExistingCEAs(batchPush, batchCea);

            console.log(
                "  Batch",
                b + 1,
                "/",
                totalBatches,
                "registered",
                batchLen,
                "pairs"
            );
        }

        vm.stopBroadcast();

        // Post-registration verification
        console.log("");
        console.log("=== Post-Registration Verification ===");

        uint256 verified = 0;
        uint256 failed = 0;

        for (uint256 i = 0; i < totalPairs; i++) {
            (address cea, bool isDeployed) = factory
                .getCEAForPushAccount(pushAccounts[i]);
            bool isCea = factory.isCEA(ceaAddresses[i]);
            address reverse = factory.getPushAccountForCEA(
                ceaAddresses[i]
            );

            if (
                cea == ceaAddresses[i]
                    && isCea
                    && reverse == pushAccounts[i]
            ) {
                verified++;
            } else {
                failed++;
                console.log("  FAIL at index", i);
                console.log(
                    "    pushAccount:", pushAccounts[i]
                );
                console.log(
                    "    expected CEA:", ceaAddresses[i]
                );
                console.log("    got CEA:", cea);
                console.log("    isCEA:", isCea);
                console.log("    reverse:", reverse);
            }
        }

        console.log("Verified:", verified, "/", totalPairs);

        if (failed > 0) {
            console.log("FAILED:", failed);
            revert("Post-registration verification failed");
        }

        console.log("");
        console.log("=== Registration Complete ===");
        console.log(
            "All", totalPairs, "old CEAs registered on new factory"
        );
        console.log(
            "Next: update Vault + UniversalGateway to point to",
            NEW_CEA_FACTORY
        );
    }
}
