// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";

/**
 * @title VerifyAllOldCEAsScript
 * @notice Reads migrations/<chainId>_old_ceas.json, verifies every
 *         pair against the CEAFactory on-chain in a single run.
 *
 * USAGE:
 *   forge script scripts/cea/verifyAllOldCEAs.s.sol:VerifyAllOldCEAsScript \
 *     --rpc-url "$BSC_TESTNET_RPC_URL" -vvvv
 *
 * CONFIGURATION:
 *   Update CEA_FACTORY below per chain.
 */
contract VerifyAllOldCEAsScript is Script {
    address public CEA_FACTORY =
        0x7e8CeeDA043ED1460540616103dD57581a66C856;

    function run() external view {
        uint256 chainId = block.chainid;

        string memory jsonPath = string(
            abi.encodePacked(
                "migrations/",
                vm.toString(chainId),
                "_old_ceas.json"
            )
        );

        console.log("=== Verify All Old CEAs ===");
        console.log("Chain ID:", chainId);
        console.log("CEAFactory:", CEA_FACTORY);
        console.log("JSON file:", jsonPath);

        string memory json = vm.readFile(jsonPath);

        uint256 totalPairs = abi.decode(
            vm.parseJson(json, ".uniquePairs"),
            (uint256)
        );

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
            "Array length mismatch"
        );
        require(
            pushAccounts.length == totalPairs,
            "Pair count mismatch"
        );

        console.log("Total pairs:", totalPairs);
        console.log("");

        CEAFactory factory = CEAFactory(CEA_FACTORY);

        uint256 matched = 0;
        uint256 mismatched = 0;
        uint256 notFound = 0;

        for (uint256 i = 0; i < totalPairs; i++) {
            address expectedPA = pushAccounts[i];
            address expectedCEA = ceaAddresses[i];

            address actualCEA = factory.pushAccountToCEA(
                expectedPA
            );

            if (actualCEA == address(0)) {
                notFound++;
                console.log("NOT FOUND at index", i);
                console.log("  pushAccount:", expectedPA);
                console.log("  expectedCEA:", expectedCEA);
                continue;
            }

            if (actualCEA != expectedCEA) {
                mismatched++;
                console.log("CEA MISMATCH at index", i);
                console.log("  pushAccount:", expectedPA);
                console.log("  expectedCEA:", expectedCEA);
                console.log("  actualCEA:  ", actualCEA);
                continue;
            }

            address reversePA = factory.ceaToPushAccount(
                actualCEA
            );

            if (reversePA != expectedPA) {
                mismatched++;
                console.log(
                    "REVERSE MISMATCH at index", i
                );
                console.log("  pushAccount:", expectedPA);
                console.log("  cea:        ", actualCEA);
                console.log("  reversePA:  ", reversePA);
                continue;
            }

            matched++;
        }

        console.log("");
        console.log("========= RESULTS =========");
        console.log("Total:     ", totalPairs);
        console.log("Matched:   ", matched);
        console.log("Mismatched:", mismatched);
        console.log("Not Found: ", notFound);

        if (mismatched > 0 || notFound > 0) {
            revert("Verification failed");
        }

        console.log("All pairs verified successfully.");
    }
}
