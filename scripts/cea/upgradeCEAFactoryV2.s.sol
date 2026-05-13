// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title UpgradeCEAFactoryV2Script
 * @notice Deploys a new CEAFactory implementation and upgrades the proxy.
 *
 * @dev This is Step 1 of a two-step upgrade:
 *      Step 1 (this script):  Deploy new implementation + upgrade proxy (no init call).
 *      Step 2 (separate script): Call initializeV2() from the deployer.
 *
 *      We intentionally do NOT use upgradeAndCall here. The upgrade and
 *      initialization are separated so that each transaction can be verified
 *      independently before proceeding.
 *
 * CONFIGURATION:
 *  Set PROXY_ADMIN_ADDRESS and CEA_FACTORY_PROXY_ADDRESS for the target chain.
 *  Environment variables needed: KEY
 */
contract UpgradeCEAFactoryV2Script is Script {
    // ============================================================================
    // UPGRADE PARAMETERS — update per chain
    // ============================================================================

    // ProxyAdmin that owns the CEAFactory proxy
    address public PROXY_ADMIN_ADDRESS = 0x0000000000000000000000000000000000000000;

    // CEAFactory TransparentUpgradeableProxy
    address public CEA_FACTORY_PROXY_ADDRESS = 0x0000000000000000000000000000000000000000;

    function run() external {
        uint256 deployerKey = uint256(vm.envBytes32("KEY"));
        address deployer = vm.addr(deployerKey);
        uint256 chainId = block.chainid;

        // ---- validate config ------------------------------------------------

        require(PROXY_ADMIN_ADDRESS != address(0), "Set PROXY_ADMIN_ADDRESS");
        require(CEA_FACTORY_PROXY_ADDRESS != address(0), "Set CEA_FACTORY_PROXY_ADDRESS");

        ProxyAdmin proxyAdmin = ProxyAdmin(PROXY_ADMIN_ADDRESS);
        require(proxyAdmin.owner() == deployer, "Deployer is not ProxyAdmin owner");

        console.log("=== CEAFactory V2 Upgrade ===");
        console.log("Chain ID:", chainId);
        console.log("Deployer:", deployer);
        console.log("ProxyAdmin:", PROXY_ADMIN_ADDRESS);
        console.log("CEAFactory proxy:", CEA_FACTORY_PROXY_ADDRESS);

        // ---- snapshot pre-upgrade state -------------------------------------

        CEAFactory factory = CEAFactory(CEA_FACTORY_PROXY_ADDRESS);

        address preVault = factory.VAULT();
        address preGateway = factory.UNIVERSAL_GATEWAY();
        address preProxyImpl = factory.CEA_PROXY_IMPLEMENTATION();
        address preCeaImpl = factory.CEA_IMPLEMENTATION();
        address preMigration = factory.CEA_MIGRATION_CONTRACT();
        bool prePaused = factory.paused();

        console.log("\n--- Pre-upgrade state ---");
        console.log("VAULT:", preVault);
        console.log("UNIVERSAL_GATEWAY:", preGateway);
        console.log("CEA_PROXY_IMPL:", preProxyImpl);
        console.log("CEA_IMPL:", preCeaImpl);
        console.log("CEA_MIGRATION:", preMigration);
        console.log("paused:", prePaused);

        // ---- deploy + upgrade -----------------------------------------------

        vm.startBroadcast(deployerKey);

        CEAFactory newImpl = new CEAFactory();
        console.log("\n[1/2] New implementation deployed:", address(newImpl));

        ITransparentUpgradeableProxy proxy =
            ITransparentUpgradeableProxy(payable(CEA_FACTORY_PROXY_ADDRESS));
        proxyAdmin.upgradeAndCall(proxy, address(newImpl), "");
        console.log("[2/2] Proxy upgraded (no init call)");

        vm.stopBroadcast();

        // ---- post-upgrade state check ---------------------------------------

        console.log("\n--- Post-upgrade state verification ---");

        require(factory.VAULT() == preVault, "VAULT changed");
        console.log("VAULT:", factory.VAULT(), "[OK]");

        require(factory.UNIVERSAL_GATEWAY() == preGateway, "UNIVERSAL_GATEWAY changed");
        console.log("UNIVERSAL_GATEWAY:", factory.UNIVERSAL_GATEWAY(), "[OK]");

        require(factory.CEA_PROXY_IMPLEMENTATION() == preProxyImpl, "CEA_PROXY_IMPLEMENTATION changed");
        console.log("CEA_PROXY_IMPL:", factory.CEA_PROXY_IMPLEMENTATION(), "[OK]");

        require(factory.CEA_IMPLEMENTATION() == preCeaImpl, "CEA_IMPLEMENTATION changed");
        console.log("CEA_IMPL:", factory.CEA_IMPLEMENTATION(), "[OK]");

        require(factory.CEA_MIGRATION_CONTRACT() == preMigration, "CEA_MIGRATION_CONTRACT changed");
        console.log("CEA_MIGRATION:", factory.CEA_MIGRATION_CONTRACT(), "[OK]");

        require(factory.paused() == prePaused, "paused state changed");
        console.log("paused:", factory.paused(), "[OK]");

        require(
            factory.hasRole(factory.DEFAULT_ADMIN_ROLE(), deployer),
            "Deployer lost DEFAULT_ADMIN_ROLE"
        );
        console.log("DEFAULT_ADMIN_ROLE:", "[OK]");

        // ---- output ---------------------------------------------------------

        string memory json = string(
            abi.encodePacked(
                "{\n",
                '  "chainId": ', vm.toString(chainId), ",\n",
                '  "deployer": "', vm.toString(deployer), '",\n',
                '  "proxyAdmin": "', vm.toString(PROXY_ADMIN_ADDRESS), '",\n',
                '  "ceaFactoryProxy": "', vm.toString(CEA_FACTORY_PROXY_ADDRESS), '",\n',
                '  "newImplementation": "', vm.toString(address(newImpl)), '",\n',
                '  "step": "upgrade-only (initializeV2 pending)"\n',
                "}"
            )
        );
        console.log("\n=== Deployment JSON ===");
        console.log(json);

        string memory filename = string(
            abi.encodePacked("deployments/", vm.toString(chainId), "_ceaFactory_upgrade.json")
        );
        vm.writeFile(filename, json);
        console.log("Saved to:", filename);

        console.log("\n=== NEXT STEP ===");
        console.log("Run InitializeCEAFactoryV2Script to call initializeV2()");
    }
}

/*
 * ============================================================================
 * USAGE
 * ============================================================================
 *
 * BSC Testnet:
 *
 * source .env && forge script \
 *   scripts/cea/upgradeCEAFactoryV2.s.sol:UpgradeCEAFactoryV2Script \
 *   --rpc-url $BSC_TESTNET_RPC_URL \
 *   --broadcast \
 *   -vvvv
 *
 * (Private key is loaded from KEY env var inside the script.)
 *
 * ============================================================================
 * VERIFY NEW IMPLEMENTATION
 * ============================================================================
 *
 * forge verify-contract \
 *   <NEW_IMPLEMENTATION_ADDRESS> \
 *   src/cea/CEAFactory.sol:CEAFactory \
 *   --chain-id 97 \
 *   --etherscan-api-key $BSC_SCAN_API_KEY
 *
 * ============================================================================
 * IMPORTANT
 * ============================================================================
 *
 * This script does NOT call initializeV2. After this script succeeds:
 *  1. Verify the new implementation on the block explorer.
 *  2. Confirm state preservation via the console output.
 *  3. Run InitializeCEAFactoryV2Script as the next step.
 */
