// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

/**
 * @title VerifyCEAFactoryV2Script
 * @notice Read-only post-upgrade verification for CEAFactory V2.
 *
 * @dev Runs all checks from the upgrade workflow doc (Step 5).
 *      No transactions are broadcast — this is a pure verification script.
 *      Every check either prints [OK] or reverts with a descriptive error.
 *
 * CONFIGURATION:
 *  Set all addresses for the target chain.
 *  Environment variables needed: (none — read-only)
 */
contract VerifyCEAFactoryV2Script is Script {
    // ============================================================================
    // ADDRESSES — update per chain
    // ============================================================================

    address public CEA_FACTORY_PROXY_ADDRESS = 0x0000000000000000000000000000000000000000;
    address public PROXY_ADMIN_ADDRESS = 0x0000000000000000000000000000000000000000;
    address public DEPLOYER = 0x0000000000000000000000000000000000000000;

    // Expected values (from pre-upgrade baseline)
    address public EXPECTED_VAULT = 0x0000000000000000000000000000000000000000;
    address public EXPECTED_GATEWAY = 0x0000000000000000000000000000000000000000;
    address public EXPECTED_CEA_PROXY_IMPL = 0x0000000000000000000000000000000000000000;
    address public EXPECTED_CEA_IMPL = 0x0000000000000000000000000000000000000000;

    function run() external view {
        require(CEA_FACTORY_PROXY_ADDRESS != address(0), "Set CEA_FACTORY_PROXY_ADDRESS");
        require(PROXY_ADMIN_ADDRESS != address(0), "Set PROXY_ADMIN_ADDRESS");
        require(DEPLOYER != address(0), "Set DEPLOYER");

        CEAFactory factory = CEAFactory(CEA_FACTORY_PROXY_ADDRESS);

        console.log("=== CEAFactory V2 Post-Upgrade Verification ===");
        console.log("Chain ID:", block.chainid);
        console.log("Proxy:", CEA_FACTORY_PROXY_ADDRESS);
        console.log("ProxyAdmin:", PROXY_ADMIN_ADDRESS);
        console.log("Deployer:", DEPLOYER);

        // =====================================================================
        // 5.1 — State preservation
        // =====================================================================

        console.log("\n--- 5.1 State preservation ---");

        if (EXPECTED_VAULT != address(0)) {
            require(factory.VAULT() == EXPECTED_VAULT, "VAULT mismatch");
            console.log("VAULT:", factory.VAULT(), "[OK]");
        } else {
            console.log("VAULT:", factory.VAULT(), "[SKIPPED - no expected value set]");
        }

        if (EXPECTED_GATEWAY != address(0)) {
            require(factory.UNIVERSAL_GATEWAY() == EXPECTED_GATEWAY, "UNIVERSAL_GATEWAY mismatch");
            console.log("UNIVERSAL_GATEWAY:", factory.UNIVERSAL_GATEWAY(), "[OK]");
        } else {
            console.log("UNIVERSAL_GATEWAY:", factory.UNIVERSAL_GATEWAY(), "[SKIPPED]");
        }

        if (EXPECTED_CEA_PROXY_IMPL != address(0)) {
            require(
                factory.CEA_PROXY_IMPLEMENTATION() == EXPECTED_CEA_PROXY_IMPL,
                "CEA_PROXY_IMPLEMENTATION mismatch"
            );
            console.log("CEA_PROXY_IMPL:", factory.CEA_PROXY_IMPLEMENTATION(), "[OK]");
        } else {
            console.log("CEA_PROXY_IMPL:", factory.CEA_PROXY_IMPLEMENTATION(), "[SKIPPED]");
        }

        console.log("paused:", factory.paused());
        require(!factory.paused(), "Factory is paused unexpectedly");
        console.log("paused: false [OK]");

        // =====================================================================
        // 5.2 — CEA_IMPLEMENTATION updated to post-audit
        // =====================================================================

        console.log("\n--- 5.2 CEA_IMPLEMENTATION ---");

        if (EXPECTED_CEA_IMPL != address(0)) {
            require(factory.CEA_IMPLEMENTATION() == EXPECTED_CEA_IMPL, "CEA_IMPLEMENTATION mismatch");
            console.log("CEA_IMPL:", factory.CEA_IMPLEMENTATION(), "[OK]");
        } else {
            console.log("CEA_IMPL:", factory.CEA_IMPLEMENTATION(), "[SKIPPED - set EXPECTED_CEA_IMPL]");
        }

        // =====================================================================
        // 5.3 — AccessControlDefaultAdminRules initialized
        // =====================================================================

        console.log("\n--- 5.3 DefaultAdminRules ---");

        require(factory.defaultAdmin() == DEPLOYER, "defaultAdmin != DEPLOYER");
        console.log("defaultAdmin():", factory.defaultAdmin(), "[OK]");

        require(factory.owner() == DEPLOYER, "owner != DEPLOYER");
        console.log("owner():", factory.owner(), "[OK]");

        require(factory.defaultAdminDelay() == 1 minutes, "defaultAdminDelay != 1 minute");
        console.log("defaultAdminDelay: 1 minute [OK]");

        // =====================================================================
        // 5.4 — Deployer has all 5 roles
        // =====================================================================

        console.log("\n--- 5.4 Deployer roles ---");

        bytes32 defaultAdminRole = factory.DEFAULT_ADMIN_ROLE();
        bytes32 roleManagerRole = factory.ROLE_MANAGER_ROLE();
        bytes32 ceaAdminRole = factory.CEA_ADMIN_ROLE();
        bytes32 operatorRole = factory.OPERATOR_ROLE();
        bytes32 pauserRole = factory.PAUSER_ROLE();

        require(factory.hasRole(defaultAdminRole, DEPLOYER), "Missing DEFAULT_ADMIN_ROLE");
        console.log("DEFAULT_ADMIN_ROLE: [OK]");

        require(factory.hasRole(roleManagerRole, DEPLOYER), "Missing ROLE_MANAGER_ROLE");
        console.log("ROLE_MANAGER_ROLE: [OK]");

        require(factory.hasRole(ceaAdminRole, DEPLOYER), "Missing CEA_ADMIN_ROLE");
        console.log("CEA_ADMIN_ROLE: [OK]");

        require(factory.hasRole(operatorRole, DEPLOYER), "Missing OPERATOR_ROLE");
        console.log("OPERATOR_ROLE: [OK]");

        require(factory.hasRole(pauserRole, DEPLOYER), "Missing PAUSER_ROLE");
        console.log("PAUSER_ROLE: [OK]");

        // =====================================================================
        // 5.5 — Role admin hierarchy
        // =====================================================================

        console.log("\n--- 5.5 Role admin hierarchy ---");

        require(
            factory.getRoleAdmin(roleManagerRole) == defaultAdminRole,
            "ROLE_MANAGER admin != DEFAULT_ADMIN"
        );
        console.log("ROLE_MANAGER admin -> DEFAULT_ADMIN: [OK]");

        require(
            factory.getRoleAdmin(ceaAdminRole) == roleManagerRole,
            "CEA_ADMIN admin != ROLE_MANAGER"
        );
        console.log("CEA_ADMIN admin -> ROLE_MANAGER: [OK]");

        require(
            factory.getRoleAdmin(operatorRole) == roleManagerRole,
            "OPERATOR admin != ROLE_MANAGER"
        );
        console.log("OPERATOR admin -> ROLE_MANAGER: [OK]");

        require(
            factory.getRoleAdmin(pauserRole) == roleManagerRole,
            "PAUSER admin != ROLE_MANAGER"
        );
        console.log("PAUSER admin -> ROLE_MANAGER: [OK]");

        // =====================================================================
        // 5.6 — New function selectors exist (confirms V2 bytecode)
        // =====================================================================

        console.log("\n--- 5.6 New selectors (V2 bytecode active) ---");

        console.log("ROLE_MANAGER_ROLE:", vm.toString(roleManagerRole));
        console.log("CEA_ADMIN_ROLE:", vm.toString(ceaAdminRole));
        console.log("OPERATOR_ROLE:", vm.toString(operatorRole));
        console.log("New role constants accessible: [OK]");

        // =====================================================================
        // 5.7 — ProxyAdmin ownership
        // =====================================================================

        console.log("\n--- 5.7 ProxyAdmin ownership ---");

        ProxyAdmin proxyAdmin = ProxyAdmin(PROXY_ADMIN_ADDRESS);
        require(proxyAdmin.owner() == DEPLOYER, "ProxyAdmin owner != DEPLOYER");
        console.log("ProxyAdmin owner:", proxyAdmin.owner(), "[OK]");

        // =====================================================================
        // Summary
        // =====================================================================

        console.log("\n========================================");
        console.log("  ALL CHECKS PASSED");
        console.log("========================================");
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
 *   scripts/cea/verifyCEAFactoryV2.s.sol:VerifyCEAFactoryV2Script \
 *   --rpc-url $BSC_TESTNET_RPC_URL \
 *   -vvvv
 *
 * No --broadcast needed — this script is read-only.
 *
 * ============================================================================
 * CONFIGURATION
 * ============================================================================
 *
 * Update the state variables at the top of the contract for your chain:
 *
 * BSC Testnet:
 *   CEA_FACTORY_PROXY_ADDRESS = 0xe2182dae2dc11cBF6AA6c8B1a7f9c8315A6B0719
 *   PROXY_ADMIN_ADDRESS       = 0xf33CBb6a1c1D511dF40764063a11978D640C41A7
 *   DEPLOYER                  = 0x6dD2cA20ec82E819541EB43e1925DbE46a441970
 *   EXPECTED_VAULT            = 0xE52AC4f8DD3e0263bDF748F3390cdFA1f02be881
 *   EXPECTED_GATEWAY          = 0x44aFFC61983F4348DdddB886349eb992C061EaC0
 *   EXPECTED_CEA_PROXY_IMPL   = 0xBDF06996BA23AE797a4aA9C8C5994D313D763a7c
 *   EXPECTED_CEA_IMPL         = 0x8FAB1Da91Bd45F4DaF3D50C47A38b49bE9afEff7  (post-audit)
 */
