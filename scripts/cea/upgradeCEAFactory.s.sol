// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy, ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title UpgradeCEAFactoryScript
 * @notice Upgrade script for CEAFactory on external EVM chains
 *
 * @dev Upgrades CEAFactory implementation through ProxyAdmin
 *
 * IMPORTANT: This script assumes the CEAFactory was deployed using TransparentUpgradeableProxy.
 * If deployed with plain ERC1967Proxy, the deployment needs to be redone with
 * TransparentUpgradeableProxy for upgrades to work.
 *
 * CONFIGURATION:
 *  Update the state variables below with your upgrade parameters.
 *  Environment variables needed: KEY, RPC_URL, ETHERSCAN_API_KEY
 */
contract UpgradeCEAFactoryScript is Script {
    // ============================================================================
    // UPGRADE PARAMETERS - Pre-Upgrade Checklist 
    // ============================================================================

    // Address of the ProxyAdmin contract (manages upgrades)
    // NOTE: This is created automatically when deploying with TransparentUpgradeableProxy
    address public PROXY_ADMIN_ADDRESS = 0x0000000000000000000000000000000000000000;

    // Address of the CEAFactory proxy to upgrade
    address public CEA_FACTORY_PROXY_ADDRESS = 0x0000000000000000000000000000000000000000;


    function run() external {
        vm.startBroadcast();

        console.log("=== CEAFactory Upgrade Configuration ===");
        console.log("Proxy Admin:", PROXY_ADMIN_ADDRESS);
        console.log("CEAFactory Proxy:", CEA_FACTORY_PROXY_ADDRESS);

        // Validate addresses
        require(PROXY_ADMIN_ADDRESS != address(0), "Invalid ProxyAdmin address");
        require(CEA_FACTORY_PROXY_ADDRESS != address(0), "Invalid CEAFactory proxy address");

        // 1. Deploy new implementation
        CEAFactory newImplementation = new CEAFactory();
        console.log("New CEAFactory implementation deployed at:", address(newImplementation));

        // 2. Connect to deployed ProxyAdmin
        ProxyAdmin proxyAdmin = ProxyAdmin(PROXY_ADMIN_ADDRESS);
        console.log("Connected to ProxyAdmin");

        // 3. Upgrade the proxy
        ITransparentUpgradeableProxy proxy = ITransparentUpgradeableProxy(payable(CEA_FACTORY_PROXY_ADDRESS));

        proxyAdmin.upgradeAndCall(proxy, address(newImplementation), "");
        console.log("Proxy upgraded successfully");

        // 4. Post-upgrade verification
        console.log("\n=== Post-Upgrade Verification ===");

        // Note: We cannot call proxy functions directly from here because ProxyAdmin intercepts calls
        // Verification should be done from a different account or through the owner account
        console.log("IMPORTANT: Verify the upgrade from the owner account (not ProxyAdmin)");
        console.log("Owner should call CEAFactory(proxy).owner() to verify upgrade succeeded");

        console.log("\n=== Upgrade Complete ===");

        vm.stopBroadcast();
    }
}

/*
 * ============================================================================
 * UPGRADE COMMAND
 * ============================================================================
 *
 * Upgrade CEAFactory on any EVM chain:
 *
 * forge script scripts/cea/upgradeCEAFactory.s.sol:UpgradeCEAFactoryScript \
 *   --rpc-url $RPC_URL \
 *   --private-key $KEY \
 *   --broadcast \
 *   -vvvv
 *
 * ============================================================================
 * POST-UPGRADE VERIFICATION
 * ============================================================================
 *
 * After upgrade, verify from a non-admin account:
 *
 * cast call <CEA_FACTORY_PROXY_ADDRESS> "owner()" --rpc-url $RPC_URL
 * cast call <CEA_FACTORY_PROXY_ADDRESS> "VAULT()" --rpc-url $RPC_URL
 * cast call <CEA_FACTORY_PROXY_ADDRESS> "CEA_IMPLEMENTATION()" --rpc-url $RPC_URL
 *
 * ============================================================================
 * VERIFICATION COMMANDS
 * ============================================================================
 *
 * Verify the new implementation on block explorer:
 *
 * forge verify-contract \
 *   <NEW_IMPLEMENTATION_ADDRESS> \
 *   src/cea/CEAFactory.sol:CEAFactory \
 *   --chain-id <CHAIN_ID> \
 *   --etherscan-api-key $ETHERSCAN_API_KEY
 *
 * ============================================================================
 * IMPORTANT NOTES
 * ============================================================================
 *
 * 1. ProxyAdmin Ownership:
 *    - The ProxyAdmin owner must be the broadcaster of this script
 *    - Or you must have access to the ProxyAdmin owner's private key
 *
 * 2. Finding ProxyAdmin Address:
 *    - If you deployed with TransparentUpgradeableProxy, ProxyAdmin was auto-created
 *    - Get it via: cast call <PROXY> "admin()" --rpc-url $RPC_URL
 *    - Or check deployment logs/JSON output
 *
 * 3. Storage Layout:
 *    - NEVER change the order of existing state variables
 *    - NEVER change the type of existing state variables
 *    - Only ADD new variables at the end
 *    - See: https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable
 *
 * 4. Initializers:
 *    - DO NOT add new `initialize()` calls without disabling them
 *    - Use `reinitializer(2)` if you need to run initialization logic in upgrade
 *
 * ============================================================================
 * TROUBLESHOOTING
 * ============================================================================
 *
 * "Ownable: caller is not the owner" error:
 * - Check that the broadcaster is the ProxyAdmin owner
 * - ProxyAdmin owner might be different from CEAFactory owner
 *
 * "TransparentUpgradeableProxy: admin cannot fallback to proxy target":
 * - You're trying to call the proxy from the ProxyAdmin address
 * - Use a different account to read proxy state
 *
 * Cannot find ProxyAdmin address:
 * - CEAFactory might have been deployed with ERC1967Proxy (not upgradeable)
 * - Check deployment script and logs
 * - May need to redeploy with TransparentUpgradeableProxy
 */
