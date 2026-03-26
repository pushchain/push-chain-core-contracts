// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";
import {CEA} from "../../src/cea/CEA.sol";
import {CEAProxy} from "../../src/cea/CEAProxy.sol";
import {CEAChainConfig} from "../config/CEAChainConfig.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

/**
 * @title DeployCEAFactoryScript
 * @notice Deployment script for CEAFactory on external EVM chains
 *
 * @dev Deploys:
 *  1. CEA implementation (logic contract)
 *  2. CEAProxy implementation (template for cloning)
 *  3. CEAFactory implementation
 *  4. ProxyAdmin (for managing upgrades)
 *  5. TransparentUpgradeableProxy wrapping CEAFactory
 *  6. Initializes CEAFactory with all required addresses
 *
 * CONFIGURATION:
 *  Chain-specific addresses are resolved from scripts/config/CEAChainConfig.sol
 *  Environment variables needed: KEY, RPC_URL, ETHERSCAN_API_KEY
 */
contract DeployCEAFactoryScript is Script, CEAChainConfig {
    function run() external {
        // Get chain ID and deployer info
        uint256 chainId = block.chainid;
        uint256 deployerKey = uint256(vm.envBytes32("KEY"));
        address deployer = vm.addr(deployerKey);

        // Load chain-specific config
        Config memory cfg = getConfig();
        address owner = cfg.owner;
        address vault = cfg.vault;
        address universalGateway = cfg.universalGateway;

        console.log("=== CEAFactory Deployment Configuration ===");
        console.log("Chain ID:", chainId);
        console.log("Deployer:", deployer);

        // Validate addresses
        require(owner != address(0), "Invalid owner address");
        require(vault != address(0), "Invalid vault address");
        require(universalGateway != address(0), "Invalid universal gateway address");

        console.log("Owner:", owner);
        console.log("Vault:", vault);
        console.log("Universal Gateway:", universalGateway);
        console.log("");

        vm.startBroadcast(deployerKey);

        // 1. Deploy CEA implementation (logic contract)
        CEA ceaImplementation = new CEA();
        console.log("[1/4] CEA Implementation:", address(ceaImplementation));

        // 2. Deploy CEAProxy implementation (template for cloning)
        CEAProxy ceaProxyImplementation = new CEAProxy();
        console.log("[2/4] CEAProxy Implementation:", address(ceaProxyImplementation));

        // 3. Deploy CEAFactory implementation
        CEAFactory ceaFactoryImplementation = new CEAFactory();
        console.log("[3/4] CEAFactory Implementation:", address(ceaFactoryImplementation));

        // 4. Deploy ProxyAdmin (manages upgrades)
        ProxyAdmin proxyAdmin = new ProxyAdmin(owner);
        console.log("[4/7] ProxyAdmin deployed:", address(proxyAdmin));

        // 5. Prepare initialization data for CEAFactory
        bytes memory initData = abi.encodeWithSelector(
            CEAFactory.initialize.selector,
            owner, // initialAdmin
            owner, // initialPauser (deployer is pauser)
            vault, // initialVault
            address(ceaProxyImplementation), // ceaProxyImplementation
            address(ceaImplementation), // ceaImplementation
            universalGateway // universalGateway
        );

        // 6. Deploy TransparentUpgradeableProxy wrapping CEAFactory
        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(ceaFactoryImplementation), address(proxyAdmin), initData);
        console.log("[5/7] CEAFactory Proxy (CANONICAL):", address(proxy));

        // 7. Wrap proxy in CEAFactory interface for verification
        CEAFactory ceaFactory = CEAFactory(address(proxy));

        // 8. Transfer ProxyAdmin ownership to the designated owner (if different from deployer)
        if (address(proxyAdmin.owner()) != owner) {
            proxyAdmin.transferOwnership(owner);
            console.log("[6/7] ProxyAdmin ownership transferred to:", owner);
        } else {
            console.log("[6/7] ProxyAdmin owner already set to:", owner);
        }

        vm.stopBroadcast();

        // 9. Post-deployment verification
        console.log("\n=== Post-Deployment Verification ===");

        bool isAdmin = ceaFactory.hasRole(ceaFactory.DEFAULT_ADMIN_ROLE(), owner);
        address verifiedVault = ceaFactory.VAULT();
        address verifiedCEAProxy = ceaFactory.CEA_PROXY_IMPLEMENTATION();
        address verifiedCEA = ceaFactory.CEA_IMPLEMENTATION();
        address verifiedGateway = ceaFactory.UNIVERSAL_GATEWAY();
        address verifiedProxyAdmin = address(proxyAdmin);

        console.log("Admin role granted to owner:", isAdmin ? "[OK]" : "[MISMATCH]");
        console.log("Vault:", verifiedVault, verifiedVault == vault ? "[OK]" : "[MISMATCH]");
        console.log(
            "CEA Proxy Impl:",
            verifiedCEAProxy,
            verifiedCEAProxy == address(ceaProxyImplementation) ? "[OK]" : "[MISMATCH]"
        );
        console.log("CEA Impl:", verifiedCEA, verifiedCEA == address(ceaImplementation) ? "[OK]" : "[MISMATCH]");
        console.log("Gateway:", verifiedGateway, verifiedGateway == universalGateway ? "[OK]" : "[MISMATCH]");
        console.log("ProxyAdmin:", verifiedProxyAdmin);

        require(isAdmin, "Owner not granted admin role");
        require(verifiedVault == vault, "Vault mismatch");
        require(verifiedCEAProxy == address(ceaProxyImplementation), "CEA Proxy Implementation mismatch");
        require(verifiedCEA == address(ceaImplementation), "CEA Implementation mismatch");
        require(verifiedGateway == universalGateway, "Universal Gateway mismatch");

        // 10. Generate JSON output for deployment tracking
        console.log("\n=== Deployment Addresses (JSON) ===");
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
                '",\n',
                '  "ceaProxyImplementation": "',
                vm.toString(address(ceaProxyImplementation)),
                '",\n',
                '  "ceaFactoryImplementation": "',
                vm.toString(address(ceaFactoryImplementation)),
                '",\n',
                '  "proxyAdmin": "',
                vm.toString(address(proxyAdmin)),
                '",\n',
                '  "ceaFactoryProxy": "',
                vm.toString(address(proxy)),
                '",\n',
                '  "owner": "',
                vm.toString(owner),
                '",\n',
                '  "vault": "',
                vm.toString(vault),
                '",\n',
                '  "universalGateway": "',
                vm.toString(universalGateway),
                '"\n',
                "}"
            )
        );
        console.log(json);

        // Write to file
        string memory filename = string(abi.encodePacked("deployments/", vm.toString(chainId), ".json"));
        vm.writeFile(filename, json);
        console.log("\nDeployment saved to:", filename);

        console.log("\n=== Deployment Complete ===");
        console.log("IMPORTANT: Use CEAFactory Proxy address for all interactions:", address(proxy));
        console.log("IMPORTANT: ProxyAdmin address (needed for upgrades):", address(proxyAdmin));
        console.log("ProxyAdmin owner (can perform upgrades):", owner);
    }
}

/*
 * ============================================================================
 * DEPLOYMENT COMMAND
 * ============================================================================
 *
 * Deploy to any EVM chain:
 *
 * forge script scripts/cea/deployCEAFactory.s.sol:DeployCEAFactoryScript \
 *   --rpc-url $RPC_URL \
 *   --private-key $KEY \
 *   --broadcast \
 *   -vvvv
 *
 * ============================================================================
 * VERIFICATION COMMANDS
 * ============================================================================
 *
 * After deployment, verify contracts on block explorer:
 *
 * 1. Verify CEA Implementation:
 * forge verify-contract \
 *   <CEA_IMPLEMENTATION_ADDRESS> \
 *   src/cea/CEA.sol:CEA \
 *   --chain-id <CHAIN_ID> \
 *   --etherscan-api-key $ETHERSCAN_API_KEY
 *
 * 2. Verify CEAProxy Implementation:
 * forge verify-contract \
 *   <CEA_PROXY_IMPLEMENTATION_ADDRESS> \
 *   src/cea/CEAProxy.sol:CEAProxy \
 *   --chain-id <CHAIN_ID> \
 *   --etherscan-api-key $ETHERSCAN_API_KEY
 *
 * 3. Verify CEAFactory Implementation:
 * forge verify-contract \
 *   <CEA_FACTORY_IMPLEMENTATION_ADDRESS> \
 *   src/cea/CEAFactory.sol:CEAFactory \
 *   --chain-id <CHAIN_ID> \
 *   --etherscan-api-key $ETHERSCAN_API_KEY
 *
 * 4. Verify ProxyAdmin:
 * forge verify-contract \
 *   <PROXY_ADMIN_ADDRESS> \
 *   lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol:ProxyAdmin \
 *   --chain-id <CHAIN_ID> \
 *   --etherscan-api-key $ETHERSCAN_API_KEY
 *
 * 5. Verify CEAFactory Proxy:
 * forge verify-contract \
 *   <CEA_FACTORY_PROXY_ADDRESS> \
 *   lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol:TransparentUpgradeableProxy \
 *   --chain-id <CHAIN_ID> \
 *   --etherscan-api-key $ETHERSCAN_API_KEY \
 *   --constructor-args $(cast abi-encode "constructor(address,address,bytes)" <CEA_FACTORY_IMPLEMENTATION_ADDRESS> <PROXY_ADMIN_ADDRESS> <INIT_DATA>)
 *
 * Note: Replace <ADDRESS> and <CHAIN_ID> with actual values from deployment output
 * Note: For constructor-args, use the addresses and init data from deployment logs
 * Note: ProxyAdmin address is saved in the deployment JSON output
 */
