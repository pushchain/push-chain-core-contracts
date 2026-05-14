// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";
import {CEA} from "../../src/cea/CEA.sol";
import {CEAProxy} from "../../src/cea/CEAProxy.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title DeployCEAFactoryScript
 * @notice Deployment script for CEAFactory on external EVM chains
 *
 * @dev Deploys:
 *  1. CEA implementation (logic contract)
 *  2. CEAProxy implementation (template for cloning)
 *  3. CEAFactory implementation
 *  4. TransparentUpgradeableProxy wrapping CEAFactory (auto-creates ProxyAdmin owned by deployer)
 *  5. Initializes CEAFactory with all required addresses
 *
 * NOTE: OZ5 TransparentUpgradeableProxy auto-creates a ProxyAdmin internally.
 * The second constructor arg is the initial OWNER of that ProxyAdmin, not a ProxyAdmin address.
 * The auto-created ProxyAdmin address can be read from the ERC1967 admin slot after deployment.
 *
 * CONFIGURATION:
 *  Update the state variables below with your deployment parameters.
 *  Environment variables needed: KEY
 */
contract DeployCEAFactoryScript is Script {
    // ============================================================================
    // DEPLOYMENT PARAMETERS — update per chain
    // ============================================================================

    // Owner/admin of the CEAFactory (receives all roles, owns ProxyAdmin)
    address public OWNER_ADDRESS = 0xe520d4A985A2356Fa615935a822Ce4eFAcA24aB6;

    // Vault contract address on this chain
    address public VAULT_ADDRESS = 0xD019Eb12D0d6eF8D299661f22B4B7d262eD4b965;

    // UniversalGateway contract address on this chain
    address public UNIVERSAL_GATEWAY_ADDRESS = 0x05bD7a3D18324c1F7e216f7fBF2b15985aE5281A;

    function run() external {
        uint256 chainId = block.chainid;
        uint256 deployerKey = uint256(vm.envBytes32("KEY"));
        address deployer = vm.addr(deployerKey);

        console.log("=== CEAFactory Deployment Configuration ===");
        console.log("Chain ID:", chainId);
        console.log("Deployer:", deployer);

        address owner = OWNER_ADDRESS;
        address vault = VAULT_ADDRESS;
        address universalGateway = UNIVERSAL_GATEWAY_ADDRESS;

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
        console.log("[1/5] CEA Implementation:", address(ceaImplementation));

        // 2. Deploy CEAProxy implementation (template for cloning)
        CEAProxy ceaProxyImplementation = new CEAProxy();
        console.log("[2/5] CEAProxy Implementation:", address(ceaProxyImplementation));

        // 3. Deploy CEAFactory implementation
        CEAFactory ceaFactoryImplementation = new CEAFactory();
        console.log("[3/5] CEAFactory Implementation:", address(ceaFactoryImplementation));

        // 4. Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            CEAFactory.initialize.selector,
            owner, // _admin (gets DEFAULT_ADMIN + ROLE_MANAGER + CEA_ADMIN + OPERATOR)
            owner, // _pauser (gets PAUSER_ROLE)
            vault,
            address(ceaProxyImplementation),
            address(ceaImplementation),
            universalGateway
        );

        // 5. Deploy TransparentUpgradeableProxy wrapping CEAFactory
        //    OZ5: second arg = initial owner of the auto-created ProxyAdmin
        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(ceaFactoryImplementation), owner, initData);
        console.log("[4/5] CEAFactory Proxy:", address(proxy));

        // Read auto-created ProxyAdmin from ERC1967 admin slot
        bytes32 adminSlot = vm.load(address(proxy), 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103);
        address proxyAdmin = address(uint160(uint256(adminSlot)));
        console.log("[5/5] ProxyAdmin (auto-created):", proxyAdmin);

        vm.stopBroadcast();

        // 6. Post-deployment verification
        console.log("\n=== Post-Deployment Verification ===");

        CEAFactory ceaFactory = CEAFactory(address(proxy));

        bool isAdmin = ceaFactory.hasRole(ceaFactory.DEFAULT_ADMIN_ROLE(), owner);
        bool isRoleManager = ceaFactory.hasRole(ceaFactory.ROLE_MANAGER_ROLE(), owner);
        bool isCeaAdmin = ceaFactory.hasRole(ceaFactory.CEA_ADMIN_ROLE(), owner);
        bool isOperator = ceaFactory.hasRole(ceaFactory.OPERATOR_ROLE(), owner);
        bool isPauser = ceaFactory.hasRole(ceaFactory.PAUSER_ROLE(), owner);
        address verifiedVault = ceaFactory.VAULT();
        address verifiedCEAProxy = ceaFactory.CEA_PROXY_IMPLEMENTATION();
        address verifiedCEA = ceaFactory.CEA_IMPLEMENTATION();
        address verifiedGateway = ceaFactory.UNIVERSAL_GATEWAY();

        console.log("DEFAULT_ADMIN_ROLE:", isAdmin ? "[OK]" : "[FAIL]");
        console.log("ROLE_MANAGER_ROLE:", isRoleManager ? "[OK]" : "[FAIL]");
        console.log("CEA_ADMIN_ROLE:", isCeaAdmin ? "[OK]" : "[FAIL]");
        console.log("OPERATOR_ROLE:", isOperator ? "[OK]" : "[FAIL]");
        console.log("PAUSER_ROLE:", isPauser ? "[OK]" : "[FAIL]");
        console.log("Vault:", verifiedVault, verifiedVault == vault ? "[OK]" : "[FAIL]");
        console.log(
            "CEA Proxy Impl:",
            verifiedCEAProxy,
            verifiedCEAProxy == address(ceaProxyImplementation) ? "[OK]" : "[FAIL]"
        );
        console.log("CEA Impl:", verifiedCEA, verifiedCEA == address(ceaImplementation) ? "[OK]" : "[FAIL]");
        console.log("Gateway:", verifiedGateway, verifiedGateway == universalGateway ? "[OK]" : "[FAIL]");
        console.log("defaultAdmin():", ceaFactory.defaultAdmin());
        console.log("owner():", ceaFactory.owner());
        console.log("defaultAdminDelay():", ceaFactory.defaultAdminDelay());

        require(isAdmin, "Missing DEFAULT_ADMIN_ROLE");
        require(isRoleManager, "Missing ROLE_MANAGER_ROLE");
        require(isCeaAdmin, "Missing CEA_ADMIN_ROLE");
        require(isOperator, "Missing OPERATOR_ROLE");
        require(isPauser, "Missing PAUSER_ROLE");
        require(verifiedVault == vault, "Vault mismatch");
        require(verifiedCEAProxy == address(ceaProxyImplementation), "CEA Proxy mismatch");
        require(verifiedCEA == address(ceaImplementation), "CEA Impl mismatch");
        require(verifiedGateway == universalGateway, "Gateway mismatch");

        // 7. JSON output
        string memory json = string(
            abi.encodePacked(
                "{\n",
                '  "chainId": ', vm.toString(chainId), ",\n",
                '  "deployer": "', vm.toString(deployer), '",\n',
                '  "ceaImplementation": "', vm.toString(address(ceaImplementation)), '",\n',
                '  "ceaProxyImplementation": "', vm.toString(address(ceaProxyImplementation)), '",\n',
                '  "ceaFactoryImplementation": "', vm.toString(address(ceaFactoryImplementation)), '",\n',
                '  "proxyAdmin": "', vm.toString(proxyAdmin), '",\n',
                '  "ceaFactoryProxy": "', vm.toString(address(proxy)), '",\n',
                '  "owner": "', vm.toString(owner), '",\n',
                '  "vault": "', vm.toString(vault), '",\n',
                '  "universalGateway": "', vm.toString(universalGateway), '"\n',
                "}"
            )
        );
        console.log("\n=== Deployment JSON ===");
        console.log(json);

        string memory filename = string(abi.encodePacked("deployments/", vm.toString(chainId), ".json"));
        vm.writeFile(filename, json);
        console.log("\nSaved to:", filename);

        console.log("\n=== Deployment Complete ===");
        console.log("CEAFactory Proxy (use this for all interactions):", address(proxy));
        console.log("ProxyAdmin (auto-created, for upgrades):", proxyAdmin);
        console.log("ProxyAdmin owner:", owner);
    }
}

/*
 * ============================================================================
 * DEPLOYMENT COMMAND
 * ============================================================================
 *
 * Deploy to any EVM chain:
 *
 * source .env && KEY=$KEY_BSC forge script \
 *   scripts/cea/deployCEAFactory.s.sol:DeployCEAFactoryScript \
 *   --rpc-url $BSC_TESTNET_RPC_URL \
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
 * ============================================================================
 * FINDING THE PROXYADMIN ADDRESS
 * ============================================================================
 *
 * OZ5 TransparentUpgradeableProxy auto-creates a ProxyAdmin. To find it:
 *
 * cast storage <PROXY_ADDRESS> \
 *   0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 \
 *   --rpc-url $RPC_URL
 *
 * The returned address (strip leading zeros) is the ProxyAdmin.
 * Its owner should be the OWNER_ADDRESS from this script.
 *
 * cast call <PROXY_ADMIN_ADDRESS> "owner()(address)" --rpc-url $RPC_URL
 */
