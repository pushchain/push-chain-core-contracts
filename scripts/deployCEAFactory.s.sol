// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CEAFactory} from "../src/CEA/CEAFactory.sol";
import {CEA} from "../src/CEA/CEA.sol";
import {CEAProxy} from "../src/CEA/CEAProxy.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title DeployCEAFactoryScript
 * @notice Deployment script for CEAFactory on external EVM chains
 *
 * @dev Deploys:
 *  1. CEA implementation (logic contract)
 *  2. CEAProxy implementation (template for cloning)
 *  3. CEAFactory implementation
 *  4. ERC1967Proxy wrapping CEAFactory
 *  5. Initializes CEAFactory with all required addresses
 *
 * Required Environment Variables:
 *  - OWNER_ADDRESS: Address that will own the CEAFactory
 *  - VAULT_ADDRESS: Address of the Vault contract on this chain
 *  - UNIVERSAL_GATEWAY_ADDRESS: Address of the UniversalGateway on this chain
 */
contract DeployCEAFactoryScript is Script {
    function run() external {
        // Read deployment parameters from environment variables
        address owner = vm.envAddress("OWNER_ADDRESS");
        address vault = vm.envAddress("VAULT_ADDRESS");
        address universalGateway = vm.envAddress("UNIVERSAL_GATEWAY_ADDRESS");

        // Validate addresses
        require(owner != address(0), "Invalid owner address");
        require(vault != address(0), "Invalid vault address");
        require(universalGateway != address(0), "Invalid universal gateway address");

        console.log("=== Starting CEAFactory Deployment ===");
        console.log("Owner:", owner);
        console.log("Vault:", vault);
        console.log("Universal Gateway:", universalGateway);

        vm.startBroadcast();

        // 1. Deploy CEA implementation (logic contract)
        CEA ceaImplementation = new CEA();
        console.log("CEA Implementation deployed at:", address(ceaImplementation));

        // 2. Deploy CEAProxy implementation (template for cloning)
        CEAProxy ceaProxyImplementation = new CEAProxy();
        console.log("CEAProxy Implementation deployed at:", address(ceaProxyImplementation));

        // 3. Deploy CEAFactory implementation
        CEAFactory ceaFactoryImplementation = new CEAFactory();
        console.log("CEAFactory Implementation deployed at:", address(ceaFactoryImplementation));

        // 4. Prepare initialization data for CEAFactory
        bytes memory initData = abi.encodeWithSelector(
            CEAFactory.initialize.selector,
            owner,                              // initialOwner
            vault,                              // initialVault
            address(ceaProxyImplementation),    // ceaProxyImplementation
            address(ceaImplementation),         // ceaImplementation
            universalGateway                    // universalGateway
        );

        // 5. Deploy ERC1967Proxy wrapping CEAFactory
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(ceaFactoryImplementation),
            initData
        );
        console.log("CEAFactory Proxy deployed at:", address(proxy));

        // 6. Wrap proxy in CEAFactory interface for verification
        CEAFactory ceaFactory = CEAFactory(address(proxy));

        // 7. Verify deployment
        console.log("\n=== Deployment Verification ===");
        console.log("Factory Owner:", ceaFactory.owner());
        console.log("Vault:", ceaFactory.VAULT());
        console.log("CEA Proxy Implementation:", ceaFactory.CEA_PROXY_IMPLEMENTATION());
        console.log("CEA Implementation:", ceaFactory.CEA_IMPLEMENTATION());
        console.log("Universal Gateway:", ceaFactory.UNIVERSAL_GATEWAY());

        require(ceaFactory.owner() == owner, "Owner mismatch");
        require(ceaFactory.VAULT() == vault, "Vault mismatch");
        require(ceaFactory.CEA_PROXY_IMPLEMENTATION() == address(ceaProxyImplementation), "CEA Proxy Implementation mismatch");
        require(ceaFactory.CEA_IMPLEMENTATION() == address(ceaImplementation), "CEA Implementation mismatch");
        require(ceaFactory.UNIVERSAL_GATEWAY() == universalGateway, "Universal Gateway mismatch");

        console.log("\n=== Deployment Summary ===");
        console.log("CEA Implementation:", address(ceaImplementation));
        console.log("CEAProxy Implementation:", address(ceaProxyImplementation));
        console.log("CEAFactory Implementation:", address(ceaFactoryImplementation));
        console.log("CEAFactory Proxy (use this):", address(proxy));
        console.log("\n=== Deployment Complete ===");

        vm.stopBroadcast();
    }
}
