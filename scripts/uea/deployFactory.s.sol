// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UEAFactory} from "../../src/UEA/UEAFactory.sol";
import {UEA_EVM} from "../../src/UEA/UEA_EVM.sol";
import {UEA_SVM} from "../../src/UEA/UEA_SVM.sol";
import {UEAProxy} from "../../src/UEA/UEAProxy.sol";

/**
 * @title DeployUEAFactoryScript
 * @notice Deployment script for UEAFactory on Push Chain
 *
 * @dev Deploys and configures:
 *  1. UEAFactory at predetermined address
 *  2. UEAProxy implementation (template for cloning)
 *  3. UEA_EVM implementation (for EVM chains)
 *  4. UEA_SVM implementation (for Solana chains)
 *  5. Registers initial chains and implementations
 *
 * CONFIGURATION:
 *  Update the state variables below with your deployment parameters.
 *  Environment variables needed: PRIVATE_KEY, RPC_URL, ETHERSCAN_API_KEY
 */
contract DeployUEAFactoryScript is Script {
    // ============================================================================
    // DEPLOYMENT PARAMETERS - Pre-Deployment Checklist 
    // ============================================================================

    // Owner of the UEAFactory (can register chains, update implementations, etc.)
    address public OWNER_ADDRESS = 0x778D3206374f8AC265728E18E3fE2Ae6b93E4ce4;

    // Predetermined factory address (must match expected CREATE2 address)
    address public FACTORY_ADDRESS = 0x00000000000000000000000000000000000000eA;

    // First EVM chain to register (Sepolia example)
    string public EVM_CHAIN_NAMESPACE = "eip155";
    string public EVM_CHAIN_ID = "11155111";

    // First SVM chain to register (Solana Devnet example)
    string public SVM_CHAIN_NAMESPACE = "solana";
    string public SVM_CHAIN_ID = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

    function run() external {
        vm.startBroadcast();

        address owner = OWNER_ADDRESS;
        bytes32 evmHash = keccak256(abi.encode("EVM"));
        bytes32 svmHash = keccak256(abi.encode("SVM"));
        bytes32 evmSepoliaHash = keccak256(abi.encode(EVM_CHAIN_NAMESPACE, EVM_CHAIN_ID));
        bytes32 solanaDevnetHash = keccak256(abi.encode(SVM_CHAIN_NAMESPACE, SVM_CHAIN_ID));

        // Initialize the factory with the initial owner
        UEAFactory factory = UEAFactory(FACTORY_ADDRESS);
        console.log("UEAFactory address:", address(factory));
        address(factory).call(
            abi.encodeWithSignature(
                "initialize(address)",
                owner
            )
        );

        // Register the EVM and SVM implementations
        factory.registerNewChain(evmSepoliaHash, evmHash);
        factory.registerNewChain(solanaDevnetHash, svmHash);
        console.log("EVM and SVM VMs registered in factory");

        UEAProxy proxyImpl = new UEAProxy();
        console.log("UEAProxy Implementation deployed at:", address(proxyImpl));

        factory.setUEAProxyImplementation(address(proxyImpl));
        console.log("UEAProxy impl set in the factory");

        // 1. Deploy UEA_EVM implementation
        UEA_EVM ueaEVMImpl = new UEA_EVM();
        console.log("UEA_EVM deployed at:", address(ueaEVMImpl));

        // // 2. Deploy UEA_SVM implementation
        UEA_SVM ueaSVMImpl = new UEA_SVM();
        console.log("UEA_SVM deployed at:", address(ueaSVMImpl));

        // Register UEA implementations
        factory.registerUEA(evmSepoliaHash, evmHash, address(ueaEVMImpl));
        factory.registerUEA(solanaDevnetHash, svmHash, address(ueaSVMImpl));
        console.log("UEA_EVM and UEA_SVM implementations registered in factory");

        UEAProxy ueaProxy = new UEAProxy();
        console.log("UEAProxy deployed at:", address(ueaProxy));

        factory.setUEAProxyImplementation(address(ueaProxy));
        console.log("UEAProxy set in the factory");

        vm.stopBroadcast();
    }
}
