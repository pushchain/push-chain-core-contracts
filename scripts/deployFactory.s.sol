// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UEAFactoryV1} from "../src/UEA/UEAFactoryV1.sol";
import {UEA_EVM} from "../src/UEA/UEA_EVM.sol";
import {UEA_SVM} from "../src/UEA/UEA_SVM.sol";

contract DeploySmartAccountScript is Script {
    function run() external {
        vm.startBroadcast();

        address owner = 0x778D3206374f8AC265728E18E3fE2Ae6b93E4ce4;
        bytes32 evmHash = keccak256(abi.encode("EVM"));
        bytes32 svmHash = keccak256(abi.encode("SVM"));
        bytes32 evmSepoliaHash = keccak256(abi.encode("eip155",'11155111'));
        bytes32 solanaDevnetHash = keccak256(abi.encode("solana","EtWTRABZaYq6iMfeYKouRu166VU2xqa1"));

        // Initialize the factory with the initial owner
        UEAFactoryV1 factory = UEAFactoryV1(0x00000000000000000000000000000000000000eA);
        // factory.registerMultipleImplementations(vmTypes, implementations);
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

        vm.stopBroadcast();
    }
}
