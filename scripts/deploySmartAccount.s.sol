// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {FactoryV1} from "../src/FactoryV1.sol";
import {SmartAccountV1} from "../src/SmartAccountV1.sol";

contract DeploySmartAccountScript is Script {
    function run() external {
        vm.startBroadcast();

        // 1. Deploy SmartAccount implementation
        SmartAccountV1 smartAccountImpl = new SmartAccountV1();
        console.log("SmartAccountV1 deployed at:", address(smartAccountImpl));

        // 2. Deploy Factory with implementation
        FactoryV1 factory = new FactoryV1(address(smartAccountImpl));
        console.log("FactoryV1 deployed at:", address(factory));

        // 3. Deploy SmartAccount for NON-EVM owner
        // Example NON-EVM key (can be changed)
        bytes memory ownerKeyNonEVM = vm.parseBytes('0x30ea71869947818d27b718592ea44010b458903bd9bf0370f50eda79e87d9f69');

        // Dummy verifier precompile address (replace with real one if required)
        address verifierPrecompile = address(0x0000000000000000000000000000000000000902);

        // Deploy SmartAccount via factory
        address smartAccountAddr = factory.deploySmartAccount(
            ownerKeyNonEVM,
            SmartAccountV1.OwnerType.NON_EVM,
            verifierPrecompile
        );
        console.log("SmartAccount (NON-EVM) deployed at:", smartAccountAddr);

        vm.stopBroadcast();
    }
}
