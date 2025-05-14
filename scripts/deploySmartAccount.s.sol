// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {FactoryV1} from "../src/SmartAccount/FactoryV1.sol";
import {SmartAccountV1} from "../src/SmartAccount/SmartAccountV1.sol";
import {CAIP10} from "../test/utils/caip.sol";

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
        string memory solanaChainId = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
        string memory solanaAddress = "HGyAQb8SeAE6X6RfhgMpGWZQuVYU8kgA5tKitaTrUHfh";

        string memory caip = CAIP10.createSolanaCAIP10(
            solanaChainId,
            solanaAddress
        );
        bytes32 salt = keccak256(abi.encode(caip));

        // Dummy verifier precompile address (replace with real one if required)
        address verifierPrecompile = address(0x0000000000000000000000000000000000000902);

        // Deploy SmartAccount via factory
        address smartAccountAddr = factory.deploySmartAccount(
            ownerKeyNonEVM,
            caip,
            SmartAccountV1.VM_TYPE.NON_EVM,
            verifierPrecompile
        );
        console.log("SmartAccount (NON-EVM) deployed at:", smartAccountAddr);

        vm.stopBroadcast();
    }
}
