// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {FactoryV1} from "../src/SmartAccount/FactoryV1.sol";
import {SmartAccountV1} from "../src/SmartAccount/SmartAccountV1.sol";
import {CAIP10} from "../test/utils/caip.sol";

contract DeploySmartAccountScript is Script {
    // Relayer Setup
    address relayer;
    uint256 relayerPk;

    // Set up the test environment - EVM
    address bob;
    uint256 bobPk;
    bytes bobKey;
    function run() external {

        relayerPk = vm.envUint("RELAYER_PRIVATE_KEY");
        bobPk = vm.envUint("BOB_PRIVATE_KEY");


        bob = vm.addr(bobPk);
        bobKey = abi.encodePacked(address(bob));

        relayer = vm.addr(relayerPk);

        vm.startBroadcast();

        // 1. Deploy SmartAccount implementation
        SmartAccountV1 smartAccountImpl = new SmartAccountV1();
        console.log("SmartAccountV1 IMPL deployed at:", address(smartAccountImpl));

        // 2. Deploy Factory with implementation
        FactoryV1 factory = new FactoryV1(address(smartAccountImpl));
        console.log("FactoryV1 deployed at:", address(factory));

        // 3. Deploy SmartAccount for EVM OWNER
        string memory caip = CAIP10.createCAIP10("eip155", "1", bob);
        bytes32 salt = keccak256(abi.encode(caip));
        address verifierPrecompile = address(0);

        // Deploy SmartAccount via factory
        address smartAccountAddr = factory.deploySmartAccount(
            bobKey,
            caip,
            SmartAccountV1.OwnerType.EVM,
            verifierPrecompile
        );
        console.log("SmartAccount (BOB) deployed at:", smartAccountAddr);

        // Check the deployed Smart ACCOUNT's State
        // SmartAccountV1 smartAccount = SmartAccountV1(address(smartAccountAddr));
        // console.logBytes(smartAccount.ownerKey());
 
        // 5. Fund the SmartAccount with 1 ether
        (bool success, ) = payable(smartAccountAddr).call{value: 1 ether}("");
        require(success, "Funding SmartAccount failed");
        console.log("SmartAccount funded with 1 ether");


        vm.stopBroadcast();
    }
}
