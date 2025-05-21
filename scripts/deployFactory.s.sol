// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {FactoryV1} from "../src/FactoryV1.sol";
import {SmartAccountEVM} from "../src/smartAccounts/SmartAccountEVM.sol";
import {SmartAccountSVM} from "../src/smartAccounts/SmartAccountSVM.sol";
import {CAIP10} from "../test/utils/caip.sol";
import {
    VM_TYPE,
    AccountId,
    CrossChainPayload,
    DOMAIN_SEPARATOR_TYPEHASH,
    PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH
} from "../src/libraries/Types.sol";

contract DeploySmartAccountScript is Script {
    function run() external {
        vm.startBroadcast();

        // 1. Deploy SmartAccountEVM implementation
        SmartAccountEVM smartAccountEVMImpl = new SmartAccountEVM();
        console.log("SmartAccountEVM deployed at:", address(smartAccountEVMImpl));

        // 2. Deploy SmartAccountSVM implementation
        SmartAccountSVM smartAccountSVMImpl = new SmartAccountSVM();
        console.log("SmartAccountSVM deployed at:", address(smartAccountSVMImpl));

        address[] memory implementations = new address[](2);
        implementations[0] = address(smartAccountEVMImpl);
        implementations[1] = address(smartAccountSVMImpl);

        uint256[] memory vmTypes = new uint256[](2);
        vmTypes[0] = uint256(VM_TYPE.EVM);
        vmTypes[1] = uint256(VM_TYPE.SVM);

        // 2. Deploy Factory with implementation
        FactoryV1 factory = new FactoryV1(
            implementations,
            vmTypes
        );
        console.log("FactoryV1 deployed at:", address(factory));

        vm.stopBroadcast();
    }
}
