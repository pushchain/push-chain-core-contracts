// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UEA_EVM} from "../src/UEA/UEA_EVM.sol";
import {UEA_SVM} from "../src/UEA/UEA_SVM.sol";
import {UEAMigration} from "../src/UEA/UEAMigration.sol";

contract DeploySmartAccountScript is Script {
    function run() external {
        vm.startBroadcast();

        // Deploy new UEA_EVM & UEA_SVM implementation
        UEA_EVM ueaEVMImpl = new UEA_EVM();
        UEA_SVM ueaSVMImpl = new UEA_SVM();

        // Deploy migration contract
        UEAMigration migrator = new UEAMigration(address(ueaEVMImpl), address(ueaSVMImpl));

        vm.stopBroadcast();
    }
}
