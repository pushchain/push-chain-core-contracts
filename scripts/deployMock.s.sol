// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import { Target } from "../src/mocks/Target.sol";

contract DeployMockScript is Script {
    function run() external {
        vm.startBroadcast();
        Target target;
        target = new Target();

        vm.stopBroadcast();
    }
}
