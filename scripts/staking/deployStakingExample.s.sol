// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {StakingExample} from
    "../../src/testnetV0/StakingExample.sol";
import {TransparentUpgradeableProxy} from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract DeployStakingExampleScript is Script {
    address public constant UGPC =
        0x00000000000000000000000000000000000000C1;
    address public constant UNIVERSAL_EXECUTOR_MODULE =
        0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    function run() external {
        address deployer = msg.sender;

        console.log("=== StakingExample Deployment ===");
        console.log("Deployer / Owner:", deployer);
        console.log("UGPC:", UGPC);
        console.log(
            "Universal Executor Module:",
            UNIVERSAL_EXECUTOR_MODULE
        );

        vm.startBroadcast();

        // 1. Deploy implementation
        StakingExample impl = new StakingExample();
        console.log("Implementation:", address(impl));

        // 2. Deploy proxy with initialize calldata
        bytes memory initData = abi.encodeWithSelector(
            StakingExample.initialize.selector,
            UGPC,
            UNIVERSAL_EXECUTOR_MODULE,
            deployer
        );

        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(
                address(impl),
                deployer,
                initData
            );
        console.log("Proxy:", address(proxy));

        vm.stopBroadcast();

        // 3. Verify initialization
        StakingExample staking = StakingExample(
            payable(address(proxy))
        );
        console.log("\n=== Post-Deploy Verification ===");
        console.log("owner():", staking.owner());
        console.log("ugpc():", staking.ugpc());
        console.log(
            "universalExecutorModule():",
            staking.universalExecutorModule()
        );
    }
}
