// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {StakingExample} from
    "../../src/testnetV0/StakingExample.sol";
import {ProxyAdmin} from
    "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract UpgradeStakingExampleScript is Script {
    address public constant PROXY_ADMIN_ADDRESS =
        0x33b7f498c0440bDf82F976C1aa4aD4f0E483dE4e;

    address public constant STAKING_PROXY_ADDRESS =
        0x8ab717A4836d0589E5f27Ff65e18804325Cd6540;

    function run() external {
        vm.startBroadcast();

        console.log("=== StakingExample Upgrade ===");
        console.log("Proxy Admin:", PROXY_ADMIN_ADDRESS);
        console.log("Staking Proxy:", STAKING_PROXY_ADDRESS);

        // 1. Deploy new implementation
        StakingExample newImpl = new StakingExample();
        console.log(
            "New implementation deployed at:",
            address(newImpl)
        );

        // 2. Upgrade via ProxyAdmin
        ProxyAdmin proxyAdmin = ProxyAdmin(PROXY_ADMIN_ADDRESS);
        ITransparentUpgradeableProxy proxy =
            ITransparentUpgradeableProxy(
                payable(STAKING_PROXY_ADDRESS)
            );

        proxyAdmin.upgradeAndCall(
            proxy, address(newImpl), ""
        );
        console.log("Proxy upgraded successfully");

        vm.stopBroadcast();

        // 3. Verify
        StakingExample staking =
            StakingExample(payable(STAKING_PROXY_ADDRESS));
        console.log("\n=== Post-Upgrade Verification ===");
        console.log("owner():", staking.owner());
        console.log("ugpc():", staking.ugpc());
        console.log(
            "universalExecutorModule():",
            staking.universalExecutorModule()
        );
    }
}
