// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UEAFactoryV1} from "../src/UEA/UEAFactoryV1.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy, ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract UpgradeFactoryScript is Script {
    function run() external {
        vm.startBroadcast(0xa96CaA79eb2312DbEb0B8E93c1Ce84C98b67bF11); // proxyAdminOwner

        // 1. Deploy new implementation
        UEAFactoryV1 newImplementation = new UEAFactoryV1();
        console.log("New UEAFactoryV1 deployed at:", address(newImplementation));

        // 2. Connect to deployed ProxyAdmin
        ProxyAdmin proxyAdmin = ProxyAdmin(0x00000000000000000000000000000000000000AA);

        // 3. Upgrade the proxy
        ITransparentUpgradeableProxy proxy = ITransparentUpgradeableProxy(payable(0x00000000000000000000000000000000000000eA));

        proxyAdmin.upgradeAndCall(proxy, address(newImplementation), "");

        // bytes32 evmHash = keccak256(abi.encode("EVM"));
        // bytes32 svmHash = keccak256(abi.encode("SVM"));
        // bytes32 evmSepoliaHash = keccak256(abi.encode("eip155",'11155111'));
        // bytes32 solanaDevnetHash = keccak256(abi.encode("solana","EtWTRABZaYq6iMfeYKouRu166VU2xqa1"));

        // 1. Deploy UEA_EVM implementation
        // UEA_EVM ueaEVMImpl = new UEA_EVM();
        // console.log("UEA_EVM deployed at:", address(ueaEVMImpl));

        // // 2. Deploy UEA_SVM implementation
        // UEA_SVM ueaSVMImpl = new UEA_SVM();
        // console.log("UEA_SVM deployed at:", address(ueaSVMImpl));

        console.log("Proxy upgraded successfully");

        vm.stopBroadcast();
    }
}
