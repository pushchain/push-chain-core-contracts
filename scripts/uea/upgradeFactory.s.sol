// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UEAFactory} from "../../src/UEA/UEAFactory.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy, ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title UpgradeUEAFactoryScript
 * @notice Upgrade script for UEAFactory on Push Chain
 *
 * @dev Upgrades UEAFactory implementation through ProxyAdmin
 *
 * CONFIGURATION:
 *  Update the state variables below with your upgrade parameters.
 *  Environment variables needed: PRIVATE_KEY, RPC_URL, ETHERSCAN_API_KEY
 */
contract UpgradeUEAFactoryScript is Script {
    // ============================================================================
    // UPGRADE PARAMETERS - Pre-Upgrade Checklist 
    // ============================================================================

    // Address of the ProxyAdmin contract (manages upgrades)
    address public PROXY_ADMIN_ADDRESS = 0x00000000000000000000000000000000000000AA;

    // Address of the UEAFactory proxy to upgrade
    address public FACTORY_PROXY_ADDRESS = 0x00000000000000000000000000000000000000eA;

    function run() external {
        vm.startBroadcast();

        console.log("=== UEAFactory Upgrade Configuration ===");
        console.log("Proxy Admin:", PROXY_ADMIN_ADDRESS);
        console.log("Factory Proxy:", FACTORY_PROXY_ADDRESS);

        // 1. Deploy new implementation
        UEAFactory newImplementation = new UEAFactory();
        console.log("New UEAFactory implementation deployed at:", address(newImplementation));

        // 2. Connect to deployed ProxyAdmin
        ProxyAdmin proxyAdmin = ProxyAdmin(PROXY_ADMIN_ADDRESS);

        // 3. Upgrade the proxy
        ITransparentUpgradeableProxy proxy = ITransparentUpgradeableProxy(payable(FACTORY_PROXY_ADDRESS));

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
