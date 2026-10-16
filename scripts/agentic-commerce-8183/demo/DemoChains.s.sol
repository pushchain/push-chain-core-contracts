// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {DemoMorphoVault} from "../../../src/mocks/DemoMorphoVault.sol";
import {Demo, IWETH} from "./DemoConfig.sol";

/// @notice The external-chain gateway's inbound request (push-chain-gateway-contracts `TypesUG.sol`).
struct UniversalTxRequest {
    address recipient; // the Push account credited; address(0) = the sender's UEA
    address token; // address(0) = native ETH
    uint256 amount;
    bytes payload;
    address revertRecipient;
    bytes signatureData;
}

interface IDemoGateway {
    function sendUniversalTx(UniversalTxRequest calldata req) external payable;
}

/// @title DemoChains — what the demo does on Base Sepolia and Ethereum Sepolia
/// @notice deployVault()  Base Sepolia: the Morpho-style WETH vault behind a proxy (admin: the deployer), at APY_BPS
///                        (default 500), with YIELD_RESERVE wei of WETH (default 0.001 ETH) to pay its yield.
///         bridge()       either chain: send AMOUNT wei of ETH through the gateway to the client UEA (RECIPIENT) on
///                        Push, where it arrives as pETH.
/// @dev Keys: CLIENT_PRIVATE_KEY (deployer, vault admin, bridging sender).
contract DemoChains is Script {
    function deployVault() external {
        uint256 key = vm.envUint("CLIENT_PRIVATE_KEY");
        address admin = vm.addr(key);
        uint256 reserve = vm.envOr("YIELD_RESERVE", uint256(0.001 ether));
        vm.startBroadcast(key);
        DemoMorphoVault impl = new DemoMorphoVault();
        DemoMorphoVault vault = DemoMorphoVault(
            address(
                new TransparentUpgradeableProxy(
                    address(impl),
                    admin,
                    abi.encodeCall(
                        DemoMorphoVault.initialize,
                        (
                            IERC20(Demo.BASE_WETH),
                            "Demo Morpho WETH",
                            "dmWETH",
                            admin,
                            vm.envOr("APY_BPS", uint256(500))
                        )
                    )
                )
            )
        );
        if (reserve != 0) {
            IWETH(Demo.BASE_WETH).deposit{value: reserve}();
            IERC20(Demo.BASE_WETH).approve(address(vault), reserve);
            vault.fundYield(reserve);
        }
        vm.stopBroadcast();
        console.log("vault (proxy):", address(vault));
        console.log("vault (implementation):", address(impl));
    }

    function bridge() external {
        uint256 key = vm.envUint("CLIENT_PRIVATE_KEY");
        address gateway = vm.envAddress("GATEWAY");
        uint256 amount = vm.envUint("AMOUNT");
        UniversalTxRequest memory req = UniversalTxRequest({
            recipient: vm.envAddress("RECIPIENT"),
            token: address(0),
            amount: amount,
            payload: "",
            revertRecipient: vm.addr(key),
            signatureData: ""
        });
        vm.startBroadcast(key);
        IDemoGateway(gateway).sendUniversalTx{value: amount}(req);
        vm.stopBroadcast();
        console.log("bridged (wei):", amount, "to", req.recipient);
    }
}
