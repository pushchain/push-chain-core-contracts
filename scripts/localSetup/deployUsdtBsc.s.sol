// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {PRC20} from "../../src/PRC20.sol";
import {IPRC20} from "../../src/interfaces/IPRC20.sol";
import {UniversalCoreV0} from "../../src/testnetV0/UniversalCoreV0.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @notice Deploys the USDT.bsc PRC20 token on the local Push Chain devnet and
 *         mints an initial supply to the owner.
 *
 * Usage:
 *   forge script scripts/localSetup/deployUsdtBsc.s.sol \
 *     --broadcast \
 *     --rpc-url http://localhost:8545 \
 *     --private-key <PRIVATE_KEY> \
 *     --slow
 *
 * The deployed proxy address is printed at the end — update:
 *   push-chain/config/testnet-donut/bsc_testnet/tokens/usdt.json
 *   push-chain-sdk/packages/core/src/lib/constants/chain.ts  (SYNTHETIC_PUSH_ERC20[LOCALNET].USDT_BNB)
 */
contract DeployUsdtBscScript is Script {
    address constant UNIVERSAL_CORE = 0x00000000000000000000000000000000000000C0;
    address owner = 0x778D3206374f8AC265728E18E3fE2Ae6b93E4ce4;

    function run() external {
        vm.startBroadcast();

        PRC20 prc20Impl = new PRC20();

        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "USDT.bsc",                                        // name
            "USDT.bsc",                                        // symbol
            uint8(6),                                          // decimals
            "eip155:97",                                       // sourceChainId (BNB Testnet)
            IPRC20.TokenType.ERC20,                            // tokenType
            UNIVERSAL_CORE,                                    // universalCore
            "0xbc14f348bc9667be46b35edc9b68653d86013dc5"       // sourceERC20 (BSC testnet USDT)
        );

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(prc20Impl),
            owner,
            initData
        );

        address usdtBsc = address(proxy);
        console.log("USDT.bsc PRC20 deployed at:", usdtBsc);

        // Mint initial supply to owner
        UniversalCoreV0(payable(UNIVERSAL_CORE)).mintPRCTokensviaAdmin(usdtBsc, 1e22, owner);
        console.log("Minted 1e22 USDT.bsc to owner:", owner);

        vm.stopBroadcast();
    }
}
