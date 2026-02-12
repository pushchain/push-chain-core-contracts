// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {PRC20} from "../../src/PRC20.sol";
import {IPRC20} from "../../src/interfaces/IPRC20.sol";
import {UniversalCore} from "../../src/UniversalCore.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title DeployUniversalCoreScript
 * @notice Deployment script for UniversalCore and PRC20 tokens on Push Chain
 *
 * @dev Deploys:
 *  1. UniversalCore implementation and proxy
 *  2. Multiple PRC20 tokens (configured in setUp())
 *
 * CONFIGURATION:
 *  Update the state variables and setUp() function below with your deployment parameters.
 *  Environment variables needed: PRIVATE_KEY, RPC_URL, ETHERSCAN_API_KEY
 */
contract DeployUniversalCoreScript is Script {
    // ============================================================================
    // DEPLOYMENT PARAMETERS - Pre-Deployment Checklist 
    // ============================================================================

    // Owner of deployed contracts (UniversalCore and PRC20 proxies)
    address public OWNER_ADDRESS = 0xa96CaA79eb2312DbEb0B8E93c1Ce84C98b67bF11;

    // Predetermined UniversalCore address (if using CREATE2, otherwise set to address(0))
    address public UNIVERSAL_CORE_ADDRESS = 0x00000000000000000000000000000000000000C0;

    // Wrapped Push Chain (WPC) token address
    address public WPC_ADDRESS = 0x0000000000000000000000000000000000000001;

    // Uniswap V3 contract addresses on Push Chain
    address public UNISWAP_V3_FACTORY_ADDRESS = 0x0000000000000000000000000000000000000002;
    address public UNISWAP_V3_ROUTER_ADDRESS = 0x0000000000000000000000000000000000000003;
    address public UNISWAP_V3_QUOTER_ADDRESS = 0x0000000000000000000000000000000000000004;

    // ===== PRC20 Token Configuration =====
    struct PRC20Config {
        string name;
        string symbol;
        uint8 decimals;
        uint256 sourceChainId;
        IPRC20.TokenType tokenType;
        uint256 gasLimit;
        uint256 fee;
        address sourceERC20;
    }

    PRC20Config[] public prc20Configs;


    function setUp() public {
        // First PRC20 (WETH from Sepolia)
        prc20Configs.push(
            PRC20Config({
                name: "WETH.eth",
                symbol: "WETH",
                decimals: 18,
                sourceChainId: 11155111,
                tokenType: IPRC20.TokenType.ERC20,
                gasLimit: 21000,
                fee: 0,
                sourceERC20: 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14
            })
        );

        // Second PRC20 (USDT from Sepolia)
        prc20Configs.push(
            PRC20Config({
                name: "USDT.eth",
                symbol: "USDT",
                decimals: 6,
                sourceChainId: 11155111,
                tokenType: IPRC20.TokenType.ERC20,
                gasLimit: 21000,
                fee: 0,
                sourceERC20: 0x7169D38820dfd117C3FA1f22a697dBA58d90BA06
            })
        );

        // Third PRC20 (pETH - native Sepolia ETH)
        prc20Configs.push(
            PRC20Config({
                name: "pETH",
                symbol: "pETH",
                decimals: 18,
                sourceChainId: 11155111,
                tokenType: IPRC20.TokenType.NATIVE,
                gasLimit: 21000,
                fee: 0,
                sourceERC20: address(0)
            })
        );
    }


    function run() external {
        vm.startBroadcast();

        console.log("=== UniversalCore Deployment Configuration ===");
        console.log("Owner:", OWNER_ADDRESS);
        console.log("UniversalCore Address:", UNIVERSAL_CORE_ADDRESS);
        console.log("WPC:", WPC_ADDRESS);
        console.log("Uniswap V3 Factory:", UNISWAP_V3_FACTORY_ADDRESS);
        console.log("Uniswap V3 Router:", UNISWAP_V3_ROUTER_ADDRESS);
        console.log("Uniswap V3 Quoter:", UNISWAP_V3_QUOTER_ADDRESS);
        console.log("");

        // Deploy UniversalCore proxy
        address universalCore = deployUniversalCore();

        // Deploy multiple PRC20s
        console.log("\n=== Deploying PRC20 Tokens ===");
        for (uint256 i = 0; i < prc20Configs.length; i++) {
            deployPRC20(universalCore, prc20Configs[i]);
        }

        console.log("\n=== Deployment Complete ===");

        vm.stopBroadcast();
    }

    /// @notice Deploy UniversalCore implementation + proxy (or use predetermined address)
    function deployUniversalCore() internal returns (address) {
        UniversalCore universalImpl = UniversalCore(UNIVERSAL_CORE_ADDRESS);
        console.log("UniversalCore implementation:", address(universalImpl));

        universalImpl.initialize(
            WPC_ADDRESS,
            UNISWAP_V3_FACTORY_ADDRESS,
            UNISWAP_V3_ROUTER_ADDRESS,
            UNISWAP_V3_QUOTER_ADDRESS
        );

        console.log("UniversalCore initialized at:", address(universalImpl));
        return address(universalImpl);
    }

    /// @notice Deploy one PRC20 with given config and universalCore
    function deployPRC20(address universalCore, PRC20Config memory cfg) internal returns (address) {
        PRC20 prc20Impl = new PRC20();

        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            cfg.name,
            cfg.symbol,
            cfg.decimals,
            cfg.sourceChainId,
            cfg.tokenType,
            cfg.gasLimit,
            cfg.fee,
            universalCore,
            cfg.sourceERC20
        );

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(prc20Impl),
            OWNER_ADDRESS,
            initData
        );

        console.log("PRC20 deployed at:", address(proxy));
        console.log("  Name:", cfg.name, "Symbol:", cfg.symbol);
        return address(proxy);
    }
}
