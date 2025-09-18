// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {PRC20} from "../src/PRC20.sol";
import {IPRC20} from "../src/interfaces/IPRC20.sol";
import {UniversalCore} from "../src/UniversalCore.sol"; // adjust path if needed
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract Deploy is Script {
    address owner = 0xa96CaA79eb2312DbEb0B8E93c1Ce84C98b67bF11;

    // ===== PRC20 Struct =====
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

    // ===== Example Configs =====
    PRC20Config[] public configs;

    // UniversalCore initializer args
    address constant WPC = 0x0000000000000000000000000000000000000001;
    address constant UNISWAP_V3_FACTORY = 0x0000000000000000000000000000000000000002;
    address constant UNISWAP_V3_ROUTER  = 0x0000000000000000000000000000000000000003;
    address constant UNISWAP_V3_QUOTER  = 0x0000000000000000000000000000000000000004;

    function setUp() public {
        // First PRC20 (WETH)
        configs.push(
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

        // Second PRC20 (USDC)
        configs.push(
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

        // Third PRC20 (ETH)
        configs.push(
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

        // Deploy UniversalCore proxy
        address universalCore = deployUniversalCore();

        // Deploy multiple PRC20s
        for (uint256 i = 0; i < configs.length; i++) {
            deployPRC20(universalCore, configs[i]);
        }

        vm.stopBroadcast();
    }

    /// @notice Deploy UniversalCore implementation + proxy (universalCore)
    function deployUniversalCore() internal returns (address) {
        UniversalCore universalImpl = UniversalCore(0x00000000000000000000000000000000000000C0);
        console.log("UniversalCore implementation:", address(universalImpl));

        universalImpl.initialize(
            WPC,
            UNISWAP_V3_FACTORY,
            UNISWAP_V3_ROUTER,
            UNISWAP_V3_QUOTER
        );

        // console.log("UniversalCore Proxy deployed at:", address(proxy));
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
            owner,
            initData
        );

        console.log("PRC20 deployed at:", address(proxy));
        console.log("    Name:", cfg.name, "Symbol:", cfg.symbol);
        return address(proxy);
    }
}
