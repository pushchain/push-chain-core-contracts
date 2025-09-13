// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {PRC20} from "../src/PRC20.sol";
import {IPRC20} from "../src/interfaces/IPRC20.sol";
import {UniversalCore} from "../src/UniversalCore.sol"; // adjust path if needed
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract Deploy is Script {
    address owner = 0x778D3206374f8AC265728E18E3fE2Ae6b93E4ce4;

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
                name: "USDC.eth",
                symbol: "USDC",
                decimals: 6,
                sourceChainId: 11155111,
                tokenType: IPRC20.TokenType.ERC20,
                gasLimit: 21000,
                fee: 0,
                sourceERC20: 0x7169D38820dfd117C3FA1f22a697dBA58d90BA06
            })
        );
    }

    function run() external {
        vm.startBroadcast();

        // Deploy handler (UniversalCore proxy)
        address handler = deployUniversalCoreHandler();

        // Deploy multiple PRC20s
        for (uint256 i = 0; i < configs.length; i++) {
            deployPRC20(handler, configs[i]);
        }

        vm.stopBroadcast();
    }

    /// @notice Deploy UniversalCore implementation + proxy (handler)
    function deployUniversalCoreHandler() internal returns (address) {
        UniversalCore universalImpl = new UniversalCore();
        console.log("UniversalCore implementation:", address(universalImpl));

        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector,
            WPC,
            UNISWAP_V3_FACTORY,
            UNISWAP_V3_ROUTER,
            UNISWAP_V3_QUOTER
        );

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(universalImpl),
            owner,
            initData
        );

        console.log("UniversalCore Proxy deployed at:", address(proxy));
        return address(proxy);
    }

    /// @notice Deploy one PRC20 with given config and handler
    function deployPRC20(address handler, PRC20Config memory cfg) internal returns (address) {
        PRC20 prc20 = new PRC20(
            cfg.name,
            cfg.symbol,
            cfg.decimals,
            cfg.sourceChainId,
            cfg.tokenType,
            cfg.gasLimit,
            cfg.fee,
            handler,
            cfg.sourceERC20
        );

        console.log("PRC20 deployed at:", address(prc20));
        console.log("    Name:", cfg.name, "Symbol:", cfg.symbol);
        return address(prc20);
    }
}
