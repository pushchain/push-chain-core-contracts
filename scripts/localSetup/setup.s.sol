// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {UEAFactory} from "../../src/UEA/UEAFactory.sol";
import {UEA_EVM} from "../../src/UEA/UEA_EVM.sol";
import {UEA_SVM} from "../../src/UEA/UEA_SVM.sol";
import {UEAProxy} from "../../src/UEA/UEAProxy.sol";
import {PRC20} from "../../src/PRC20.sol";
import {IPRC20} from "../../src/Interfaces/IPRC20.sol";
import {UniversalCoreV0} from "../../src/UniversalCoreV0.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy, ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract LocalSetupScript is Script {
    address owner = 0x778D3206374f8AC265728E18E3fE2Ae6b93E4ce4;
    
    // ===== PRC20 Struct =====
    struct PRC20Config {
        string name;
        string symbol;
        uint8 decimals;
        string sourceChainId;
        IPRC20.TokenType tokenType;
        uint256 gasLimit;
        uint256 fee;
        string sourceERC20;
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
                name: "pETH.eth",
                symbol: "pETH",
                decimals: 18,
                sourceChainId: "eip155:11155111",
                tokenType: IPRC20.TokenType.ERC20,
                gasLimit: 21000,
                fee: 0,
                sourceERC20: "0x0000000000000000000000000000000000000000"
            })
        );
        configs.push(
            PRC20Config({
                name: "USDT.eth",
                symbol: "USDT.eth",
                decimals: 6,
                sourceChainId: "eip155:11155111",
                tokenType: IPRC20.TokenType.ERC20,
                gasLimit: 21000,
                fee: 0,
                sourceERC20: "0x7169D38820dfd117C3FA1f22a697dBA58d90BA06"
            })
        );
        configs.push(
            PRC20Config({
                name: "pETH.base",
                symbol: "pETH.base",
                decimals: 18,
                sourceChainId: "eip155:84532",
                tokenType: IPRC20.TokenType.ERC20,
                gasLimit: 21000,
                fee: 0,
                sourceERC20: "0x0000000000000000000000000000000000000000"
            })
        );
        configs.push(
            PRC20Config({
                name: "pETH.arb",
                symbol: "pETH.arb",
                decimals: 18,
                sourceChainId: "eip155:421614",
                tokenType: IPRC20.TokenType.ERC20,
                gasLimit: 21000,
                fee: 0,
                sourceERC20: "0x0000000000000000000000000000000000000000"
            })
        );
         configs.push(
            PRC20Config({
                name: "pBNB",
                symbol: "pBNB",
                decimals: 18,
                sourceChainId: "eip155:97",
                tokenType: IPRC20.TokenType.ERC20,
                gasLimit: 21000,
                fee: 0,
                sourceERC20: "0x0000000000000000000000000000000000000000"
            })
        );
        configs.push(
            PRC20Config({
                name: "pSOL",
                symbol: "pSOL",
                decimals: 9,
                sourceChainId: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                tokenType: IPRC20.TokenType.NATIVE,
                gasLimit: 21000,
                fee: 0,
                sourceERC20: "11111111111111111111111111111111"
            })
        );
    }

    function run() external {
        vm.startBroadcast();

        bytes32 evmHash = keccak256(abi.encode("EVM"));
        bytes32 svmHash = keccak256(abi.encode("SVM"));
        bytes32 evmSepoliaHash = keccak256(abi.encode("eip155",'11155111'));
            bytes32 arbitrumSepoliaHash = keccak256(abi.encode("eip155", "421614"));
            bytes32 baseSepoliaHash = keccak256(abi.encode("eip155", "84532"));
            bytes32 bscTestnetHash = keccak256(abi.encode("eip155", "97"));
            bytes32 solanaDevnetHash = keccak256(abi.encode("solana","EtWTRABZaYq6iMfeYKouRu166VU2xqa1"));

        // Initialize the factory with the initial owner
        UEAFactory factory = UEAFactory(0x00000000000000000000000000000000000000eA);
        (bool initialized,) = address(factory).call(
            abi.encodeWithSignature(
                "initialize(address)",
                owner
            )
        );
        require(initialized, "UEAFactory initialize failed");

        // Register the EVM and SVM implementations
        factory.registerNewChain(evmSepoliaHash, evmHash);
            factory.registerNewChain(arbitrumSepoliaHash, evmHash);
            factory.registerNewChain(baseSepoliaHash, evmHash);
            factory.registerNewChain(bscTestnetHash, evmHash);
            factory.registerNewChain(solanaDevnetHash, svmHash);
        console.log("EVM and SVM registered in factory");

        UEAProxy proxyImpl = new UEAProxy();
        console.log("UEAProxy Implementation deployed at:", address(proxyImpl));

        factory.setUEAProxyImplementation(address(proxyImpl));
        console.log("UEAProxy impl set in the factory");

        // 1. Deploy UEA_EVM implementation
        UEA_EVM ueaEVMImpl = new UEA_EVM();
        console.log("UEA_EVM deployed at:", address(ueaEVMImpl));

        // 2. Deploy UEA_SVM implementation
        UEA_SVM ueaSVMImpl = new UEA_SVM();
        console.log("UEA_SVM deployed at:", address(ueaSVMImpl));


        // Register UEA implementations
        factory.registerUEA(evmSepoliaHash, evmHash, address(ueaEVMImpl));
            factory.registerUEA(arbitrumSepoliaHash, evmHash, address(ueaEVMImpl));
            factory.registerUEA(baseSepoliaHash, evmHash, address(ueaEVMImpl));
            factory.registerUEA(bscTestnetHash, evmHash, address(ueaEVMImpl));
            factory.registerUEA(solanaDevnetHash, svmHash, address(ueaSVMImpl));
        console.log("UEA_EVM and UEA_SVM implementations registered in factory");

        // Deploy UniversalCore proxy
        address universalCore = deployUniversalCore();
        console.log("UniversalCore addr: ", universalCore);

        UniversalCoreV0 newImplementation = new UniversalCoreV0();
        console.log("New UniversalCoreV0 deployed at:", address(newImplementation));

        // 2. Connect to deployed ProxyAdmin
        ProxyAdmin proxyAdmin = ProxyAdmin(0xf2000000000000000000000000000000000000c0);

        // 3. Upgrade the proxy
        ITransparentUpgradeableProxy proxy = ITransparentUpgradeableProxy(payable(0x00000000000000000000000000000000000000C0));

        proxyAdmin.upgradeAndCall(proxy, address(newImplementation), "");
        console.log("Proxy upgraded successfully");

        // Deploy multiple PRC20s
        for (uint256 i = 0; i < configs.length; i++) {
            address token = deployPRC20(universalCore, configs[i]);

            UniversalCoreV0(payable(universalCore)).mintPRCTokensviaAdmin(token, 1e22, owner);
        }

        vm.stopBroadcast();
    }

    /// @notice Deploy UniversalCore implementation + proxy (universalCore)
    function deployUniversalCore() internal returns (address) {
        UniversalCoreV0 universalImpl = UniversalCoreV0(payable(0x00000000000000000000000000000000000000C0));
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
        console.log("UniversalCore addr inside fn: ", universalCore);
        PRC20 prc20Impl = new PRC20();

        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            cfg.name,
            cfg.symbol,
            cfg.decimals,
            cfg.sourceChainId,
            cfg.tokenType,
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
