// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../src/UniversalCore.sol";
import "../../src/PRC20.sol";
import "../../src/interfaces/IPRC20.sol";
import "../../src/interfaces/IUniversalCore.sol";
import {UniversalCoreErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import "../../test/helpers/UpgradeableContractHelper.sol";
import "../../test/mocks/MockUniswapV3Factory.sol";
import "../../test/mocks/MockUniswapV3Router.sol";
import "../../test/mocks/MockUniswapV3Quoter.sol";
import "../../test/mocks/MockWPC.sol";
import "../../test/mocks/MockPRC20.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

contract UniversalCoreSwapFeeTest is Test, UpgradeableContractHelper {
    UniversalCore public universalCore;
    PRC20 public prc20Token;
    MockUniswapV3Factory public mockFactory;
    MockUniswapV3Router public mockRouter;
    MockUniswapV3Quoter public mockQuoter;
    MockWPC public mockWPC;
    MockPRC20 public gasTokenMock;

    address public constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    string public constant SOURCE_TOKEN_ADDRESS = "0x0000000000000000000000000000000000000000";

    address public deployer;
    address public gateway;
    address public vault;
    address public nonGateway;

    string public constant CHAIN_NAMESPACE = "eip155:1";
    uint256 public constant PROTOCOL_FEE = 1000;
    uint256 public constant GAS_PRICE = 50 * 10 ** 9;
    uint24 public constant FEE_TIER = 3000;

    event SwapPCForGasToken(
        address indexed prc20, address indexed gasToken,
        uint256 pcIn, uint256 gasTokenOut, uint24 fee, address indexed vault
    );

    function setUp() public {
        deployer = address(this);
        gateway = makeAddr("gateway");
        vault = makeAddr("vault");
        nonGateway = makeAddr("nonGateway");

        mockFactory = new MockUniswapV3Factory();
        mockRouter = new MockUniswapV3Router();
        mockQuoter = new MockUniswapV3Quoter();
        mockWPC = new MockWPC();
        gasTokenMock = new MockPRC20();

        // Deploy PRC20 via proxy (needed for SOURCE_CHAIN_NAMESPACE)
        PRC20 implementationPrc20 = new PRC20();
        bytes memory initDataPrc20 = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "Test PRC20",
            "TPRC20",
            18,
            CHAIN_NAMESPACE,
            IPRC20.TokenType.ERC20,
            PROTOCOL_FEE,
            address(0x1),
            SOURCE_TOKEN_ADDRESS
        );
        address proxyAddressPrc20 = deployUpgradeableContract(address(implementationPrc20), initDataPrc20);
        prc20Token = PRC20(payable(proxyAddressPrc20));

        // Deploy UniversalCore via proxy
        UniversalCore implementation = new UniversalCore();
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector,
            address(mockWPC),
            address(mockFactory),
            address(mockRouter),
            address(mockQuoter)
        );
        address proxyAddress = deployUpgradeableContract(address(implementation), initData);
        universalCore = UniversalCore(payable(proxyAddress));

        // Update PRC20 universalCore
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        prc20Token.updateUniversalCore(address(universalCore));

        // Set BASE_GAS_LIMIT (proxy storage defaults to 0)
        universalCore.updateBaseGasLimit(500_000);

        // Grant GATEWAY_ROLE to gateway
        universalCore.grantRole(universalCore.GATEWAY_ROLE(), gateway);

        // Configure gas token and gas price
        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPrice(CHAIN_NAMESPACE, GAS_PRICE);
        universalCore.setGasTokenPRC20(CHAIN_NAMESPACE, address(gasTokenMock));
        vm.stopPrank();

        // Set default fee tier and slippage for gas token
        universalCore.setDefaultFeeTier(address(gasTokenMock), FEE_TIER);
        universalCore.setSlippageTolerance(address(gasTokenMock), 300);

        // Setup mock pool (wPC <-> gasToken)
        address pool = makeAddr("mockPool");
        if (address(mockWPC) < address(gasTokenMock)) {
            mockFactory.setPool(address(mockWPC), address(gasTokenMock), FEE_TIER, pool);
        } else {
            mockFactory.setPool(address(gasTokenMock), address(mockWPC), FEE_TIER, pool);
        }

        // Fund the gateway
        vm.deal(gateway, 100 ether);
    }

    // ========================================
    // 1) Access Control
    // ========================================

    function test_SwapPCForGasToken_OnlyGatewayRole() public {
        vm.deal(nonGateway, 1 ether);
        bytes32 gatewayRole = universalCore.GATEWAY_ROLE();
        vm.prank(nonGateway);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                nonGateway,
                gatewayRole
            )
        );
        universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), vault, 0, 0, 0
        );
    }

    function test_SwapPCForGasToken_UEModuleCannotCall() public {
        vm.deal(UNIVERSAL_EXECUTOR_MODULE, 1 ether);
        bytes32 gatewayRole = universalCore.GATEWAY_ROLE();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                UNIVERSAL_EXECUTOR_MODULE,
                gatewayRole
            )
        );
        universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), vault, 0, 0, 0
        );
    }

    function test_SwapPCForGasToken_AdminCanGrantRole() public {
        address newGateway = makeAddr("newGateway");
        vm.deal(newGateway, 1 ether);

        universalCore.grantRole(universalCore.GATEWAY_ROLE(), newGateway);

        vm.prank(newGateway);
        uint256 gasTokenOut = universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), vault, 0, 0, 0
        );
        assertGt(gasTokenOut, 0);
    }

    // ========================================
    // 2) Input Validation
    // ========================================

    function test_SwapPCForGasToken_ZeroPRC20Reverts() public {
        vm.prank(gateway);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.swapPCForGasToken{value: 1 ether}(
            address(0), vault, 0, 0, 0
        );
    }

    function test_SwapPCForGasToken_ZeroVaultReverts() public {
        vm.prank(gateway);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), address(0), 0, 0, 0
        );
    }

    function test_SwapPCForGasToken_ZeroMsgValueReverts() public {
        vm.prank(gateway);
        vm.expectRevert(CommonErrors.ZeroAmount.selector);
        universalCore.swapPCForGasToken{value: 0}(
            address(prc20Token), vault, 0, 0, 0
        );
    }

    function test_SwapPCForGasToken_NoGasTokenReverts() public {
        // Create PRC20 for a chain with no gas token configured
        PRC20 newPrc20Impl = new PRC20();
        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "New PRC20",
            "NPRC20",
            18,
            "eip155:999",
            IPRC20.TokenType.ERC20,
            PROTOCOL_FEE,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );
        address proxyAddress = deployUpgradeableContract(address(newPrc20Impl), initData);

        vm.prank(gateway);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.swapPCForGasToken{value: 1 ether}(
            proxyAddress, vault, 0, 0, 0
        );
    }

    function test_SwapPCForGasToken_NoDefaultFeeReverts() public {
        // Create a gas token with no default fee tier
        MockPRC20 newGasToken = new MockPRC20();

        // Configure the gas token but NOT the default fee tier
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasTokenPRC20("eip155:56", address(newGasToken));

        // Deploy PRC20 for BSC chain
        PRC20 bscPrc20Impl = new PRC20();
        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "BSC PRC20",
            "BPRC20",
            18,
            "eip155:56",
            IPRC20.TokenType.ERC20,
            PROTOCOL_FEE,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );
        address proxyAddress = deployUpgradeableContract(address(bscPrc20Impl), initData);

        vm.prank(gateway);
        vm.expectRevert(UniversalCoreErrors.InvalidFeeTier.selector);
        universalCore.swapPCForGasToken{value: 1 ether}(
            proxyAddress, vault, 0, 0, 0
        );
    }

    // ========================================
    // 3) Happy Path
    // ========================================

    function test_SwapPCForGasToken_HappyPath() public {
        vm.prank(gateway);
        uint256 gasTokenOut = universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), vault, 0, 0, 0
        );

        // Mock router returns 90% of input
        uint256 expectedOut = 1 ether * 90 / 100;
        assertEq(gasTokenOut, expectedOut);
    }

    function test_SwapPCForGasToken_VaultReceivesGasToken() public {
        uint256 vaultBalanceBefore = gasTokenMock.balanceOf(vault);

        vm.prank(gateway);
        uint256 gasTokenOut = universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), vault, 0, 0, 0
        );

        uint256 vaultBalanceAfter = gasTokenMock.balanceOf(vault);
        assertEq(vaultBalanceAfter - vaultBalanceBefore, gasTokenOut);
    }

    function test_SwapPCForGasToken_EmitsEvent() public {
        uint256 expectedOut = 1 ether * 90 / 100;

        vm.expectEmit(true, true, true, true);
        emit SwapPCForGasToken(
            address(prc20Token), address(gasTokenMock),
            1 ether, expectedOut, FEE_TIER, vault
        );

        vm.prank(gateway);
        universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), vault, 0, 0, 0
        );
    }

    function test_SwapPCForGasToken_ExplicitParams() public {
        uint256 explicitMinOut = 0.5 ether;
        uint256 explicitDeadline = block.timestamp + 1 hours;

        vm.prank(gateway);
        uint256 gasTokenOut = universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), vault, FEE_TIER, explicitMinOut, explicitDeadline
        );

        assertGe(gasTokenOut, explicitMinOut);
    }

    function test_SwapPCForGasToken_MultipleChains() public {
        // Setup BSC chain
        MockPRC20 bscGasToken = new MockPRC20();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasTokenPRC20("eip155:56", address(bscGasToken));
        universalCore.setDefaultFeeTier(address(bscGasToken), FEE_TIER);

        // Setup BSC pool
        address bscPool = makeAddr("bscPool");
        if (address(mockWPC) < address(bscGasToken)) {
            mockFactory.setPool(address(mockWPC), address(bscGasToken), FEE_TIER, bscPool);
        } else {
            mockFactory.setPool(address(bscGasToken), address(mockWPC), FEE_TIER, bscPool);
        }

        // Deploy BSC PRC20
        PRC20 bscPrc20Impl = new PRC20();
        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "BSC PRC20",
            "BPRC20",
            18,
            "eip155:56",
            IPRC20.TokenType.ERC20,
            PROTOCOL_FEE,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );
        address bscProxy = deployUpgradeableContract(address(bscPrc20Impl), initData);

        // Swap for ETH chain gas token
        vm.prank(gateway);
        uint256 ethGasOut = universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), vault, 0, 0, 0
        );

        // Swap for BSC chain gas token
        vm.prank(gateway);
        uint256 bscGasOut = universalCore.swapPCForGasToken{value: 1 ether}(
            bscProxy, vault, 0, 0, 0
        );

        // Both swaps should succeed with different gas tokens
        assertGt(ethGasOut, 0);
        assertGt(bscGasOut, 0);
        // Vault received both tokens
        assertEq(gasTokenMock.balanceOf(vault), ethGasOut);
        assertEq(bscGasToken.balanceOf(vault), bscGasOut);
    }

    // ========================================
    // 4) Edge Cases
    // ========================================

    function test_SwapPCForGasToken_WhenPausedReverts() public {
        universalCore.pause();

        vm.prank(gateway);
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector));
        universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), vault, 0, 0, 0
        );
    }

    function test_SwapPCForGasToken_ExpiredDeadlineReverts() public {
        vm.warp(1000);
        uint256 pastDeadline = block.timestamp - 1;

        vm.prank(gateway);
        vm.expectRevert(CommonErrors.DeadlineExpired.selector);
        universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), vault, FEE_TIER, 0, pastDeadline
        );
    }

    function test_SwapPCForGasToken_PoolNotFoundReverts() public {
        // Use a fee tier with no pool configured
        uint24 unusedFeeTier = 500;

        vm.prank(gateway);
        vm.expectRevert(UniversalCoreErrors.PoolNotFound.selector);
        universalCore.swapPCForGasToken{value: 1 ether}(
            address(prc20Token), vault, unusedFeeTier, 0, 0
        );
    }

    // ========================================
    // 5) Storage & Constants
    // ========================================

    function test_GatewayRole_Value() public view {
        assertEq(universalCore.GATEWAY_ROLE(), keccak256("GATEWAY_ROLE"));
    }

    function test_ExistingStorage_Preserved() public view {
        assertEq(universalCore.gasPriceByChainNamespace(CHAIN_NAMESPACE), GAS_PRICE);
        assertEq(universalCore.gasTokenPRC20ByChainNamespace(CHAIN_NAMESPACE), address(gasTokenMock));
        assertTrue(universalCore.isSupportedToken(address(gasTokenMock)) == false);
        assertEq(universalCore.BASE_GAS_LIMIT(), 500_000);
    }
}
