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
    address public user;
    address public nonGateway;

    string public constant CHAIN_NAMESPACE = "eip155:1";
    uint256 public constant PROTOCOL_FEE = 1000;
    uint256 public constant GAS_PRICE = 50 * 10 ** 9;
    uint24 public constant FEE_TIER = 3000;

    uint256 public constant GAS_FEE = 0.4 ether;
    uint256 public constant PROTOCOL_FEE_AMOUNT = 0.1 ether;

    event SwapAndBurnGas(
        address indexed gasToken, address indexed vault,
        uint256 pcIn, uint256 gasFee, uint256 protocolFee,
        uint24 fee, address indexed caller
    );

    function setUp() public {
        deployer = address(this);
        gateway = makeAddr("gateway");
        vault = makeAddr("vault");
        user = makeAddr("user");
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

    function test_SwapAndBurnGas_OnlyGatewayRole() public {
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
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );
    }

    function test_SwapAndBurnGas_UEModuleCannotCall() public {
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
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );
    }

    function test_SwapAndBurnGas_AdminCanGrantRole() public {
        address newGateway = makeAddr("newGateway");
        vm.deal(newGateway, 1 ether);

        universalCore.grantRole(universalCore.GATEWAY_ROLE(), newGateway);

        vm.prank(newGateway);
        (uint256 gasTokenOut, ) = universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );
        assertEq(gasTokenOut, GAS_FEE + PROTOCOL_FEE_AMOUNT);
    }

    // ========================================
    // 2) Input Validation
    // ========================================

    function test_SwapAndBurnGas_ZeroGasTokenReverts() public {
        vm.prank(gateway);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(0), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );
    }

    function test_SwapAndBurnGas_ZeroVaultReverts() public {
        vm.prank(gateway);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), address(0), 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );
    }

    function test_SwapAndBurnGas_ZeroCallerReverts() public {
        vm.prank(gateway);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, address(0)
        );
    }

    function test_SwapAndBurnGas_ZeroMsgValueReverts() public {
        vm.prank(gateway);
        vm.expectRevert(CommonErrors.ZeroAmount.selector);
        universalCore.swapAndBurnGas{value: 0}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );
    }

    function test_SwapAndBurnGas_ZeroGasFeeReverts() public {
        vm.prank(gateway);
        vm.expectRevert(CommonErrors.ZeroAmount.selector);
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, 0, PROTOCOL_FEE_AMOUNT, 0, user
        );
    }

    function test_SwapAndBurnGas_NoDefaultFeeReverts() public {
        MockPRC20 newGasToken = new MockPRC20();

        vm.prank(gateway);
        vm.expectRevert(UniversalCoreErrors.InvalidFeeTier.selector);
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(newGasToken), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );
    }

    // ========================================
    // 3) Happy Path
    // ========================================

    function test_SwapAndBurnGas_HappyPath() public {
        uint256 totalRequired = GAS_FEE + PROTOCOL_FEE_AMOUNT;

        vm.prank(gateway);
        (uint256 gasTokenOut, uint256 refund) = universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );

        assertEq(gasTokenOut, totalRequired);

        // Mock router consumes amountOut * 100 / 90 as input
        uint256 expectedInput = totalRequired * 100 / 90;
        assertEq(refund, 1 ether - expectedInput);
    }

    function test_SwapAndBurnGas_BurnsGasFee() public {
        uint256 supplyBefore = gasTokenMock.totalSupply();

        vm.prank(gateway);
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );

        uint256 supplyAfter = gasTokenMock.totalSupply();
        // Total supply increased by totalRequired (from swap), then decreased by gasFee (from burn)
        // Net: supplyAfter = supplyBefore + totalRequired - gasFee = supplyBefore + protocolFee
        assertEq(supplyAfter, supplyBefore + PROTOCOL_FEE_AMOUNT);
    }

    function test_SwapAndBurnGas_VaultReceivesOnlyProtocolFee() public {
        uint256 vaultBalanceBefore = gasTokenMock.balanceOf(vault);

        vm.prank(gateway);
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );

        uint256 vaultBalanceAfter = gasTokenMock.balanceOf(vault);
        assertEq(vaultBalanceAfter - vaultBalanceBefore, PROTOCOL_FEE_AMOUNT);
    }

    function test_SwapAndBurnGas_ZeroProtocolFee() public {
        uint256 supplyBefore = gasTokenMock.totalSupply();
        uint256 vaultBalanceBefore = gasTokenMock.balanceOf(vault);

        vm.prank(gateway);
        (uint256 gasTokenOut, ) = universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, 0, 0, user
        );

        assertEq(gasTokenOut, GAS_FEE);
        // All burned, nothing to vault
        assertEq(gasTokenMock.totalSupply(), supplyBefore);
        assertEq(gasTokenMock.balanceOf(vault), vaultBalanceBefore);
    }

    function test_SwapAndBurnGas_UniversalCoreHoldsNoTokensAfter() public {
        vm.prank(gateway);
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );

        assertEq(gasTokenMock.balanceOf(address(universalCore)), 0);
        assertEq(address(universalCore).balance, 0);
    }

    function test_SwapAndBurnGas_EmitsEvent() public {
        uint256 totalRequired = GAS_FEE + PROTOCOL_FEE_AMOUNT;
        uint256 expectedInput = totalRequired * 100 / 90;

        vm.expectEmit(true, true, true, true);
        emit SwapAndBurnGas(
            address(gasTokenMock), vault,
            expectedInput, GAS_FEE, PROTOCOL_FEE_AMOUNT, FEE_TIER, user
        );

        vm.prank(gateway);
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );
    }

    function test_SwapAndBurnGas_ExplicitParams() public {
        uint256 explicitDeadline = block.timestamp + 1 hours;

        vm.prank(gateway);
        (uint256 gasTokenOut, ) = universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, FEE_TIER, GAS_FEE, PROTOCOL_FEE_AMOUNT, explicitDeadline, user
        );

        assertEq(gasTokenOut, GAS_FEE + PROTOCOL_FEE_AMOUNT);
    }

    function test_SwapAndBurnGas_MultipleChains() public {
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

        // Swap for ETH chain gas token
        vm.prank(gateway);
        (uint256 ethGasOut, ) = universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );

        // Swap for BSC chain gas token
        vm.prank(gateway);
        (uint256 bscGasOut, ) = universalCore.swapAndBurnGas{value: 1 ether}(
            address(bscGasToken), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );

        uint256 totalRequired = GAS_FEE + PROTOCOL_FEE_AMOUNT;
        assertEq(ethGasOut, totalRequired);
        assertEq(bscGasOut, totalRequired);
        // Vault received only protocolFee from each
        assertEq(gasTokenMock.balanceOf(vault), PROTOCOL_FEE_AMOUNT);
        assertEq(bscGasToken.balanceOf(vault), PROTOCOL_FEE_AMOUNT);
    }

    // ========================================
    // 4) Refund Behavior
    // ========================================

    function test_SwapAndBurnGas_RefundExcessPC() public {
        uint256 totalRequired = GAS_FEE + PROTOCOL_FEE_AMOUNT;
        uint256 sendAmount = 2 ether;
        uint256 expectedInput = totalRequired * 100 / 90;
        uint256 expectedRefund = sendAmount - expectedInput;

        uint256 userBalanceBefore = user.balance;

        vm.prank(gateway);
        (uint256 gasTokenOut, uint256 refund) = universalCore.swapAndBurnGas{value: sendAmount}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );

        assertEq(gasTokenOut, totalRequired);
        assertEq(refund, expectedRefund);
        assertEq(user.balance, userBalanceBefore + refund);
        assertEq(address(universalCore).balance, 0);
    }

    function test_SwapAndBurnGas_NoRefundWhenExactMatch() public {
        uint256 totalRequired = GAS_FEE + PROTOCOL_FEE_AMOUNT;
        // Mock router needs totalRequired * 100 / 90
        uint256 exactInput = totalRequired * 100 / 90;

        vm.prank(gateway);
        (uint256 gasTokenOut, uint256 refund) = universalCore.swapAndBurnGas{value: exactInput}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );

        assertEq(gasTokenOut, totalRequired);
        assertEq(refund, 0);
        assertEq(address(universalCore).balance, 0);
    }

    function test_SwapAndBurnGas_RefundGoesToCaller() public {
        uint256 userBalanceBefore = user.balance;
        uint256 gatewayBalanceBefore = gateway.balance;
        uint256 vaultBalanceBefore = vault.balance;

        vm.prank(gateway);
        (, uint256 refund) = universalCore.swapAndBurnGas{value: 2 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );

        assertGt(refund, 0);
        assertEq(user.balance, userBalanceBefore + refund);
        assertEq(gateway.balance, gatewayBalanceBefore - 2 ether);
        assertEq(vault.balance, vaultBalanceBefore);
    }

    // ========================================
    // 5) Edge Cases
    // ========================================

    function test_SwapAndBurnGas_WhenPausedReverts() public {
        universalCore.pause();

        vm.prank(gateway);
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector));
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, 0, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );
    }

    function test_SwapAndBurnGas_ExpiredDeadlineReverts() public {
        vm.warp(1000);
        uint256 pastDeadline = block.timestamp - 1;

        vm.prank(gateway);
        vm.expectRevert(CommonErrors.DeadlineExpired.selector);
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, FEE_TIER, GAS_FEE, PROTOCOL_FEE_AMOUNT, pastDeadline, user
        );
    }

    function test_SwapAndBurnGas_PoolNotFoundReverts() public {
        uint24 unusedFeeTier = 500;

        vm.prank(gateway);
        vm.expectRevert(UniversalCoreErrors.PoolNotFound.selector);
        universalCore.swapAndBurnGas{value: 1 ether}(
            address(gasTokenMock), vault, unusedFeeTier, GAS_FEE, PROTOCOL_FEE_AMOUNT, 0, user
        );
    }

    // ========================================
    // 6) withdrawGasFee / withdrawGasFeeWithGasLimit
    // ========================================

    function test_WithdrawGasFee_Returns4Values() public view {
        (
            address gasToken,
            uint256 gasFee,
            uint256 protocolFee,
            string memory chainNamespace
        ) = universalCore.withdrawGasFee(address(prc20Token));

        assertEq(gasToken, address(gasTokenMock));
        assertEq(gasFee, GAS_PRICE * universalCore.BASE_GAS_LIMIT());
        assertEq(protocolFee, prc20Token.PC_PROTOCOL_FEE());
        assertEq(keccak256(bytes(chainNamespace)), keccak256(bytes(CHAIN_NAMESPACE)));
    }

    function test_WithdrawGasFeeWithGasLimit_Returns4Values() public view {
        uint256 customGasLimit = 300_000;
        (
            address gasToken,
            uint256 gasFee,
            uint256 protocolFee,
            string memory chainNamespace
        ) = universalCore.withdrawGasFeeWithGasLimit(address(prc20Token), customGasLimit);

        assertEq(gasToken, address(gasTokenMock));
        assertEq(gasFee, GAS_PRICE * customGasLimit);
        assertEq(protocolFee, PROTOCOL_FEE);
        assertEq(keccak256(bytes(chainNamespace)), keccak256(bytes(CHAIN_NAMESPACE)));
    }

    // ========================================
    // 7) Storage & Constants
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
