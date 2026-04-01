// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../src/UniversalCore.sol";
import "../../src/interfaces/IPRC20.sol";
import "../../src/interfaces/IUniversalCore.sol";
import {UniversalCoreErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import "../../test/helpers/UpgradeableContractHelper.sol";
import "../../test/mocks/MockUniswapV3Factory.sol";
import "../../test/mocks/MockUniswapV3Router.sol";
import "../../test/mocks/MockPRC20.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/// @dev Mock that satisfies both MockPRC20 (for mock router) and WPC (for withdraw) interfaces.
contract MockWPCLike {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function deposit(address to, uint256 amount) external returns (bool) {
        balanceOf[to] += amount;
        totalSupply += amount;
        return true;
    }

    function approve(address, uint256) external returns (bool) {
        return true;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function withdraw(uint256 wad) external {
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).transfer(wad);
    }

    receive() external payable {}
}

contract UniversalCoreRefundTest is Test, UpgradeableContractHelper {
    UniversalCore public universalCore;
    MockUniswapV3Factory public mockFactory;
    MockUniswapV3Router public mockRouter;
    MockWPCLike public mockWPC;
    MockPRC20 public gasTokenMock;

    address public constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    address public recipient;
    address public nonUEModule;
    address public pauser;

    uint24 public constant FEE_TIER = 3000;
    uint256 public constant REFUND_AMOUNT = 2 ether;
    uint256 public constant MIN_PC_OUT = 1 ether;

    event RefundUnusedGas(
        address indexed gasToken, uint256 amount, address indexed recipient, bool swapped, uint256 pcOut
    );

    event DepositPRC20WithAutoSwap(
        address prc20, uint256 amountIn, address pcToken, uint256 amountOut, uint24 fee, address recipient
    );

    function setUp() public {
        recipient = makeAddr("recipient");
        nonUEModule = makeAddr("nonUEModule");
        pauser = makeAddr("pauser");

        mockFactory = new MockUniswapV3Factory();
        mockRouter = new MockUniswapV3Router();
        mockWPC = new MockWPCLike();
        gasTokenMock = new MockPRC20();

        // Fund MockWPCLike with ETH for withdraw calls
        vm.deal(address(mockWPC), 100 ether);

        UniversalCore implementation = new UniversalCore();
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector,
            address(mockWPC),
            address(mockFactory),
            address(mockRouter),
            pauser
        );
        address proxyAddress = deployUpgradeableContract(address(implementation), initData);
        universalCore = UniversalCore(payable(proxyAddress));

        // Configure auto-swap support
        universalCore.setAutoSwapSupported(address(gasTokenMock), true);
        universalCore.setDefaultFeeTier(address(gasTokenMock), FEE_TIER);

        // Setup mock pool (gasToken <-> wPC)
        address pool = makeAddr("mockPool");
        if (address(gasTokenMock) < address(mockWPC)) {
            mockFactory.setPool(address(gasTokenMock), address(mockWPC), FEE_TIER, pool);
        } else {
            mockFactory.setPool(address(mockWPC), address(gasTokenMock), FEE_TIER, pool);
        }
    }

    // ========================================
    // Access Control
    // ========================================

    function test_RefundUnusedGas_OnlyUEModule() public {
        vm.prank(nonUEModule);
        vm.expectRevert(UniversalCoreErrors.CallerIsNotUEModule.selector);
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, recipient, false, 0, 0);
    }

    function test_RefundUnusedGas_WhenPaused_Reverts() public {
        vm.prank(pauser);
        universalCore.pause();

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector));
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, recipient, false, 0, 0);
    }

    // ========================================
    // Input Validation
    // ========================================

    function test_RefundUnusedGas_ZeroGasToken_Reverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.refundUnusedGas(address(0), REFUND_AMOUNT, recipient, false, 0, 0);
    }

    function test_RefundUnusedGas_ZeroAmount_Reverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(CommonErrors.ZeroAmount.selector);
        universalCore.refundUnusedGas(address(gasTokenMock), 0, recipient, false, 0, 0);
    }

    function test_RefundUnusedGas_ZeroRecipient_Reverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, address(0), false, 0, 0);
    }

    function test_RefundUnusedGas_InvalidTarget_UEModule_Reverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.InvalidTarget.selector);
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, UNIVERSAL_EXECUTOR_MODULE, false, 0, 0);
    }

    function test_RefundUnusedGas_InvalidTarget_Self_Reverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.InvalidTarget.selector);
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, address(universalCore), false, 0, 0);
    }

    function test_RefundUnusedGas_WithSwap_ZeroMinPCOut_Reverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.MinPCOutRequired.selector);
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, recipient, true, 0, 0);
    }

    function test_RefundUnusedGas_WithSwap_NotSupported_Reverts() public {
        MockPRC20 unsupported = new MockPRC20();

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.AutoSwapNotSupported.selector);
        universalCore.refundUnusedGas(address(unsupported), REFUND_AMOUNT, recipient, true, 0, MIN_PC_OUT);
    }

    function test_RefundUnusedGas_WithSwap_NoPool_Reverts() public {
        MockPRC20 noPool = new MockPRC20();
        universalCore.setAutoSwapSupported(address(noPool), true);
        universalCore.setDefaultFeeTier(address(noPool), FEE_TIER);

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.PoolNotFound.selector);
        universalCore.refundUnusedGas(address(noPool), REFUND_AMOUNT, recipient, true, 0, MIN_PC_OUT);
    }

    // ========================================
    // Happy Path (no swap)
    // ========================================

    function test_RefundUnusedGas_NoSwap_DepositsPRC20() public {
        uint256 balanceBefore = gasTokenMock.balanceOf(recipient);

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, recipient, false, 0, 0);

        assertEq(gasTokenMock.balanceOf(recipient), balanceBefore + REFUND_AMOUNT);
    }

    function test_RefundUnusedGas_NoSwap_EmitsEvent() public {
        vm.expectEmit(true, true, false, true);
        emit RefundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, recipient, false, 0);

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, recipient, false, 0, 0);
    }

    // ========================================
    // Happy Path (with swap) — delivers native PC
    // ========================================

    function test_RefundUnusedGas_WithSwap_SendsNativePC() public {
        uint256 balanceBefore = recipient.balance;
        uint256 expectedOut = REFUND_AMOUNT * 90 / 100; // mock router: 90% output

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, recipient, true, FEE_TIER, expectedOut);

        assertEq(recipient.balance, balanceBefore + expectedOut);
    }

    function test_RefundUnusedGas_WithSwap_EmitsEvent() public {
        uint256 expectedOut = REFUND_AMOUNT * 90 / 100;

        vm.expectEmit(true, true, false, true);
        emit RefundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, recipient, true, expectedOut);

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, recipient, true, FEE_TIER, expectedOut);
    }

    function test_RefundUnusedGas_WithSwap_UsesDefaultFee() public {
        uint256 expectedOut = REFUND_AMOUNT * 90 / 100;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, recipient, true, 0, expectedOut);

        assertEq(recipient.balance, expectedOut);
    }

    function test_RefundUnusedGas_WithSwap_ExplicitFee() public {
        uint256 expectedOut = REFUND_AMOUNT * 90 / 100;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(address(gasTokenMock), REFUND_AMOUNT, recipient, true, FEE_TIER, expectedOut);

        assertEq(recipient.balance, expectedOut);
    }

    // ========================================
    // Regression: depositPRC20WithAutoSwap — delivers native PC
    // ========================================

    function test_DepositPRC20WithAutoSwap_StillWorks() public {
        address target = makeAddr("target");
        uint256 amount = 1 ether;
        uint256 expectedOut = amount * 90 / 100;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(address(gasTokenMock), amount, target, FEE_TIER, expectedOut, 0);

        assertEq(target.balance, expectedOut);
    }

    function test_DepositPRC20WithAutoSwap_EmitsResolvedFee() public {
        address target = makeAddr("target");
        uint256 amount = 1 ether;
        uint256 expectedOut = amount * 90 / 100;

        vm.expectEmit(false, false, false, true);
        emit DepositPRC20WithAutoSwap(address(gasTokenMock), amount, address(mockWPC), expectedOut, FEE_TIER, target);

        // Pass fee=0 so it resolves to default FEE_TIER
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(address(gasTokenMock), amount, target, 0, expectedOut, 0);
    }
}
