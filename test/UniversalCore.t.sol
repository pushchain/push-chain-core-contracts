// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../src/UniversalCore.sol";
import "../src/PRC20.sol";
import "../src/interfaces/IPRC20.sol";
import "../src/interfaces/IUniversalCore.sol";
import "../src/libraries/Errors.sol";
import "../test/helpers/UpgradeableContractHelper.sol";
import "../test/mocks/MockUniswapV3Factory.sol";
import "../test/mocks/MockUniswapV3Router.sol";
import "../test/mocks/MockUniswapV3Quoter.sol";
import "../test/mocks/MockWPC.sol";
import "../test/mocks/MockPRC20.sol";
import "../test/mocks/MaliciousPRC20.sol";
import "../test/mocks/RevertingPRC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

contract UniversalCoreTest is Test, UpgradeableContractHelper {
    UniversalCore public universalCore;
    PRC20 public prc20Token;
    MockUniswapV3Factory public mockFactory;
    MockUniswapV3Router public mockRouter;
    MockUniswapV3Quoter public mockQuoter;
    MockWPC public mockWPC;
    
    address public constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    address public deployer;
    address public nonOwner;
    address public nonUEModule;
    address public user;
    MockPRC20 public mockPRC20;
    
    uint256 public constant CHAIN_ID = 1;
    uint256 public constant GAS_LIMIT = 21000;
    uint256 public constant PROTOCOL_FEE = 1000;
    uint24 public constant FEE_TIER = 3000;
    
    event SystemContractDeployed();
    event SetAutoSwapSupported(address indexed token, bool supported);
    event SetWPC(address indexed wpc);
    event SetGasPCPool(uint256 indexed chainId, address indexed pool, uint24 fee);
    event SetGasPrice(uint256 indexed chainId, uint256 price);
    event SetGasToken(uint256 indexed chainId, address indexed prc20);
    event DepositPRC20WithAutoSwap(
        address indexed prc20,
        uint256 amountIn,
        address indexed pcToken,
        uint256 amountOut,
        uint24 fee,
        address indexed target
    );
    event Paused(address account);
    event Unpaused(address account);

    function setUp() public {
        // Setup accounts
        deployer = address(this); // The test contract is the deployer
        nonOwner = makeAddr("nonOwner");
        nonUEModule = makeAddr("nonUEModule");
        user = makeAddr("user");
        
        // Deploy mocks
        mockFactory = new MockUniswapV3Factory();
        mockRouter = new MockUniswapV3Router();
        mockQuoter = new MockUniswapV3Quoter();
        mockWPC = new MockWPC();
        mockPRC20 = new MockPRC20();

        // Deploy PRC20 token implementation
        PRC20 implementationPrc20 = new PRC20();

        // Deploy proxy and initialize
        bytes memory initDataPrc20 = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "Test PRC20",
            "TPRC20",
            18,
            CHAIN_ID,
            IPRC20.TokenType.ERC20,
            GAS_LIMIT,
            PROTOCOL_FEE,
            address(0x1), // Temporary address, will be updated
            makeAddr("sourceERC20")
        );

        address proxyAddressPrc20 = deployUpgradeableContract(address(implementationPrc20), initDataPrc20);
        prc20Token = PRC20(payable(proxyAddressPrc20));
        
        // Deploy UniversalCore implementation
        UniversalCore implementation = new UniversalCore();
        
        // Deploy proxy and initialize
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector,
            address(mockWPC),
            address(mockFactory),
            address(mockRouter),
            address(mockQuoter)
        );
        
        address proxyAddress = deployUpgradeableContract(address(implementation), initData);
        universalCore = UniversalCore(payable(proxyAddress));
        
        // Update PRC20 universalCore contract
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        prc20Token.updateUniversalCore(address(universalCore));
        
        // Setup mock pool
        address pool = makeAddr("mockPool");
        mockFactory.setPool(address(mockWPC), address(prc20Token), FEE_TIER, pool);
    }

    // ========================================
    // 0) Initialization & Roles
    // ========================================

    function test_Constructor_DisablesInitializers() public {
        UniversalCore newHandler = new UniversalCore();
        // Should not be able to call initialize on implementation directly
        vm.expectRevert();
        newHandler.initialize(
            address(mockWPC),
            address(mockFactory),
            address(mockRouter),
            address(mockQuoter)
        );
    }

    function test_Initialize_GrantsAdminRoleToDeployer() public {
        // Deploy new universalCore with different deployer
        address newDeployer = makeAddr("newDeployer");
        vm.startPrank(newDeployer);
        
        UniversalCore newImplementation = new UniversalCore();
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector,
            address(mockWPC),
            address(mockFactory),
            address(mockRouter),
            address(mockQuoter)
        );
        
        address newProxyAddress = deployUpgradeableContract(address(newImplementation), initData);
        UniversalCore newHandler = UniversalCore(payable(newProxyAddress));
        
        // Check that deployer has admin role
        assertTrue(newHandler.hasRole(newHandler.DEFAULT_ADMIN_ROLE(), newDeployer));
        vm.stopPrank();
    }

    function test_Initialize_SetsAddresses() public view {
        assertEq(universalCore.wPCContractAddress(), address(mockWPC));
        assertEq(universalCore.uniswapV3FactoryAddress(), address(mockFactory));
        assertEq(universalCore.uniswapV3SwapRouterAddress(), address(mockRouter));
        assertEq(universalCore.uniswapV3QuoterAddress(), address(mockQuoter));
    }

    function test_Initialize_RevertsOnSecondCall() public {
        vm.expectRevert();
        universalCore.initialize(
            address(mockWPC),
            address(mockFactory),
            address(mockRouter),
            address(mockQuoter)
        );
    }

    function test_UniversalExecutorModule_IsImmutable() public view {
        assertEq(universalCore.UNIVERSAL_EXECUTOR_MODULE(), UNIVERSAL_EXECUTOR_MODULE);
    }

    function test_ReceiveETH_Reverts() public {
        // Handler contract has no receive function, so sending ETH should revert
        vm.expectRevert();
        (bool success,) = address(universalCore).call{value: 1 ether}("");
        // Note: This test documents that universalCore doesn't accept ETH directly
        // The assertion will fail if ETH is successfully sent, which is expected
    }

    // ========================================
    // 1) Admin-specific (DEFAULT_ADMIN_ROLE) setters
    // ========================================

    function test_SetAutoSwapSupported_OnlyOwner() public {
        address token = makeAddr("token");
        
        // Non-owner should revert
        vm.prank(nonOwner);
        vm.expectRevert(UniversalCoreErrors.CallerIsNotOwner.selector);
        universalCore.setAutoSwapSupported(token, true);
        
        // Deployer (who has admin role) should succeed
        vm.prank(deployer);
        universalCore.setAutoSwapSupported(token, true);
        assertTrue(universalCore.isAutoSwapSupported(token));
    }

    function test_SetAutoSwapSupported_HappyPath() public {
        address token = makeAddr("token");
        
        vm.prank(deployer);
        universalCore.setAutoSwapSupported(token, true);
        assertTrue(universalCore.isAutoSwapSupported(token));
        
        // Test flipping to false
        vm.prank(deployer);
        universalCore.setAutoSwapSupported(token, false);
        assertFalse(universalCore.isAutoSwapSupported(token));
    }

    function test_SetAutoSwapSupported_ZeroAddressAllowed() public {
        // Current implementation allows zero address
        vm.prank(deployer);
        universalCore.setAutoSwapSupported(address(0), true);
        assertTrue(universalCore.isAutoSwapSupported(address(0)));
    }

    function test_SetWPCContractAddress_OnlyOwner() public {
        address newWPC = makeAddr("newWPC");
        
        // Non-owner should revert
        vm.prank(nonOwner);
        vm.expectRevert(UniversalCoreErrors.CallerIsNotOwner.selector);
        universalCore.setWPCContractAddress(newWPC);
        
        // Deployer (who has admin role) should succeed
        vm.prank(deployer);
        universalCore.setWPCContractAddress(newWPC);
        assertEq(universalCore.wPCContractAddress(), newWPC);
    }

    function test_SetWPCContractAddress_HappyPath() public {
        address newWPC = makeAddr("newWPC");
        
        vm.prank(deployer);
        universalCore.setWPCContractAddress(newWPC);
        
        assertEq(universalCore.wPCContractAddress(), newWPC);
    }

    function test_SetWPCContractAddress_ZeroAddressReverts() public {
        vm.prank(deployer);
        vm.expectRevert(UniversalCoreErrors.ZeroAddress.selector);
        universalCore.setWPCContractAddress(address(0));
    }

    // ========================================
    // 2) UE-module-specific (onlyUEModule) config
    // ========================================

    function test_SetGasPCPool_OnlyUEModule() public {
        address gasToken = makeAddr("gasToken");
        address pool = makeAddr("pool");
        
        // Setup mock pool (both orderings)
        if (address(mockWPC) < gasToken) {
            mockFactory.setPool(address(mockWPC), gasToken, FEE_TIER, pool);
        } else {
            mockFactory.setPool(gasToken, address(mockWPC), FEE_TIER, pool);
        }
        
        // Non-UEM should revert
        vm.prank(nonUEModule);
        vm.expectRevert(UniversalCoreErrors.CallerIsNotUEModule.selector);
        universalCore.setGasPCPool(CHAIN_ID, gasToken, FEE_TIER);
        
        // UEM should succeed
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPCPool(CHAIN_ID, gasToken, FEE_TIER);
    }

    function test_SetGasPCPool_ZeroAddressReverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.ZeroAddress.selector);
        universalCore.setGasPCPool(CHAIN_ID, address(0), FEE_TIER);
    }

    function test_SetGasPCPool_PoolNotFoundReverts() public {
        address gasToken = makeAddr("gasToken");
        
        // Mock factory returns no pool
        mockFactory.setPool(address(mockWPC), gasToken, FEE_TIER, address(0));
        
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.PoolNotFound.selector);
        universalCore.setGasPCPool(CHAIN_ID, gasToken, FEE_TIER);
    }

    function test_SetGasPCPool_HappyPath() public {
        address gasToken = makeAddr("gasToken");
        address pool = makeAddr("pool");
        
        // Setup mock pool (both orderings)
        if (address(mockWPC) < gasToken) {
            mockFactory.setPool(address(mockWPC), gasToken, FEE_TIER, pool);
        } else {
            mockFactory.setPool(gasToken, address(mockWPC), FEE_TIER, pool);
        }
        
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPCPool(CHAIN_ID, gasToken, FEE_TIER);
        
        assertEq(universalCore.gasPCPoolByChainId(CHAIN_ID), pool);
    }

    function test_SetGasPCPool_AddressOrdering() public {
        address gasToken = makeAddr("gasToken");
        address pool = makeAddr("pool");
        
        // Test both ordering scenarios
        if (address(mockWPC) < gasToken) {
            mockFactory.setPool(address(mockWPC), gasToken, FEE_TIER, pool);
        } else {
            mockFactory.setPool(gasToken, address(mockWPC), FEE_TIER, pool);
        }
        
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPCPool(CHAIN_ID, gasToken, FEE_TIER);
        
        assertEq(universalCore.gasPCPoolByChainId(CHAIN_ID), pool);
    }

    function test_SetGasPCPool_AfterWPCChange() public {
        address newWPC = makeAddr("newWPC");
        address gasToken = makeAddr("gasToken");
        address pool = makeAddr("pool");
        
        // Change WPC first
        vm.prank(deployer);
        universalCore.setWPCContractAddress(newWPC);
        
        // Setup pool with new WPC (both orderings)
        if (newWPC < gasToken) {
            mockFactory.setPool(newWPC, gasToken, FEE_TIER, pool);
        } else {
            mockFactory.setPool(gasToken, newWPC, FEE_TIER, pool);
        }
        
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPCPool(CHAIN_ID, gasToken, FEE_TIER);
        
        assertEq(universalCore.gasPCPoolByChainId(CHAIN_ID), pool);
    }

    function test_SetGasPrice_OnlyUEModule() public {
        uint256 price = 1000;
        
        // Non-UEM should revert
        vm.prank(nonUEModule);
        vm.expectRevert(UniversalCoreErrors.CallerIsNotUEModule.selector);
        universalCore.setGasPrice(CHAIN_ID, price);
        
        // UEM should succeed
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPrice(CHAIN_ID, price);
        assertEq(universalCore.gasPriceByChainId(CHAIN_ID), price);
    }

    function test_SetGasPrice_HappyPath() public {
        uint256 price = 1000;
        
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPrice(CHAIN_ID, price);
        
        assertEq(universalCore.gasPriceByChainId(CHAIN_ID), price);
    }

    function test_SetGasPrice_ZeroPriceAllowed() public {
        // Current implementation allows zero price
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPrice(CHAIN_ID, 0);
        assertEq(universalCore.gasPriceByChainId(CHAIN_ID), 0);
    }

    function test_SetGasTokenPRC20_OnlyUEModule() public {
        address prc20 = makeAddr("prc20");
        
        // Non-UEM should revert
        vm.prank(nonUEModule);
        vm.expectRevert(UniversalCoreErrors.CallerIsNotUEModule.selector);
        universalCore.setGasTokenPRC20(CHAIN_ID, prc20);
        
        // UEM should succeed
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasTokenPRC20(CHAIN_ID, prc20);
        assertEq(universalCore.gasTokenPRC20ByChainId(CHAIN_ID), prc20);
    }

    function test_SetGasTokenPRC20_ZeroAddressReverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.ZeroAddress.selector);
        universalCore.setGasTokenPRC20(CHAIN_ID, address(0));
    }

    function test_SetGasTokenPRC20_HappyPath() public {
        address prc20 = makeAddr("prc20");
        
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasTokenPRC20(CHAIN_ID, prc20);
        
        assertEq(universalCore.gasTokenPRC20ByChainId(CHAIN_ID), prc20);
    }

    // ========================================
    // 3) Deposit functions (UE-module only)
    // ========================================

    function test_DepositPRC20Token_OnlyUEModule() public {
        // Non-UEM should revert
        vm.prank(nonUEModule);
        vm.expectRevert(UniversalCoreErrors.CallerIsNotUEModule.selector);
        universalCore.depositPRC20Token(address(prc20Token), 1000, makeAddr("target"));
        
        // UEM should succeed
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20Token(address(prc20Token), 1000, makeAddr("target"));
    }

    function test_DepositPRC20Token_InvalidTargets() public {
        // Target cannot be UNIVERSAL_EXECUTOR_MODULE
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.InvalidTarget.selector);
        universalCore.depositPRC20Token(address(prc20Token), 1000, UNIVERSAL_EXECUTOR_MODULE);
        
        // Target cannot be universalCore contract itself
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.InvalidTarget.selector);
        universalCore.depositPRC20Token(address(prc20Token), 1000, address(universalCore));
    }

    function test_DepositPRC20Token_ZeroAddressAllowed() public {
        // Current implementation allows zero address target
        // Note: PRC20.deposit() will revert on zero address, so this documents current behavior
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(PRC20Errors.ZeroAddress.selector);
        universalCore.depositPRC20Token(address(prc20Token), 1000, address(0));
    }

    function test_DepositPRC20Token_ZeroAmountAllowed() public {
        address target = makeAddr("target");
        
        // Current implementation allows zero amount
        // Note: PRC20.deposit() will revert on zero amount, so this documents current behavior
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(PRC20Errors.ZeroAmount.selector);
        universalCore.depositPRC20Token(address(prc20Token), 0, target);
    }

    function test_DepositPRC20Token_ZeroPRC20Address() public {
        address target = makeAddr("target");
        
        // Zero PRC20 address should cause low-level revert
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert();
        universalCore.depositPRC20Token(address(0), 1000, target);
    }

    function test_DepositPRC20Token_HappyPath() public {
        address target = makeAddr("target");
        uint256 amount = 1000;
        
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20Token(address(prc20Token), amount, target);
        
        // Verify tokens were minted to target
        assertEq(prc20Token.balanceOf(target), amount);
        assertEq(prc20Token.totalSupply(), amount);
    }

    function test_DepositPRC20Token_ReentrancyProtection() public {
        // Deploy malicious PRC20 that tries to reenter
        MaliciousPRC20 maliciousToken = new MaliciousPRC20(address(universalCore));
        
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        // Should revert due to reentrancy attempt
        vm.expectRevert("Reentry failed");
        universalCore.depositPRC20Token(address(maliciousToken), 1000, makeAddr("target"));
    }

    function test_DepositPRC20Token_Atomicity() public {
        // Deploy PRC20 that reverts on deposit
        RevertingPRC20 revertingToken = new RevertingPRC20();
        
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert("Deposit failed");
        universalCore.depositPRC20Token(address(revertingToken), 1000, makeAddr("target"));
        
        // Verify universalCore state unchanged
        assertEq(universalCore.wPCContractAddress(), address(mockWPC));
    }

    // ============ Pause/Unpause Tests ============

    function test_Pause_OnlyOwner() public {
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(UniversalCoreErrors.CallerIsNotOwner.selector));
        universalCore.pause();
    }

    function test_Pause_HappyPath() public {
        vm.prank(deployer);
        vm.expectEmit(true, true, true, true);
        emit Paused(deployer);
        universalCore.pause();
        
        assertTrue(universalCore.paused());
    }

    function test_Unpause_OnlyOwner() public {
        // First pause the contract
        vm.prank(deployer);
        universalCore.pause();
        
        // Try to unpause as non-owner
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(UniversalCoreErrors.CallerIsNotOwner.selector));
        universalCore.unpause();
    }

    function test_Unpause_HappyPath() public {
        // First pause the contract
        vm.prank(deployer);
        universalCore.pause();
        assertTrue(universalCore.paused());
        
        // Unpause
        vm.prank(deployer);
        vm.expectEmit(true, true, true, true);
        emit Unpaused(deployer);
        universalCore.unpause();
        
        assertFalse(universalCore.paused());
    }

    function test_DepositPRC20Token_WhenPaused_Reverts() public {
        // Pause the contract
        vm.prank(deployer);
        universalCore.pause();
        
        // Try to deposit when paused
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector));
        universalCore.depositPRC20Token(address(mockPRC20), 1000, user);
    }

    function test_DepositPRC20WithAutoSwap_WhenPaused_Reverts() public {
        // Setup auto-swap support
        vm.prank(deployer);
        universalCore.setAutoSwapSupported(address(mockPRC20), true);
        
        // Pause the contract
        vm.prank(deployer);
        universalCore.pause();
        
        // Try to deposit with auto-swap when paused
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector));
        universalCore.depositPRC20WithAutoSwap(address(mockPRC20), 1000, user, 0, 0, 0);
    }

    function test_DepositPRC20Token_AfterUnpause_Works() public {
        // Pause the contract
        vm.prank(deployer);
        universalCore.pause();
        
        // Unpause the contract
        vm.prank(deployer);
        universalCore.unpause();
        
        // Now deposit should work
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20Token(address(mockPRC20), 1000, user);
        
        assertEq(mockPRC20.balanceOf(user), 1000);
    }
}

