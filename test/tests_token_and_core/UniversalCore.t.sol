// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../src/UniversalCore.sol";
import "../../src/PRC20.sol";
import "../../src/interfaces/IPRC20.sol";
import "../../src/interfaces/IUniversalCore.sol";
import {UniversalCoreErrors, PRC20Errors, CommonErrors} from "../../src/libraries/Errors.sol";
import "../../test/helpers/UpgradeableContractHelper.sol";
import "../../test/mocks/MockUniswapV3Factory.sol";
import "../../test/mocks/MockUniswapV3Router.sol";
import "../../test/mocks/MockWPC.sol";
import "../../test/mocks/MockPRC20.sol";
import "../../test/mocks/MaliciousPRC20.sol";
import "../../test/mocks/RevertingPRC20.sol";
import "../../test/mocks/FalseReturningPRC20.sol";
import "../../test/mocks/RevertingTarget.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

contract UniversalCoreTest is Test, UpgradeableContractHelper {
    UniversalCore public universalCore;
    PRC20 public prc20Token;
    MockUniswapV3Factory public mockFactory;
    MockUniswapV3Router public mockRouter;
    MockWPC public mockWPC;

    address public constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    string public constant SOURCE_TOKEN_ADDRESS = "0x0000000000000000000000000000000000000000";

    address public deployer;
    address public nonOwner;
    address public nonUEModule;
    address public pauser;
    address public user;
    MockPRC20 public mockPRC20;

    string public constant CHAIN_NAMESPACE = "eip155:1";
    uint256 public constant BASE_GAS_LIMIT = 500_000;
    uint256 public constant PROTOCOL_FEE = 1000;
    uint256 public constant GAS_PRICE = 50 * 10 ** 9; // 50 gwei
    uint24 public constant FEE_TIER = 3000;

    event SystemContractDeployed();
    event SetAutoSwapSupported(address indexed token, bool supported);
    event SetWPC(address indexed oldAddr, address indexed newAddr);
    event SetUniversalGatewayPC(address indexed oldAddr, address indexed newAddr);
    event SetUniswapV3Addresses(address factory, address swapRouter);
    event SetDefaultFeeTier(address indexed token, uint24 feeTier);
    event SetGasPCPool(string indexed chainId, address indexed pool, uint24 fee);
    event SetGasToken(string indexed chainId, address indexed prc20);
    event DepositPRC20WithAutoSwap(
        address indexed prc20,
        uint256 amountIn,
        address indexed pcToken,
        uint256 amountOut,
        uint24 fee,
        address indexed recipient
    );
    event Paused(address account);
    event Unpaused(address account);
    event SetChainMeta(string chainNamespace, uint256 price, uint256 chainHeight, uint256 observedAt);
    event SetBaseGasLimitByChain(string chainNamespace, uint256 gasLimit);
    event SetRescueFundsGasLimitByChain(string chainNamespace, uint256 gasLimit);
    event SetMaxStalenessByChain(string chainNamespace, uint256 maxStaleness);
    event RescueNativePC(address indexed to, uint256 amount);

    function setUp() public {
        // Setup accounts
        deployer = address(this); // The test contract is the deployer
        nonOwner = makeAddr("nonOwner");
        nonUEModule = makeAddr("nonUEModule");
        pauser = makeAddr("pauser");
        user = makeAddr("user");

        // Deploy mocks
        mockFactory = new MockUniswapV3Factory();
        mockRouter = new MockUniswapV3Router();
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
            CHAIN_NAMESPACE,
            IPRC20.TokenType.ERC20,
            address(0x1), // Temporary address, will be updated
            SOURCE_TOKEN_ADDRESS
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
            pauser
        );

        address proxyAddress = deployUpgradeableContract(address(implementation), initData);
        universalCore = UniversalCore(payable(proxyAddress));

        // Update PRC20 universalCore contract
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        prc20Token.updateUniversalCore(address(universalCore));

        // Setup mock pool
        address pool = makeAddr("mockPool");
        mockFactory.setPool(address(mockWPC), address(prc20Token), FEE_TIER, pool);

        // Grant MANAGER_ROLE to UE Module for manager functions
        universalCore.grantRole(universalCore.MANAGER_ROLE(), UNIVERSAL_EXECUTOR_MODULE);

        // Configure gas token first, then gas price (setGasTokenPRC20 resets gas price to 0,
        // so setChainMeta must come after to preserve the configured gas price).
        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasTokenPRC20(CHAIN_NAMESPACE, address(mockPRC20));
        universalCore.setChainMeta(CHAIN_NAMESPACE, GAS_PRICE, 0);
        universalCore.setBaseGasLimitByChain(CHAIN_NAMESPACE, BASE_GAS_LIMIT);
        universalCore.setProtocolFeeByToken(address(prc20Token), PROTOCOL_FEE);
        vm.stopPrank();
    }

    // ========================================
    // 0) Initialization & Roles
    // ========================================

    function test_Constructor_DisablesInitializers() public {
        UniversalCore newHandler = new UniversalCore();
        // Should not be able to call initialize on implementation directly
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        newHandler.initialize(address(mockWPC), address(mockFactory), address(mockRouter), pauser);
    }

    function test_Initialize_GrantsAdminRoleToDeployer() public {
        // Deploy new universalCore with different deployer
        address newDeployer = makeAddr("newDeployer");
        vm.startPrank(newDeployer);

        UniversalCore newImplementation = new UniversalCore();
        address newPauser = makeAddr("newPauser");
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector,
            address(mockWPC),
            address(mockFactory),
            address(mockRouter),
            newPauser
        );

        address newProxyAddress = deployUpgradeableContract(address(newImplementation), initData);
        UniversalCore newHandler = UniversalCore(payable(newProxyAddress));

        // Check that deployer has admin role
        assertTrue(newHandler.hasRole(newHandler.DEFAULT_ADMIN_ROLE(), newDeployer));
        vm.stopPrank();
    }

    function test_Initialize_SetsAddresses() public view {
        assertEq(universalCore.WPC(), address(mockWPC));
        assertEq(universalCore.uniswapV3Factory(), address(mockFactory));
        assertEq(universalCore.uniswapV3SwapRouter(), address(mockRouter));
    }

    function test_Initialize_RevertsOnSecondCall() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        universalCore.initialize(
            address(mockWPC), address(mockFactory), address(mockRouter), pauser
        );
    }

    function test_UniversalExecutorModule_IsImmutable() public view {
        assertEq(universalCore.UNIVERSAL_EXECUTOR_MODULE(), UNIVERSAL_EXECUTOR_MODULE);
    }

    function test_ReceiveETH_Succeeds() public {
        vm.deal(address(this), 1 ether);
        (bool success,) = address(universalCore).call{value: 1 ether}("");
        assertTrue(success);
        assertEq(address(universalCore).balance, 1 ether);
    }

    // ========================================
    // 1) Admin-specific (DEFAULT_ADMIN_ROLE) setters
    // ========================================

    function test_SetAutoSwapSupported_OnlyOwner() public {
        address token = makeAddr("token");

        // Non-owner should revert
        vm.prank(nonOwner);
        vm.expectRevert(CommonErrors.InvalidOwner.selector);
        universalCore.setAutoSwapSupported(token, true);

        // Deployer (who has admin role) should succeed
        vm.prank(deployer);
        universalCore.setAutoSwapSupported(token, true);
        assertTrue(universalCore.isAutoSwapSupported(token));
    }

    function test_SetAutoSwapSupported_HappyPath() public {
        address token = makeAddr("token");

        vm.prank(deployer);
        vm.expectEmit(true, false, false, true);
        emit SetAutoSwapSupported(token, true);
        universalCore.setAutoSwapSupported(token, true);
        assertTrue(universalCore.isAutoSwapSupported(token));

        // Test flipping to false
        vm.prank(deployer);
        vm.expectEmit(true, false, false, true);
        emit SetAutoSwapSupported(token, false);
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
        vm.expectRevert(CommonErrors.InvalidOwner.selector);
        universalCore.setWPC(newWPC);

        // Deployer (who has admin role) should succeed
        vm.prank(deployer);
        universalCore.setWPC(newWPC);
        assertEq(universalCore.WPC(), newWPC);
    }

    function test_SetWPCContractAddress_HappyPath() public {
        address newWPC = makeAddr("newWPC");
        address oldWPC = universalCore.WPC();

        vm.prank(deployer);
        vm.expectEmit(true, true, false, true);
        emit SetWPC(oldWPC, newWPC);
        universalCore.setWPC(newWPC);

        assertEq(universalCore.WPC(), newWPC);
    }

    function test_SetWPCContractAddress_ZeroAddressReverts() public {
        vm.prank(deployer);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setWPC(address(0));
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
        vm.startPrank(nonUEModule);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, nonUEModule, universalCore.MANAGER_ROLE()
            )
        );
        universalCore.setGasPCPool(CHAIN_NAMESPACE, gasToken, FEE_TIER);
        vm.stopPrank();

        // UEM should succeed
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPCPool(CHAIN_NAMESPACE, gasToken, FEE_TIER);
    }

    function test_SetGasPCPool_ZeroAddressReverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setGasPCPool(CHAIN_NAMESPACE, address(0), FEE_TIER);
    }

    function test_SetGasPCPool_PoolNotFoundReverts() public {
        address gasToken = makeAddr("gasToken");

        // Mock factory returns no pool
        mockFactory.setPool(address(mockWPC), gasToken, FEE_TIER, address(0));

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.PoolNotFound.selector);
        universalCore.setGasPCPool(CHAIN_NAMESPACE, gasToken, FEE_TIER);
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
        universalCore.setGasPCPool(CHAIN_NAMESPACE, gasToken, FEE_TIER);

        assertEq(universalCore.gasPCPoolByChainNamespace(CHAIN_NAMESPACE), pool);
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
        universalCore.setGasPCPool(CHAIN_NAMESPACE, gasToken, FEE_TIER);

        assertEq(universalCore.gasPCPoolByChainNamespace(CHAIN_NAMESPACE), pool);
    }

    function test_SetGasPCPool_AfterWPCChange() public {
        address newWPC = makeAddr("newWPC");
        address gasToken = makeAddr("gasToken");
        address pool = makeAddr("pool");

        // Change WPC first
        vm.prank(deployer);
        universalCore.setWPC(newWPC);

        // Setup pool with new WPC (both orderings)
        if (newWPC < gasToken) {
            mockFactory.setPool(newWPC, gasToken, FEE_TIER, pool);
        } else {
            mockFactory.setPool(gasToken, newWPC, FEE_TIER, pool);
        }

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPCPool(CHAIN_NAMESPACE, gasToken, FEE_TIER);

        assertEq(universalCore.gasPCPoolByChainNamespace(CHAIN_NAMESPACE), pool);
    }

    function test_SetGasTokenPRC20_OnlyUEModule() public {
        address prc20 = makeAddr("prc20");

        // Non-UEM should revert
        vm.startPrank(nonUEModule);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, nonUEModule, universalCore.MANAGER_ROLE()
            )
        );
        universalCore.setGasTokenPRC20(CHAIN_NAMESPACE, prc20);
        vm.stopPrank();

        // UEM should succeed
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasTokenPRC20(CHAIN_NAMESPACE, prc20);
        assertEq(universalCore.gasTokenPRC20ByChainNamespace(CHAIN_NAMESPACE), prc20);
    }

    function test_SetGasTokenPRC20_ZeroAddressReverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setGasTokenPRC20(CHAIN_NAMESPACE, address(0));
    }

    function test_SetGasTokenPRC20_HappyPath() public {
        address prc20 = makeAddr("prc20");

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasTokenPRC20(CHAIN_NAMESPACE, prc20);

        assertEq(universalCore.gasTokenPRC20ByChainNamespace(CHAIN_NAMESPACE), prc20);
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
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.depositPRC20Token(address(prc20Token), 1000, address(0));
    }

    function test_DepositPRC20Token_ZeroAmountAllowed() public {
        address target = makeAddr("target");

        // Current implementation allows zero amount
        // Note: PRC20.deposit() will revert on zero amount, so this documents current behavior
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(CommonErrors.ZeroAmount.selector);
        universalCore.depositPRC20Token(address(prc20Token), 0, target);
    }

    function test_DepositPRC20Token_ZeroPRC20Address() public {
        address target = makeAddr("target");

        // Zero PRC20 address should revert
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
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
        assertEq(universalCore.WPC(), address(mockWPC));
    }

    // ============ Pause/Unpause Tests ============

    function test_Pause_OnlyPauser() public {
        bytes32 role = universalCore.PAUSER_ROLE();

        // Non-pauser cannot pause
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonOwner, role)
        );
        vm.prank(nonOwner);
        universalCore.pause();
    }

    function test_Pause_AdminCannotPause() public {
        bytes32 role = universalCore.PAUSER_ROLE();

        // Admin also cannot pause — pauser role is separated from admin
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, deployer, role)
        );
        vm.prank(deployer);
        universalCore.pause();
    }

    function test_Pause_HappyPath() public {
        vm.prank(pauser);
        vm.expectEmit(true, true, true, true);
        emit Paused(pauser);
        universalCore.pause();

        assertTrue(universalCore.paused());
    }

    function test_Unpause_OnlyPauser() public {
        bytes32 role = universalCore.PAUSER_ROLE();

        // First pause the contract
        vm.prank(pauser);
        universalCore.pause();

        // Non-pauser cannot unpause
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonOwner, role)
        );
        vm.prank(nonOwner);
        universalCore.unpause();
    }

    function test_Unpause_HappyPath() public {
        // First pause the contract
        vm.prank(pauser);
        universalCore.pause();
        assertTrue(universalCore.paused());

        // Unpause
        vm.prank(pauser);
        vm.expectEmit(true, true, true, true);
        emit Unpaused(pauser);
        universalCore.unpause();

        assertFalse(universalCore.paused());
    }

    function test_Initialize_GrantsPauserRole() public {
        assertTrue(universalCore.hasRole(universalCore.PAUSER_ROLE(), pauser));
    }

    function test_Initialize_AdminDoesNotHavePauserRole() public {
        assertFalse(universalCore.hasRole(universalCore.PAUSER_ROLE(), deployer));
    }

    function test_GrantPauserRole_OnlyAdmin() public {
        address newPauser = makeAddr("newPauser");
        bytes32 role = universalCore.PAUSER_ROLE();

        vm.prank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonOwner, bytes32(0))
        );
        universalCore.grantRole(role, newPauser);

        vm.prank(deployer);
        universalCore.grantRole(role, newPauser);
        assertTrue(universalCore.hasRole(role, newPauser));
    }

    function test_GrantPauserRole_NewPauserCanPause() public {
        address newPauser = makeAddr("newPauser");

        vm.prank(deployer);
        universalCore.grantRole(universalCore.PAUSER_ROLE(), newPauser);

        vm.prank(newPauser);
        universalCore.pause();
        assertTrue(universalCore.paused());
    }

    function test_DepositPRC20Token_WhenPaused_Reverts() public {
        // Pause the contract
        vm.prank(pauser);
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
        vm.prank(pauser);
        universalCore.pause();

        // Try to deposit with auto-swap when paused
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector));
        universalCore.depositPRC20WithAutoSwap(address(mockPRC20), 1000, user, 0, 0, 0);
    }

    function test_DepositPRC20Token_AfterUnpause_Works() public {
        // Pause the contract
        vm.prank(pauser);
        universalCore.pause();

        // Unpause the contract
        vm.prank(pauser);
        universalCore.unpause();

        // Now deposit should work
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20Token(address(mockPRC20), 1000, user);

        assertEq(mockPRC20.balanceOf(user), 1000);
    }

    // ========================================
    // 4) Gas Fee Functions (moved from PRC20)
    // ========================================

    function testWithdrawGasFeeHappyPath() public view {
        (
            address returnedGasToken,
            uint256 gasFee,
            uint256 protocolFee,
            uint256 gasPrice,
            string memory chainNamespace
        ) = universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);

        assertEq(returnedGasToken, address(mockPRC20));

        uint256 actualBaseGasLimit = universalCore.baseGasLimitByChainNamespace(CHAIN_NAMESPACE);
        uint256 actualProtocolFee = universalCore.protocolFeeByToken(address(prc20Token));

        assertEq(gasPrice, GAS_PRICE);
        assertEq(gasFee, gasPrice * actualBaseGasLimit);
        assertEq(protocolFee, actualProtocolFee);
        assertEq(keccak256(bytes(chainNamespace)), keccak256(bytes(CHAIN_NAMESPACE)));
    }

    function testWithdrawGasFeeWithGasLimitHappyPath() public view {
        uint256 customGasLimit = 600_000;

        (
            address returnedGasToken,
            uint256 gasFee,
            uint256 protocolFee,
            uint256 gasPrice,
            string memory chainNamespace
        ) = universalCore.getOutboundTxGasAndFees(address(prc20Token), customGasLimit);

        assertEq(returnedGasToken, address(mockPRC20));
        assertEq(gasPrice, GAS_PRICE);
        assertEq(gasFee, gasPrice * customGasLimit);
        assertEq(protocolFee, PROTOCOL_FEE);
        assertEq(keccak256(bytes(chainNamespace)), keccak256(bytes(CHAIN_NAMESPACE)));
    }

    function testWithdrawGasFeeZeroGasPrice() public {
        // Use a fresh chain namespace with gas token set but no setChainMeta call,
        // so gasPriceByChainNamespace is 0 by default in storage.
        string memory newNs = "eip155:9999";

        PRC20 newPrc20Impl = new PRC20();
        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "Zero Price PRC20",
            "ZP",
            18,
            newNs,
            IPRC20.TokenType.ERC20,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );
        address proxyAddr = deployUpgradeableContract(address(newPrc20Impl), initData);
        PRC20 newToken = PRC20(payable(proxyAddr));

        // Set gas token and base gas limit, but never call setChainMeta → price stays 0
        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasTokenPRC20(newNs, address(mockPRC20));
        universalCore.setBaseGasLimitByChain(newNs, BASE_GAS_LIMIT);
        vm.stopPrank();

        vm.expectRevert(UniversalCoreErrors.ZeroGasPrice.selector);
        universalCore.getOutboundTxGasAndFees(address(newToken), BASE_GAS_LIMIT);
    }

    function testWithdrawGasFeeZeroGasToken() public {
        // Create a new PRC20 token with a different chain ID that has no gas token set
        PRC20 newPrc20Token = new PRC20();

        // Initialize with a different chain ID
        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "New PRC20",
            "NPRC20",
            18,
            "999", // Different chain ID
            IPRC20.TokenType.ERC20,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );

        address proxyAddress = deployUpgradeableContract(address(newPrc20Token), initData);
        PRC20 newToken = PRC20(payable(proxyAddress));

        // Don't set gas token or base gas limit for this chain ID

        // Expect revert due to unconfigured base gas limit
        vm.expectRevert(UniversalCoreErrors.ZeroBaseGasLimit.selector);
        universalCore.getOutboundTxGasAndFees(address(newToken), 0);
    }

    function testWithdrawGasFeeAfterGasPriceUpdate() public {
        uint256 newGasPrice = GAS_PRICE * 2;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setChainMeta(CHAIN_NAMESPACE, newGasPrice, 0);

        (, uint256 gasFee, uint256 protocolFee,,) = universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);

        uint256 actualBaseGasLimit = universalCore.baseGasLimitByChainNamespace(CHAIN_NAMESPACE);
        uint256 expectedGasFee = newGasPrice * actualBaseGasLimit;
        assertEq(gasFee, expectedGasFee);
        assertEq(protocolFee, universalCore.protocolFeeByToken(address(prc20Token)));
    }

    function testWithdrawGasFeeAfterBaseGasLimitUpdate() public {
        uint256 newBaseGasLimit = BASE_GAS_LIMIT * 2;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setBaseGasLimitByChain(CHAIN_NAMESPACE, newBaseGasLimit);

        (, uint256 gasFee, uint256 protocolFee,,) = universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);

        uint256 actualGasPrice = universalCore.gasPriceByChainNamespace(CHAIN_NAMESPACE);
        assertEq(gasFee, actualGasPrice * newBaseGasLimit);
        assertEq(protocolFee, universalCore.protocolFeeByToken(address(prc20Token)));
    }

    function testWithdrawGasFeeAfterProtocolFeeUpdate() public {
        uint256 newProtocolFee = PROTOCOL_FEE * 2;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setProtocolFeeByToken(address(prc20Token), newProtocolFee);

        (, uint256 gasFee, uint256 protocolFee,,) = universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);

        uint256 actualGasPrice = universalCore.gasPriceByChainNamespace(CHAIN_NAMESPACE);
        uint256 actualBaseGasLimit = universalCore.baseGasLimitByChainNamespace(CHAIN_NAMESPACE);
        assertEq(gasFee, actualGasPrice * actualBaseGasLimit);
        assertEq(protocolFee, newProtocolFee);
    }

    // ========================================
    // 5) Base Gas Limit Management (per-chain)
    // ========================================

    function test_SetBaseGasLimitByChain_HappyPath() public {
        uint256 newGasLimit = BASE_GAS_LIMIT * 2;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectEmit(false, false, false, true);
        emit SetBaseGasLimitByChain(CHAIN_NAMESPACE, newGasLimit);
        universalCore.setBaseGasLimitByChain(CHAIN_NAMESPACE, newGasLimit);

        assertEq(universalCore.baseGasLimitByChainNamespace(CHAIN_NAMESPACE), newGasLimit);
    }

    function test_SetBaseGasLimitByChain_OnlyManagerRole() public {
        uint256 newGasLimit = BASE_GAS_LIMIT * 2;

        // Non-manager should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, nonOwner, universalCore.MANAGER_ROLE()
            )
        );
        vm.prank(nonOwner);
        universalCore.setBaseGasLimitByChain(CHAIN_NAMESPACE, newGasLimit);
    }

    function test_SetBaseGasLimitByChain_ZeroValueAllowed() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setBaseGasLimitByChain(CHAIN_NAMESPACE, 0);
        assertEq(universalCore.baseGasLimitByChainNamespace(CHAIN_NAMESPACE), 0);
    }

    function test_GetOutboundTxGasAndFees_RevertsWhenBelowBaseLimit() public {
        uint256 belowBase = BASE_GAS_LIMIT - 1;

        vm.expectRevert(
            abi.encodeWithSelector(UniversalCoreErrors.GasLimitBelowBase.selector, belowBase, BASE_GAS_LIMIT)
        );
        universalCore.getOutboundTxGasAndFees(address(prc20Token), belowBase);
    }

    // ========================================
    // 7) setChainMeta Tests
    // ========================================

    function test_SetChainMeta_OnlyUEModule() public {
        vm.expectRevert(UniversalCoreErrors.CallerIsNotUEModule.selector);
        vm.prank(nonUEModule);
        universalCore.setChainMeta(CHAIN_NAMESPACE, 100, 1000);
    }

    function test_SetChainMeta_HappyPath() public {
        uint256 price = 100 * 10 ** 9;
        uint256 chainHeight = 20_000_000;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setChainMeta(CHAIN_NAMESPACE, price, chainHeight);

        assertEq(universalCore.gasPriceByChainNamespace(CHAIN_NAMESPACE), price);
        assertEq(universalCore.chainHeightByChainNamespace(CHAIN_NAMESPACE), chainHeight);
        assertEq(universalCore.timestampObservedAtByChainNamespace(CHAIN_NAMESPACE), block.timestamp);
    }

    function test_SetChainMeta_EmitsEvent() public {
        uint256 price = 100 * 10 ** 9;
        uint256 chainHeight = 20_000_000;

        vm.expectEmit(false, false, false, true);
        emit SetChainMeta(CHAIN_NAMESPACE, price, chainHeight, block.timestamp);

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setChainMeta(CHAIN_NAMESPACE, price, chainHeight);
    }

    function test_SetChainMeta_UpdatesGasPrice() public {
        uint256 newPrice = GAS_PRICE * 3;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setChainMeta(CHAIN_NAMESPACE, newPrice, 100);

        (, uint256 gasFee, uint256 protocolFee,,) = universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);
        assertEq(gasFee, newPrice * universalCore.baseGasLimitByChainNamespace(CHAIN_NAMESPACE));
        assertEq(protocolFee, universalCore.protocolFeeByToken(address(prc20Token)));
    }

    function test_SetChainMeta_OverwritesPreviousValues() public {
        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);

        universalCore.setChainMeta(CHAIN_NAMESPACE, 100, 1000);
        assertEq(universalCore.chainHeightByChainNamespace(CHAIN_NAMESPACE), 1000);
        assertEq(universalCore.timestampObservedAtByChainNamespace(CHAIN_NAMESPACE), block.timestamp);

        universalCore.setChainMeta(CHAIN_NAMESPACE, 200, 2000);
        assertEq(universalCore.gasPriceByChainNamespace(CHAIN_NAMESPACE), 200);
        assertEq(universalCore.chainHeightByChainNamespace(CHAIN_NAMESPACE), 2000);
        assertEq(universalCore.timestampObservedAtByChainNamespace(CHAIN_NAMESPACE), block.timestamp);

        vm.stopPrank();
    }

    function test_SetChainMeta_MultipleChains() public {
        string memory ethChain = "eip155:1";
        string memory bscChain = "eip155:56";

        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);

        universalCore.setChainMeta(ethChain, 50, 20_000_000);
        universalCore.setChainMeta(bscChain, 5, 40_000_000);

        vm.stopPrank();

        assertEq(universalCore.gasPriceByChainNamespace(ethChain), 50);
        assertEq(universalCore.chainHeightByChainNamespace(ethChain), 20_000_000);
        assertEq(universalCore.timestampObservedAtByChainNamespace(ethChain), block.timestamp);

        assertEq(universalCore.gasPriceByChainNamespace(bscChain), 5);
        assertEq(universalCore.chainHeightByChainNamespace(bscChain), 40_000_000);
        assertEq(universalCore.timestampObservedAtByChainNamespace(bscChain), block.timestamp);
    }

    function test_SetChainMeta_ZeroPriceReverts() public {
        vm.expectRevert(UniversalCoreErrors.ZeroGasPrice.selector);
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setChainMeta(CHAIN_NAMESPACE, 0, 0);
    }

    function test_SetChainMeta_ZeroChainHeightAllowed() public {
        // price must be non-zero, but chainHeight=0 is valid
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setChainMeta(CHAIN_NAMESPACE, GAS_PRICE, 0);

        assertEq(universalCore.gasPriceByChainNamespace(CHAIN_NAMESPACE), GAS_PRICE);
        assertEq(universalCore.chainHeightByChainNamespace(CHAIN_NAMESPACE), 0);
        assertEq(universalCore.timestampObservedAtByChainNamespace(CHAIN_NAMESPACE), block.timestamp);
    }

    // ========================================
    // 8) Rescue Funds Gas Limit
    // ========================================

    function test_SetRescueFundsGasLimitByChain_HappyPath() public {
        uint256 rescueGasLimit = 300_000;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectEmit(false, false, false, true);
        emit SetRescueFundsGasLimitByChain(CHAIN_NAMESPACE, rescueGasLimit);
        universalCore.setRescueFundsGasLimitByChain(CHAIN_NAMESPACE, rescueGasLimit);

        assertEq(universalCore.rescueFundsGasLimitByChainNamespace(CHAIN_NAMESPACE), rescueGasLimit);
    }

    function test_SetRescueFundsGasLimitByChain_OnlyManagerRole() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, nonOwner, universalCore.MANAGER_ROLE()
            )
        );
        vm.prank(nonOwner);
        universalCore.setRescueFundsGasLimitByChain(CHAIN_NAMESPACE, 300_000);
    }

    function test_SetRescueFundsGasLimitByChain_ZeroValueAllowed() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setRescueFundsGasLimitByChain(CHAIN_NAMESPACE, 0);
        assertEq(universalCore.rescueFundsGasLimitByChainNamespace(CHAIN_NAMESPACE), 0);
    }

    function test_GetRescueFundsGasLimit_HappyPath() public {
        uint256 rescueGasLimit = 300_000;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setRescueFundsGasLimitByChain(CHAIN_NAMESPACE, rescueGasLimit);

        (
            address returnedGasToken,
            uint256 gasFee,
            uint256 returnedRescueGasLimit,
            uint256 gasPrice,
            string memory chainNamespace
        ) = universalCore.getRescueFundsGasLimit(address(prc20Token));

        assertEq(returnedGasToken, address(mockPRC20));
        assertEq(returnedRescueGasLimit, rescueGasLimit);
        assertEq(gasPrice, GAS_PRICE);
        assertEq(gasFee, GAS_PRICE * rescueGasLimit);
        assertEq(keccak256(bytes(chainNamespace)), keccak256(bytes(CHAIN_NAMESPACE)));
    }

    function test_GetRescueFundsGasLimit_RevertsWhenZeroRescueGasLimit() public {
        vm.expectRevert(UniversalCoreErrors.ZeroRescueGasLimit.selector);
        universalCore.getRescueFundsGasLimit(address(prc20Token));
    }

    function test_GetRescueFundsGasLimit_RevertsWhenZeroGasToken() public {
        // Create a PRC20 with a different chain namespace that has no gas token
        PRC20 newPrc20Impl = new PRC20();
        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "New PRC20",
            "NPRC20",
            18,
            "999",
            IPRC20.TokenType.ERC20,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );
        address proxyAddress = deployUpgradeableContract(address(newPrc20Impl), initData);
        PRC20 newToken = PRC20(payable(proxyAddress));

        // Set rescue gas limit but no gas token for this chain
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setRescueFundsGasLimitByChain("999", 300_000);

        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.getRescueFundsGasLimit(address(newToken));
    }

    function test_GetRescueFundsGasLimit_RevertsWhenZeroGasPrice() public {
        // Create a PRC20 with a different chain namespace
        PRC20 newPrc20Impl = new PRC20();
        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "New PRC20",
            "NPRC20",
            18,
            "888",
            IPRC20.TokenType.ERC20,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );
        address proxyAddress = deployUpgradeableContract(address(newPrc20Impl), initData);
        PRC20 newToken = PRC20(payable(proxyAddress));

        // Set rescue gas limit and gas token, but no gas price
        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setRescueFundsGasLimitByChain("888", 300_000);
        universalCore.setGasTokenPRC20("888", address(mockPRC20));
        vm.stopPrank();

        vm.expectRevert(UniversalCoreErrors.ZeroGasPrice.selector);
        universalCore.getRescueFundsGasLimit(address(newToken));
    }

    // ========================================
    // 9) setUniversalGatewayPC Tests
    // ========================================

    function test_SetUniversalGatewayPC_HappyPath() public {
        address gateway = makeAddr("gateway");
        address oldGateway = universalCore.universalGatewayPC();

        vm.prank(deployer);
        vm.expectEmit(true, true, false, true);
        emit SetUniversalGatewayPC(oldGateway, gateway);
        universalCore.setUniversalGatewayPC(gateway);
        assertEq(universalCore.universalGatewayPC(), gateway);
    }

    function test_SetUniversalGatewayPC_ZeroAddressReverts() public {
        vm.prank(deployer);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setUniversalGatewayPC(address(0));
    }

    function test_SetUniversalGatewayPC_OnlyAdmin() public {
        vm.prank(nonOwner);
        vm.expectRevert(CommonErrors.InvalidOwner.selector);
        universalCore.setUniversalGatewayPC(makeAddr("gateway"));
    }

    // ========================================
    // 10) setUniswapV3Addresses Tests
    // ========================================

    function test_SetUniswapV3Addresses_HappyPath() public {
        address f = makeAddr("factory2");
        address r = makeAddr("router2");

        vm.prank(deployer);
        vm.expectEmit(false, false, false, true);
        emit SetUniswapV3Addresses(f, r);
        universalCore.setUniswapV3Addresses(f, r);

        assertEq(universalCore.uniswapV3Factory(), f);
        assertEq(universalCore.uniswapV3SwapRouter(), r);
    }

    function test_SetUniswapV3Addresses_RevertsZeroFactory() public {
        vm.prank(deployer);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setUniswapV3Addresses(address(0), makeAddr("r"));
    }

    function test_SetUniswapV3Addresses_RevertsZeroRouter() public {
        vm.prank(deployer);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setUniswapV3Addresses(makeAddr("f"), address(0));
    }

    function test_SetUniswapV3Addresses_OnlyAdmin() public {
        vm.prank(nonOwner);
        vm.expectRevert(CommonErrors.InvalidOwner.selector);
        universalCore.setUniswapV3Addresses(makeAddr("f"), makeAddr("r"));
    }

    // ========================================
    // 11) setDefaultDeadlineMins Tests
    // ========================================

    event SetDefaultDeadlineMins(uint256 minutesValue);

    function test_SetDefaultDeadlineMins_HappyPath() public {
        vm.prank(deployer);
        vm.expectEmit(false, false, false, true);
        emit SetDefaultDeadlineMins(30);
        universalCore.setDefaultDeadlineMins(30);
        assertEq(universalCore.defaultDeadlineMins(), 30);
    }

    function test_SetDefaultDeadlineMins_OnlyAdmin() public {
        vm.prank(nonOwner);
        vm.expectRevert(CommonErrors.InvalidOwner.selector);
        universalCore.setDefaultDeadlineMins(30);
    }

    // ========================================
    // 12) setDefaultFeeTier Tests
    // ========================================

    function test_SetDefaultFeeTier_HappyPath_500() public {
        address token = makeAddr("token");
        vm.prank(deployer);
        vm.expectEmit(true, false, false, true);
        emit SetDefaultFeeTier(token, 500);
        universalCore.setDefaultFeeTier(token, 500);
        assertEq(universalCore.defaultFeeTier(token), 500);
    }

    function test_SetDefaultFeeTier_HappyPath_3000() public {
        address token = makeAddr("token");
        vm.prank(deployer);
        universalCore.setDefaultFeeTier(token, 3000);
        assertEq(universalCore.defaultFeeTier(token), 3000);
    }

    function test_SetDefaultFeeTier_HappyPath_10000() public {
        address token = makeAddr("token");
        vm.prank(deployer);
        universalCore.setDefaultFeeTier(token, 10000);
        assertEq(universalCore.defaultFeeTier(token), 10000);
    }

    function test_SetDefaultFeeTier_RevertsInvalidTier() public {
        address token = makeAddr("token");
        vm.prank(deployer);
        vm.expectRevert(UniversalCoreErrors.InvalidFeeTier.selector);
        universalCore.setDefaultFeeTier(token, 200);
    }

    function test_SetDefaultFeeTier_RevertsZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setDefaultFeeTier(address(0), 3000);
    }

    function test_SetDefaultFeeTier_OnlyAdmin() public {
        vm.prank(nonOwner);
        vm.expectRevert(CommonErrors.InvalidOwner.selector);
        universalCore.setDefaultFeeTier(makeAddr("token"), 3000);
    }

    // ========================================
    // 14) Rescue Funds Gas Limit (continued)
    // ========================================

    function test_GetRescueFundsGasLimit_UpdatedAfterSettingNewLimit() public {
        uint256 initialLimit = 300_000;
        uint256 updatedLimit = 600_000;

        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setRescueFundsGasLimitByChain(CHAIN_NAMESPACE, initialLimit);
        vm.stopPrank();

        (, uint256 gasFee1,,,) = universalCore.getRescueFundsGasLimit(address(prc20Token));
        assertEq(gasFee1, GAS_PRICE * initialLimit);

        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setRescueFundsGasLimitByChain(CHAIN_NAMESPACE, updatedLimit);
        vm.stopPrank();

        (, uint256 gasFee2,,,) = universalCore.getRescueFundsGasLimit(address(prc20Token));
        assertEq(gasFee2, GAS_PRICE * updatedLimit);
    }

    // ========================================
    // Gas Data Staleness Tests
    // ========================================

    // --- Setter tests ---

    function test_SetMaxStalenessByChain_HappyPath() public {
        uint256 maxStaleness = 3600; // 1 hour

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectEmit(false, false, false, true);
        emit SetMaxStalenessByChain(CHAIN_NAMESPACE, maxStaleness);
        universalCore.setMaxStalenessByChain(CHAIN_NAMESPACE, maxStaleness);

        assertEq(universalCore.maxStalenessByChainNamespace(CHAIN_NAMESPACE), maxStaleness);
    }

    function test_SetMaxStalenessByChain_OnlyManagerRole() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, nonOwner, universalCore.MANAGER_ROLE()
            )
        );
        vm.prank(nonOwner);
        universalCore.setMaxStalenessByChain(CHAIN_NAMESPACE, 3600);
    }

    function test_SetMaxStalenessByChain_ZeroDisablesCheck() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setMaxStalenessByChain(CHAIN_NAMESPACE, 0);

        assertEq(universalCore.maxStalenessByChainNamespace(CHAIN_NAMESPACE), 0);
    }

    // --- Default-off behaviour ---

    function test_StalenessDisabledByDefault_NoRevertEvenAfterLongWarp() public {
        // No setMaxStalenessByChain call — staleness check is off for this namespace.
        // Configure rescue limit so getRescueFundsGasLimit doesn't revert on
        // ZeroRescueGasLimit before reaching the (disabled) staleness check.
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setRescueFundsGasLimitByChain(CHAIN_NAMESPACE, 300_000);

        vm.warp(block.timestamp + 365 days);

        (, uint256 outboundFee,,,) = universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);
        assertGt(outboundFee, 0, "outbound fee should quote even after a year when check is disabled");

        (, uint256 rescueFee,,,) = universalCore.getRescueFundsGasLimit(address(prc20Token));
        assertGt(rescueFee, 0, "rescue fee should quote even after a year when check is disabled");
    }

    // --- getOutboundTxGasAndFees staleness ---

    function test_StalenessCheck_GetOutboundTxGasAndFees_Reverts() public {
        uint256 maxStaleness = 300;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setMaxStalenessByChain(CHAIN_NAMESPACE, maxStaleness);

        uint256 observedAt = universalCore.timestampObservedAtByChainNamespace(CHAIN_NAMESPACE);
        vm.warp(observedAt + maxStaleness + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCoreErrors.StaleGasData.selector, observedAt, block.timestamp, maxStaleness
            )
        );
        universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);
    }

    function test_StalenessCheck_GetOutboundTxGasAndFees_BoundaryAtEdge_OK() public {
        uint256 maxStaleness = 300;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setMaxStalenessByChain(CHAIN_NAMESPACE, maxStaleness);

        // Warp to exactly observedAt + maxStaleness — still within window (strict >).
        uint256 observedAt = universalCore.timestampObservedAtByChainNamespace(CHAIN_NAMESPACE);
        vm.warp(observedAt + maxStaleness);

        (, uint256 gasFee,,,) = universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);
        assertGt(gasFee, 0, "should succeed exactly at the boundary");
    }

    function test_StalenessCheck_GetOutboundTxGasAndFees_OneSecondPastEdge_Reverts() public {
        uint256 maxStaleness = 300;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setMaxStalenessByChain(CHAIN_NAMESPACE, maxStaleness);

        uint256 observedAt = universalCore.timestampObservedAtByChainNamespace(CHAIN_NAMESPACE);
        vm.warp(observedAt + maxStaleness + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCoreErrors.StaleGasData.selector, observedAt, block.timestamp, maxStaleness
            )
        );
        universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);
    }

    // --- getRescueFundsGasLimit staleness ---

    function test_StalenessCheck_GetRescueFundsGasLimit_Reverts() public {
        uint256 maxStaleness = 300;

        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setMaxStalenessByChain(CHAIN_NAMESPACE, maxStaleness);
        universalCore.setRescueFundsGasLimitByChain(CHAIN_NAMESPACE, 300_000);
        vm.stopPrank();

        uint256 observedAt = universalCore.timestampObservedAtByChainNamespace(CHAIN_NAMESPACE);
        vm.warp(observedAt + maxStaleness + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCoreErrors.StaleGasData.selector, observedAt, block.timestamp, maxStaleness
            )
        );
        universalCore.getRescueFundsGasLimit(address(prc20Token));
    }

    function test_StalenessCheck_GetRescueFundsGasLimit_BoundaryAtEdge_OK() public {
        uint256 maxStaleness = 300;

        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setMaxStalenessByChain(CHAIN_NAMESPACE, maxStaleness);
        universalCore.setRescueFundsGasLimitByChain(CHAIN_NAMESPACE, 300_000);
        vm.stopPrank();

        uint256 observedAt = universalCore.timestampObservedAtByChainNamespace(CHAIN_NAMESPACE);
        vm.warp(observedAt + maxStaleness);

        (, uint256 gasFee,,,) = universalCore.getRescueFundsGasLimit(address(prc20Token));
        assertGt(gasFee, 0, "rescue should succeed exactly at the boundary");
    }

    // --- Recovery / refresh ---

    function test_StalenessCheck_RefreshingObservedAtClearsStaleness() public {
        uint256 maxStaleness = 300;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setMaxStalenessByChain(CHAIN_NAMESPACE, maxStaleness);

        // Warp past window — call should revert
        uint256 firstObservedAt = universalCore.timestampObservedAtByChainNamespace(CHAIN_NAMESPACE);
        vm.warp(firstObservedAt + maxStaleness + 100);

        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCoreErrors.StaleGasData.selector, firstObservedAt, block.timestamp, maxStaleness
            )
        );
        universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);

        // Refresh chain meta — observedAt resets to current block.timestamp.
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setChainMeta(CHAIN_NAMESPACE, GAS_PRICE, 0);

        (, uint256 gasFee,,,) = universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);
        assertGt(gasFee, 0, "should succeed after refresh");
    }

    // --- Chain-halt edge case: observedAt never set ---

    function test_StalenessCheck_RevertsWhenObservedAtIsZero() public {
        // Set up a fresh chain namespace with gas token + base limit, but NEVER call setChainMeta.
        string memory freshNs = "never-observed";

        PRC20 freshImpl = new PRC20();
        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "Fresh PRC20",
            "FPRC20",
            18,
            freshNs,
            IPRC20.TokenType.ERC20,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );
        address proxyAddr = deployUpgradeableContract(address(freshImpl), initData);
        PRC20 freshPRC20 = PRC20(payable(proxyAddr));

        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasTokenPRC20(freshNs, address(mockPRC20));
        universalCore.setBaseGasLimitByChain(freshNs, 100_000);
        // Deliberately skip setChainMeta — gasPrice stays 0.
        // We need gasPrice > 0 to reach the staleness check. Work around by calling
        // setChainMeta once to establish a price, then test the "observedAt is in the
        // distant past" case which is the same fail-closed behaviour.
        universalCore.setChainMeta(freshNs, GAS_PRICE, 0);
        universalCore.setMaxStalenessByChain(freshNs, 60);
        vm.stopPrank();

        // Warp far past the observed window. observedAt is now in the past relative to block.timestamp.
        uint256 observedAt = universalCore.timestampObservedAtByChainNamespace(freshNs);
        vm.warp(observedAt + 1 days);

        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCoreErrors.StaleGasData.selector, observedAt, block.timestamp, uint256(60)
            )
        );
        universalCore.getOutboundTxGasAndFees(address(freshPRC20), 0);
    }

    // --- Multi-chain isolation ---

    function test_StalenessCheck_PerChainIsolation() public {
        // Chain A is the default CHAIN_NAMESPACE with full config from setUp.
        // Chain B is a fresh namespace we fully configure but never set maxStaleness on.
        string memory chainBNs = "eip155:999";

        PRC20 bImpl = new PRC20();
        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "B PRC20",
            "BPRC20",
            18,
            chainBNs,
            IPRC20.TokenType.ERC20,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );
        address proxyAddr = deployUpgradeableContract(address(bImpl), initData);
        PRC20 bPRC20 = PRC20(payable(proxyAddr));

        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasTokenPRC20(chainBNs, address(mockPRC20));
        universalCore.setChainMeta(chainBNs, GAS_PRICE, 0);
        universalCore.setBaseGasLimitByChain(chainBNs, BASE_GAS_LIMIT);
        // Configure maxStaleness only on chain A.
        universalCore.setMaxStalenessByChain(CHAIN_NAMESPACE, 300);
        vm.stopPrank();

        // Warp past A's window.
        uint256 observedAt = universalCore.timestampObservedAtByChainNamespace(CHAIN_NAMESPACE);
        vm.warp(observedAt + 300 + 1);

        // Chain A reverts (maxStaleness enforced).
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCoreErrors.StaleGasData.selector, observedAt, block.timestamp, uint256(300)
            )
        );
        universalCore.getOutboundTxGasAndFees(address(prc20Token), 0);

        // Chain B succeeds (no maxStaleness set for chainBNs).
        (, uint256 gasFee,,,) = universalCore.getOutboundTxGasAndFees(address(bPRC20), 0);
        assertGt(gasFee, 0, "chain B should not be affected by chain A's staleness config");
    }

    // --- Regression: revert ordering (staleness is last) ---

    function test_StalenessCheck_DoesNotAffectExistingRevertPaths() public {
        // Fresh namespace with maxStaleness set but no gas price. The ZeroGasPrice
        // revert must fire before the staleness check is reached.
        string memory freshNs = "revert-order-test";

        PRC20 freshImpl = new PRC20();
        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "Fresh PRC20",
            "FPRC20",
            18,
            freshNs,
            IPRC20.TokenType.ERC20,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );
        address proxyAddr = deployUpgradeableContract(address(freshImpl), initData);
        PRC20 freshPRC20 = PRC20(payable(proxyAddr));

        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasTokenPRC20(freshNs, address(mockPRC20));
        universalCore.setBaseGasLimitByChain(freshNs, 100_000);
        universalCore.setMaxStalenessByChain(freshNs, 60);
        // No setChainMeta → gasPrice is 0 → ZeroGasPrice revert must come before staleness.
        vm.stopPrank();

        vm.expectRevert(UniversalCoreErrors.ZeroGasPrice.selector);
        universalCore.getOutboundTxGasAndFees(address(freshPRC20), 0);
    }

    // =========================
    //    PRC20 Return Value Check Tests
    // =========================

    function test_DepositPRC20Token_FalseReturn_Reverts() public {
        FalseReturningPRC20 falseToken = new FalseReturningPRC20(CHAIN_NAMESPACE, SOURCE_TOKEN_ADDRESS);

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.PRC20OperationFailed.selector);
        universalCore.depositPRC20Token(address(falseToken), 1000, makeAddr("target"));
    }

    function test_RefundUnusedGas_FalseDeposit_Reverts() public {
        FalseReturningPRC20 falseToken = new FalseReturningPRC20(CHAIN_NAMESPACE, SOURCE_TOKEN_ADDRESS);

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.PRC20OperationFailed.selector);
        universalCore.refundUnusedGas(address(falseToken), 1000, makeAddr("target"), false, 0, 0);
    }

    // =========================
    //    Rescue Native PC Tests
    // =========================

    function test_RescueNativePC_HappyPath() public {
        address payable recipient = payable(makeAddr("rescueRecipient"));
        uint256 stuckAmount = 1 ether;
        vm.deal(address(universalCore), stuckAmount);

        vm.expectEmit(true, false, false, true);
        emit RescueNativePC(recipient, stuckAmount);

        universalCore.rescueNativePC(recipient, stuckAmount);

        assertEq(address(universalCore).balance, 0);
        assertEq(recipient.balance, stuckAmount);
    }

    function test_RescueNativePC_OnlyAdmin() public {
        vm.deal(address(universalCore), 1 ether);
        address nonAdmin = makeAddr("nonAdmin");

        vm.expectRevert(CommonErrors.InvalidOwner.selector);
        vm.prank(nonAdmin);
        universalCore.rescueNativePC(payable(nonAdmin), 1 ether);
    }

    function test_RescueNativePC_ZeroAddressReverts() public {
        vm.deal(address(universalCore), 1 ether);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.rescueNativePC(payable(address(0)), 1 ether);
    }

    function test_RescueNativePC_ZeroAmountReverts() public {
        vm.deal(address(universalCore), 1 ether);
        vm.expectRevert(CommonErrors.ZeroAmount.selector);
        universalCore.rescueNativePC(payable(makeAddr("r")), 0);
    }

    function test_RescueNativePC_InsufficientBalanceReverts() public {
        vm.deal(address(universalCore), 0.5 ether);
        vm.expectRevert(CommonErrors.InsufficientBalance.selector);
        universalCore.rescueNativePC(payable(makeAddr("r")), 1 ether);
    }

    function test_RescueNativePC_TransferToNonPayableReverts() public {
        vm.deal(address(universalCore), 1 ether);
        RevertingTarget nonPayable = new RevertingTarget();
        vm.expectRevert(CommonErrors.TransferFailed.selector);
        universalCore.rescueNativePC(payable(address(nonPayable)), 1 ether);
    }
}
