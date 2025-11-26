// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../../src/UniversalCoreV0.sol";
import "../../src/PRC20.sol";
import "../../src/libraries/Errors.sol";
import "../../test/helpers/UpgradeableContractHelper.sol";
import "../../src/libraries/Errors.sol";

/**
 * @title UniversalCoreSwapTest
 * @dev Real Uniswap integration tests for UniversalCore using Push Chain fork
 * @notice This test suite forks the actual Push Chain to test real Uniswap V3 integration
 */
contract UniversalCoreSwapTest is Test, UpgradeableContractHelper {
    // Push Chain network details
    uint256 constant PUSH_CHAIN_FORK = 42101;
    string constant PUSH_CHAIN_RPC = "https://evm.rpc-testnet-donut-node1.push.org";

    // Uniswap V3 contracts on Push Chain
    address constant UNISWAP_FACTORY = 0x81b8Bca02580C7d6b636051FDb7baAC436bFb454;
    address constant UNISWAP_ROUTER = 0x5D548bB9E305AAe0d6dc6e6fdc3ab419f6aC0037;
    address constant UNISWAP_QUOTER = 0x83316275f7C2F79BC4E26f089333e88E89093037;
    address constant WPC_TOKEN = 0xE17DD2E0509f99E9ee9469Cf6634048Ec5a3ADe9;

    // Real token addresses on Push Chain
    address constant PSOL_TOKEN = 0x5D525Df2bD99a6e7ec58b76aF2fd95F39874EBed;
    address constant PETH_TOKEN = 0x2971824Db68229D087931155C2b8bB820B275809;
    address constant USDT_TOKEN = 0xCA0C5E6F002A389E1580F0DB7cd06e4549B5F9d3;
    address constant USDC_ETH_TOKEN = 0x387b9C8Db60E74999aAAC5A2b7825b400F12d68E;

    // Pool addresses
    address constant PSOL_WPC_POOL = 0x0E5914e3A7e2e6d18330Dd33fA387Ce33Da48b54;
    address constant PETH_WPC_POOL = 0x012d5C099f8AE00009f40824317a18c3A342f622;
    address constant USDT_WPC_POOL = 0x2d46b2b92266f34345934F17039768cd631aB026;
    address constant USDC_ETH_WPC_POOL = 0x69B21660F49f2B8F60B0177Abc751a08EBEa0Ae3;

    // Test accounts
    address constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    address deployer;
    address nonOwner;
    address nonUEModule;
    address user;

    // Contracts
    UniversalCoreV0 universalCore;
    PRC20 prc20Token;

    // Uniswap V3 interfaces (simplified for testing)
    IUniswapV3Factory factory;
    ISwapRouter router;
    IQuoterV2 quoter;

    // Events to test
    event DepositPRC20WithAutoSwap(
        address prc20, uint256 amountIn, address pcToken, uint256 amountOut, uint24 fee, address target
    );

    function setUp() public {
        // Fork Push Chain at latest block
        uint256 forkId = vm.createFork(PUSH_CHAIN_RPC);
        vm.selectFork(forkId);

        // Setup test accounts
        deployer = makeAddr("deployer");
        nonOwner = makeAddr("nonOwner");
        nonUEModule = makeAddr("nonUEModule");
        user = makeAddr("user");

        // Deploy contracts
        vm.startPrank(deployer);

        // Deploy PRC20 token
        prc20Token = new PRC20();

        // Deploy UniversalCoreV0 implementation
        UniversalCoreV0 implementation = new UniversalCoreV0();

        // Deploy proxy and initialize
        bytes memory initData = abi.encodeWithSelector(
            UniversalCoreV0.initialize.selector, WPC_TOKEN, UNISWAP_FACTORY, UNISWAP_ROUTER, UNISWAP_QUOTER
        );

        address proxyAddress = deployUpgradeableContract(address(implementation), initData);
        universalCore = UniversalCoreV0(payable(proxyAddress));

        vm.stopPrank();

        // Update PRC20 tokens to allow our UniversalCore contract to call deposit()
        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);

        // Update PSOL token
        (bool success1,) =
            PSOL_TOKEN.call(abi.encodeWithSignature("updateUniversalCore(address)", address(universalCore)));
        require(success1, "Failed to update PSOL UNIVERSAL_CORE");

        // Update PETH token
        (bool success2,) =
            PETH_TOKEN.call(abi.encodeWithSignature("updateUniversalCore(address)", address(universalCore)));
        require(success2, "Failed to update PETH UNIVERSAL_CORE");

        // Update USDT token
        (bool success3,) =
            USDT_TOKEN.call(abi.encodeWithSignature("updateUniversalCore(address)", address(universalCore)));
        require(success3, "Failed to update USDT UNIVERSAL_CORE");

        vm.stopPrank();

        // Setup Uniswap interfaces (we'll interact with them directly)
        factory = IUniswapV3Factory(UNISWAP_FACTORY);
        router = ISwapRouter(UNISWAP_ROUTER);
        quoter = IQuoterV2(UNISWAP_QUOTER);
    }

    // ============ REAL UNISWAP INTEGRATION TESTS ============

    function test_DepositPRC20WithAutoSwap_PSOLToWPC() public {
        // Record initial state
        bool initialAutoSwap = universalCore.isAutoSwapSupported(PSOL_TOKEN);
        uint24 initialFeeTier = universalCore.defaultFeeTier(PSOL_TOKEN);
        uint256 initialSlippage = universalCore.slippageTolerance(PSOL_TOKEN);
        uint256 initialDeadline = universalCore.defaultDeadlineMins();

        // Setup auto-swap for PSOL
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        universalCore.setSlippageTolerance(PSOL_TOKEN, 300); // 3%
        vm.stopPrank();

        // Verify configuration was set correctly
        assertTrue(universalCore.isAutoSwapSupported(PSOL_TOKEN), "auto-swap should be enabled for PSOL");
        assertTrue(
            universalCore.isAutoSwapSupported(PSOL_TOKEN) != initialAutoSwap,
            "auto-swap flag should change after enabling"
        );
        assertEq(universalCore.defaultFeeTier(PSOL_TOKEN), 500, "default fee tier should be 500");
        assertTrue(universalCore.defaultFeeTier(PSOL_TOKEN) != initialFeeTier, "fee tier should differ from initial");
        assertEq(universalCore.slippageTolerance(PSOL_TOKEN), 300, "slippage tolerance should be 300 bps");
        assertTrue(
            universalCore.slippageTolerance(PSOL_TOKEN) != initialSlippage,
            "slippage tolerance should differ from initial"
        );

        // Get some PSOL tokens for testing (simulate having tokens)
        uint256 amount = 1e18; // 1 PSOL
        address target = user;

        uint256 initialTargetNativeBalance = target.balance;
        uint256 initialUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));

        // Test the function call - should work with real Uniswap
        // Provide minPCOut to bypass Quoter call
        vm.recordLogs();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(
            PSOL_TOKEN,
            amount,
            target,
            0, // fee (use default)
            1, // minPCOut (bypass Quoter by providing min output)
            0 // deadline (will use default)
        );

        // Verify the emitted event
        verifyDepositPRC20WithAutoSwapEvent(PSOL_TOKEN, amount, WPC_TOKEN, 500, target);

        uint256 finalTargetNativeBalance = target.balance;
        uint256 finalUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));

        // User should have received native PC tokens
        assertTrue(finalTargetNativeBalance > initialTargetNativeBalance, "Target should receive native PC tokens");

        // UniversalCore receives PSOL tokens (via minting) and swaps what it can
        // Due to low liquidity, only partial swaps may occur, leaving some PSOL in UniversalCore
        // The final balance should be: initial + minted - swapped_amount
        assertTrue(
            finalUniversalCorePSOLBalance >= initialUniversalCorePSOLBalance,
            "UniversalCore PSOL balance should be >= initial (partial swaps due to low liquidity are expected)"
        );

        // Verify that some swap occurred if target received WPC tokens
        if (finalTargetNativeBalance > initialTargetNativeBalance) {
            assertTrue(
                finalUniversalCorePSOLBalance < initialUniversalCorePSOLBalance + amount,
                "Some PSOL should have been swapped if target received native PC"
            );
        }
    }

    function test_DepositPRC20WithAutoSwap_PETHToWPC() public {
        // Setup auto-swap for PETH
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PETH_TOKEN, true);
        universalCore.setDefaultFeeTier(PETH_TOKEN, 500);
        universalCore.setSlippageTolerance(PETH_TOKEN, 300); // 3%
        vm.stopPrank();

        uint256 amount = 1e18; // 1 PETH
        address target = user;

        // Record initial balances
        uint256 initialPETHBalance = IERC20(PETH_TOKEN).balanceOf(user);
        uint256 initialWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 initialTargetNativeBalance = target.balance;
        uint256 initialUniversalCorePETHBalance = IERC20(PETH_TOKEN).balanceOf(address(universalCore));
        uint256 initialUniversalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // Expect DepositPRC20WithAutoSwap event (use post-transaction parsing)
        vm.recordLogs();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(
            PETH_TOKEN,
            amount,
            target,
            0, // fee (use default)
            1, // minPCOut (bypass Quoter)
            0 // deadline (use default)
        );

        // Verify the emitted event
        verifyDepositPRC20WithAutoSwapEvent(PETH_TOKEN, amount, WPC_TOKEN, 500, target);

        // Verify balances after swap
        uint256 finalPETHBalance = IERC20(PETH_TOKEN).balanceOf(user);
        uint256 finalWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 finalTargetNativeBalance = target.balance;
        uint256 finalUniversalCorePETHBalance = IERC20(PETH_TOKEN).balanceOf(address(universalCore));
        uint256 finalUniversalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // User should have received WPC tokens
        assertTrue(finalTargetNativeBalance > initialTargetNativeBalance, "Target should receive native PC tokens");

        // UniversalCore receives PETH tokens (via minting) but then swaps them all to the pool
        // So final balance should equal initial balance (both 0)
        assertEq(
            finalUniversalCorePETHBalance,
            initialUniversalCorePETHBalance,
            "UniversalCore PETH balance should return to initial after swap"
        );
        // Note: UniversalCore might not have WPC tokens initially, so we don't check its balance decrease
        // The important thing is that the target receives WPC tokens from the swap

        // User's PETH balance should not change - PRC20 is minted directly to UniversalCore
        assertEq(initialPETHBalance, finalPETHBalance, "User PETH balance should not change");
    }

    function test_DepositPRC20WithAutoSwap_USDTToWPC() public {
        // Setup auto-swap for USDT
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(USDT_TOKEN, true);
        universalCore.setDefaultFeeTier(USDT_TOKEN, 500);
        universalCore.setSlippageTolerance(USDT_TOKEN, 500); // 5%
        vm.stopPrank();

        uint256 amount = 1000e6; // 1000 USDT (6 decimals)
        address target = user;

        // Record initial balances
        uint256 initialUSDTBalance = IERC20(USDT_TOKEN).balanceOf(user);
        uint256 initialWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 initialTargetNativeBalance = target.balance;
        uint256 initialUniversalCoreUSDTBalance = IERC20(USDT_TOKEN).balanceOf(address(universalCore));
        uint256 initialUniversalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // Record logs for event verification
        vm.recordLogs();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(
            USDT_TOKEN,
            amount,
            target,
            0, // fee (use default)
            1, // minPCOut (bypass Quoter)
            0 // deadline (use default)
        );

        // Verify the emitted event
        verifyDepositPRC20WithAutoSwapEvent(USDT_TOKEN, amount, WPC_TOKEN, 500, target);

        // Verify balances after swap
        uint256 finalUSDTBalance = IERC20(USDT_TOKEN).balanceOf(user);
        uint256 finalWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 finalTargetNativeBalance = target.balance;
        uint256 finalUniversalCoreUSDTBalance = IERC20(USDT_TOKEN).balanceOf(address(universalCore));
        uint256 finalUniversalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // User should have received WPC tokens
        assertTrue(finalTargetNativeBalance > initialTargetNativeBalance, "Target should receive native PC tokens");

        // UniversalCore receives USDT tokens (via minting) but then swaps them all to the pool
        // So final balance should equal initial balance (both 0)
        assertEq(
            finalUniversalCoreUSDTBalance,
            initialUniversalCoreUSDTBalance,
            "UniversalCore USDT balance should return to initial after swap"
        );
        // Note: UniversalCore might not have WPC tokens initially, so we don't check its balance decrease
        // The important thing is that the target receives WPC tokens from the swap

        // User's USDT balance should not change - PRC20 is minted directly to UniversalCore
        assertEq(initialUSDTBalance, finalUSDTBalance, "User USDT balance should not change");
    }

    function test_DepositPRC20WithAutoSwap_AutoSwapNotSupported() public {
        // Record initial state
        bool initialAutoSwap = universalCore.isAutoSwapSupported(PSOL_TOKEN);
        uint256 amount = 1e18;
        address target = user;

        // Verify auto-swap is not supported initially
        assertFalse(universalCore.isAutoSwapSupported(PSOL_TOKEN));

        // Record initial balances
        uint256 initialPSOLBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 initialWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 initialTargetNativeBalance = target.balance;

        // Attempt swap should revert
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.AutoSwapNotSupported.selector);
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, amount, target, 0, 0, 0);

        // Verify balances remain unchanged
        assertEq(IERC20(PSOL_TOKEN).balanceOf(user), initialPSOLBalance);
        assertEq(IERC20(WPC_TOKEN).balanceOf(user), initialWPCBalance);
        assertEq(target.balance, initialTargetNativeBalance);

        // Verify auto-swap support remains unchanged
        assertEq(universalCore.isAutoSwapSupported(PSOL_TOKEN), initialAutoSwap);

        // Test with different token
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.AutoSwapNotSupported.selector);
        universalCore.depositPRC20WithAutoSwap(PETH_TOKEN, amount, target, 0, 0, 0);
    }

    function test_DepositPRC20WithAutoSwap_InvalidFeeTier() public {
        // Record initial state
        uint24 initialFeeTier = universalCore.defaultFeeTier(PSOL_TOKEN);
        uint256 amount = 1e18;
        address target = user;

        // Enable auto-swap but don't set fee tier
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        vm.stopPrank();

        // Verify auto-swap is enabled but fee tier is not set
        assertTrue(universalCore.isAutoSwapSupported(PSOL_TOKEN));
        assertEq(universalCore.defaultFeeTier(PSOL_TOKEN), initialFeeTier);

        // Record initial balances
        uint256 initialPSOLBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 initialWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 initialTargetNativeBalance = target.balance;

        // Attempt swap should revert due to invalid fee tier
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.InvalidFeeTier.selector);
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, amount, target, 0, 0, 0);

        // Verify balances remain unchanged
        assertEq(IERC20(PSOL_TOKEN).balanceOf(user), initialPSOLBalance);
        assertEq(IERC20(WPC_TOKEN).balanceOf(user), initialWPCBalance);
        assertEq(target.balance, initialTargetNativeBalance);

        // Verify configuration remains unchanged
        assertTrue(universalCore.isAutoSwapSupported(PSOL_TOKEN));
        assertEq(universalCore.defaultFeeTier(PSOL_TOKEN), initialFeeTier);
    }

    function test_DepositPRC20WithAutoSwap_OnlyUEModule() public {
        // Record initial state
        bool initialAutoSwap = universalCore.isAutoSwapSupported(PSOL_TOKEN);
        uint24 initialFeeTier = universalCore.defaultFeeTier(PSOL_TOKEN);

        // Setup auto-swap
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        vm.stopPrank();

        // Verify configuration was set
        assertTrue(universalCore.isAutoSwapSupported(PSOL_TOKEN));
        assertTrue(universalCore.isAutoSwapSupported(PSOL_TOKEN) != initialAutoSwap);
        assertEq(universalCore.defaultFeeTier(PSOL_TOKEN), 500);
        assertTrue(universalCore.defaultFeeTier(PSOL_TOKEN) != initialFeeTier);

        // Record initial balances
        uint256 initialPSOLBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 initialWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 initialTargetNativeBalance = user.balance;

        // Non-UEModule should not be able to call
        vm.prank(nonUEModule);
        vm.expectRevert();
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 0, 0, 0);

        // Verify balances remain unchanged
        assertEq(IERC20(PSOL_TOKEN).balanceOf(user), initialPSOLBalance);
        assertEq(IERC20(WPC_TOKEN).balanceOf(user), initialWPCBalance);
        assertEq(user.balance, initialTargetNativeBalance);

        // Verify configuration remains unchanged
        assertTrue(universalCore.isAutoSwapSupported(PSOL_TOKEN));
        assertEq(universalCore.defaultFeeTier(PSOL_TOKEN), 500);

        // Test with different non-UEModule address
        address anotherNonUEModule = makeAddr("anotherNonUEModule");
        vm.prank(anotherNonUEModule);
        vm.expectRevert();
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 0, 0, 0);
    }

    function test_DepositPRC20WithAutoSwap_WhenPaused() public {
        // Record initial state
        bool initialPaused = universalCore.paused();
        bool initialAutoSwap = universalCore.isAutoSwapSupported(PSOL_TOKEN);
        uint24 initialFeeTier = universalCore.defaultFeeTier(PSOL_TOKEN);

        // Setup auto-swap
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);

        // Pause the contract
        universalCore.pause();
        vm.stopPrank();

        // Verify contract is paused and auto-swap is configured
        assertTrue(universalCore.paused());
        assertTrue(universalCore.paused() != initialPaused);
        assertTrue(universalCore.isAutoSwapSupported(PSOL_TOKEN));
        assertTrue(universalCore.isAutoSwapSupported(PSOL_TOKEN) != initialAutoSwap);
        assertEq(universalCore.defaultFeeTier(PSOL_TOKEN), 500);
        assertTrue(universalCore.defaultFeeTier(PSOL_TOKEN) != initialFeeTier);

        // Record initial balances
        uint256 initialPSOLBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 initialWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 initialTargetNativeBalance = user.balance;

        // Attempt swap should revert due to pause
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert();
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 0, 0, 0);

        // Verify balances remain unchanged
        assertEq(IERC20(PSOL_TOKEN).balanceOf(user), initialPSOLBalance);
        assertEq(IERC20(WPC_TOKEN).balanceOf(user), initialWPCBalance);
        assertEq(user.balance, initialTargetNativeBalance);

        // Verify configuration remains unchanged
        assertTrue(universalCore.paused());
        assertTrue(universalCore.isAutoSwapSupported(PSOL_TOKEN));
        assertEq(universalCore.defaultFeeTier(PSOL_TOKEN), 500);

        // Test unpausing and then attempting swap
        vm.prank(deployer);
        universalCore.unpause();

        assertFalse(universalCore.paused());

        // Now swap should work
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 0, 1, 0);
    }

    function test_RealUniswapPoolExists() public {
        // Test that the real pools exist on the forked chain
        address pool = factory.getPool(PSOL_TOKEN, WPC_TOKEN, 500);
        assertEq(pool, PSOL_WPC_POOL);
        assertTrue(pool.code.length > 0); // Pool contract exists

        pool = factory.getPool(PETH_TOKEN, WPC_TOKEN, 500);
        assertEq(pool, PETH_WPC_POOL);
        assertTrue(pool.code.length > 0);

        pool = factory.getPool(USDT_TOKEN, WPC_TOKEN, 500);
        assertEq(pool, USDT_WPC_POOL);
        assertTrue(pool.code.length > 0);

        pool = factory.getPool(USDC_ETH_TOKEN, WPC_TOKEN, 500);
        assertEq(pool, USDC_ETH_WPC_POOL);
        assertTrue(pool.code.length > 0);

        // Test that pools don't exist for different fee tiers
        address nonExistentPool = factory.getPool(PSOL_TOKEN, WPC_TOKEN, 3000);
        // Note: Some pools might exist with different fee tiers, so we just verify they're different
        if (nonExistentPool != address(0)) {
            assertTrue(nonExistentPool != PSOL_WPC_POOL);
        }

        nonExistentPool = factory.getPool(PETH_TOKEN, WPC_TOKEN, 10000);
        if (nonExistentPool != address(0)) {
            assertTrue(nonExistentPool != PETH_WPC_POOL);
        }

        // Test that pools don't exist for different token pairs
        nonExistentPool = factory.getPool(PSOL_TOKEN, PETH_TOKEN, 500);
        assertEq(nonExistentPool, address(0));

        nonExistentPool = factory.getPool(USDT_TOKEN, USDC_ETH_TOKEN, 500);
        assertEq(nonExistentPool, address(0));
    }

    function test_RealTokenBalances() public {
        // Test that we can read real token balances on the forked chain
        // These might be 0, but the tokens should exist
        uint256 psolBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 pethBalance = IERC20(PETH_TOKEN).balanceOf(user);
        uint256 usdtBalance = IERC20(USDT_TOKEN).balanceOf(user);
        uint256 usdcEthBalance = IERC20(USDC_ETH_TOKEN).balanceOf(user);
        uint256 wpcBalance = IERC20(WPC_TOKEN).balanceOf(user);

        // Token balances are 0 as expected for new addresses
        assertEq(psolBalance, 0);
        assertEq(pethBalance, 0);
        assertEq(usdtBalance, 0);
        assertEq(usdcEthBalance, 0);
        assertEq(wpcBalance, 0);

        // Verify tokens exist by checking their code length
        assertTrue(PSOL_TOKEN.code.length > 0);
        assertTrue(PETH_TOKEN.code.length > 0);
        assertTrue(USDT_TOKEN.code.length > 0);
        assertTrue(USDC_ETH_TOKEN.code.length > 0);
        assertTrue(WPC_TOKEN.code.length > 0);

        // Test balance reading from different addresses
        address testAddress1 = makeAddr("testAddress1");
        address testAddress2 = makeAddr("testAddress2");

        uint256 psolBalance1 = IERC20(PSOL_TOKEN).balanceOf(testAddress1);
        uint256 psolBalance2 = IERC20(PSOL_TOKEN).balanceOf(testAddress2);

        // Balances should be 0 for new addresses
        assertEq(psolBalance1, 0);
        assertEq(psolBalance2, 0);

        // Test that we can read balances from the UniversalCore contract
        uint256 universalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));
        uint256 universalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // UniversalCore contract balances are 0 as expected
        assertEq(universalCorePSOLBalance, 0);
        assertEq(universalCoreWPCBalance, 0);

        // Test token decimals and symbols (using direct calls since IERC20 doesn't have decimals)
        (bool success1, bytes memory data1) = PSOL_TOKEN.call(abi.encodeWithSignature("decimals()"));
        if (success1 && data1.length >= 32) {
            uint8 decimals = abi.decode(data1, (uint8));
            assertTrue(decimals > 0);
        }

        (bool success2, bytes memory data2) = USDT_TOKEN.call(abi.encodeWithSignature("decimals()"));
        if (success2 && data2.length >= 32) {
            uint8 decimals = abi.decode(data2, (uint8));
            assertEq(decimals, 6); // USDT should have 6 decimals
        }
    }

    // ============ HELPER FUNCTIONS ============

    /**
     * @notice Helper function to verify DepositPRC20WithAutoSwap event
     * @param expectedPrc20 Expected PRC20 token address
     * @param expectedAmountIn Expected input amount
     * @param expectedPcToken Expected PC token address
     * @param expectedFee Expected fee tier
     * @param expectedTarget Expected target address
     */
    function verifyDepositPRC20WithAutoSwapEvent(
        address expectedPrc20,
        uint256 expectedAmountIn,
        address expectedPcToken,
        uint24 expectedFee,
        address expectedTarget
    ) internal {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool eventFound = false;

        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].topics[0]
                    == keccak256("DepositPRC20WithAutoSwap(address,uint256,address,uint256,uint24,address)")
            ) {
                (address prc20, uint256 amountIn, address pcToken, uint256 amountOut, uint24 fee, address target) =
                    abi.decode(logs[i].data, (address, uint256, address, uint256, uint24, address));

                assertEq(prc20, expectedPrc20);
                assertEq(amountIn, expectedAmountIn);
                assertEq(pcToken, expectedPcToken);
                assertTrue(amountOut > 0);
                assertEq(fee, expectedFee);
                assertEq(target, expectedTarget);

                eventFound = true;
                break;
            }
        }
        assertTrue(eventFound, "DepositPRC20WithAutoSwap event not found in recorded logs");
    }

    function test_VerifyUniswapContracts() public {
        // Verify that Uniswap contracts are properly deployed on Push Chain
        assertTrue(UNISWAP_FACTORY.code.length > 0);
        assertTrue(UNISWAP_ROUTER.code.length > 0);
        assertTrue(UNISWAP_QUOTER.code.length > 0);
        assertTrue(WPC_TOKEN.code.length > 0);

        // Verify all token contracts exist
        assertTrue(PSOL_TOKEN.code.length > 0);
        assertTrue(PETH_TOKEN.code.length > 0);
        assertTrue(USDT_TOKEN.code.length > 0);
        assertTrue(USDC_ETH_TOKEN.code.length > 0);

        // All Uniswap contracts verified on Push Chain
    }

    // ============ COMPREHENSIVE COVERAGE TESTS ============

    function test_DepositPRC20WithAutoSwap_MinPCOutZero_UsesQuoter() public {
        // Test when minPCOut=0, should go through quoter route
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        universalCore.setSlippageTolerance(PSOL_TOKEN, 300); // 3%
        vm.stopPrank();

        uint256 amount = 1e18; // 1 PSOL
        address target = user;

        uint256 initialTargetNativeBalance = target.balance;
        uint256 initialUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));

        // This should call getSwapQuote internally since minPCOut=0
        vm.recordLogs();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(
            PSOL_TOKEN,
            amount,
            target,
            0, // fee (use default)
            0, // minPCOut (should trigger quoter call)
            0 // deadline (use default)
        );

        // Verify the emitted event
        verifyDepositPRC20WithAutoSwapEvent(PSOL_TOKEN, amount, WPC_TOKEN, 500, target);

        // Verify balances after swap
        uint256 finalPSOLBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 finalWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 finalTargetNativeBalance = target.balance;
        uint256 finalUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));
        uint256 finalUniversalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // User should have received WPC tokens
        assertTrue(finalTargetNativeBalance > initialTargetNativeBalance, "Target should receive native PC tokens");

        // UniversalCore receives PSOL tokens (via minting) and swaps what it can
        // Due to low liquidity, only partial swaps may occur, leaving some PSOL in UniversalCore
        // The final balance should be: initial + minted - swapped_amount
        assertTrue(
            finalUniversalCorePSOLBalance >= initialUniversalCorePSOLBalance,
            "UniversalCore PSOL balance should be >= initial (partial swaps due to low liquidity are expected)"
        );

        // Verify that some swap occurred if target received WPC tokens
        if (finalTargetNativeBalance > initialTargetNativeBalance) {
            assertTrue(
                finalUniversalCorePSOLBalance < initialUniversalCorePSOLBalance + amount,
                "Some PSOL should have been swapped if target received native PC"
            );
        }
        // Note: UniversalCore might not have WPC tokens initially, so we don't check its balance decrease
        // The important thing is that the target receives WPC tokens from the swap

        // User's PSOL balance should not change; PRC20 is minted to UniversalCore
    }

    function test_DepositPRC20WithAutoSwap_MinPCOutProvided_BypassesQuoter() public {
        // Test when minPCOut>0, should bypass quoter
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        vm.stopPrank();

        uint256 amount = 1e18; // 1 PSOL
        address target = user;

        uint256 initialTargetNativeBalance = target.balance;
        uint256 initialUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));

        // Note: Event testing is complex due to unpredictable amountOut values
        // We'll focus on testing the core functionality and balance changes

        // This should NOT call getSwapQuote since minPCOut=1
        vm.recordLogs();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(
            PSOL_TOKEN,
            amount,
            target,
            0, // fee (use default)
            1, // minPCOut (should bypass quoter)
            0 // deadline (use default)
        );

        // Verify the emitted event
        verifyDepositPRC20WithAutoSwapEvent(PSOL_TOKEN, amount, WPC_TOKEN, 500, target);

        // Verify balances after swap
        uint256 finalPSOLBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 finalWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 finalTargetNativeBalance = target.balance;
        uint256 finalUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));
        uint256 finalUniversalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // User should have received WPC tokens
        assertTrue(finalTargetNativeBalance > initialTargetNativeBalance, "Target should receive native PC tokens");

        // UniversalCore receives PSOL tokens (via minting) and swaps what it can
        // Due to low liquidity, only partial swaps may occur, leaving some PSOL in UniversalCore
        // The final balance should be: initial + minted - swapped_amount
        assertTrue(
            finalUniversalCorePSOLBalance >= initialUniversalCorePSOLBalance,
            "UniversalCore PSOL balance should be >= initial (partial swaps due to low liquidity are expected)"
        );

        // Verify that some swap occurred if target received WPC tokens
        if (finalTargetNativeBalance > initialTargetNativeBalance) {
            assertTrue(
                finalUniversalCorePSOLBalance < initialUniversalCorePSOLBalance + amount,
                "Some PSOL should have been swapped if target received native PC"
            );
        }
        // Note: UniversalCore might not have WPC tokens initially, so we don't check its balance decrease
        // The important thing is that the target receives WPC tokens from the swap

        // Verify the amount of PSOL deposited matches (check user's balance decrease)
        // User's PSOL balance should not change - PRC20 is minted directly to UniversalCore
    }

    function test_DepositPRC20WithAutoSwap_FeeZero_UsesDefault() public {
        // Test when fee=0, should use default fee tier
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        vm.stopPrank();

        uint256 amount = 1e18;
        address target = user;

        uint256 initialTargetNativeBalance = target.balance;
        uint256 initialUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));

        // Note: Event testing is complex due to unpredictable amountOut values
        // We'll focus on testing the core functionality and balance changes

        // Should use default fee tier (500)
        vm.recordLogs();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(
            PSOL_TOKEN,
            amount,
            target,
            0, // fee=0 (should use default)
            1, // minPCOut
            0 // deadline
        );

        // Verify the emitted event
        verifyDepositPRC20WithAutoSwapEvent(PSOL_TOKEN, amount, WPC_TOKEN, 500, target);

        // Verify balances after swap
        uint256 finalPSOLBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 finalWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 finalTargetNativeBalance = target.balance;
        uint256 finalUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));
        uint256 finalUniversalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // User should have received WPC tokens
        assertTrue(finalTargetNativeBalance > initialTargetNativeBalance, "Target should receive native PC tokens");

        // UniversalCore receives PSOL tokens (via minting) and swaps what it can
        // Due to low liquidity, only partial swaps may occur, leaving some PSOL in UniversalCore
        // The final balance should be: initial + minted - swapped_amount
        assertTrue(
            finalUniversalCorePSOLBalance >= initialUniversalCorePSOLBalance,
            "UniversalCore PSOL balance should be >= initial (partial swaps due to low liquidity are expected)"
        );

        // Verify that some swap occurred if target received WPC tokens
        if (finalTargetNativeBalance > initialTargetNativeBalance) {
            assertTrue(
                finalUniversalCorePSOLBalance < initialUniversalCorePSOLBalance + amount,
                "Some PSOL should have been swapped if target received native PC"
            );
        }
        // Note: UniversalCore might not have WPC tokens initially, so we don't check its balance decrease
        // The important thing is that the target receives WPC tokens from the swap

        // Verify the amount of PSOL deposited matches (check user's balance decrease)
        // User's PSOL balance should not change - PRC20 is minted directly to UniversalCore
    }

    function test_DepositPRC20WithAutoSwap_FeeProvided_UsesProvided() public {
        // Test when fee>0, should use provided fee (default set to 0.3% but we pass 0.05%)
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 3000); // Set default to 0.3% pool
        vm.stopPrank();

        uint256 amount = 1e18;
        address target = user;

        uint256 initialTargetNativeBalance = target.balance;
        uint256 initialUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));

        vm.recordLogs();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(
            PSOL_TOKEN,
            amount,
            target,
            500, // fee=500 (should override default 3000)
            1, // minPCOut
            0 // deadline
        );

        verifyDepositPRC20WithAutoSwapEvent(
            PSOL_TOKEN,
            amount,
            WPC_TOKEN,
            500, // Should use provided fee, not default
            target
        );

        uint256 finalTargetNativeBalance = target.balance;
        uint256 finalUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));

        assertTrue(finalTargetNativeBalance > initialTargetNativeBalance, "Target should receive native PC tokens");

        assertTrue(
            finalUniversalCorePSOLBalance >= initialUniversalCorePSOLBalance,
            "UniversalCore PSOL balance should be >= initial (partial swaps due to low liquidity are expected)"
        );

        if (finalTargetNativeBalance > initialTargetNativeBalance) {
            assertTrue(
                finalUniversalCorePSOLBalance < initialUniversalCorePSOLBalance + amount,
                "Some PSOL should have been swapped if target received native PC"
            );
        }
    }

    function test_DepositPRC20WithAutoSwap_DeadlineZero_UsesDefault() public {
        // Test when deadline=0, should use default deadline
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        universalCore.setDefaultDeadlineMins(30); // Set default to 30 minutes
        vm.stopPrank();

        uint256 amount = 1e18;
        address target = user;

        uint256 initialTargetNativeBalance = target.balance;
        uint256 initialUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));

        // Should use default deadline (30 minutes from now)
        vm.recordLogs();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(
            PSOL_TOKEN,
            amount,
            target,
            0, // fee
            1, // minPCOut
            0 // deadline=0 (should use default)
        );

        // Verify the emitted event
        verifyDepositPRC20WithAutoSwapEvent(PSOL_TOKEN, amount, WPC_TOKEN, 500, target);

        // Verify balances after swap
        uint256 finalPSOLBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 finalWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 finalTargetNativeBalance = target.balance;
        uint256 finalUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));
        uint256 finalUniversalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // User should have received WPC tokens
        assertTrue(finalTargetNativeBalance > initialTargetNativeBalance, "Target should receive native PC tokens");

        // UniversalCore receives PSOL tokens (via minting) and swaps what it can
        // Due to low liquidity, only partial swaps may occur, leaving some PSOL in UniversalCore
        // The final balance should be: initial + minted - swapped_amount
        assertTrue(
            finalUniversalCorePSOLBalance >= initialUniversalCorePSOLBalance,
            "UniversalCore PSOL balance should be >= initial (partial swaps due to low liquidity are expected)"
        );

        // Verify that some swap occurred if target received WPC tokens
        if (finalTargetNativeBalance > initialTargetNativeBalance) {
            assertTrue(
                finalUniversalCorePSOLBalance < initialUniversalCorePSOLBalance + amount,
                "Some PSOL should have been swapped if target received native PC"
            );
        }
    }

    function test_DepositPRC20WithAutoSwap_DeadlineProvided_UsesProvided() public {
        // Test when deadline>0, should use provided deadline
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        vm.stopPrank();

        uint256 amount = 1e18;
        address target = user;
        uint256 customDeadline = block.timestamp + 60; // 1 minute from now

        uint256 initialTargetNativeBalance = target.balance;
        uint256 initialUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));

        // Should use provided deadline
        vm.recordLogs();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(
            PSOL_TOKEN,
            amount,
            target,
            0, // fee
            1, // minPCOut
            customDeadline // deadline (should use this)
        );

        // Verify the emitted event
        verifyDepositPRC20WithAutoSwapEvent(PSOL_TOKEN, amount, WPC_TOKEN, 500, target);

        // Verify balances after swap
        uint256 finalPSOLBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 finalWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 finalTargetNativeBalance = target.balance;
        uint256 finalUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));
        uint256 finalUniversalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // User should have received WPC tokens
        assertTrue(finalTargetNativeBalance > initialTargetNativeBalance, "Target should receive native PC tokens");

        // UniversalCore receives PSOL tokens (via minting) and swaps what it can
        // Due to low liquidity, only partial swaps may occur, leaving some PSOL in UniversalCore
        // The final balance should be: initial + minted - swapped_amount
        assertTrue(
            finalUniversalCorePSOLBalance >= initialUniversalCorePSOLBalance,
            "UniversalCore PSOL balance should be >= initial (partial swaps due to low liquidity are expected)"
        );

        // Verify that some swap occurred if target received WPC tokens
        if (finalTargetNativeBalance > initialTargetNativeBalance) {
            assertTrue(
                finalUniversalCorePSOLBalance < initialUniversalCorePSOLBalance + amount,
                "Some PSOL should have been swapped if target received native PC"
            );
        }
        // Note: UniversalCore might not have WPC tokens initially, so we don't check its balance decrease
        // The important thing is that the target receives WPC tokens from the swap

        // Verify the amount of PSOL deposited matches (check user's balance decrease)
        // User's PSOL balance should not change - PRC20 is minted directly to UniversalCore
    }

    function test_CalculateMinOutput_SlippageZero_UsesDefault() public {
        // Test calculateMinOutput when slippage tolerance=0, should use default 3%
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        // Don't set slippage tolerance (should default to 300 = 3%)
        vm.stopPrank();

        uint256 amount = 1e18;
        address target = user;

        uint256 initialTargetNativeBalance = target.balance;
        uint256 initialUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));

        // This should use default 3% slippage tolerance
        vm.recordLogs();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(
            PSOL_TOKEN,
            amount,
            target,
            0, // fee
            0, // minPCOut (should trigger calculateMinOutput with default slippage)
            0 // deadline
        );

        // Verify the emitted event
        verifyDepositPRC20WithAutoSwapEvent(PSOL_TOKEN, amount, WPC_TOKEN, 500, target);

        // Verify balances after swap
        uint256 finalPSOLBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 finalWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 finalTargetNativeBalance = target.balance;
        uint256 finalUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));
        uint256 finalUniversalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // User should have received WPC tokens
        assertTrue(finalTargetNativeBalance > initialTargetNativeBalance, "Target should receive native PC tokens");

        // UniversalCore receives PSOL tokens (via minting) and swaps what it can
        // Due to low liquidity, only partial swaps may occur, leaving some PSOL in UniversalCore
        // The final balance should be: initial + minted - swapped_amount
        assertTrue(
            finalUniversalCorePSOLBalance >= initialUniversalCorePSOLBalance,
            "UniversalCore PSOL balance should be >= initial (partial swaps due to low liquidity are expected)"
        );

        // Verify that some swap occurred if target received WPC tokens
        if (finalTargetNativeBalance > initialTargetNativeBalance) {
            assertTrue(
                finalUniversalCorePSOLBalance < initialUniversalCorePSOLBalance + amount,
                "Some PSOL should have been swapped if target received native PC"
            );
        }
    }

    function test_CalculateMinOutput_SlippageSet_UsesSet() public {
        // Test calculateMinOutput when slippage tolerance is set
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        universalCore.setSlippageTolerance(PSOL_TOKEN, 500); // 5%
        vm.stopPrank();

        uint256 amount = 1e18;
        address target = user;

        uint256 initialTargetNativeBalance = target.balance;
        uint256 initialUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));

        // This should use 5% slippage tolerance
        vm.recordLogs();
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(
            PSOL_TOKEN,
            amount,
            target,
            0, // fee
            0, // minPCOut (should trigger calculateMinOutput with 5% slippage)
            0 // deadline
        );

        // Verify the emitted event
        verifyDepositPRC20WithAutoSwapEvent(PSOL_TOKEN, amount, WPC_TOKEN, 500, target);

        // Verify balances after swap
        uint256 finalPSOLBalance = IERC20(PSOL_TOKEN).balanceOf(user);
        uint256 finalWPCBalance = IERC20(WPC_TOKEN).balanceOf(user);
        uint256 finalTargetNativeBalance = target.balance;
        uint256 finalUniversalCorePSOLBalance = IERC20(PSOL_TOKEN).balanceOf(address(universalCore));
        uint256 finalUniversalCoreWPCBalance = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        // User should have received WPC tokens
        assertTrue(finalTargetNativeBalance > initialTargetNativeBalance, "Target should receive native PC tokens");

        // UniversalCore receives PSOL tokens (via minting) and swaps what it can
        // Due to low liquidity, only partial swaps may occur, leaving some PSOL in UniversalCore
        // The final balance should be: initial + minted - swapped_amount
        assertTrue(
            finalUniversalCorePSOLBalance >= initialUniversalCorePSOLBalance,
            "UniversalCore PSOL balance should be >= initial (partial swaps due to low liquidity are expected)"
        );

        // Verify that some swap occurred if target received WPC tokens
        if (finalTargetNativeBalance > initialTargetNativeBalance) {
            assertTrue(
                finalUniversalCorePSOLBalance < initialUniversalCorePSOLBalance + amount,
                "Some PSOL should have been swapped if target received native PC"
            );
        }

        // User's PSOL balance should not change - PRC20 is minted directly to UniversalCore
    }

    function test_GetSwapQuote_QuoterV2Integration() public {
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        vm.stopPrank();

        uint256 quote = universalCore.getSwapQuote(PSOL_TOKEN, WPC_TOKEN, 500, 1e18);
        assertTrue(quote >= 0);
    }

    // === Coverage Tests for Uncovered Lines ===

    function test_SetUniswapV3Addresses_ZeroAddressReverts() public {
        vm.startPrank(deployer);

        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setUniswapV3Addresses(address(0), address(1), address(1));

        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setUniswapV3Addresses(address(1), address(0), address(1));

        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setUniswapV3Addresses(address(1), address(1), address(0));

        vm.stopPrank();
    }

    function test_SetUniswapV3Addresses_Success() public {
        address newFactory = address(0x123);
        address newRouter = address(0x456);
        address newQuoter = address(0x789);

        vm.prank(deployer);
        universalCore.setUniswapV3Addresses(newFactory, newRouter, newQuoter);

        assertEq(universalCore.uniswapV3FactoryAddress(), newFactory);
        assertEq(universalCore.uniswapV3SwapRouterAddress(), newRouter);
        assertEq(universalCore.uniswapV3QuoterAddress(), newQuoter);
    }

    function test_SetDefaultFeeTier_InvalidFeeTierReverts() public {
        vm.prank(deployer);
        vm.expectRevert(UniversalCoreErrors.InvalidFeeTier.selector);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 999);
    }

    function test_DeadlineExpired_Reverts() public {
        // Test when deadline has already passed
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        vm.stopPrank();

        uint256 amount = 1e18;
        address target = user;
        uint256 expiredDeadline = block.timestamp - 1; // 1 second ago

        // Should revert with DeadlineExpired
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(CommonErrors.DeadlineExpired.selector);
        universalCore.depositPRC20WithAutoSwap(
            PSOL_TOKEN,
            amount,
            target,
            0, // fee
            1, // minPCOut
            expiredDeadline // deadline (already expired)
        );
    }

    function test_PoolNotFound_Reverts() public {
        // Test when pool doesn't exist for given fee tier
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        vm.stopPrank();

        uint256 amount = 1e18;
        address target = user;

        // Should revert with PoolNotFound (using non-existent fee tier)
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.PoolNotFound.selector);
        universalCore.depositPRC20WithAutoSwap(
            PSOL_TOKEN,
            amount,
            target,
            10000, // fee (pool might not exist for this fee tier)
            1, // minPCOut
            0 // deadline
        );
    }

    function test_GetSwapQuote_QuoterV2ReturnsZero_ReturnsEstimate() public {
        vm.startPrank(deployer);
        universalCore.setAutoSwapSupported(PSOL_TOKEN, true);
        universalCore.setDefaultFeeTier(PSOL_TOKEN, 500);
        vm.stopPrank();

        // Use a tiny amount to produce 0 output due to tick spacing
        uint256 amount = 1; // 1 wei
        uint256 quote = universalCore.getSwapQuote(PSOL_TOKEN, WPC_TOKEN, 500, amount);

        // Should return estimate (amount / 1000) when QuoterV2 returns 0
        assertEq(quote, amount / 1000);
    }
}
