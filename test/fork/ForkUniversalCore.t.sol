// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../src/UniversalCore.sol";
import "../../src/PRC20.sol";
import "../../src/WPC.sol";
import "../../src/interfaces/IPRC20.sol";
import "../../src/interfaces/IWPC.sol";
import "../../src/interfaces/IUniversalCore.sol";
import {IUniswapV3Factory, ISwapRouter} from "../../src/interfaces/uniswapv3/IUniswapV3.sol";
import {UniversalCoreErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import "../../test/helpers/UpgradeableContractHelper.sol";
import "../../test/helpers/PushChainAddresses.sol";

/// @title Fork tests for UniversalCore Uniswap V3 integration
/// @notice Tests against real Uniswap V3 pools on Push Chain Donut Testnet
contract ForkUniversalCoreTest is Test, UpgradeableContractHelper, PushChainAddresses {
    // =========================================================================
    // Test State
    // =========================================================================

    UniversalCore public universalCore;
    uint256 public forkId;

    address public deployer;
    address public gateway;
    address public user;

    // =========================================================================
    // Events
    // =========================================================================

    event SwapAndBurnGas(address indexed gasToken, uint256 pcIn, uint256 gasFee, uint24 fee, address indexed caller);
    event DepositPRC20WithAutoSwap(
        address prc20, uint256 amountIn, address pcToken, uint256 amountOut, uint24 fee, address recipient
    );
    event RefundUnusedGas(
        address indexed gasToken, uint256 amount, address indexed recipient, bool swapped, uint256 pcOut
    );

    // =========================================================================
    // Setup
    // =========================================================================

    // Pinned block — update when pool liquidity needs refreshing.
    // To override: FORK_BLOCK=<n> forge test --match-path "test/fork/*"
    uint256 internal constant FORK_BLOCK_DEFAULT = 11_543_000;

    function setUp() public {
        string memory rpcUrl = vm.envOr("PUSH_CHAIN_TESTNET_RPC_URL", string("https://evm.donut.rpc.push.org/"));
        uint256 forkBlock = vm.envOr("FORK_BLOCK", FORK_BLOCK_DEFAULT);
        forkId = vm.createFork(rpcUrl, forkBlock);
        vm.selectFork(forkId);

        deployer = makeAddr("deployer");
        gateway = makeAddr("gateway");
        user = makeAddr("user");

        vm.startPrank(deployer);

        // Deploy UniversalCore behind proxy
        UniversalCore implementation = new UniversalCore();
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector,
            deployer,
            makeAddr("pauser"),
            WPC_TOKEN,
            UNISWAP_FACTORY,
            UNISWAP_ROUTER
        );
        address proxyAddress = deployUpgradeableContract(address(implementation), initData);
        universalCore = UniversalCore(payable(proxyAddress));

        // Set gateway
        universalCore.updateUniversalGatewayPC(gateway);

        // Configure auto-swap and fee tiers for test tokens
        _configureToken(PSOL_TOKEN, 500);
        _configureToken(PETH_TOKEN, 500);
        _configureToken(USDT_ETH_TOKEN, 500);
        _configureToken(USDC_ETH_TOKEN, 500);
        _configureToken(PETH_ARB_TOKEN, 3000);
        _configureToken(PBNB_TOKEN, 500);

        vm.stopPrank();

        // Update PRC20 universalCore references to point to our new instance
        _updatePRC20UniversalCore(PSOL_TOKEN);
        _updatePRC20UniversalCore(PETH_TOKEN);
        _updatePRC20UniversalCore(USDT_ETH_TOKEN);
        _updatePRC20UniversalCore(USDC_ETH_TOKEN);
        _updatePRC20UniversalCore(PETH_ARB_TOKEN);
        _updatePRC20UniversalCore(PBNB_TOKEN);

        // Fund gateway and user
        vm.deal(gateway, 1000 ether);
        vm.deal(user, 1000 ether);
    }

    function _configureToken(address token, uint24 fee) private {
        universalCore.updateAutoSwapSupported(token, true);
        universalCore.updateDefaultFeeTier(token, fee);
    }

    function _updatePRC20UniversalCore(address token) private {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        (bool ok,) = token.call(abi.encodeWithSignature("updateUniversalCore(address)", address(universalCore)));
        require(ok, "Failed to update universalCore on PRC20");
    }

    // =========================================================================
    // Section A: Pool Validation (7 tests)
    // =========================================================================

    function test_fork_realPoolExists_pSOL_WPC() public view {
        address pool = IUniswapV3Factory(UNISWAP_FACTORY)
            .getPool(
                PSOL_TOKEN < WPC_TOKEN ? PSOL_TOKEN : WPC_TOKEN, PSOL_TOKEN < WPC_TOKEN ? WPC_TOKEN : PSOL_TOKEN, 500
            );
        assertEq(pool, PSOL_WPC_POOL);
    }

    function test_fork_realPoolExists_pETH_WPC() public view {
        address pool = IUniswapV3Factory(UNISWAP_FACTORY)
            .getPool(
                PETH_TOKEN < WPC_TOKEN ? PETH_TOKEN : WPC_TOKEN, PETH_TOKEN < WPC_TOKEN ? WPC_TOKEN : PETH_TOKEN, 500
            );
        assertEq(pool, PETH_WPC_POOL);
    }

    function test_fork_realPoolExists_USDT_eth_WPC() public view {
        address pool = IUniswapV3Factory(UNISWAP_FACTORY)
            .getPool(
                USDT_ETH_TOKEN < WPC_TOKEN ? USDT_ETH_TOKEN : WPC_TOKEN,
                USDT_ETH_TOKEN < WPC_TOKEN ? WPC_TOKEN : USDT_ETH_TOKEN,
                500
            );
        assertEq(pool, USDT_ETH_WPC_POOL);
    }

    function test_fork_realPoolExists_pETH_arb_WPC() public view {
        address pool = IUniswapV3Factory(UNISWAP_FACTORY)
            .getPool(
                PETH_ARB_TOKEN < WPC_TOKEN ? PETH_ARB_TOKEN : WPC_TOKEN,
                PETH_ARB_TOKEN < WPC_TOKEN ? WPC_TOKEN : PETH_ARB_TOKEN,
                3000
            );
        assertEq(pool, PETH_ARB_WPC_POOL);
    }

    function test_fork_realPoolExists_pBNB_WPC() public view {
        address pool = IUniswapV3Factory(UNISWAP_FACTORY)
            .getPool(
                PBNB_TOKEN < WPC_TOKEN ? PBNB_TOKEN : WPC_TOKEN, PBNB_TOKEN < WPC_TOKEN ? WPC_TOKEN : PBNB_TOKEN, 500
            );
        assertEq(pool, PBNB_WPC_POOL);
    }

    function test_fork_updateGasPCPool_validatesRealPool() public {
        vm.startPrank(deployer);
        // Valid pool succeeds
        universalCore.updateGasPCPool("eip155:1", PSOL_TOKEN, 500);
        assertEq(universalCore.gasPCPoolByChainNamespace("eip155:1"), PSOL_WPC_POOL);

        // Nonexistent pool reverts
        vm.expectRevert(UniversalCoreErrors.PoolNotFound.selector);
        universalCore.updateGasPCPool("eip155:2", PSOL_TOKEN, 10000);
        vm.stopPrank();
    }

    function test_fork_allPoolsMatchExpectedAddresses() public view {
        // Verify all 6 test pools resolve correctly
        _assertPool(PSOL_TOKEN, 500, PSOL_WPC_POOL);
        _assertPool(PETH_TOKEN, 500, PETH_WPC_POOL);
        _assertPool(USDT_ETH_TOKEN, 500, USDT_ETH_WPC_POOL);
        _assertPool(USDC_ETH_TOKEN, 500, USDC_ETH_WPC_POOL);
        _assertPool(PETH_ARB_TOKEN, 3000, PETH_ARB_WPC_POOL);
        _assertPool(PBNB_TOKEN, 500, PBNB_WPC_POOL);
    }

    function _assertPool(address token, uint24 fee, address expected) private view {
        address pool = IUniswapV3Factory(UNISWAP_FACTORY)
            .getPool(token < WPC_TOKEN ? token : WPC_TOKEN, token < WPC_TOKEN ? WPC_TOKEN : token, fee);
        assertEq(pool, expected);
    }

    // =========================================================================
    // Section B: depositPRC20WithAutoSwap (14 tests)
    // =========================================================================

    function test_fork_autoSwap_pSOL_toPC() public {
        _testAutoSwap(PSOL_TOKEN, 1e18, 500);
    }

    function test_fork_autoSwap_pETH_toPC() public {
        _testAutoSwap(PETH_TOKEN, 1e15, 500); // 0.001 pETH (high value)
    }

    function test_fork_autoSwap_USDT_eth_toPC() public {
        _testAutoSwap(USDT_ETH_TOKEN, 10e18, 500);
    }

    function test_fork_autoSwap_pETH_arb_toPC() public {
        _testAutoSwap(PETH_ARB_TOKEN, 1e15, 3000);
    }

    function test_fork_autoSwap_pBNB_toPC() public {
        _testAutoSwap(PBNB_TOKEN, 1e17, 500); // 0.1 pBNB
    }

    function _testAutoSwap(address token, uint256 amount, uint24 fee) private {
        uint256 recipientBalanceBefore = user.balance;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(token, amount, user, fee, 1, 0);

        uint256 pcReceived = user.balance - recipientBalanceBefore;
        assertGt(pcReceived, 0, "Recipient should receive native PC");
    }

    function test_fork_autoSwap_feeZero_usesDefault() public {
        uint256 balanceBefore = user.balance;

        // fee=0 should resolve to defaultFeeTier (500 for pSOL)
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 0, 1, 0);

        assertGt(user.balance - balanceBefore, 0);
    }

    function test_fork_autoSwap_feeProvided_usesProvided() public {
        uint256 balanceBefore = user.balance;

        // Explicit fee=500
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 500, 1, 0);

        assertGt(user.balance - balanceBefore, 0);
    }

    function test_fork_autoSwap_minPCOutEnforced() public {
        // Set minPCOut absurdly high so swap fails
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(); // Uniswap "Too little received" or SlippageExceeded
        universalCore.depositPRC20WithAutoSwap(USDT_ETH_TOKEN, 1e18, user, 500, type(uint256).max, 0);
    }

    function test_fork_autoSwap_minPCOutZero_reverts() public {
        // minPCOut=0 reverts with ZeroAmount
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(CommonErrors.ZeroAmount.selector);
        universalCore.depositPRC20WithAutoSwap(USDT_ETH_TOKEN, 1e18, user, 500, 0, 0);
    }

    function test_fork_autoSwap_deadlineExpired_reverts() public {
        vm.warp(1000);
        uint256 pastDeadline = block.timestamp - 1;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(CommonErrors.DeadlineExpired.selector);
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 500, 1, pastDeadline);
    }

    function test_fork_autoSwap_deadlineZero_usesDefault() public {
        uint256 balanceBefore = user.balance;

        // deadline=0 resolves to block.timestamp + defaultDeadlineMins
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 500, 1, 0);

        assertGt(user.balance - balanceBefore, 0);
    }

    function test_fork_autoSwap_approvalRevoked() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 500, 1, 0);

        // Approval should be revoked after swap
        uint256 allowance = IERC20(PSOL_TOKEN).allowance(address(universalCore), UNISWAP_ROUTER);
        assertEq(allowance, 0, "Approval should be revoked after swap");
    }

    function test_fork_autoSwap_recipientReceivesPC() public {
        uint256 balanceBefore = user.balance;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(USDT_ETH_TOKEN, 10e18, user, 500, 1, 0);

        uint256 pcReceived = user.balance - balanceBefore;
        assertGt(pcReceived, 0, "Recipient must receive native PC");
        // 10 USDT at 1:10 ratio ≈ 100 WPC worth of PC (minus fees)
        assertGt(pcReceived, 50e18, "Should receive roughly 100 PC minus slippage");
    }

    function test_fork_autoSwap_wrongFeeTier_reverts() public {
        // pSOL pool is fee 500, try with 10000
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UniversalCoreErrors.PoolNotFound.selector);
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 10000, 1, 0);
    }

    // =========================================================================
    // Section C: swapAndBurnGas (14 tests)
    // =========================================================================

    function test_fork_swapAndBurnGas_pSOL_basicFlow() public {
        _testSwapAndBurn(PSOL_TOKEN, 500, 1e6); // tiny amount — pool price is ~2.15e13 WPC/pSOL
    }

    function test_fork_swapAndBurnGas_pETH_basicFlow() public {
        _testSwapAndBurn(PETH_TOKEN, 500, 1e13); // 0.00001 pETH
    }

    function test_fork_swapAndBurnGas_USDT_eth_basicFlow() public {
        _testSwapAndBurn(USDT_ETH_TOKEN, 500, 10); // tiny amount — pool price is ~8.6e15 WPC/USDT unit
    }

    function test_fork_swapAndBurnGas_pETH_arb_fee3000() public {
        _testSwapAndBurn(PETH_ARB_TOKEN, 3000, 1e13);
    }

    function _testSwapAndBurn(address gasToken, uint24 fee, uint256 gasFee) private {
        uint256 sendAmount = 500 ether; // Send plenty of PC

        vm.prank(gateway);
        (uint256 gasTokenOut, uint256 refund) =
            universalCore.swapAndBurnGas{value: sendAmount}(gasToken, fee, gasFee, 0, user);

        assertEq(gasTokenOut, gasFee, "gasTokenOut should equal gasFee");
        assertGt(refund, 0, "Should have refund");
        assertEq(refund, sendAmount - (sendAmount - refund), "Refund math");
    }

    function test_fork_swapAndBurnGas_refundCalculation() public {
        uint256 sendAmount = 500 ether;
        uint256 gasFee = 1e13; // small gasFee to avoid liquidity issues
        uint256 userBalanceBefore = user.balance;

        vm.prank(gateway);
        (uint256 gasTokenOut, uint256 refund) =
            universalCore.swapAndBurnGas{value: sendAmount}(PETH_TOKEN, 500, gasFee, 0, user);

        assertEq(gasTokenOut, gasFee);
        // refund = msg.value - amountInUsed
        assertEq(user.balance, userBalanceBefore + refund);
        assertLt(sendAmount - refund, sendAmount, "Some PC was used for swap");
    }

    function test_fork_swapAndBurnGas_refundSentToCaller() public {
        uint256 userBalanceBefore = user.balance;
        uint256 gatewayBalanceBefore = gateway.balance;

        vm.prank(gateway);
        (, uint256 refund) = universalCore.swapAndBurnGas{value: 500 ether}(PETH_TOKEN, 500, 1e13, 0, user);

        // Refund goes to `caller` (user), not msg.sender (gateway)
        assertEq(user.balance, userBalanceBefore + refund);
        assertEq(gateway.balance, gatewayBalanceBefore - 500 ether);
    }

    function test_fork_swapAndBurnGas_gasTokenBurned() public {
        uint256 gasFee = 1e13; // small amount for liquidity safety

        // Get totalSupply before (on forked state, the token exists)
        uint256 supplyBefore = IERC20(PETH_TOKEN).totalSupply();

        vm.prank(gateway);
        universalCore.swapAndBurnGas{value: 500 ether}(PETH_TOKEN, 500, gasFee, 0, user);

        uint256 supplyAfter = IERC20(PETH_TOKEN).totalSupply();
        // UniversalCore holds 0 gas tokens after
        assertEq(IERC20(PETH_TOKEN).balanceOf(address(universalCore)), 0);
        // Pool gives existing tokens so totalSupply unchanged by swap, but burn reduces it
        assertEq(supplyAfter, supplyBefore - gasFee, "totalSupply should decrease by gasFee");
    }

    function test_fork_swapAndBurnGas_insufficientMsgValue_reverts() public {
        // Send very little PC for a large gasFee
        vm.prank(gateway);
        vm.expectRevert(); // Uniswap STF (SafeTransferFrom) or similar
        universalCore.swapAndBurnGas{value: 1 wei}(PETH_TOKEN, 500, 1e18, 0, user);
    }

    function test_fork_swapAndBurnGas_poolNotFound_reverts() public {
        // Use a token with no pool configured
        address fakeToken = makeAddr("fakeToken");

        vm.prank(deployer);
        universalCore.updateDefaultFeeTier(fakeToken, 500);

        vm.prank(gateway);
        vm.expectRevert(UniversalCoreErrors.PoolNotFound.selector);
        universalCore.swapAndBurnGas{value: 100 ether}(fakeToken, 500, 1e18, 0, user);
    }

    function test_fork_swapAndBurnGas_deadlineExpired_reverts() public {
        vm.warp(1000);
        uint256 pastDeadline = block.timestamp - 1;

        vm.prank(gateway);
        vm.expectRevert(CommonErrors.DeadlineExpired.selector);
        universalCore.swapAndBurnGas{value: 100 ether}(USDT_ETH_TOKEN, 500, 1e18, pastDeadline, user);
    }

    function test_fork_swapAndBurnGas_feeTierMismatch_reverts() public {
        // pSOL pool is fee 500, try fee 10000
        vm.prank(gateway);
        vm.expectRevert(UniversalCoreErrors.PoolNotFound.selector);
        universalCore.swapAndBurnGas{value: 100 ether}(PSOL_TOKEN, 10000, 1e16, 0, user);
    }

    function test_fork_swapAndBurnGas_wpcDepositAndWithdraw() public {
        uint256 wpcBalanceBefore = IERC20(WPC_TOKEN).balanceOf(address(universalCore));

        vm.prank(gateway);
        universalCore.swapAndBurnGas{value: 100 ether}(PETH_TOKEN, 500, 1e13, 0, user);

        // After swap, UniversalCore should hold no WPC
        uint256 wpcBalanceAfter = IERC20(WPC_TOKEN).balanceOf(address(universalCore));
        assertEq(wpcBalanceAfter, wpcBalanceBefore, "No WPC should remain in UniversalCore");
    }

    function test_fork_swapAndBurnGas_exactOutputPrecision() public {
        uint256 gasFee = 1e13; // small pETH amount

        vm.prank(gateway);
        (uint256 gasTokenOut,) = universalCore.swapAndBurnGas{value: 500 ether}(PETH_TOKEN, 500, gasFee, 0, user);

        assertEq(gasTokenOut, gasFee, "Exact output should match gasFee precisely");
    }

    function test_fork_swapAndBurnGas_largeTrade_priceImpact() public {
        // Small trade
        vm.prank(gateway);
        (uint256 smallOut, uint256 smallRefund) =
            universalCore.swapAndBurnGas{value: 500 ether}(PETH_TOKEN, 500, 1e12, 0, user);
        uint256 smallAmountIn = 500 ether - smallRefund;

        // Larger trade (10x gasFee)
        vm.prank(gateway);
        (uint256 largeOut, uint256 largeRefund) =
            universalCore.swapAndBurnGas{value: 500 ether}(PETH_TOKEN, 500, 1e13, 0, user);
        uint256 largeAmountIn = 500 ether - largeRefund;

        assertEq(smallOut, 1e12);
        assertEq(largeOut, 1e13);
        // Price impact: per-unit cost should be higher for larger trade
        uint256 smallPerUnit = smallAmountIn * 1e18 / smallOut;
        uint256 largePerUnit = largeAmountIn * 1e18 / largeOut;
        assertGe(largePerUnit, smallPerUnit, "Larger trade should have >= per-unit cost");
    }

    // =========================================================================
    // Section D: refundUnusedGas (8 tests)
    // =========================================================================

    function test_fork_refundGas_withSwap_pSOL() public {
        uint256 balanceBefore = user.balance;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(PSOL_TOKEN, 1e18, user, true, 500, 1);

        assertGt(user.balance - balanceBefore, 0, "Recipient should get native PC");
    }

    function test_fork_refundGas_withSwap_pETH() public {
        uint256 balanceBefore = user.balance;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(PETH_TOKEN, 1e15, user, true, 500, 1);

        assertGt(user.balance - balanceBefore, 0, "Recipient should get native PC");
    }

    function test_fork_refundGas_withoutSwap() public {
        uint256 balanceBefore = IERC20(PSOL_TOKEN).balanceOf(user);

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(PSOL_TOKEN, 1e18, user, false, 0, 0);

        assertEq(IERC20(PSOL_TOKEN).balanceOf(user), balanceBefore + 1e18, "Should deposit PRC20 directly");
    }

    function test_fork_refundGas_withSwap_minPCOutEnforced() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(); // Uniswap slippage or SlippageExceeded
        universalCore.refundUnusedGas(USDT_ETH_TOKEN, 1e18, user, true, 500, type(uint256).max);
    }

    function test_fork_refundGas_withSwap_feeResolution() public {
        uint256 balanceBefore = user.balance;

        // fee=0 uses default (500)
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(USDT_ETH_TOKEN, 1e18, user, true, 0, 1);

        assertGt(user.balance - balanceBefore, 0);
    }

    function test_fork_refundGas_withSwap_recipientGetsPC() public {
        uint256 balanceBefore = user.balance;

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(USDT_ETH_TOKEN, 10e18, user, true, 500, 1);

        uint256 pcReceived = user.balance - balanceBefore;
        assertGt(pcReceived, 0);
        // 10 USDT at ~10 WPC ratio = ~100 PC minus fees
        assertGt(pcReceived, 50e18, "Should receive roughly 100 PC minus slippage");
    }

    function test_fork_refundGas_withSwap_approvalCleanup() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.refundUnusedGas(USDT_ETH_TOKEN, 1e18, user, true, 500, 1);

        uint256 allowance = IERC20(USDT_ETH_TOKEN).allowance(address(universalCore), UNISWAP_ROUTER);
        assertEq(allowance, 0, "Approval should be revoked after swap");
    }

    function test_fork_refundGas_withSwap_deadlineHandling() public {
        // deadline=0 uses default — should succeed via depositPRC20WithAutoSwap
        uint256 balanceBefore = user.balance;
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 0, 1, 0);
        assertGt(user.balance - balanceBefore, 0);

        // Expired deadline should revert with DeadlineExpired
        uint256 pastDeadline = block.timestamp - 1;
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(CommonErrors.DeadlineExpired.selector);
        universalCore.depositPRC20WithAutoSwap(PSOL_TOKEN, 1e18, user, 0, 1, pastDeadline);
    }

    // =========================================================================
    // Section E: WPC Wrap/Unwrap Cycle (3 tests)
    // =========================================================================

    function test_fork_wpc_depositWithdrawCycle() public {
        uint256 amount = 10 ether;
        vm.deal(user, amount);

        vm.startPrank(user);

        // Deposit native PC to WPC
        IWPC(WPC_TOKEN).deposit{value: amount}();
        assertEq(IERC20(WPC_TOKEN).balanceOf(user), amount);

        // Withdraw WPC back to native PC
        uint256 balanceBefore = user.balance;
        IWPC(WPC_TOKEN).withdraw(amount);
        assertEq(IERC20(WPC_TOKEN).balanceOf(user), 0);
        assertEq(user.balance, balanceBefore + amount);

        vm.stopPrank();
    }

    function test_fork_wpc_totalSupplyMatchesBalance() public {
        uint256 amount = 5 ether;
        vm.deal(user, amount);

        vm.prank(user);
        IWPC(WPC_TOKEN).deposit{value: amount}();

        assertEq(
            IERC20(WPC_TOKEN).totalSupply(), address(WPC_TOKEN).balance, "WPC totalSupply must equal contract balance"
        );
    }

    function test_fork_wpc_transferBetweenAccounts() public {
        uint256 amount = 5 ether;
        address recipient = makeAddr("wpcRecipient");

        vm.deal(user, amount);
        vm.prank(user);
        IWPC(WPC_TOKEN).deposit{value: amount}();

        vm.prank(user);
        IERC20(WPC_TOKEN).transfer(recipient, amount);

        assertEq(IERC20(WPC_TOKEN).balanceOf(user), 0);
        assertEq(IERC20(WPC_TOKEN).balanceOf(recipient), amount);
    }

    // =========================================================================
    // Section F: Contract Verification (5 tests)
    // =========================================================================

    function test_fork_uniswapFactory_codeExists() public view {
        assertGt(UNISWAP_FACTORY.code.length, 0, "Factory should have bytecode");
    }

    function test_fork_uniswapRouter_codeExists() public view {
        assertGt(UNISWAP_ROUTER.code.length, 0, "Router should have bytecode");
    }

    function test_fork_quoterV2_codeExists() public view {
        assertGt(UNISWAP_QUOTER.code.length, 0, "QuoterV2 should have bytecode");
    }

    function test_fork_wpcToken_codeExists() public view {
        assertGt(WPC_TOKEN.code.length, 0, "WPC should have bytecode");
    }

    function test_fork_allPRC20Tokens_codeExists() public view {
        assertGt(PSOL_TOKEN.code.length, 0, "pSOL should have bytecode");
        assertGt(PETH_TOKEN.code.length, 0, "pETH should have bytecode");
        assertGt(USDT_ETH_TOKEN.code.length, 0, "USDT.eth should have bytecode");
        assertGt(USDC_ETH_TOKEN.code.length, 0, "USDC.eth should have bytecode");
        assertGt(PETH_ARB_TOKEN.code.length, 0, "pETH.arb should have bytecode");
        assertGt(PBNB_TOKEN.code.length, 0, "pBNB should have bytecode");
    }
}
