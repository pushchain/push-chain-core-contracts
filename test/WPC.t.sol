// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../src/WPC.sol";
import "../src/Interfaces/IWPC.sol";

/**
 * @title WPCTest
 * @notice Comprehensive test suite for the WPC (Wrapped PC) contract
 * @dev Tests all functionality including deposits, withdrawals, transfers, and approvals
 */
contract WPCTest is Test {
    // Contract under test
    WPC public wpc;
    
    // Test accounts
    address public alice;
    address public bob;
    address public charlie;
    address public attacker;
    
    // Test values
    uint256 public constant DEPOSIT_AMOUNT = 1 ether;
    uint256 public constant LARGE_AMOUNT = 10 ether;
    uint256 public constant SMALL_AMOUNT = 0.001 ether;
    uint256 public constant ZERO_AMOUNT = 0;
    
    // Events to test
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);
    event Transfer(address indexed src, address indexed dst, uint256 wad);
    event Approval(address indexed src, address indexed guy, uint256 wad);

    function setUp() public {
        // Deploy the WPC contract
        wpc = new WPC();
        
        // Create test accounts
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");
        attacker = makeAddr("attacker");
        
        // Fund test accounts with ETH
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(charlie, 100 ether);
        vm.deal(attacker, 100 ether);
    }

    function testName() public view {
        assertEq(wpc.name(), "Wrapped PC");
    }

    function testSymbol() public view {
        assertEq(wpc.symbol(), "WPC");
    }

    function testDecimals() public view {
        assertEq(wpc.decimals(), 18);
    }

    function testInitialBalanceOf() public view {
        assertEq(wpc.balanceOf(alice), 0);
        assertEq(wpc.balanceOf(bob), 0);
    }

    function testInitialAllowance() public view {
        assertEq(wpc.allowance(alice, bob), 0);
        assertEq(wpc.allowance(bob, alice), 0);
    }

    function testInitialTotalSupply() public view {
        assertEq(wpc.totalSupply(), 0);
    }

    // =========================
    //    DEPOSIT TESTS
    // =========================

    function testDeposit() public {
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Deposit(alice, DEPOSIT_AMOUNT);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        assertEq(wpc.balanceOf(alice), DEPOSIT_AMOUNT);
        assertEq(wpc.totalSupply(), DEPOSIT_AMOUNT);
        assertEq(address(wpc).balance, DEPOSIT_AMOUNT);
    }

    function testDepositZero() public {
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Deposit(alice, ZERO_AMOUNT);
        wpc.deposit{value: ZERO_AMOUNT}();
        
        assertEq(wpc.balanceOf(alice), ZERO_AMOUNT);
        assertEq(wpc.totalSupply(), ZERO_AMOUNT);
    }

    function testDepositLargeAmount() public {
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Deposit(alice, LARGE_AMOUNT);
        wpc.deposit{value: LARGE_AMOUNT}();
        
        assertEq(wpc.balanceOf(alice), LARGE_AMOUNT);
        assertEq(wpc.totalSupply(), LARGE_AMOUNT);
    }

    function testDepositFromDifferentAccounts() public {
        // Alice deposits
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Deposit(alice, DEPOSIT_AMOUNT);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        // Bob deposits
        vm.prank(bob);
        vm.expectEmit(true, false, false, true);
        emit Deposit(bob, DEPOSIT_AMOUNT);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        assertEq(wpc.balanceOf(alice), DEPOSIT_AMOUNT);
        assertEq(wpc.balanceOf(bob), DEPOSIT_AMOUNT);
        assertEq(wpc.totalSupply(), 2 * DEPOSIT_AMOUNT);
    }

    function testReceive() public {
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Deposit(alice, DEPOSIT_AMOUNT);
        (bool success,) = address(wpc).call{value: DEPOSIT_AMOUNT}("");
        require(success, "Receive failed");
        
        assertEq(wpc.balanceOf(alice), DEPOSIT_AMOUNT);
        assertEq(wpc.totalSupply(), DEPOSIT_AMOUNT);
    }

    // =========================
    //    WITHDRAW TESTS
    // =========================

    function testWithdraw() public {
        // First deposit
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        uint256 balanceBeforeWithdraw = alice.balance;
        
        // Withdraw
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Withdrawal(alice, DEPOSIT_AMOUNT);
        wpc.withdraw(DEPOSIT_AMOUNT);
        
        assertEq(wpc.balanceOf(alice), 0);
        assertEq(wpc.totalSupply(), 0);
        assertEq(alice.balance, balanceBeforeWithdraw + DEPOSIT_AMOUNT);
        assertEq(address(wpc).balance, 0);
    }

    function testWithdrawPartial() public {
        // Deposit large amount
        vm.prank(alice);
        wpc.deposit{value: LARGE_AMOUNT}();
        
        uint256 initialBalance = alice.balance;
        
        // Withdraw partial amount
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Withdrawal(alice, DEPOSIT_AMOUNT);
        wpc.withdraw(DEPOSIT_AMOUNT);
        
        assertEq(wpc.balanceOf(alice), LARGE_AMOUNT - DEPOSIT_AMOUNT);
        assertEq(wpc.totalSupply(), LARGE_AMOUNT - DEPOSIT_AMOUNT);
        assertEq(alice.balance, initialBalance + DEPOSIT_AMOUNT);
    }

    function testWithdrawZero() public {
        // Deposit first
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        uint256 initialBalance = alice.balance;
        
        // Withdraw zero
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Withdrawal(alice, ZERO_AMOUNT);
        wpc.withdraw(ZERO_AMOUNT);
        
        assertEq(wpc.balanceOf(alice), DEPOSIT_AMOUNT);
        assertEq(wpc.totalSupply(), DEPOSIT_AMOUNT);
        assertEq(alice.balance, initialBalance);
    }

    function testWithdrawInsufficientBalance() public {
        // Try to withdraw without depositing
        vm.prank(alice);
        vm.expectRevert();
        wpc.withdraw(DEPOSIT_AMOUNT);
    }

    function testWithdrawMoreThanBalance() public {
        // Deposit small amount
        vm.prank(alice);
        wpc.deposit{value: SMALL_AMOUNT}();
        
        // Try to withdraw more
        vm.prank(alice);
        vm.expectRevert();
        wpc.withdraw(DEPOSIT_AMOUNT);
    }

    function testWithdrawAll() public {
        // Deposit amount
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        uint256 balanceBeforeWithdraw = alice.balance;
        
        // Withdraw all
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Withdrawal(alice, DEPOSIT_AMOUNT);
        wpc.withdraw(DEPOSIT_AMOUNT);
        
        assertEq(wpc.balanceOf(alice), 0);
        assertEq(wpc.totalSupply(), 0);
        assertEq(alice.balance, balanceBeforeWithdraw + DEPOSIT_AMOUNT);
    }

    function testWithdrawMultiple() public {
        // Deposit large amount
        vm.prank(alice);
        wpc.deposit{value: LARGE_AMOUNT}();
        
        uint256 initialBalance = alice.balance;
        
        // First withdrawal
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Withdrawal(alice, DEPOSIT_AMOUNT);
        wpc.withdraw(DEPOSIT_AMOUNT);
        
        // Second withdrawal
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Withdrawal(alice, DEPOSIT_AMOUNT);
        wpc.withdraw(DEPOSIT_AMOUNT);
        
        assertEq(wpc.balanceOf(alice), LARGE_AMOUNT - 2 * DEPOSIT_AMOUNT);
        assertEq(wpc.totalSupply(), LARGE_AMOUNT - 2 * DEPOSIT_AMOUNT);
        assertEq(alice.balance, initialBalance + 2 * DEPOSIT_AMOUNT);
    }

    // =========================
    //    APPROVE TESTS
    // =========================

    function testApprove() public {
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, bob, DEPOSIT_AMOUNT);
        bool success = wpc.approve(bob, DEPOSIT_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.allowance(alice, bob), DEPOSIT_AMOUNT);
    }

    function testApproveZero() public {
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, bob, ZERO_AMOUNT);
        bool success = wpc.approve(bob, ZERO_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.allowance(alice, bob), ZERO_AMOUNT);
    }

    function testApproveLargeAmount() public {
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, bob, LARGE_AMOUNT);
        bool success = wpc.approve(bob, LARGE_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.allowance(alice, bob), LARGE_AMOUNT);
    }

    function testApproveMaxUint256() public {
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, bob, type(uint256).max);
        bool success = wpc.approve(bob, type(uint256).max);
        
        assertTrue(success);
        assertEq(wpc.allowance(alice, bob), type(uint256).max);
    }

    function testApproveSelf() public {
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, alice, DEPOSIT_AMOUNT);
        bool success = wpc.approve(alice, DEPOSIT_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.allowance(alice, alice), DEPOSIT_AMOUNT);
    }

    function testApproveZeroAddress() public {
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, address(0), DEPOSIT_AMOUNT);
        bool success = wpc.approve(address(0), DEPOSIT_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.allowance(alice, address(0)), DEPOSIT_AMOUNT);
    }

    function testApproveUpdate() public {
        // First approval
        vm.prank(alice);
        wpc.approve(bob, DEPOSIT_AMOUNT);
        assertEq(wpc.allowance(alice, bob), DEPOSIT_AMOUNT);
        
        // Update approval
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, bob, LARGE_AMOUNT);
        wpc.approve(bob, LARGE_AMOUNT);
        
        assertEq(wpc.allowance(alice, bob), LARGE_AMOUNT);
    }

    // =========================
    //    TRANSFER TESTS
    // =========================

    function testTransfer() public {
        // Alice deposits
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        // Alice transfers to Bob
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, bob, DEPOSIT_AMOUNT);
        bool success = wpc.transfer(bob, DEPOSIT_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.balanceOf(alice), 0);
        assertEq(wpc.balanceOf(bob), DEPOSIT_AMOUNT);
        assertEq(wpc.totalSupply(), DEPOSIT_AMOUNT);
    }

    function testTransferZero() public {
        // Alice deposits
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        // Alice transfers zero to Bob
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, bob, ZERO_AMOUNT);
        bool success = wpc.transfer(bob, ZERO_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.balanceOf(alice), DEPOSIT_AMOUNT);
        assertEq(wpc.balanceOf(bob), 0);
    }

    function testTransferPartial() public {
        // Alice deposits large amount
        vm.prank(alice);
        wpc.deposit{value: LARGE_AMOUNT}();
        
        // Alice transfers partial amount to Bob
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, bob, DEPOSIT_AMOUNT);
        bool success = wpc.transfer(bob, DEPOSIT_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.balanceOf(alice), LARGE_AMOUNT - DEPOSIT_AMOUNT);
        assertEq(wpc.balanceOf(bob), DEPOSIT_AMOUNT);
    }

    function testTransferInsufficientBalance() public {
        // Try to transfer without depositing
        vm.prank(alice);
        vm.expectRevert();
        wpc.transfer(bob, DEPOSIT_AMOUNT);
    }

    function testTransferMoreThanBalance() public {
        // Alice deposits small amount
        vm.prank(alice);
        wpc.deposit{value: SMALL_AMOUNT}();
        
        // Try to transfer more than balance
        vm.prank(alice);
        vm.expectRevert();
        wpc.transfer(bob, DEPOSIT_AMOUNT);
    }

    function testTransferToSelf() public {
        // Alice deposits
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        // Alice transfers to herself
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, alice, DEPOSIT_AMOUNT);
        bool success = wpc.transfer(alice, DEPOSIT_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.balanceOf(alice), DEPOSIT_AMOUNT);
    }

    function testTransferToZeroAddress() public {
        // Alice deposits
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        // Alice transfers to zero address
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, address(0), DEPOSIT_AMOUNT);
        bool success = wpc.transfer(address(0), DEPOSIT_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.balanceOf(alice), 0);
        assertEq(wpc.balanceOf(address(0)), DEPOSIT_AMOUNT);
    }

    // =========================
    //    TRANSFERFROM TESTS
    // =========================

    function testTransferFrom() public {
        // Alice deposits and approves Bob
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        vm.prank(alice);
        wpc.approve(bob, DEPOSIT_AMOUNT);
        
        // Bob transfers from Alice to Charlie
        vm.prank(bob);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, charlie, DEPOSIT_AMOUNT);
        bool success = wpc.transferFrom(alice, charlie, DEPOSIT_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.balanceOf(alice), 0);
        assertEq(wpc.balanceOf(charlie), DEPOSIT_AMOUNT);
        assertEq(wpc.allowance(alice, bob), 0);
    }

    function testTransferFromZero() public {
        // Alice deposits and approves Bob
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        vm.prank(alice);
        wpc.approve(bob, DEPOSIT_AMOUNT);
        
        // Bob transfers zero from Alice to Charlie
        vm.prank(bob);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, charlie, ZERO_AMOUNT);
        bool success = wpc.transferFrom(alice, charlie, ZERO_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.balanceOf(alice), DEPOSIT_AMOUNT);
        assertEq(wpc.balanceOf(charlie), 0);
        assertEq(wpc.allowance(alice, bob), DEPOSIT_AMOUNT);
    }

    function testTransferFromInsufficientBalance() public {
        // Alice approves Bob but doesn't deposit
        vm.prank(alice);
        wpc.approve(bob, DEPOSIT_AMOUNT);
        
        // Bob tries to transfer from Alice
        vm.prank(bob);
        vm.expectRevert();
        wpc.transferFrom(alice, charlie, DEPOSIT_AMOUNT);
    }

    function testTransferFromInsufficientAllowance() public {
        // Alice deposits but doesn't approve Bob
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        // Bob tries to transfer from Alice
        vm.prank(bob);
        vm.expectRevert();
        wpc.transferFrom(alice, charlie, DEPOSIT_AMOUNT);
    }

    function testTransferFromSelf() public {
        // Alice deposits and approves herself
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        vm.prank(alice);
        wpc.approve(alice, DEPOSIT_AMOUNT);
        
        // Alice transfers from herself to Bob
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, bob, DEPOSIT_AMOUNT);
        bool success = wpc.transferFrom(alice, bob, DEPOSIT_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.balanceOf(alice), 0);
        assertEq(wpc.balanceOf(bob), DEPOSIT_AMOUNT);
        // When src == msg.sender, allowance is not checked, so it remains unchanged
        assertEq(wpc.allowance(alice, alice), DEPOSIT_AMOUNT);
    }

    function testTransferFromMaxAllowance() public {
        // Alice deposits and approves max allowance
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        vm.prank(alice);
        wpc.approve(bob, type(uint256).max);
        
        // Bob transfers from Alice to Charlie
        vm.prank(bob);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, charlie, DEPOSIT_AMOUNT);
        bool success = wpc.transferFrom(alice, charlie, DEPOSIT_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.balanceOf(alice), 0);
        assertEq(wpc.balanceOf(charlie), DEPOSIT_AMOUNT);
        assertEq(wpc.allowance(alice, bob), type(uint256).max);
    }

    function testTransferFromToZeroAddress() public {
        // Alice deposits and approves Bob
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        vm.prank(alice);
        wpc.approve(bob, DEPOSIT_AMOUNT);
        
        // Bob transfers from Alice to zero address
        vm.prank(bob);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, address(0), DEPOSIT_AMOUNT);
        bool success = wpc.transferFrom(alice, address(0), DEPOSIT_AMOUNT);
        
        assertTrue(success);
        assertEq(wpc.balanceOf(alice), 0);
        assertEq(wpc.balanceOf(address(0)), DEPOSIT_AMOUNT);
        assertEq(wpc.allowance(alice, bob), 0);
    }

    // =========================
    //    EDGE CASE TESTS
    // =========================

    function testTransferAfterDeposit() public {
        // Alice deposits
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        // Alice transfers to Bob
        vm.prank(alice);
        wpc.transfer(bob, DEPOSIT_AMOUNT);
        
        // Bob withdraws
        uint256 balanceBeforeWithdraw = bob.balance;
        vm.prank(bob);
        wpc.withdraw(DEPOSIT_AMOUNT);
        
        assertEq(wpc.balanceOf(bob), 0);
        assertEq(wpc.totalSupply(), 0);
        assertEq(bob.balance, balanceBeforeWithdraw + DEPOSIT_AMOUNT);
    }

    function testTransferFromAfterDeposit() public {
        // Alice deposits and approves Bob
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        vm.prank(alice);
        wpc.approve(bob, DEPOSIT_AMOUNT);
        
        // Bob transfers from Alice to Charlie
        vm.prank(bob);
        wpc.transferFrom(alice, charlie, DEPOSIT_AMOUNT);
        
        // Charlie withdraws
        uint256 balanceBeforeWithdraw = charlie.balance;
        vm.prank(charlie);
        wpc.withdraw(DEPOSIT_AMOUNT);
        
        assertEq(wpc.balanceOf(charlie), 0);
        assertEq(wpc.totalSupply(), 0);
        assertEq(charlie.balance, balanceBeforeWithdraw + DEPOSIT_AMOUNT);
    }

    function testContractBalanceConsistency() public {
        // Multiple users deposit
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        vm.prank(bob);
        wpc.deposit{value: LARGE_AMOUNT}();
        
        assertEq(address(wpc).balance, DEPOSIT_AMOUNT + LARGE_AMOUNT);
        assertEq(wpc.totalSupply(), DEPOSIT_AMOUNT + LARGE_AMOUNT);
        
        // Alice withdraws
        vm.prank(alice);
        wpc.withdraw(DEPOSIT_AMOUNT);
        
        assertEq(address(wpc).balance, LARGE_AMOUNT);
        assertEq(wpc.totalSupply(), LARGE_AMOUNT);
    }

    function testMaxUint256Values() public {
        // Test with max uint256 values
        uint256 maxValue = type(uint256).max;
        
        // Approve max value
        vm.prank(alice);
        wpc.approve(bob, maxValue);
        assertEq(wpc.allowance(alice, bob), maxValue);
        
        // Test that max allowance doesn't get reduced
        vm.prank(alice);
        wpc.deposit{value: DEPOSIT_AMOUNT}();
        
        vm.prank(bob);
        wpc.transferFrom(alice, charlie, DEPOSIT_AMOUNT);
        
        assertEq(wpc.allowance(alice, bob), maxValue);
    }
}
