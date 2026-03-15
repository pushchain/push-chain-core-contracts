// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../src/WPC.sol";

contract WPC_Fuzz is Test {
    WPC public wpc;

    // Max amount to avoid vm.deal overflow; keep values sane
    uint256 constant MAX_AMOUNT = 100 ether;

    function setUp() public {
        wpc = new WPC();
    }

    // =========================================================================
    // 2.1 Deposit / Withdraw Properties
    // =========================================================================

    function testFuzz_deposit_mintsExactAmount(uint256 amount) public {
        amount = bound(amount, 0, MAX_AMOUNT);
        address user = makeAddr("user");
        vm.deal(user, amount);

        uint256 balanceBefore = wpc.balanceOf(user);

        vm.prank(user);
        wpc.deposit{value: amount}();

        assertEq(wpc.balanceOf(user), balanceBefore + amount);
    }

    function testFuzz_deposit_totalSupplyEqualsContractBalance(uint256 amount) public {
        amount = bound(amount, 0, MAX_AMOUNT);
        address user = makeAddr("user");
        vm.deal(user, amount);

        vm.prank(user);
        wpc.deposit{value: amount}();

        assertEq(wpc.totalSupply(), address(wpc).balance);
    }

    function testFuzz_withdraw_burnsExactAmount(uint256 depositAmt, uint256 withdrawAmt) public {
        depositAmt = bound(depositAmt, 0, MAX_AMOUNT);
        withdrawAmt = bound(withdrawAmt, 0, depositAmt);

        address user = makeAddr("user");
        vm.deal(user, depositAmt);

        vm.prank(user);
        wpc.deposit{value: depositAmt}();

        uint256 balanceBefore = wpc.balanceOf(user);

        vm.prank(user);
        wpc.withdraw(withdrawAmt);

        assertEq(wpc.balanceOf(user), balanceBefore - withdrawAmt);
    }

    function testFuzz_withdraw_sendsNativePC(uint256 depositAmt, uint256 withdrawAmt) public {
        depositAmt = bound(depositAmt, 0, MAX_AMOUNT);
        withdrawAmt = bound(withdrawAmt, 0, depositAmt);

        address user = makeAddr("user");
        vm.deal(user, depositAmt);

        vm.prank(user);
        wpc.deposit{value: depositAmt}();

        uint256 nativeBalanceBefore = user.balance;

        vm.prank(user);
        wpc.withdraw(withdrawAmt);

        assertEq(user.balance, nativeBalanceBefore + withdrawAmt);
    }

    function testFuzz_withdraw_exceedsBalance_reverts(uint256 depositAmt, uint256 excess) public {
        depositAmt = bound(depositAmt, 0, MAX_AMOUNT);
        excess = bound(excess, 1, MAX_AMOUNT);

        address user = makeAddr("user");
        vm.deal(user, depositAmt);

        vm.prank(user);
        wpc.deposit{value: depositAmt}();

        vm.prank(user);
        vm.expectRevert();
        wpc.withdraw(depositAmt + excess);
    }

    function testFuzz_depositWithdraw_roundtrip(uint256 amount) public {
        amount = bound(amount, 0, MAX_AMOUNT);

        address user = makeAddr("user");
        vm.deal(user, amount);

        vm.prank(user);
        wpc.deposit{value: amount}();

        vm.prank(user);
        wpc.withdraw(amount);

        assertEq(wpc.balanceOf(user), 0);
    }

    function testFuzz_receive_triggersDeposit(uint256 amount) public {
        amount = bound(amount, 0, MAX_AMOUNT);

        address user = makeAddr("user");
        vm.deal(user, amount);

        uint256 balanceBefore = wpc.balanceOf(user);

        vm.prank(user);
        (bool ok,) = address(wpc).call{value: amount}("");
        assertTrue(ok);

        assertEq(wpc.balanceOf(user), balanceBefore + amount);
        assertEq(wpc.totalSupply(), address(wpc).balance);
    }

    // =========================================================================
    // 2.2 Transfer Properties
    // =========================================================================

    function testFuzz_transfer_conservesBalance(
        address dst,
        uint256 depositAmt,
        uint256 transferAmt
    ) public {
        vm.assume(dst != address(0));
        vm.assume(dst > address(0x10));
        depositAmt = bound(depositAmt, 0, MAX_AMOUNT);
        transferAmt = bound(transferAmt, 0, depositAmt);

        address src = makeAddr("src");
        vm.assume(src != dst);
        vm.deal(src, depositAmt);

        vm.prank(src);
        wpc.deposit{value: depositAmt}();

        uint256 srcBefore = wpc.balanceOf(src);
        uint256 dstBefore = wpc.balanceOf(dst);

        vm.prank(src);
        wpc.transfer(dst, transferAmt);

        assertEq(wpc.balanceOf(src) + wpc.balanceOf(dst), srcBefore + dstBefore);
    }

    function testFuzz_transfer_exceedsBalance_reverts(
        address dst,
        uint256 depositAmt,
        uint256 excess
    ) public {
        vm.assume(dst != address(0));
        depositAmt = bound(depositAmt, 0, MAX_AMOUNT);
        excess = bound(excess, 1, MAX_AMOUNT);

        address src = makeAddr("src");
        vm.deal(src, depositAmt);

        vm.prank(src);
        wpc.deposit{value: depositAmt}();

        vm.prank(src);
        vm.expectRevert();
        wpc.transfer(dst, depositAmt + excess);
    }

    function testFuzz_transfer_selfTransfer(uint256 depositAmt, uint256 transferAmt) public {
        depositAmt = bound(depositAmt, 0, MAX_AMOUNT);
        transferAmt = bound(transferAmt, 0, depositAmt);

        address user = makeAddr("user");
        vm.deal(user, depositAmt);

        vm.prank(user);
        wpc.deposit{value: depositAmt}();

        uint256 balanceBefore = wpc.balanceOf(user);

        vm.prank(user);
        wpc.transfer(user, transferAmt);

        assertEq(wpc.balanceOf(user), balanceBefore);
    }

    function testFuzz_transfer_toZeroAddress(uint256 depositAmt, uint256 transferAmt) public {
        depositAmt = bound(depositAmt, 0, MAX_AMOUNT);
        transferAmt = bound(transferAmt, 0, depositAmt);

        address src = makeAddr("src");
        vm.deal(src, depositAmt);

        vm.prank(src);
        wpc.deposit{value: depositAmt}();

        // WPC has no zero-address check; transfer to address(0) succeeds
        vm.prank(src);
        bool ok = wpc.transfer(address(0), transferAmt);
        assertTrue(ok);

        assertEq(wpc.balanceOf(address(0)), transferAmt);
        assertEq(wpc.balanceOf(src), depositAmt - transferAmt);
    }

    // =========================================================================
    // 2.3 TransferFrom and Allowance Properties
    // =========================================================================

    function testFuzz_transferFrom_decreasesAllowance(
        address src,
        address dst,
        uint256 depositAmt,
        uint256 approveAmt,
        uint256 transferAmt
    ) public {
        vm.assume(src != address(0) && dst != address(0));
        vm.assume(src > address(0x10) && dst > address(0x10));
        vm.assume(src != dst);
        depositAmt = bound(depositAmt, 1, MAX_AMOUNT);
        approveAmt = bound(approveAmt, 1, depositAmt);
        // Exclude type(uint256).max to test allowance decrement
        vm.assume(approveAmt != type(uint256).max);
        transferAmt = bound(transferAmt, 0, approveAmt);

        address spender = makeAddr("spender");
        vm.assume(spender != src);

        vm.deal(src, depositAmt);

        vm.prank(src);
        wpc.deposit{value: depositAmt}();

        vm.prank(src);
        wpc.approve(spender, approveAmt);

        uint256 allowanceBefore = wpc.allowance(src, spender);

        vm.prank(spender);
        wpc.transferFrom(src, dst, transferAmt);

        assertEq(wpc.allowance(src, spender), allowanceBefore - transferAmt);
    }

    function testFuzz_transferFrom_infiniteAllowance_noDecrease(
        address src,
        address dst,
        uint256 depositAmt,
        uint256 transferAmt
    ) public {
        vm.assume(src != address(0) && dst != address(0));
        vm.assume(src > address(0x10) && dst > address(0x10));
        vm.assume(src != dst);
        depositAmt = bound(depositAmt, 1, MAX_AMOUNT);
        transferAmt = bound(transferAmt, 0, depositAmt);

        address spender = makeAddr("spender");
        vm.assume(spender != src);

        vm.deal(src, depositAmt);

        vm.prank(src);
        wpc.deposit{value: depositAmt}();

        vm.prank(src);
        wpc.approve(spender, type(uint256).max);

        vm.prank(spender);
        wpc.transferFrom(src, dst, transferAmt);

        assertEq(wpc.allowance(src, spender), type(uint256).max);
    }

    function testFuzz_transferFrom_insufficientAllowance_reverts(
        address src,
        address dst,
        uint256 depositAmt,
        uint256 approveAmt,
        uint256 excess
    ) public {
        vm.assume(src != address(0) && dst != address(0));
        vm.assume(src > address(0x10));
        depositAmt = bound(depositAmt, 1, MAX_AMOUNT);
        approveAmt = bound(approveAmt, 0, depositAmt - 1);
        excess = bound(excess, 1, MAX_AMOUNT);
        // Ensure transferAmt > approveAmt and <= depositAmt
        uint256 transferAmt = approveAmt + excess;
        vm.assume(transferAmt <= depositAmt);
        vm.assume(approveAmt != type(uint256).max);

        address spender = makeAddr("spender");
        vm.assume(spender != src);

        vm.deal(src, depositAmt);

        vm.prank(src);
        wpc.deposit{value: depositAmt}();

        vm.prank(src);
        wpc.approve(spender, approveAmt);

        vm.prank(spender);
        vm.expectRevert();
        wpc.transferFrom(src, dst, transferAmt);
    }

    function testFuzz_transferFrom_selfApproval_bypassed(
        address dst,
        uint256 depositAmt,
        uint256 transferAmt
    ) public {
        vm.assume(dst != address(0));
        vm.assume(dst > address(0x10));
        depositAmt = bound(depositAmt, 0, MAX_AMOUNT);
        transferAmt = bound(transferAmt, 0, depositAmt);

        address src = makeAddr("src");
        vm.assume(src != dst);
        vm.deal(src, depositAmt);

        vm.prank(src);
        wpc.deposit{value: depositAmt}();

        // No approval set; src == msg.sender bypasses allowance check
        uint256 allowanceBefore = wpc.allowance(src, src);

        vm.prank(src);
        wpc.transferFrom(src, dst, transferAmt);

        // Allowance is unchanged because src == msg.sender branch skips it
        assertEq(wpc.allowance(src, src), allowanceBefore);
    }

    // =========================================================================
    // 2.4 Invariant-Like Properties
    // =========================================================================

    function testFuzz_totalSupply_alwaysEqualsContractBalance(
        uint256 depositAmt1,
        uint256 depositAmt2,
        uint256 withdrawAmt
    ) public {
        depositAmt1 = bound(depositAmt1, 0, MAX_AMOUNT);
        depositAmt2 = bound(depositAmt2, 0, MAX_AMOUNT);

        address user1 = makeAddr("user1");
        address user2 = makeAddr("user2");
        vm.deal(user1, depositAmt1);
        vm.deal(user2, depositAmt2);

        vm.prank(user1);
        wpc.deposit{value: depositAmt1}();

        vm.prank(user2);
        wpc.deposit{value: depositAmt2}();

        withdrawAmt = bound(withdrawAmt, 0, depositAmt1);
        vm.prank(user1);
        wpc.withdraw(withdrawAmt);

        assertEq(wpc.totalSupply(), address(wpc).balance);
    }

    function testFuzz_approve_setsExactAllowance(address guy, uint256 wad) public {
        vm.assume(guy != address(0));

        address owner = makeAddr("owner");

        vm.prank(owner);
        wpc.approve(guy, wad);

        assertEq(wpc.allowance(owner, guy), wad);
    }
}
