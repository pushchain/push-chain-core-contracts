// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../src/PRC20.sol";
import "../src/interfaces/IPRC20.sol";
import "../src/libraries/Errors.sol";
import "./mocks/MockGasToken.sol";
import "./mocks/MockHandlerContract.sol";

/**
 * @title PRC20Test
 * @notice Test suite for the PRC20 contract focusing on ERC-20 core semantics
 */
contract PRC20Test is Test {
    // Contracts under test
    PRC20 public prc20;
    MockHandlerContract public handler;
    MockGasToken public gasToken;
    
    // Actors
    address public uExec; // Universal Executor Module
    address public alice;
    address public bob;
    address public attacker;
    
    // Constants
    uint256 public constant SOURCE_CHAIN_ID = 1; // Ethereum
    uint256 public constant GAS_LIMIT = 500_000;
    uint256 public constant PC_PROTOCOL_FEE = 10_000;
    uint256 public constant GAS_PRICE = 50 gwei;
    
    // Test values
    uint256 public constant INITIAL_BALANCE = 1_000_000 ether;
    uint256 public constant TRANSFER_AMOUNT = 100_000 ether;
    uint256 public constant APPROVAL_AMOUNT = 50_000 ether;
    
    // Events to test
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    function setUp() public {
        // Setup actors
        uExec = makeAddr("uExec");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        attacker = makeAddr("attacker");
        
        // Deploy mock gas token
        gasToken = new MockGasToken();
        
        // Deploy mock handler contract
        handler = new MockHandlerContract(uExec);
        
        // Configure handler
        handler.setGasPrice(SOURCE_CHAIN_ID, GAS_PRICE);
        handler.setGasTokenPRC20(SOURCE_CHAIN_ID, address(gasToken));
        
        // Deploy PRC20
        prc20 = new PRC20(
            "Push Chain Token",
            "PUSH",
            18,
            SOURCE_CHAIN_ID,
            IPRC20.TokenType.PC,
            GAS_LIMIT,
            PC_PROTOCOL_FEE,
            uExec,
            address(handler)
        );
        
        // Mint initial tokens to alice via deposit (from uExec)
        vm.startPrank(uExec);
        prc20.deposit(alice, INITIAL_BALANCE);
        vm.stopPrank();
        
        // Mint gas tokens to alice for withdraw tests
        gasToken.mint(alice, INITIAL_BALANCE);
        
        // Alice approves gas token spending to PRC20 contract for withdraw tests
        vm.prank(alice);
        gasToken.approve(address(prc20), type(uint256).max);
    }
    
    /*//////////////////////////////////////////////////////////////
                        1.1 METADATA & VIEWS
    //////////////////////////////////////////////////////////////*/
    
    function test_name() public view {
        assertEq(prc20.name(), "Push Chain Token");
    }
    
    function test_symbol() public view {
        assertEq(prc20.symbol(), "PUSH");
    }
    
    function test_decimals() public view {
        assertEq(prc20.decimals(), 18);
    }
    
    function test_totalSupply() public {
        // Initial supply after setup
        assertEq(prc20.totalSupply(), INITIAL_BALANCE);
        
        // Mint more via deposit
        vm.prank(uExec);
        prc20.deposit(bob, 1000 ether);
        assertEq(prc20.totalSupply(), INITIAL_BALANCE + 1000 ether);
        
        // Burn some
        vm.prank(alice);
        prc20.burn(500 ether);
        assertEq(prc20.totalSupply(), INITIAL_BALANCE + 1000 ether - 500 ether);
    }
    
    function test_balanceOf() public {
        assertEq(prc20.balanceOf(alice), INITIAL_BALANCE);
        assertEq(prc20.balanceOf(bob), 0);
        
        // After transfer
        vm.prank(alice);
        prc20.transfer(bob, TRANSFER_AMOUNT);
        assertEq(prc20.balanceOf(alice), INITIAL_BALANCE - TRANSFER_AMOUNT);
        assertEq(prc20.balanceOf(bob), TRANSFER_AMOUNT);
    }
    
    function test_allowance() public {
        assertEq(prc20.allowance(alice, bob), 0);
        
        // After approval
        vm.prank(alice);
        prc20.approve(bob, APPROVAL_AMOUNT);
        assertEq(prc20.allowance(alice, bob), APPROVAL_AMOUNT);
    }
    
    /*//////////////////////////////////////////////////////////////
                            1.2 TRANSFER
    //////////////////////////////////////////////////////////////*/
    
    function test_transfer_happyPath() public {
        vm.prank(alice);
        
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, bob, TRANSFER_AMOUNT);
        
        bool success = prc20.transfer(bob, TRANSFER_AMOUNT);
        
        assertTrue(success);
        assertEq(prc20.balanceOf(alice), INITIAL_BALANCE - TRANSFER_AMOUNT);
        assertEq(prc20.balanceOf(bob), TRANSFER_AMOUNT);
    }
    
    function test_transfer_revertZeroAddress() public {
        vm.prank(alice);
        vm.expectRevert(PRC20Errors.ZeroAddress.selector);
        prc20.transfer(address(0), TRANSFER_AMOUNT);
    }
    
    function test_transfer_revertInsufficientBalance() public {
        vm.prank(alice);
        vm.expectRevert(PRC20Errors.LowBalance.selector);
        prc20.transfer(bob, INITIAL_BALANCE + 1);
    }
    
    /*//////////////////////////////////////////////////////////////
                            1.3 APPROVE
    //////////////////////////////////////////////////////////////*/
    
    function test_approve_happyPath() public {
        vm.prank(alice);
        
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, bob, APPROVAL_AMOUNT);
        
        bool success = prc20.approve(bob, APPROVAL_AMOUNT);
        
        assertTrue(success);
        assertEq(prc20.allowance(alice, bob), APPROVAL_AMOUNT);
    }
    
    function test_approve_revertZeroAddress() public {
        vm.prank(alice);
        vm.expectRevert(PRC20Errors.ZeroAddress.selector);
        prc20.approve(address(0), APPROVAL_AMOUNT);
    }
    
    function test_approve_overwrite() public {
        // First approval
        vm.prank(alice);
        prc20.approve(bob, APPROVAL_AMOUNT);
        assertEq(prc20.allowance(alice, bob), APPROVAL_AMOUNT);
        
        // Overwrite with new amount
        uint256 newAmount = APPROVAL_AMOUNT * 2;
        vm.prank(alice);
        prc20.approve(bob, newAmount);
        assertEq(prc20.allowance(alice, bob), newAmount);
        
        // Overwrite with zero
        vm.prank(alice);
        prc20.approve(bob, 0);
        assertEq(prc20.allowance(alice, bob), 0);
    }
    
    /*//////////////////////////////////////////////////////////////
                            1.4 TRANSFER FROM
    //////////////////////////////////////////////////////////////*/
    
    function test_transferFrom_happyPath() public {
        // Alice approves Bob to spend tokens
        vm.prank(alice);
        prc20.approve(bob, APPROVAL_AMOUNT);
        
        // Bob transfers from Alice to himself
        vm.prank(bob);
        
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, bob, APPROVAL_AMOUNT);
        
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, bob, 0);
        
        bool success = prc20.transferFrom(alice, bob, APPROVAL_AMOUNT);
        
        assertTrue(success);
        assertEq(prc20.balanceOf(alice), INITIAL_BALANCE - APPROVAL_AMOUNT);
        assertEq(prc20.balanceOf(bob), APPROVAL_AMOUNT);
        assertEq(prc20.allowance(alice, bob), 0);
    }
    
    function test_transferFrom_revertInsufficientAllowance() public {
        // Alice approves Bob to spend tokens
        vm.prank(alice);
        prc20.approve(bob, APPROVAL_AMOUNT);
        
        // Bob tries to transfer more than allowed
        vm.prank(bob);
        vm.expectRevert(PRC20Errors.LowAllowance.selector);
        prc20.transferFrom(alice, bob, APPROVAL_AMOUNT + 1);
    }
    
    function test_transferFrom_revertZeroAddressSender() public {
        vm.prank(bob);
        vm.expectRevert(PRC20Errors.ZeroAddress.selector);
        prc20.transferFrom(address(0), bob, APPROVAL_AMOUNT);
    }
    
    function test_transferFrom_revertZeroAddressRecipient() public {
        // Alice approves Bob to spend tokens
        vm.prank(alice);
        prc20.approve(bob, APPROVAL_AMOUNT);
        
        // Bob tries to transfer to zero address
        vm.prank(bob);
        vm.expectRevert(PRC20Errors.ZeroAddress.selector);
        prc20.transferFrom(alice, address(0), APPROVAL_AMOUNT);
    }
    
    function test_transferFrom_revertInsufficientBalance() public {
        // Alice approves Bob to spend more than her balance
        vm.prank(alice);
        prc20.approve(bob, INITIAL_BALANCE * 2);
        
        // Bob tries to transfer more than Alice's balance
        vm.prank(bob);
        vm.expectRevert(PRC20Errors.LowBalance.selector);
        prc20.transferFrom(alice, bob, INITIAL_BALANCE + 1);
    }
    
    function test_transferFrom_infiniteAllowance() public {
        // Set maximum allowance
        vm.prank(alice);
        prc20.approve(bob, type(uint256).max);
        
        // Bob transfers some tokens
        vm.prank(bob);
        prc20.transferFrom(alice, bob, TRANSFER_AMOUNT);
        
        // Check that allowance was decremented (even for "infinite" allowance)
        assertEq(prc20.allowance(alice, bob), type(uint256).max - TRANSFER_AMOUNT);
    }
    
    /*//////////////////////////////////////////////////////////////
                                1.5 BURN
    //////////////////////////////////////////////////////////////*/
    
    function test_burn_happyPath() public {
        uint256 burnAmount = 1000 ether;
        uint256 initialSupply = prc20.totalSupply();
        
        vm.prank(alice);
        
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, address(0), burnAmount);
        
        bool success = prc20.burn(burnAmount);
        
        assertTrue(success);
        assertEq(prc20.balanceOf(alice), INITIAL_BALANCE - burnAmount);
        assertEq(prc20.totalSupply(), initialSupply - burnAmount);
    }
    
    function test_burn_revertZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(PRC20Errors.ZeroAmount.selector);
        prc20.burn(0);
    }
    
    function test_burn_revertInsufficientBalance() public {
        vm.prank(alice);
        vm.expectRevert(PRC20Errors.LowBalance.selector);
        prc20.burn(INITIAL_BALANCE + 1);
    }
}