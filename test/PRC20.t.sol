// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../src/PRC20.sol";
import "../src/UniversalCore.sol";
import "../src/interfaces/IPRC20.sol";
import "../src/interfaces/IUniswapV3.sol";
import "./mocks/MockGasToken.sol";
import "./helpers/UpgradeableContractHelper.sol";
import {PRC20Errors, UniversalCoreErrors, UEAErrors, CommonErrors} from "../src/libraries/Errors.sol";

/**
 * @title PRC20Test
 * @notice Test suite for the PRC20 contract focusing on ERC-20 core semantics
 */
contract PRC20Test is Test, UpgradeableContractHelper {
    // Contracts under test
    PRC20 public prc20;
    UniversalCore public universalCore;
    UniversalCore public universalCoreImplementation;
    MockGasToken public gasToken;

    // Actors
    address public uExec; // Universal Executor Module
    address public alice;
    address public bob;
    address public attacker;

    // Constants
    string public constant SOURCE_CHAIN_ID = "1"; // Ethereum
    string public constant SOURCE_TOKEN_ADDRESS = "0x0000000000000000000000000000000000000000";
    uint256 public constant GAS_LIMIT = 500000;
    uint256 public constant PC_PROTOCOL_FEE = 10000;
    uint256 public constant GAS_PRICE = 50 * 10 ** 9; // 50 gwei

    // Test values
    uint256 public constant INITIAL_BALANCE = 1000000 ether;
    uint256 public constant TRANSFER_AMOUNT = 100000 ether;
    uint256 public constant APPROVAL_AMOUNT = 50000 ether;

    // Events to test
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Deposit(bytes from, address to, uint256 amount);
    event Withdrawal(address from, bytes to, uint256 amount, uint256 gasFee, uint256 protocolFlatFee);
    event UpdatedUniversalCore(address universalCore);
    event UpdatedGasLimit(uint256 gasLimit);
    event UpdatedProtocolFlatFee(uint256 protocolFlatFee);

    function setUp() public {
        // Setup actors
        uExec = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        attacker = makeAddr("attacker");

        // Deploy mock gas token
        gasToken = new MockGasToken();

        // Create addresses for Uniswap V3 contracts
        address mockWPC = makeAddr("wPC");
        address mockUniswapFactory = makeAddr("uniswapFactory");
        address mockUniswapRouter = makeAddr("uniswapRouter");
        address mockUniswapQuoter = makeAddr("uniswapQuoter");

        // Deploy universalCore implementation
        universalCoreImplementation = new UniversalCore();

        // Create initialization data
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector, mockWPC, mockUniswapFactory, mockUniswapRouter, mockUniswapQuoter
        );

        // Deploy proxy and initialize
        address proxyAddress = deployUpgradeableContract(address(universalCoreImplementation), initData);
        universalCore = UniversalCore(proxyAddress);

        // Configure universalCore
        vm.startPrank(uExec);
        universalCore.setGasPrice(SOURCE_CHAIN_ID, GAS_PRICE);
        universalCore.setGasTokenPRC20(SOURCE_CHAIN_ID, address(gasToken));
        vm.stopPrank();

        // Deploy PRC20 token implementation
        PRC20 implementationPrc20 = new PRC20();

        // Deploy proxy and initialize
        bytes memory initDataPrc20 = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "Push Chain Token",
            "PUSH",
            18,
            SOURCE_CHAIN_ID,
            IPRC20.TokenType.PC,
            GAS_LIMIT,
            PC_PROTOCOL_FEE,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );

        address proxyAddressPrc20 = deployUpgradeableContract(address(implementationPrc20), initDataPrc20);
        prc20 = PRC20(payable(proxyAddressPrc20));

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

    // =========================================================================
    // METADATA & VIEWS
    // =========================================================================

    function testName() public view {
        assertEq(prc20.name(), "Push Chain Token");
    }

    function testSymbol() public view {
        assertEq(prc20.symbol(), "PUSH");
    }

    function testDecimals() public view {
        assertEq(prc20.decimals(), 18);
    }

    function testTotalSupply() public {
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

    function testBalanceOf() public {
        assertEq(prc20.balanceOf(alice), INITIAL_BALANCE);
        assertEq(prc20.balanceOf(bob), 0);

        // After transfer
        vm.prank(alice);
        prc20.transfer(bob, TRANSFER_AMOUNT);
        assertEq(prc20.balanceOf(alice), INITIAL_BALANCE - TRANSFER_AMOUNT);
        assertEq(prc20.balanceOf(bob), TRANSFER_AMOUNT);
    }

    function testAllowance() public {
        assertEq(prc20.allowance(alice, bob), 0);

        // After approval
        vm.prank(alice);
        prc20.approve(bob, APPROVAL_AMOUNT);
        assertEq(prc20.allowance(alice, bob), APPROVAL_AMOUNT);
    }

    // =========================================================================
    // TRANSFER
    // =========================================================================

    function testTransferHappyPath() public {
        vm.prank(alice);

        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, bob, TRANSFER_AMOUNT);

        bool success = prc20.transfer(bob, TRANSFER_AMOUNT);

        assertTrue(success);
        assertEq(prc20.balanceOf(alice), INITIAL_BALANCE - TRANSFER_AMOUNT);
        assertEq(prc20.balanceOf(bob), TRANSFER_AMOUNT);
    }

    function testTransferRevertZeroAddress() public {
        vm.prank(alice);
        vm.expectRevert(PRC20Errors.ZeroAddress.selector);
        prc20.transfer(address(0), TRANSFER_AMOUNT);
    }

    function testTransferRevertInsufficientBalance() public {
        vm.prank(alice);
        vm.expectRevert(PRC20Errors.LowBalance.selector);
        prc20.transfer(bob, INITIAL_BALANCE + 1);
    }

    // =========================================================================
    // APPROVE
    // =========================================================================

    function testApproveHappyPath() public {
        vm.prank(alice);

        vm.expectEmit(true, true, false, true);
        emit Approval(alice, bob, APPROVAL_AMOUNT);

        bool success = prc20.approve(bob, APPROVAL_AMOUNT);

        assertTrue(success);
        assertEq(prc20.allowance(alice, bob), APPROVAL_AMOUNT);
    }

    function testApproveRevertZeroAddress() public {
        vm.prank(alice);
        vm.expectRevert(PRC20Errors.ZeroAddress.selector);
        prc20.approve(address(0), APPROVAL_AMOUNT);
    }

    function testApproveOverwrite() public {
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

    // =========================================================================
    // TRANSFER FROM
    // =========================================================================

    function testTransferFromHappyPath() public {
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

    function testTransferFromRevertInsufficientAllowance() public {
        // Alice approves Bob to spend tokens
        vm.prank(alice);
        prc20.approve(bob, APPROVAL_AMOUNT);

        // Bob tries to transfer more than allowed
        vm.prank(bob);
        vm.expectRevert(PRC20Errors.LowAllowance.selector);
        prc20.transferFrom(alice, bob, APPROVAL_AMOUNT + 1);
    }

    function testTransferFromRevertZeroAddressSender() public {
        vm.prank(bob);
        vm.expectRevert(PRC20Errors.ZeroAddress.selector);
        prc20.transferFrom(address(0), bob, APPROVAL_AMOUNT);
    }

    function testTransferFromRevertZeroAddressRecipient() public {
        // Alice approves Bob to spend tokens
        vm.prank(alice);
        prc20.approve(bob, APPROVAL_AMOUNT);

        // Bob tries to transfer to zero address
        vm.prank(bob);
        vm.expectRevert(PRC20Errors.ZeroAddress.selector);
        prc20.transferFrom(alice, address(0), APPROVAL_AMOUNT);
    }

    function testTransferFromRevertInsufficientBalance() public {
        // Alice approves Bob to spend more than her balance
        vm.prank(alice);
        prc20.approve(bob, INITIAL_BALANCE * 2);

        // Bob tries to transfer more than Alice's balance
        vm.prank(bob);
        vm.expectRevert(PRC20Errors.LowBalance.selector);
        prc20.transferFrom(alice, bob, INITIAL_BALANCE + 1);
    }

    function testTransferFromInfiniteAllowance() public {
        // Set maximum allowance
        vm.prank(alice);
        prc20.approve(bob, type(uint256).max);

        // Bob transfers some tokens
        vm.prank(bob);
        prc20.transferFrom(alice, bob, TRANSFER_AMOUNT);

        // Check that allowance was decremented (even for "infinite" allowance)
        assertEq(prc20.allowance(alice, bob), type(uint256).max - TRANSFER_AMOUNT);
    }

    // =========================================================================
    // BURN
    // =========================================================================

    function testBurnHappyPath() public {
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

    function testBurnRevertZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(PRC20Errors.ZeroAmount.selector);
        prc20.burn(0);
    }

    function testBurnRevertInsufficientBalance() public {
        vm.prank(alice);
        vm.expectRevert(PRC20Errors.LowBalance.selector);
        prc20.burn(INITIAL_BALANCE + 1);
    }

    // =========================================================================
    // DEPOSIT / MINTING (BRIDGE INBOUND)
    // =========================================================================

    function testDepositFromHandler() public {
        uint256 depositAmount = 1000 ether;
        uint256 initialSupply = prc20.totalSupply();
        uint256 initialBalance = prc20.balanceOf(bob);

        // Deposit from universalCore
        vm.prank(address(universalCore));

        // Expect Transfer event
        vm.expectEmit(true, true, false, true);
        emit Transfer(address(0), bob, depositAmount);

        // Expect Deposit event with UNIVERSAL_EXECUTOR_MODULE as from (encoded as bytes)
        vm.expectEmit(false, true, false, true);
        emit Deposit(abi.encodePacked(uExec), bob, depositAmount);

        bool success = prc20.deposit(bob, depositAmount);

        assertTrue(success);
        assertEq(prc20.balanceOf(bob), initialBalance + depositAmount);
        assertEq(prc20.totalSupply(), initialSupply + depositAmount);
    }

    function testDepositFromUExec() public {
        uint256 depositAmount = 1000 ether;
        uint256 initialSupply = prc20.totalSupply();
        uint256 initialBalance = prc20.balanceOf(bob);

        // Deposit from Universal Executor Module
        vm.prank(uExec);

        // Expect Transfer event
        vm.expectEmit(true, true, false, true);
        emit Transfer(address(0), bob, depositAmount);

        // Expect Deposit event with UNIVERSAL_EXECUTOR_MODULE as from (encoded as bytes)
        vm.expectEmit(false, true, false, true);
        emit Deposit(abi.encodePacked(uExec), bob, depositAmount);

        bool success = prc20.deposit(bob, depositAmount);

        assertTrue(success);
        assertEq(prc20.balanceOf(bob), initialBalance + depositAmount);
        assertEq(prc20.totalSupply(), initialSupply + depositAmount);
    }

    function testDepositFromUnauthorized() public {
        // Attempt deposit from unauthorized caller
        vm.prank(attacker);
        vm.expectRevert(PRC20Errors.InvalidSender.selector);
        prc20.deposit(bob, 1000 ether);
    }

    function testDepositToZeroAddress() public {
        // Attempt deposit to zero address
        vm.prank(uExec);
        vm.expectRevert(PRC20Errors.ZeroAddress.selector);
        prc20.deposit(address(0), 1000 ether);
    }

    function testDepositZeroAmount() public {
        // Attempt deposit with zero amount
        vm.prank(uExec);
        vm.expectRevert(PRC20Errors.ZeroAmount.selector);
        prc20.deposit(bob, 0);
    }

    function testDepositEventEncoding() public {
        uint256 depositAmount = 1000 ether;

        // Capture events to verify encoding
        vm.recordLogs();

        // Deposit from universalCore (not UExec)
        vm.prank(address(universalCore));
        prc20.deposit(bob, depositAmount);

        // Get the emitted events
        Vm.Log[] memory entries = vm.getRecordedLogs();

        // Find the Deposit event (should be the second event, after Transfer)
        assertEq(entries.length, 2); // Transfer + Deposit

        // The second event should be the Deposit event
        Vm.Log memory depositEvent = entries[1];

        // Check topic0 is the Deposit event signature
        bytes32 depositEventSig = keccak256("Deposit(bytes,address,uint256)");
        assertEq(depositEvent.topics[0], depositEventSig);

        // Decode the event data
        (bytes memory from, address to, uint256 amount) = abi.decode(depositEvent.data, (bytes, address, uint256));

        // Verify the event data
        assertEq(to, bob);
        assertEq(amount, depositAmount);

        // Verify the from field is encoded as UNIVERSAL_EXECUTOR_MODULE, not universalCore
        assertEq(from.length, 20); // Should be 20 bytes (address length)
        assertEq(address(bytes20(from)), uExec);
    }

    function testFuzzDeposit(address to, uint96 amount) public {
        // Filter out zero address and zero amount
        vm.assume(to != address(0));
        vm.assume(amount > 0);

        uint256 initialSupply = prc20.totalSupply();
        uint256 initialBalance = prc20.balanceOf(to);

        // Deposit from Universal Executor Module
        vm.prank(uExec);
        bool success = prc20.deposit(to, amount);

        assertTrue(success);
        assertEq(prc20.balanceOf(to), initialBalance + amount);
        assertEq(prc20.totalSupply(), initialSupply + amount);
    }

    // =========================================================================
    // FEE QUOTING (withdrawGasFee & withdrawGasFeeWithGasLimit)
    // =========================================================================

    function testWithdrawGasFeeHappyPath() public view {
        // Get the gas fee quote
        (address returnedGasToken, uint256 gasFee) = prc20.withdrawGasFee();

        // Verify returned gas token
        assertEq(returnedGasToken, address(gasToken));

        // Verify fee calculation: price * GAS_LIMIT + PC_PROTOCOL_FEE
        uint256 expectedFee = GAS_PRICE * GAS_LIMIT + PC_PROTOCOL_FEE;
        assertEq(gasFee, expectedFee);
    }

    function testWithdrawGasFeeWithCustomGasLimit() public view {
        uint256 customGasLimit = 300000;

        // Get the gas fee quote with custom gas limit
        (address returnedGasToken, uint256 gasFee) = prc20.withdrawGasFeeWithGasLimit(customGasLimit);

        // Verify returned gas token
        assertEq(returnedGasToken, address(gasToken));

        // Verify fee calculation: price * customGasLimit + PC_PROTOCOL_FEE
        uint256 expectedFee = GAS_PRICE * customGasLimit + PC_PROTOCOL_FEE;
        assertEq(gasFee, expectedFee);
    }

    function testWithdrawGasFeeZeroGasPrice() public {
        vm.startPrank(uExec);
        // Set gas price to zero
        universalCore.setGasPrice(SOURCE_CHAIN_ID, 0);
        vm.stopPrank();
        // Expect revert when getting gas fee
        vm.expectRevert(PRC20Errors.ZeroGasPrice.selector);
        prc20.withdrawGasFee();
    }

    function testWithdrawGasFeeAfterHandlerUpdate() public {
        // Create a new universalCore with different gas price
        address newGasToken = address(new MockGasToken());
        uint256 newGasPrice = GAS_PRICE * 2;

        // Initialize the new universalCore
        address mockWPC = makeAddr("newWPC");
        address mockUniswapFactory = makeAddr("newUniswapFactory");
        address mockUniswapRouter = makeAddr("newUniswapRouter");
        address mockUniswapQuoter = makeAddr("newUniswapQuoter");

        // Initialize and configure new universalCore
        vm.startPrank(uExec);
        // Deploy new universalCore implementation
        UniversalCore newHandlerImpl = new UniversalCore();

        // Create initialization data
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector, mockWPC, mockUniswapFactory, mockUniswapRouter, mockUniswapQuoter
        );

        // Deploy proxy and initialize
        address proxyAddress = deployUpgradeableContract(address(newHandlerImpl), initData);
        UniversalCore newHandler = UniversalCore(proxyAddress);
        newHandler.setGasTokenPRC20(SOURCE_CHAIN_ID, newGasToken);
        newHandler.setGasPrice(SOURCE_CHAIN_ID, newGasPrice);
        vm.stopPrank();

        // Update universalCore contract
        vm.prank(uExec);

        vm.expectEmit(false, false, false, true);
        emit UpdatedUniversalCore(address(newHandler));

        prc20.updateUniversalCore(address(newHandler));

        // Get the gas fee quote with new universalCore
        (address gasTokenResult, uint256 gasFee) = prc20.withdrawGasFee();

        // Verify returned gas token from new universalCore
        assertEq(gasTokenResult, newGasToken);

        // Verify fee calculation with new gas price
        uint256 expectedFee = newGasPrice * GAS_LIMIT + PC_PROTOCOL_FEE;
        assertEq(gasFee, expectedFee);
    }

    function testWithdrawGasFeeAfterGasLimitUpdate() public {
        uint256 newGasLimit = GAS_LIMIT * 2;

        // Update gas limit
        vm.prank(uExec);

        vm.expectEmit(false, false, false, true);
        emit UpdatedGasLimit(newGasLimit);

        prc20.updateGasLimit(newGasLimit);

        // Get the gas fee quote
        (address gasTokenIgnored, uint256 gasFee) = prc20.withdrawGasFee();

        // Verify fee calculation with new gas limit
        uint256 expectedFee = GAS_PRICE * newGasLimit + PC_PROTOCOL_FEE;
        assertEq(gasFee, expectedFee);
    }

    function testWithdrawGasFeeAfterProtocolFeeUpdate() public {
        uint256 newProtocolFee = PC_PROTOCOL_FEE * 2;

        // Update protocol fee
        vm.prank(uExec);

        vm.expectEmit(false, false, false, true);
        emit UpdatedProtocolFlatFee(newProtocolFee);

        prc20.updateProtocolFlatFee(newProtocolFee);

        // Get the gas fee quote
        (address gasTokenIgnored, uint256 gasFee) = prc20.withdrawGasFee();

        // Verify fee calculation with new protocol fee
        uint256 expectedFee = GAS_PRICE * GAS_LIMIT + newProtocolFee;
        assertEq(gasFee, expectedFee);
    }

    // =========================================================================
    // ADMIN & GOVERNANCE CONTROLS
    // =========================================================================

    function testUpdateUniversalCoreFromUExec() public {
        // Create a new universalCore contract
        address mockWPC = makeAddr("newWPC");
        address mockUniswapFactory = makeAddr("newUniswapFactory");
        address mockUniswapRouter = makeAddr("newUniswapRouter");
        address mockUniswapQuoter = makeAddr("newUniswapQuoter");

        vm.prank(uExec);
        // Deploy new universalCore implementation
        UniversalCore newHandlerImpl = new UniversalCore();

        // Create initialization data
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector, mockWPC, mockUniswapFactory, mockUniswapRouter, mockUniswapQuoter
        );

        // Deploy proxy and initialize
        address proxyAddress = deployUpgradeableContract(address(newHandlerImpl), initData);
        UniversalCore newHandler = UniversalCore(proxyAddress);

        // Update universalCore contract from Universal Executor Module
        vm.prank(uExec);

        vm.expectEmit(false, false, false, true);
        emit UpdatedUniversalCore(address(newHandler));

        prc20.updateUniversalCore(address(newHandler));

        // Verify universalCore contract was updated
        assertEq(prc20.UNIVERSAL_CORE(), address(newHandler));
    }

    function testUpdateUniversalCoreFromNonUExec() public {
        // Create a new universalCore contract
        address mockWPC = makeAddr("newWPC");
        address mockUniswapFactory = makeAddr("newUniswapFactory");
        address mockUniswapRouter = makeAddr("newUniswapRouter");
        address mockUniswapQuoter = makeAddr("newUniswapQuoter");

        vm.prank(uExec);
        // Deploy new universalCore implementation
        UniversalCore newHandlerImpl = new UniversalCore();

        // Create initialization data
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector, mockWPC, mockUniswapFactory, mockUniswapRouter, mockUniswapQuoter
        );

        // Deploy proxy and initialize
        address proxyAddress = deployUpgradeableContract(address(newHandlerImpl), initData);
        UniversalCore newHandler = UniversalCore(proxyAddress);

        // Attempt to update universalCore contract from non-Universal Executor Module
        vm.prank(attacker);
        vm.expectRevert(PRC20Errors.CallerIsNotUniversalExecutor.selector);
        prc20.updateUniversalCore(address(newHandler));
    }

    function testUpdateUniversalCoreZeroAddress() public {
        // Attempt to update universalCore contract to zero address
        vm.prank(uExec);
        vm.expectRevert(PRC20Errors.ZeroAddress.selector);
        prc20.updateUniversalCore(address(0));
    }

    function testUpdateGasLimitFromUExec() public {
        uint256 newGasLimit = GAS_LIMIT * 2;

        // Update gas limit from Universal Executor Module
        vm.prank(uExec);

        vm.expectEmit(false, false, false, true);
        emit UpdatedGasLimit(newGasLimit);

        prc20.updateGasLimit(newGasLimit);

        // Verify gas limit was updated
        assertEq(prc20.GAS_LIMIT(), newGasLimit);
    }

    function testUpdateGasLimitFromNonUExec() public {
        uint256 newGasLimit = GAS_LIMIT * 2;

        // Attempt to update gas limit from non-Universal Executor Module
        vm.prank(attacker);
        vm.expectRevert(PRC20Errors.CallerIsNotUniversalExecutor.selector);
        prc20.updateGasLimit(newGasLimit);
    }

    function testUpdateProtocolFlatFeeFromUExec() public {
        uint256 newProtocolFee = PC_PROTOCOL_FEE * 2;

        // Update protocol fee from Universal Executor Module
        vm.prank(uExec);

        vm.expectEmit(false, false, false, true);
        emit UpdatedProtocolFlatFee(newProtocolFee);

        prc20.updateProtocolFlatFee(newProtocolFee);

        // Verify protocol fee was updated
        assertEq(prc20.PC_PROTOCOL_FEE(), newProtocolFee);
    }

    function testUpdateProtocolFlatFeeFromNonUExec() public {
        uint256 newProtocolFee = PC_PROTOCOL_FEE * 2;

        // Attempt to update protocol fee from non-Universal Executor Module
        vm.prank(attacker);
        vm.expectRevert(PRC20Errors.CallerIsNotUniversalExecutor.selector);
        prc20.updateProtocolFlatFee(newProtocolFee);
    }

    function testSetNameFromUExec() public {
        string memory newName = "New Push Token";

        // Set name from Universal Executor Module
        vm.prank(uExec);
        prc20.setName(newName);

        // Verify name was updated
        assertEq(prc20.name(), newName);
    }

    function testSetNameFromNonUExec() public {
        string memory newName = "New Push Token";

        // Attempt to set name from non-Universal Executor Module
        vm.prank(attacker);
        vm.expectRevert(PRC20Errors.CallerIsNotUniversalExecutor.selector);
        prc20.setName(newName);
    }

    function testSetSymbolFromUExec() public {
        string memory newSymbol = "NPUSH";

        // Set symbol from Universal Executor Module
        vm.prank(uExec);
        prc20.setSymbol(newSymbol);

        // Verify symbol was updated
        assertEq(prc20.symbol(), newSymbol);
    }

    function testSetSymbolFromNonUExec() public {
        string memory newSymbol = "NPUSH";

        // Attempt to set symbol from non-Universal Executor Module
        vm.prank(attacker);
        vm.expectRevert(PRC20Errors.CallerIsNotUniversalExecutor.selector);
        prc20.setSymbol(newSymbol);
    }
}
