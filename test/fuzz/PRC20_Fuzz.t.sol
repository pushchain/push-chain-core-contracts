// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../src/PRC20.sol";
import "../../src/UniversalCore.sol";
import "../../src/interfaces/IPRC20.sol";
import "../helpers/UpgradeableContractHelper.sol";
import {PRC20Errors, CommonErrors} from "../../src/libraries/Errors.sol";

contract PRC20_Fuzz is Test, UpgradeableContractHelper {
    PRC20 public prc20;
    UniversalCore public universalCore;

    address public constant UEXEC = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    function setUp() public {
        // Deploy UniversalCore via proxy
        UniversalCore ucImpl = new UniversalCore();
        address mockWPC = makeAddr("wpc");
        address mockFactory = makeAddr("factory");
        address mockRouter = makeAddr("router");
        address mockQuoter = makeAddr("quoter");
        address mockPauser = makeAddr("pauser");
        bytes memory ucInit = abi.encodeWithSelector(
            UniversalCore.initialize.selector, mockWPC, mockFactory, mockRouter, mockQuoter, mockPauser
        );
        address ucProxy = deployUpgradeableContract(address(ucImpl), ucInit);
        universalCore = UniversalCore(payable(ucProxy));

        // Deploy PRC20 via proxy
        PRC20 prc20Impl = new PRC20();
        bytes memory prc20Init = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "Push Chain Token",
            "PUSH",
            18,
            "eip155:1",
            IPRC20.TokenType.PC,
            address(universalCore),
            "0x0000000000000000000000000000000000000000"
        );
        address prc20Proxy = deployUpgradeableContract(address(prc20Impl), prc20Init);
        prc20 = PRC20(prc20Proxy);
    }

    // =========================================================================
    // 1.1 Transfer Properties
    // =========================================================================

    function testFuzz_transfer_conservesBalance(address sender, address recipient, uint256 mintAmt, uint256 transferAmt)
        public
    {
        vm.assume(sender != address(0) && recipient != address(0));
        vm.assume(sender != recipient);
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(transferAmt > 0 && transferAmt <= mintAmt);

        vm.prank(UEXEC);
        prc20.deposit(sender, mintAmt);

        uint256 senderBefore = prc20.balanceOf(sender);
        uint256 recipientBefore = prc20.balanceOf(recipient);
        uint256 supplyBefore = prc20.totalSupply();

        vm.prank(sender);
        prc20.transfer(recipient, transferAmt);

        assertEq(prc20.balanceOf(sender) + prc20.balanceOf(recipient), senderBefore + recipientBefore);
        assertEq(prc20.totalSupply(), supplyBefore);
    }

    function testFuzz_transfer_exactDeduction(address sender, address recipient, uint256 mintAmt, uint256 transferAmt)
        public
    {
        vm.assume(sender != address(0) && recipient != address(0));
        vm.assume(sender != recipient);
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(transferAmt > 0 && transferAmt <= mintAmt);

        vm.prank(UEXEC);
        prc20.deposit(sender, mintAmt);

        uint256 senderBefore = prc20.balanceOf(sender);
        uint256 recipientBefore = prc20.balanceOf(recipient);

        vm.prank(sender);
        prc20.transfer(recipient, transferAmt);

        assertEq(prc20.balanceOf(sender), senderBefore - transferAmt);
        assertEq(prc20.balanceOf(recipient), recipientBefore + transferAmt);
    }

    function testFuzz_transfer_zeroAmount(address sender, address recipient) public {
        vm.assume(sender != address(0) && recipient != address(0));

        uint256 senderBefore = prc20.balanceOf(sender);
        uint256 recipientBefore = prc20.balanceOf(recipient);

        vm.prank(sender);
        // PRC20 _mint reverts on zero, but transfer of 0 is not separately checked in _transfer
        // The _transfer function checks senderBalance < amount; with 0 amount, 0 < 0 is false so it proceeds
        // However _mint(0) reverts — but deposit(sender,0) would revert. Here we call transfer(recipient, 0) directly.
        // balanceOf(sender) == 0, transferAmt == 0, so 0 < 0 is false => no revert, balances unchanged.
        prc20.transfer(recipient, 0);

        assertEq(prc20.balanceOf(sender), senderBefore);
        assertEq(prc20.balanceOf(recipient), recipientBefore);
    }

    function testFuzz_transfer_fullBalance(address sender, address recipient, uint256 mintAmt) public {
        vm.assume(sender != address(0) && recipient != address(0));
        vm.assume(sender != recipient);
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);

        vm.prank(UEXEC);
        prc20.deposit(sender, mintAmt);

        uint256 fullBalance = prc20.balanceOf(sender);
        vm.prank(sender);
        prc20.transfer(recipient, fullBalance);

        assertEq(prc20.balanceOf(sender), 0);
    }

    function testFuzz_transfer_exceedsBalance_reverts(
        address sender,
        address recipient,
        uint256 mintAmt,
        uint256 excess
    ) public {
        vm.assume(sender != address(0) && recipient != address(0));
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(excess > 0 && excess <= type(uint128).max);

        vm.prank(UEXEC);
        prc20.deposit(sender, mintAmt);

        vm.prank(sender);
        vm.expectRevert(CommonErrors.InsufficientBalance.selector);
        prc20.transfer(recipient, mintAmt + excess);
    }

    function testFuzz_transfer_toZeroAddress_reverts(address sender, uint256 amount) public {
        vm.assume(sender != address(0));

        vm.prank(sender);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        prc20.transfer(address(0), amount);
    }

    function testFuzz_transfer_selfTransfer(address sender, uint256 mintAmt, uint256 transferAmt) public {
        vm.assume(sender != address(0));
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(transferAmt <= mintAmt);

        vm.prank(UEXEC);
        prc20.deposit(sender, mintAmt);

        uint256 balanceBefore = prc20.balanceOf(sender);

        vm.prank(sender);
        prc20.transfer(sender, transferAmt);

        assertEq(prc20.balanceOf(sender), balanceBefore);
    }

    // =========================================================================
    // 1.2 TransferFrom Properties
    // =========================================================================

    function testFuzz_transferFrom_decreasesAllowance(
        address owner,
        address spender,
        address recipient,
        uint256 mintAmt,
        uint256 approveAmt,
        uint256 transferAmt
    ) public {
        vm.assume(owner != address(0) && spender != address(0) && recipient != address(0));
        vm.assume(owner != recipient);
        vm.assume(spender != owner);
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(approveAmt > 0 && approveAmt <= mintAmt);
        vm.assume(transferAmt > 0 && transferAmt <= approveAmt);

        vm.prank(UEXEC);
        prc20.deposit(owner, mintAmt);

        vm.prank(owner);
        prc20.approve(spender, approveAmt);

        uint256 allowanceBefore = prc20.allowance(owner, spender);

        vm.prank(spender);
        prc20.transferFrom(owner, recipient, transferAmt);

        assertEq(prc20.allowance(owner, spender), allowanceBefore - transferAmt);
    }

    function testFuzz_transferFrom_insufficientAllowance_reverts(
        address owner,
        address spender,
        address recipient,
        uint256 mintAmt,
        uint256 approveAmt,
        uint256 transferAmt
    ) public {
        vm.assume(owner != address(0) && spender != address(0) && recipient != address(0));
        vm.assume(spender != owner);
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(approveAmt < type(uint128).max);
        vm.assume(transferAmt > approveAmt);
        vm.assume(transferAmt <= mintAmt);

        vm.prank(UEXEC);
        prc20.deposit(owner, mintAmt);

        vm.prank(owner);
        prc20.approve(spender, approveAmt);

        vm.prank(spender);
        vm.expectRevert(PRC20Errors.LowAllowance.selector);
        prc20.transferFrom(owner, recipient, transferAmt);
    }

    function testFuzz_transferFrom_conservesBalance(
        address owner,
        address spender,
        address recipient,
        uint256 mintAmt,
        uint256 approveAmt,
        uint256 transferAmt
    ) public {
        vm.assume(owner != address(0) && spender != address(0) && recipient != address(0));
        vm.assume(owner != recipient);
        vm.assume(spender != owner);
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(approveAmt > 0 && approveAmt <= mintAmt);
        vm.assume(transferAmt > 0 && transferAmt <= approveAmt);

        vm.prank(UEXEC);
        prc20.deposit(owner, mintAmt);

        vm.prank(owner);
        prc20.approve(spender, approveAmt);

        uint256 ownerBefore = prc20.balanceOf(owner);
        uint256 recipientBefore = prc20.balanceOf(recipient);
        uint256 supplyBefore = prc20.totalSupply();

        vm.prank(spender);
        prc20.transferFrom(owner, recipient, transferAmt);

        assertEq(prc20.balanceOf(owner) + prc20.balanceOf(recipient), ownerBefore + recipientBefore);
        assertEq(prc20.totalSupply(), supplyBefore);
    }

    function testFuzz_transferFrom_allowanceAfterTransfer_matches(
        address owner,
        address spender,
        address recipient,
        uint256 mintAmt,
        uint256 approveAmt,
        uint256 transferAmt
    ) public {
        vm.assume(owner != address(0) && spender != address(0) && recipient != address(0));
        vm.assume(owner != recipient);
        vm.assume(spender != owner);
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(approveAmt > 0 && approveAmt <= mintAmt);
        vm.assume(transferAmt > 0 && transferAmt <= approveAmt);

        vm.prank(UEXEC);
        prc20.deposit(owner, mintAmt);

        vm.prank(owner);
        prc20.approve(spender, approveAmt);

        vm.prank(spender);
        prc20.transferFrom(owner, recipient, transferAmt);

        uint256 expectedAllowance = approveAmt - transferAmt;
        assertEq(prc20.allowance(owner, spender), expectedAllowance);
    }

    // =========================================================================
    // 1.3 Approve Properties
    // =========================================================================

    function testFuzz_approve_setsAllowance(address owner, address spender, uint256 amount) public {
        vm.assume(owner != address(0) && spender != address(0));

        vm.prank(owner);
        prc20.approve(spender, amount);

        assertEq(prc20.allowance(owner, spender), amount);
    }

    function testFuzz_approve_overwrite(address owner, address spender, uint256 amt1, uint256 amt2) public {
        vm.assume(owner != address(0) && spender != address(0));

        vm.prank(owner);
        prc20.approve(spender, amt1);

        vm.prank(owner);
        prc20.approve(spender, amt2);

        assertEq(prc20.allowance(owner, spender), amt2);
    }

    function testFuzz_approve_zeroAddress_reverts(uint256 amount) public {
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        prc20.approve(address(0), amount);
    }

    // =========================================================================
    // 1.4 Burn Properties
    // =========================================================================

    function testFuzz_burn_reducesTotalSupply(address account, uint256 mintAmt, uint256 burnAmt) public {
        vm.assume(account != address(0));
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(burnAmt > 0 && burnAmt <= mintAmt);

        vm.prank(UEXEC);
        prc20.deposit(account, mintAmt);

        uint256 supplyBefore = prc20.totalSupply();

        vm.prank(account);
        prc20.burn(burnAmt);

        assertEq(prc20.totalSupply(), supplyBefore - burnAmt);
    }

    function testFuzz_burn_reducesBalance(address account, uint256 mintAmt, uint256 burnAmt) public {
        vm.assume(account != address(0));
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(burnAmt > 0 && burnAmt <= mintAmt);

        vm.prank(UEXEC);
        prc20.deposit(account, mintAmt);

        uint256 balanceBefore = prc20.balanceOf(account);

        vm.prank(account);
        prc20.burn(burnAmt);

        assertEq(prc20.balanceOf(account), balanceBefore - burnAmt);
    }

    function testFuzz_burn_exceedsBalance_reverts(address account, uint256 mintAmt, uint256 excess) public {
        vm.assume(account != address(0));
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(excess > 0 && excess <= type(uint128).max);

        vm.prank(UEXEC);
        prc20.deposit(account, mintAmt);

        vm.prank(account);
        vm.expectRevert(CommonErrors.InsufficientBalance.selector);
        prc20.burn(mintAmt + excess);
    }

    function testFuzz_burn_zeroAmount_reverts(address account, uint256 mintAmt) public {
        vm.assume(account != address(0));
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);

        vm.prank(UEXEC);
        prc20.deposit(account, mintAmt);

        vm.prank(account);
        vm.expectRevert(CommonErrors.ZeroAmount.selector);
        prc20.burn(0);
    }

    function testFuzz_burn_entireBalance(address account, uint256 mintAmt) public {
        vm.assume(account != address(0));
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);

        vm.prank(UEXEC);
        prc20.deposit(account, mintAmt);

        uint256 fullBalance = prc20.balanceOf(account);
        vm.prank(account);
        prc20.burn(fullBalance);

        assertEq(prc20.balanceOf(account), 0);
    }

    // =========================================================================
    // 1.5 Deposit Properties
    // =========================================================================

    function testFuzz_deposit_increasesTotalSupply(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(amount > 0 && amount <= type(uint128).max);

        uint256 supplyBefore = prc20.totalSupply();

        vm.prank(UEXEC);
        prc20.deposit(to, amount);

        assertEq(prc20.totalSupply(), supplyBefore + amount);
    }

    function testFuzz_deposit_increasesBalance(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(amount > 0 && amount <= type(uint128).max);

        uint256 balanceBefore = prc20.balanceOf(to);

        vm.prank(UEXEC);
        prc20.deposit(to, amount);

        assertEq(prc20.balanceOf(to), balanceBefore + amount);
    }

    function testFuzz_deposit_unauthorizedCaller_reverts(address caller, address to, uint256 amount) public {
        vm.assume(caller != UEXEC && caller != address(universalCore));
        vm.assume(to != address(0));
        vm.assume(amount > 0);

        vm.prank(caller);
        vm.expectRevert(PRC20Errors.InvalidSender.selector);
        prc20.deposit(to, amount);
    }

    function testFuzz_deposit_toZeroAddress_reverts(uint256 amount) public {
        vm.assume(amount > 0);

        vm.prank(UEXEC);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        prc20.deposit(address(0), amount);
    }

    // =========================================================================
    // 1.6 Composite / Multi-Operation Properties
    // =========================================================================

    function testFuzz_mintTransferBurn_totalSupplyConsistent(
        address a,
        address b,
        uint256 mintAmt,
        uint256 transferAmt,
        uint256 burnAmt
    ) public {
        vm.assume(a != address(0) && b != address(0));
        vm.assume(a != b);
        vm.assume(mintAmt > 0 && mintAmt <= type(uint128).max);
        vm.assume(transferAmt > 0 && transferAmt <= mintAmt);
        vm.assume(burnAmt > 0 && burnAmt <= transferAmt);

        vm.prank(UEXEC);
        prc20.deposit(a, mintAmt);

        vm.prank(a);
        prc20.transfer(b, transferAmt);

        vm.prank(b);
        prc20.burn(burnAmt);

        assertEq(prc20.totalSupply(), mintAmt - burnAmt);
    }

    function testFuzz_multipleDeposits_totalSupplySum(uint8 count, uint256 seed) public {
        uint256 length = bound(count, 1, 10);
        uint256 totalExpected = 0;

        for (uint256 i = 0; i < length; i++) {
            address to = address(uint160(uint256(keccak256(abi.encodePacked(seed, i)))));
            // Avoid zero address
            if (to == address(0)) to = address(1);
            uint256 amount = bound(uint256(keccak256(abi.encodePacked(seed, i, "amt"))), 1, 1e18);

            vm.prank(UEXEC);
            prc20.deposit(to, amount);
            totalExpected += amount;
        }

        assertEq(prc20.totalSupply(), totalExpected);
    }
}
