// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";

import {UniversalCore} from "../../src/UniversalCore.sol";
import {PRC20} from "../../src/PRC20.sol";
import {IPRC20} from "../../src/interfaces/IPRC20.sol";
import {UniversalCoreErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import {UpgradeableContractHelper} from "../../test/helpers/UpgradeableContractHelper.sol";
import {MockGasToken} from "../../test/mocks/MockGasToken.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

contract UniversalCore_Fuzz is Test, UpgradeableContractHelper {
    UniversalCore universalCore;
    PRC20 prc20;
    MockGasToken gasToken;

    address constant uExec = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    address gateway;
    address pauser;

    // Chain namespace configured in setUp — must match prc20.SOURCE_CHAIN_NAMESPACE()
    string constant CHAIN_NS = "1";

    function setUp() public {
        gasToken = new MockGasToken();

        address mockWPC = makeAddr("wPC");
        address mockFactory = makeAddr("uniswapFactory");
        address mockRouter = makeAddr("uniswapRouter");
        pauser = makeAddr("pauser");

        UniversalCore impl = new UniversalCore();
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector, mockWPC, mockFactory, mockRouter, pauser
        );
        address proxyAddr = deployUpgradeableContract(address(impl), initData);
        universalCore = UniversalCore(payable(proxyAddr));

        universalCore.grantRole(universalCore.MANAGER_ROLE(), uExec);

        gateway = makeAddr("gateway");
        universalCore.setUniversalGatewayPC(gateway);

        // Deploy PRC20 with SOURCE_CHAIN_NAMESPACE = "1" (matches CHAIN_NS)
        PRC20 prc20Impl = new PRC20();
        bytes memory prc20Init = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "Test",
            "TST",
            18,
            CHAIN_NS,
            IPRC20.TokenType.NATIVE,
            address(universalCore),
            "0x0"
        );
        address prc20Addr = deployUpgradeableContract(address(prc20Impl), prc20Init);
        prc20 = PRC20(payable(prc20Addr));

        // Configure chain gas — setChainMeta is onlyUEModule
        vm.prank(uExec);
        universalCore.setChainMeta(CHAIN_NS, 50 gwei, 0);

        // setGasTokenPRC20 is onlyRole(MANAGER_ROLE), uExec has it
        vm.prank(uExec);
        universalCore.setGasTokenPRC20(CHAIN_NS, address(gasToken));
    }

    // =============================================
    // 12.1 Gas Fee Calculation Properties
    // =============================================

    function testFuzz_getOutboundTxGasAndFees_calculatesCorrectly(uint128 gasPrice, uint128 gasLimit, uint128 baseLimit)
        public
    {
        vm.assume(gasPrice > 0);
        vm.assume(baseLimit > 0);
        vm.assume(gasLimit >= baseLimit);

        vm.prank(uExec);
        universalCore.setChainMeta(CHAIN_NS, gasPrice, 0);

        vm.prank(uExec);
        universalCore.setBaseGasLimitByChain(CHAIN_NS, baseLimit);

        (, uint256 gasFee,,,) = universalCore.getOutboundTxGasAndFees(address(prc20), gasLimit);

        assertEq(gasFee, uint256(gasPrice) * uint256(gasLimit));
    }

    function testFuzz_getOutboundTxGasAndFees_zeroGasLimit_usesBase(uint128 gasPrice, uint128 baseLimit) public {
        vm.assume(gasPrice > 0);
        vm.assume(baseLimit > 0);

        vm.prank(uExec);
        universalCore.setChainMeta(CHAIN_NS, gasPrice, 0);

        vm.prank(uExec);
        universalCore.setBaseGasLimitByChain(CHAIN_NS, baseLimit);

        // gasLimitWithBaseLimit == 0 → uses baseLimit
        (, uint256 gasFee,,,) = universalCore.getOutboundTxGasAndFees(address(prc20), 0);

        assertEq(gasFee, uint256(gasPrice) * uint256(baseLimit));
    }

    function testFuzz_getOutboundTxGasAndFees_belowBase_reverts(uint128 baseLimit, uint128 provided) public {
        vm.assume(baseLimit > 1);
        vm.assume(provided > 0 && provided < baseLimit);

        vm.prank(uExec);
        universalCore.setBaseGasLimitByChain(CHAIN_NS, baseLimit);

        vm.expectRevert(abi.encodeWithSelector(UniversalCoreErrors.GasLimitBelowBase.selector, provided, baseLimit));
        universalCore.getOutboundTxGasAndFees(address(prc20), provided);
    }

    function testFuzz_getOutboundTxGasAndFees_zeroGasPrice_reverts(uint128 gasLimit) public {
        uint256 baseLimit = 100_000;
        vm.assume(gasLimit >= baseLimit);

        // Set base gas limit so we pass the zero-base check
        vm.prank(uExec);
        universalCore.setBaseGasLimitByChain(CHAIN_NS, baseLimit);

        // Set gas price to 0 — setChainMeta is onlyUEModule
        vm.prank(uExec);
        universalCore.setChainMeta(CHAIN_NS, 0, 0);

        vm.expectRevert(UniversalCoreErrors.ZeroGasPrice.selector);
        universalCore.getOutboundTxGasAndFees(address(prc20), gasLimit);
    }

    function testFuzz_getOutboundTxGasAndFees_zeroGasToken_reverts(uint128 gasLimit) public {
        uint256 baseLimit = 100_000;
        vm.assume(gasLimit >= baseLimit);

        // Set base gas limit for "nogas" chain so we pass the zero-base check
        vm.prank(uExec);
        universalCore.setBaseGasLimitByChain("nogas", baseLimit);

        // Deploy a fresh PRC20 on chain "nogas" — no gas token configured for "nogas"
        PRC20 prc20Impl = new PRC20();
        bytes memory prc20Init = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "NoGas",
            "NGS",
            18,
            "nogas",
            IPRC20.TokenType.NATIVE,
            address(universalCore),
            "0x0"
        );
        address prc20Addr = deployUpgradeableContract(address(prc20Impl), prc20Init);
        PRC20 noGasPRC20 = PRC20(payable(prc20Addr));

        // Set gas price for "nogas" chain but leave gas token as address(0)
        vm.prank(uExec);
        universalCore.setChainMeta("nogas", 50 gwei, 0);

        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.getOutboundTxGasAndFees(address(noGasPRC20), gasLimit);
    }

    // =============================================
    // 12.2 Rescue Gas Limit Properties
    // =============================================

    function testFuzz_getRescueFundsGasLimit_calculatesCorrectly(uint128 gasPrice, uint128 rescueLimit) public {
        vm.assume(gasPrice > 0);
        vm.assume(rescueLimit > 0);

        vm.prank(uExec);
        universalCore.setChainMeta(CHAIN_NS, gasPrice, 0);

        vm.prank(uExec);
        universalCore.setRescueFundsGasLimitByChain(CHAIN_NS, rescueLimit);

        (, uint256 gasFee, uint256 returnedRescueLimit,,) = universalCore.getRescueFundsGasLimit(address(prc20));

        assertEq(returnedRescueLimit, rescueLimit);
        assertEq(gasFee, uint256(gasPrice) * uint256(rescueLimit));
    }

    function testFuzz_getRescueFundsGasLimit_zeroRescueLimit_reverts() public {
        // rescueFundsGasLimitByChainNamespace["1"] is 0 by default (not set in setUp)
        vm.expectRevert(UniversalCoreErrors.ZeroRescueGasLimit.selector);
        universalCore.getRescueFundsGasLimit(address(prc20));
    }

    // =============================================
    // 12.3 Parameter Validation Properties
    // =============================================

    function testFuzz_validateParams_zeroToken_reverts(uint128 amount, address recipient) public {
        vm.assume(amount > 0);
        vm.assume(recipient != address(0));
        vm.assume(recipient != uExec);
        vm.assume(recipient != address(universalCore));

        vm.prank(uExec);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.depositPRC20Token(address(0), amount, recipient);
    }

    function testFuzz_validateParams_zeroRecipient_reverts(address token, uint128 amount) public {
        vm.assume(token != address(0));
        vm.assume(amount > 0);

        vm.prank(uExec);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.depositPRC20Token(token, amount, address(0));
    }

    function testFuzz_validateParams_zeroAmount_reverts(address token, address recipient) public {
        vm.assume(token != address(0));
        vm.assume(recipient != address(0));
        vm.assume(recipient != uExec);
        vm.assume(recipient != address(universalCore));

        vm.prank(uExec);
        vm.expectRevert(CommonErrors.ZeroAmount.selector);
        universalCore.depositPRC20Token(token, 0, recipient);
    }

    function testFuzz_validateParams_recipientIsUEModule_reverts(address token, uint128 amount) public {
        vm.assume(token != address(0));
        vm.assume(amount > 0);

        vm.prank(uExec);
        vm.expectRevert(UniversalCoreErrors.InvalidTarget.selector);
        universalCore.depositPRC20Token(token, amount, uExec);
    }

    function testFuzz_validateParams_recipientIsContract_reverts(address token, uint128 amount) public {
        vm.assume(token != address(0));
        vm.assume(amount > 0);

        vm.prank(uExec);
        vm.expectRevert(UniversalCoreErrors.InvalidTarget.selector);
        universalCore.depositPRC20Token(token, amount, address(universalCore));
    }

    // =============================================
    // 12.4 Fee Tier Validation Properties
    // =============================================

    function testFuzz_setDefaultFeeTier_validTiers(address token, uint24 feeTier) public {
        vm.assume(token != address(0));

        bool isValid = feeTier == 500 || feeTier == 3000 || feeTier == 10000;

        if (isValid) {
            universalCore.setDefaultFeeTier(token, feeTier);
            assertEq(universalCore.defaultFeeTier(token), feeTier);
        } else {
            vm.expectRevert(UniversalCoreErrors.InvalidFeeTier.selector);
            universalCore.setDefaultFeeTier(token, feeTier);
        }
    }

    function testFuzz_setSlippageTolerance_boundary(address token, uint256 tolerance) public {
        vm.assume(token != address(0));

        if (tolerance <= 5000) {
            universalCore.setSlippageTolerance(token, tolerance);
            assertEq(universalCore.slippageTolerance(token), tolerance);
        } else {
            vm.expectRevert(UniversalCoreErrors.InvalidSlippageTolerance.selector);
            universalCore.setSlippageTolerance(token, tolerance);
        }
    }

    // =============================================
    // 12.5 Deadline Validation Properties
    // =============================================

    function testFuzz_setDefaultDeadlineMins_storesValue(uint256 mins) public {
        // setDefaultDeadlineMins is onlyAdmin — test contract is DEFAULT_ADMIN_ROLE
        universalCore.setDefaultDeadlineMins(mins);
        assertEq(universalCore.defaultDeadlineMins(), mins);
    }

    function testFuzz_swapAndBurnGas_expiredDeadline_reverts(uint256 pastOffset) public {
        // Warp to a high timestamp so we have room to produce a past deadline
        uint256 warpedTime = 10_000_000;
        vm.warp(warpedTime);
        // bound pastOffset so underflow is impossible: deadline = warpedTime - pastOffset - 1 >= 1
        pastOffset = bound(pastOffset, 0, warpedTime - 2);
        uint256 deadline = warpedTime - pastOffset - 1;

        // Fund gateway so msg.value > 0 check passes; expired deadline check fires next
        vm.deal(gateway, 1 ether);
        vm.prank(gateway);
        vm.expectRevert(CommonErrors.DeadlineExpired.selector);
        universalCore.swapAndBurnGas{value: 1 ether}(address(gasToken), 3000, 1 ether, deadline, address(this));
    }

    // =============================================
    // 12.6 Access Control Properties
    // =============================================

    function testFuzz_depositPRC20Token_nonUEModule_reverts(
        address caller,
        address token,
        uint128 amount,
        address recipient
    ) public {
        vm.assume(caller != uExec);

        vm.prank(caller);
        vm.expectRevert(UniversalCoreErrors.CallerIsNotUEModule.selector);
        universalCore.depositPRC20Token(token, amount, recipient);
    }

    function testFuzz_swapAndBurnGas_nonGateway_reverts(address caller) public {
        vm.assume(caller != gateway);

        vm.prank(caller);
        vm.expectRevert(UniversalCoreErrors.CallerIsNotGatewayPC.selector);
        universalCore.swapAndBurnGas{value: 0}(address(gasToken), 3000, 1, 0, address(this));
    }

    function testFuzz_setProtocolFeeByToken_nonManager_reverts(address caller, address token, uint256 fee) public {
        vm.assume(caller != uExec);
        // Cache role before prank — external calls inside vm.expectRevert would consume the prank
        bytes32 managerRole = universalCore.MANAGER_ROLE();
        vm.assume(!universalCore.hasRole(managerRole, caller));

        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, caller, managerRole)
        );
        universalCore.setProtocolFeeByToken(token, fee);
    }

    function testFuzz_setWPC_nonAdmin_reverts(address caller, address newWPC) public {
        // Cache role before prank to avoid consuming prank via external call
        bytes32 adminRole = universalCore.DEFAULT_ADMIN_ROLE();
        vm.assume(!universalCore.hasRole(adminRole, caller));

        vm.prank(caller);
        vm.expectRevert(CommonErrors.InvalidOwner.selector);
        universalCore.setWPC(newWPC);
    }

    function testFuzz_pause_nonPauser_reverts(address caller) public {
        bytes32 pauserRole = universalCore.PAUSER_ROLE();
        vm.assume(!universalCore.hasRole(pauserRole, caller));

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, caller, pauserRole)
        );
        vm.prank(caller);
        universalCore.pause();
    }

    function testFuzz_depositPRC20Token_whenPaused_reverts(address token, uint128 amount, address recipient) public {
        // Pauser pauses
        vm.prank(pauser);
        universalCore.pause();

        vm.prank(uExec);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        universalCore.depositPRC20Token(token, amount, recipient);
    }

    // =============================================
    // 12.7 Setter Zero-Address Validation Properties
    // =============================================

    function testFuzz_setWPC_zeroAddress_reverts() public {
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setWPC(address(0));
    }

    function testFuzz_setUniversalGatewayPC_zeroAddress_reverts() public {
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setUniversalGatewayPC(address(0));
    }

    function testFuzz_setUniswapV3Addresses_anyZero_reverts(address f, address r) public {
        bool anyZero = f == address(0) || r == address(0);

        if (anyZero) {
            vm.expectRevert(CommonErrors.ZeroAddress.selector);
            universalCore.setUniswapV3Addresses(f, r);
        } else {
            // No revert expected — just verify it stores values
            universalCore.setUniswapV3Addresses(f, r);
        }
    }

    function testFuzz_setGasTokenPRC20_zeroAddress_reverts(string memory chainNamespace) public {
        vm.prank(uExec);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setGasTokenPRC20(chainNamespace, address(0));
    }

    function testFuzz_setProtocolFeeByToken_zeroToken_reverts(uint256 fee) public {
        vm.prank(uExec);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setProtocolFeeByToken(address(0), fee);
    }

    function testFuzz_setSupportedToken_zeroAddress_reverts(bool supported) public {
        vm.prank(uExec);
        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.setSupportedToken(address(0), supported);
    }
}
