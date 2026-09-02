// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {UniversalCallback} from "../../src/UniversalCallback.sol";
import {
    ReadSpec,
    PendingRead,
    RequestStatus,
    MIN_CONFIRMATIONS_FLOOR,
    MAX_CALLBACK_GAS_LIMIT
} from "../../src/libraries/ReadTypes.sol";
import {UniversalCallbackErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import {UniversalAccountId} from "../../src/libraries/Types.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {MockUniversalCore} from "../mocks/MockUniversalCore.sol";
import {MockVaultPC} from "../mocks/MockVaultPC.sol";

contract UniversalCallbackTest is Test {
    UniversalCallback callback;
    MockUniversalCore mockCore;
    MockVaultPC mockVault;

    address defaultAdmin = address(0xAAAA);
    address ucallbackModule = 0x07a0258D367A4A4cd9d6E4b7eEE8E7eF491CC519;
    address uvAdmin = address(0xBBBB);
    address user = address(0xCCCC);
    address pauser = address(0xDDDD);
    address vaultPC = makeAddr("vaultPC");

    ReadSpec defaultSpec;
    bytes4 constant CALLBACK_SEL = bytes4(keccak256("onResponse(uint256,bytes)"));

    uint256 constant DEPOSIT = 1 ether;
    uint256 constant PROTOCOL_FEE = 0.01 ether;
    /// @dev Derived, never hardcoded: the protocol fee leaves at request time, so
    ///      only this remains escrowed and refundable.
    uint256 constant BUDGET = DEPOSIT - PROTOCOL_FEE;

    /// @dev Drives one request through fulfill + report, asserting the model at
    ///      each step, then simulates the module's burn.
    function _fulfillAndBurn(uint256 requestId, bytes memory data, uint256 gasBurned)
        internal
        returns (uint256 burned)
    {
        uint256 balBefore = address(callback).balance;
        uint256 escBefore = callback.totalEscrowed();
        address recipient = callback.getPendingRead(requestId).revertRecipient;
        uint256 recipientBefore = recipient.balance;

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, data);

        // Fulfillment must not move a wei.
        assertEq(address(callback).balance, balBefore, "fulfill moved value");
        assertEq(callback.totalEscrowed(), escBefore, "fulfill touched escrow");
        assertEq(recipient.balance, recipientBefore, "fulfill paid the recipient");

        vm.prank(ucallbackModule);
        burned = callback.reportCallbackGas(requestId, gasBurned);

        // The strong form: proves escrow released exactly the budget, the refund was
        // pushed in full, and the leftover slack is precisely what the module may
        // take. assertGe here would pass with wrong amounts.
        assertEq(
            address(callback).balance,
            callback.totalEscrowed() + burned,
            "slack must equal exactly the pending burn"
        );

        // Simulate the module's BurnCoins -- vm.deal removes supply, which a
        // transfer to address(0) would not.
        vm.deal(address(callback), address(callback).balance - burned);

        assertGe(
            address(callback).balance,
            callback.totalEscrowed(),
            "invariant broken after burn"
        );
    }

    function setUp() public {
        mockCore = new MockUniversalCore();
        mockVault = new MockVaultPC();

        UniversalCallback impl = new UniversalCallback();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(
                UniversalCallback.initialize.selector,
                address(mockCore),
                address(mockVault),
                defaultAdmin
            )
        );
        callback = UniversalCallback(payable(address(proxy)));

        vm.startPrank(defaultAdmin);
        callback.grantRole(callback.UVCALLBACK_ADMIN_ROLE(), uvAdmin);
        callback.grantRole(callback.PAUSER_ROLE(), pauser);
        callback.grantRole(callback.UVCALLBACK_ADMIN_ROLE(), defaultAdmin);
        vm.stopPrank();

        defaultSpec = ReadSpec({
            account: UniversalAccountId({
                chainNamespace: "eip155",
                chainId: "1",
                owner: abi.encode(user)
            }),
            query: abi.encode("someData"),
            minConfirmations: 10,
            blockNumber: 100,
            expiryPushChainHeight: uint64(block.number + 1000),
            maxFee: 10 ether,
            revertRecipient: user
        });

        mockCore.setReadBaseFee("eip155", "1", 0.01 ether);
        mockCore.setChainHeight("eip155:1", 1000);
    }

    function test_Initialize_SetsState() public {
        assertEq(address(callback.universalCore()), address(mockCore));
        assertEq(callback.vaultPC(), address(mockVault));
        assertTrue(callback.hasRole(callback.DEFAULT_ADMIN_ROLE(), defaultAdmin));
        assertTrue(callback.hasRole(callback.UVCALLBACK_ADMIN_ROLE(), defaultAdmin));
        assertTrue(callback.hasRole(callback.UVCALLBACK_ADMIN_ROLE(), uvAdmin));
    }

    function test_Initialize_RevertWhen_ZeroAddressCore() public {
        UniversalCallback impl = new UniversalCallback();
        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.ZeroAddressInit.selector));
        new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(
                UniversalCallback.initialize.selector,
                address(0), address(mockVault), defaultAdmin
            )
        );
    }

    function test_Initialize_RevertWhen_ZeroAddressVault() public {
        UniversalCallback impl = new UniversalCallback();
        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.ZeroAddressInit.selector));
        new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(
                UniversalCallback.initialize.selector,
                address(mockCore), address(0), defaultAdmin
            )
        );
    }

    function test_Initialize_RevertWhen_ZeroAddressAdmin() public {
        UniversalCallback impl = new UniversalCallback();
        vm.expectRevert(); // AccessControl: admin cannot be zero
        new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(
                UniversalCallback.initialize.selector,
                address(mockCore), address(mockVault), address(0)
            )
        );
    }

    function test_RequestExternalRead_EmitsEvent() public {
        vm.deal(user, 10 ether);
        vm.prank(user);

        vm.expectEmit(false, true, true, true);
        emit IUniversalCallback.ReadRequested(
            0, defaultSpec, user, user, 50000, DEPOSIT, PROTOCOL_FEE, BUDGET
        );

        uint256 requestId = callback.requestExternalReadSelf{value: DEPOSIT}(
            defaultSpec, CALLBACK_SEL, 50000
        );
        assertGt(requestId, 0);
    }

    function test_RequestExternalRead_StoresPending() public {
        vm.deal(user, DEPOSIT);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: DEPOSIT}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        PendingRead memory p = callback.getPendingRead(requestId);
        assertEq(p.callbackTarget, user);
        assertEq(p.originalFunder, user);
        assertEq(p.callbackBudget, BUDGET, "budget excludes the protocol fee");
        assertEq(p.revertRecipient, defaultSpec.revertRecipient);
        assertEq(p.expiryHeight, defaultSpec.expiryPushChainHeight);
        assertEq(uint8(callback.statusOf(requestId)), uint8(RequestStatus.PENDING));
    }

    function test_Request_PushesFeeToVaultImmediately() public {
        // Snapshot BEFORE the request -- the fee has already moved by the time
        // requestExternalReadSelf returns.
        uint256 vaultBefore = mockVault.totalReceived();

        vm.deal(user, 10 ether);
        vm.prank(user);
        callback.requestExternalReadSelf{value: DEPOSIT}(defaultSpec, CALLBACK_SEL, 50000);

        assertEq(mockVault.totalReceived(), vaultBefore + PROTOCOL_FEE);
        assertEq(callback.totalEscrowed(), BUDGET, "escrow excludes the fee");
        assertEq(address(callback).balance, BUDGET);
    }

    function test_Request_ExactMinimumFee_ZeroBudget() public {
        vm.deal(user, PROTOCOL_FEE);
        vm.prank(user);
        uint256 requestId =
            callback.requestExternalReadSelf{value: PROTOCOL_FEE}(defaultSpec, CALLBACK_SEL, 50000);

        assertEq(callback.getPendingRead(requestId).callbackBudget, 0);
        assertEq(callback.totalEscrowed(), 0);
    }

    function test_Request_RevertWhen_ZeroRevertRecipient() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.revertRecipient = address(0);

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.ZeroRevertRecipient.selector));
        callback.requestExternalReadSelf{value: DEPOSIT}(spec, CALLBACK_SEL, 50000);
    }

    function test_EstimateFee_IgnoresGasPrice() public {
        vm.txGasPrice(500 gwei);
        assertEq(callback.estimateFee("eip155", "1"), PROTOCOL_FEE);
        vm.txGasPrice(1);
        assertEq(callback.estimateFee("eip155", "1"), PROTOCOL_FEE);
    }

    function test_RequestExternalRead_RevertWhen_InsufficientFee() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.InsufficientFee.selector, 0.001 ether, 0.01 ether)
        );
        callback.requestExternalReadSelf{value: 0.001 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_FeeExceedsMaxFee() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.maxFee = 0.5 ether;

        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.ExcessiveFee.selector, 1 ether, 0.5 ether)
        );
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_EmptyOwner() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.account.owner = "";

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidAccountId.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_EmptyChainNamespace() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.account.chainNamespace = "";

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidAccountId.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_EmptyChainId() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.account.chainId = "";

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidAccountId.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_EmptyQuery() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.query = "";

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.EmptyQuery.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_MinConfirmationsBelowFloor() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.minConfirmations = 0;

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidMinConfirmations.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_ZeroBlockNumber() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.blockNumber = 0;

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidBlockNumber.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_BlockNumberAboveOracleHeight() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.blockNumber = 1001; // oracle height is 1000

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidBlockNumber.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_ExpiryNotInFuture() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.expiryPushChainHeight = uint64(block.number);

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidExpiryHeight.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_DomainBlocked() public {
        vm.prank(uvAdmin);
        callback.updateBlockedDomain("eip155", "1", true);

        vm.deal(user, 10 ether);
        vm.prank(user);

        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.DomainBlocked.selector, "eip155", "1")
        );
        callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_ZeroCallbackGasLimit() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.ZeroCallbackGasLimit.selector)
        );
        callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 0
        );
    }

    function test_RequestExternalRead_RevertWhen_CallbackGasLimitExceedsMax() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.CallbackGasLimitExceeded.selector, MAX_CALLBACK_GAS_LIMIT + 1, MAX_CALLBACK_GAS_LIMIT)
        );
        callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, MAX_CALLBACK_GAS_LIMIT + 1
        );
    }

    function test_FulfillExternalCallback_Success() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        bytes memory resultData = abi.encode("result");

        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.ReadFulfilled(requestId, resultData);

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, resultData);

        assertTrue(callback.isFulfilled(requestId));
    }

    function test_FulfillExternalCallback_RevertWhen_NotUCallbackModule() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.CallerIsNotUCallbackModule.selector));
        callback.fulfillExternalCallback(requestId, "");
    }

    function test_FulfillExternalCallback_RevertWhen_AlreadyFulfilled() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, "");

        vm.prank(ucallbackModule);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCallbackErrors.InvalidRequestStatus.selector,
                requestId, uint8(RequestStatus.EXECUTED), uint8(RequestStatus.PENDING)
            )
        );
        callback.fulfillExternalCallback(requestId, "");
    }

    function test_FulfillExternalCallback_RevertWhen_InvalidRequestId() public {
        vm.prank(ucallbackModule);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCallbackErrors.InvalidRequestStatus.selector,
                uint256(999), uint8(RequestStatus.NONE), uint8(RequestStatus.PENDING)
            )
        );
        callback.fulfillExternalCallback(999, "");
    }

    function test_FulfillExternalCallback_CallbackReverts_EmitsCallbackFailed() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.mockCallRevert(
            user,
            abi.encodeWithSelector(CALLBACK_SEL, requestId, ""),
            abi.encodeWithSignature("CustomError()")
        );

        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.CallbackFailed(requestId, abi.encodeWithSignature("CustomError()"));

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, "");
    }

    function test_ExpireExternalRead_Success() public {
        vm.deal(user, DEPOSIT);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: DEPOSIT}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.roll(defaultSpec.expiryPushChainHeight);

        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.RequestExpired(requestId, defaultSpec.revertRecipient, BUDGET);

        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);

        assertTrue(callback.isFulfilled(requestId));
        assertEq(uint8(callback.statusOf(requestId)), uint8(RequestStatus.EXPIRED));
        assertEq(defaultSpec.revertRecipient.balance, BUDGET);
    }

    function test_ExpireExternalRead_RefundsFullBudget_KeepsProtocolFee() public {
        // Snapshot BEFORE the request: the fee moves at request time now.
        uint256 vaultBefore = mockVault.totalReceived();

        vm.deal(user, DEPOSIT);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: DEPOSIT}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        uint256 recipientBalanceBefore = defaultSpec.revertRecipient.balance;

        vm.roll(defaultSpec.expiryPushChainHeight);
        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);

        // No callback ran, so nothing burned: the whole budget is refundable and
        // the fee stays with the vault.
        assertEq(mockVault.totalReceived(), vaultBefore + PROTOCOL_FEE);
        assertEq(defaultSpec.revertRecipient.balance, BUDGET);
        assertEq(
            defaultSpec.revertRecipient.balance,
            recipientBalanceBefore + BUDGET,
            "budget pushed straight to the recipient"
        );
        assertEq(address(callback).balance, 0, "refund was pushed out");
        assertEq(callback.totalEscrowed(), 0);
    }

    function test_ExpireExternalRead_EmitsFeeRefundCredited() public {
        vm.deal(user, DEPOSIT);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: DEPOSIT}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.roll(defaultSpec.expiryPushChainHeight);

        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.RefundSent(requestId, defaultSpec.revertRecipient, BUDGET);

        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);
    }

    function test_ExpireExternalRead_RevertWhen_NotYetExpired() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        // block.number is still below expiryHeight
        vm.prank(ucallbackModule);
        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.RequestNotYetExpired.selector));
        callback.expireExternalRead(requestId);
    }

    function test_ExpireExternalRead_RevertWhen_NotUCallbackModule() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.CallerIsNotUCallbackModule.selector));
        callback.expireExternalRead(requestId);
    }

    function test_EstimateFee_Works() public view {
        uint256 fee = callback.estimateFee("eip155", "1");
        assertGe(fee, 0.01 ether);
    }

    function test_UpdateBlockedDomain_SetsValue() public {
        vm.prank(uvAdmin);
        callback.updateBlockedDomain("solana", "mainnet", true);

        assertTrue(callback.isDomainBlocked("solana", "mainnet"));
    }

    function test_UpdateBlockedDomain_RevertWhen_NotAdmin() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.CallerIsNotAdmin.selector));
        callback.updateBlockedDomain("solana", "mainnet", true);
    }

    function test_Pause_RevertWhen_NotPauser() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.UnauthorizedCaller.selector));
        callback.pause();
    }

    function test_Pause_BlocksNewRequests() public {
        vm.prank(pauser);
        callback.pause();

        vm.deal(user, 10 ether);
        vm.prank(user);
        vm.expectRevert();
        callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );
    }

    function test_RescueNativePC_OnlyDefaultAdmin() public {
        vm.deal(address(callback), 1 ether);
        address recipient = makeAddr("recipient");

        vm.prank(uvAdmin);
        vm.expectRevert();
        callback.rescueNativePC(payable(recipient), 0.5 ether);

        vm.prank(defaultAdmin);
        callback.rescueNativePC(payable(recipient), 0.5 ether);
        assertEq(recipient.balance, 0.5 ether);
    }

    function test_RescueNativePC_RevertWhen_ZeroAmount() public {
        vm.deal(address(callback), 1 ether);

        vm.prank(defaultAdmin);
        vm.expectRevert(abi.encodeWithSelector(CommonErrors.ZeroAmount.selector));
        callback.rescueNativePC(payable(makeAddr("recipient")), 0);
    }

    function test_RescueNativePC_RevertWhen_ZeroRecipient() public {
        vm.deal(address(callback), 1 ether);

        vm.prank(defaultAdmin);
        vm.expectRevert(abi.encodeWithSelector(CommonErrors.ZeroAddress.selector));
        callback.rescueNativePC(payable(address(0)), 0.5 ether);
    }

    function test_RescueNativePC_EmitsEvent() public {
        vm.deal(address(callback), 1 ether);
        address recipient = makeAddr("recipient");

        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.NativePCRescued(recipient, 0.5 ether);

        vm.prank(defaultAdmin);
        callback.rescueNativePC(payable(recipient), 0.5 ether);
    }

    // =========================
    //   PULL-PAYMENT LEDGER
    // =========================

    function _requestAndExpire() private returns (uint256 requestId, uint256 credited) {
        vm.deal(user, DEPOSIT);
        vm.prank(user);
        requestId = callback.requestExternalReadSelf{value: DEPOSIT}(
            defaultSpec, CALLBACK_SEL, 50000
        );
        vm.roll(defaultSpec.expiryPushChainHeight);
        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);
        // Expiry runs no callback, so the entire budget comes back.
        credited = BUDGET;
    }






    function test_Fulfill_MovesNoMoney() public {
        vm.deal(user, DEPOSIT);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: DEPOSIT}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        uint256 balBefore = address(callback).balance;
        uint256 vaultBefore = mockVault.totalReceived();

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, "");

        // The clearest single expression of the new design.
        assertEq(address(callback).balance, balBefore);
        assertEq(mockVault.totalReceived(), vaultBefore);
        assertEq(user.balance, 0);
        assertEq(callback.totalEscrowed(), BUDGET);
        assertEq(uint8(callback.statusOf(requestId)), uint8(RequestStatus.EXECUTED));
    }

    function test_Report_CreditsRemainderAfterBurn() public {
        vm.deal(user, DEPOSIT);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: DEPOSIT}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        uint256 gasBurned = 0.4 ether;
        uint256 burned = _fulfillAndBurn(requestId, "", gasBurned);

        assertEq(burned, gasBurned);
        assertEq(user.balance, BUDGET - gasBurned);
        assertEq(callback.totalEscrowed(), 0);
        assertEq(uint8(callback.statusOf(requestId)), uint8(RequestStatus.SETTLED));
    }

    function test_Report_FailedCallbackChargedIdentically() public {
        vm.deal(user, DEPOSIT);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: DEPOSIT}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.mockCallRevert(
            user,
            abi.encodeWithSelector(CALLBACK_SEL, requestId, ""),
            abi.encodeWithSignature("CustomError()")
        );

        uint256 gasBurned = 0.4 ether;
        _fulfillAndBurn(requestId, "", gasBurned);

        // Success and failure settle identically -- the gas was spent either way.
        assertEq(user.balance, BUDGET - gasBurned);
    }

    function test_ZeroProtocolFee_CreditsFullDeposit() public {
        mockCore.setReadBaseFee("eip155", "1", 0);

        vm.deal(user, DEPOSIT);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: DEPOSIT}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        uint256 vaultBefore = mockVault.totalReceived();

        vm.roll(defaultSpec.expiryPushChainHeight);
        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);

        assertEq(user.balance, DEPOSIT);
        assertEq(mockVault.totalReceived(), vaultBefore);
    }

    function test_RescueNativePC_ExcludesWithdrawable() public {
        _requestAndExpire();

        address recipient = makeAddr("recipient");
        assertEq(address(callback).balance, 0, "refund was pushed out");

        vm.prank(defaultAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCallbackErrors.InsufficientContractBalance.selector, 1, 0
            )
        );
        callback.rescueNativePC(payable(recipient), 1);
    }

    function test_RescueNativePC_AllowsStrayEth() public {
        _requestAndExpire();

        uint256 stray = 0.25 ether;
        vm.deal(address(callback), address(callback).balance + stray);

        address recipient = makeAddr("recipient");
        vm.prank(defaultAdmin);
        callback.rescueNativePC(payable(recipient), stray);

        assertEq(recipient.balance, stray);
        // The refund had already been pushed out and was untouched by the sweep.
        assertEq(user.balance, BUDGET);
    }

    // =========================
    //   IN-FLIGHT ESCROW
    // =========================

    function _request() private returns (uint256 requestId) {
        vm.deal(user, DEPOSIT);
        vm.prank(user);
        requestId = callback.requestExternalReadSelf{value: DEPOSIT}(
            defaultSpec, CALLBACK_SEL, 50000
        );
    }

    function test_TotalEscrowed_IncrementsOnRequest() public {
        assertEq(callback.totalEscrowed(), 0);
        _request();
        // Escrow holds the budget only -- the protocol fee already left.
        assertEq(callback.totalEscrowed(), BUDGET);
    }

    function test_TotalEscrowed_HeldUntilReport() public {
        uint256 requestId = _request();

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, "");
        assertEq(callback.totalEscrowed(), BUDGET, "fulfill must not release escrow");

        vm.prank(ucallbackModule);
        callback.reportCallbackGas(requestId, 0);
        assertEq(callback.totalEscrowed(), 0);
    }

    function test_TotalEscrowed_ReturnsToZeroAfterExpire() public {
        uint256 requestId = _request();

        vm.roll(defaultSpec.expiryPushChainHeight);
        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);

        assertEq(callback.totalEscrowed(), 0);
    }

    function test_TotalEscrowed_MultipleConcurrentRequests() public {
        vm.deal(user, 10 ether);

        uint256[] memory ids = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) {
            ReadSpec memory spec = defaultSpec;
            spec.query = abi.encode(i);
            vm.prank(user);
            ids[i] = callback.requestExternalReadSelf{value: DEPOSIT}(spec, CALLBACK_SEL, 50000);
            assertEq(callback.totalEscrowed(), (i + 1) * BUDGET);
        }

        vm.roll(defaultSpec.expiryPushChainHeight);
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(ucallbackModule);
            callback.expireExternalRead(ids[i]);
        }

        assertEq(callback.totalEscrowed(), 0);
    }

    function test_RescueNativePC_ExcludesInFlightDeposit() public {
        _request();
        assertEq(callback.totalEscrowed(), BUDGET);

        uint256 stray = 0.3 ether;
        vm.deal(address(callback), address(callback).balance + stray);

        address recipient = makeAddr("recipient");

        // The in-flight deposit is user money and must not be sweepable.
        vm.prank(defaultAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCallbackErrors.InsufficientContractBalance.selector, stray + 1, stray
            )
        );
        callback.rescueNativePC(payable(recipient), stray + 1);

        // Only the stray amount is available.
        vm.prank(defaultAdmin);
        callback.rescueNativePC(payable(recipient), stray);
        assertEq(recipient.balance, stray);
    }

    function test_SettlementSucceedsAfterMaxSweep() public {
        uint256 requestId = _request();

        uint256 stray = 0.3 ether;
        vm.deal(address(callback), address(callback).balance + stray);

        // What an admin could take if escrow were ignored -- this is the amount
        // that drains the deposit and bricks settlement.
        uint256 unsafeSweep = address(callback).balance;
        assertGt(unsafeSweep, stray, "test must actually attempt an over-sweep");

        vm.prank(defaultAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCallbackErrors.InsufficientContractBalance.selector, unsafeSweep, stray
            )
        );
        callback.rescueNativePC(payable(makeAddr("recipient")), unsafeSweep);

        // The most that may legitimately be taken is the stray amount.
        vm.prank(defaultAdmin);
        callback.rescueNativePC(payable(makeAddr("recipient")), stray);

        // The request still settles and the funder is still made whole.
        _fulfillAndBurn(requestId, "", 0);

        assertEq(user.balance, BUDGET, "refund pushed on settlement");
    }

    // =========================
    //   STATE MACHINE
    // =========================

    function _expectBadStatus(uint256 id, RequestStatus actual, RequestStatus expected) private {
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCallbackErrors.InvalidRequestStatus.selector,
                id, uint8(actual), uint8(expected)
            )
        );
    }

    function test_Transition_ReportBeforeFulfill_Reverts() public {
        uint256 requestId = _request();

        vm.prank(ucallbackModule);
        _expectBadStatus(requestId, RequestStatus.PENDING, RequestStatus.EXECUTED);
        callback.reportCallbackGas(requestId, 0);
    }

    function test_Transition_DoubleReport_Reverts() public {
        uint256 requestId = _request();
        _fulfillAndBurn(requestId, "", 0);

        vm.prank(ucallbackModule);
        _expectBadStatus(requestId, RequestStatus.SETTLED, RequestStatus.EXECUTED);
        callback.reportCallbackGas(requestId, 0);
    }

    function test_Transition_ExpireAfterExecute_Reverts() public {
        uint256 requestId = _request();

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, "");

        vm.roll(defaultSpec.expiryPushChainHeight);

        // An executed callback consumed real gas -- it must settle via the report
        // path, never be refunded in full.
        vm.prank(ucallbackModule);
        _expectBadStatus(requestId, RequestStatus.EXECUTED, RequestStatus.PENDING);
        callback.expireExternalRead(requestId);
    }

    function test_Transition_ReportAfterExpire_Reverts() public {
        (uint256 requestId,) = _requestAndExpire();

        vm.prank(ucallbackModule);
        _expectBadStatus(requestId, RequestStatus.EXPIRED, RequestStatus.EXECUTED);
        callback.reportCallbackGas(requestId, 0);
    }

    function test_Transition_FulfillAfterExpire_Reverts() public {
        (uint256 requestId,) = _requestAndExpire();

        vm.prank(ucallbackModule);
        _expectBadStatus(requestId, RequestStatus.EXPIRED, RequestStatus.PENDING);
        callback.fulfillExternalCallback(requestId, "");
    }

    function test_Transition_DoubleExpire_Reverts() public {
        (uint256 requestId,) = _requestAndExpire();

        vm.prank(ucallbackModule);
        _expectBadStatus(requestId, RequestStatus.EXPIRED, RequestStatus.PENDING);
        callback.expireExternalRead(requestId);
    }

    /// @dev Regression test for NONE being the zero enum value: an id that was
    ///      never created must not read as a live PENDING request.
    function test_Transition_UnknownId_RevertsEverywhere() public {
        uint256 ghost = 123456789;
        assertEq(uint8(callback.statusOf(ghost)), uint8(RequestStatus.NONE));

        vm.prank(ucallbackModule);
        _expectBadStatus(ghost, RequestStatus.NONE, RequestStatus.PENDING);
        callback.fulfillExternalCallback(ghost, "");

        vm.prank(ucallbackModule);
        _expectBadStatus(ghost, RequestStatus.NONE, RequestStatus.EXECUTED);
        callback.reportCallbackGas(ghost, 0);

        vm.prank(ucallbackModule);
        _expectBadStatus(ghost, RequestStatus.NONE, RequestStatus.PENDING);
        callback.expireExternalRead(ghost);
    }

    function test_Report_RevertWhen_NotUCallbackModule() public {
        uint256 requestId = _request();
        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, "");

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.CallerIsNotUCallbackModule.selector));
        callback.reportCallbackGas(requestId, 0);
    }

    // =========================
    //   BURN CLAMPING
    // =========================

    function test_Report_ClampsToBudget() public {
        uint256 requestId = _request();
        uint256 burned = _fulfillAndBurn(requestId, "", BUDGET + 1);

        assertEq(burned, BUDGET, "burn clamped to the authorized budget");
        assertEq(user.balance, 0);
    }

    function test_Report_ClampsAtExtreme() public {
        uint256 requestId = _request();
        uint256 burned = _fulfillAndBurn(requestId, "", type(uint256).max);

        assertEq(burned, BUDGET, "no overflow, still clamped");
    }

    function test_Report_ExactBudget_NoRefund() public {
        uint256 requestId = _request();
        uint256 burned = _fulfillAndBurn(requestId, "", BUDGET);

        assertEq(burned, BUDGET);
        assertEq(user.balance, 0);
    }

    function test_Report_ZeroGasBurned_RefundsFullBudget() public {
        uint256 requestId = _request();
        uint256 burned = _fulfillAndBurn(requestId, "", 0);

        assertEq(burned, 0);
        assertEq(user.balance, BUDGET);
    }

    function test_Report_ZeroBudget_NoRevert() public {
        vm.deal(user, PROTOCOL_FEE);
        vm.prank(user);
        uint256 requestId =
            callback.requestExternalReadSelf{value: PROTOCOL_FEE}(defaultSpec, CALLBACK_SEL, 50000);

        uint256 burned = _fulfillAndBurn(requestId, "", 5 ether);

        assertEq(burned, 0, "nothing to burn against a zero budget");
        assertEq(user.balance, 0);
    }

    function test_Report_EmitsRawAndClamped() public {
        uint256 requestId = _request();
        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, "");

        // Over-reporting must be observable on-chain.
        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.CallbackGasReported(requestId, BUDGET + 5, BUDGET, 0);

        vm.prank(ucallbackModule);
        callback.reportCallbackGas(requestId, BUDGET + 5);
    }

    // =========================
    //   REVERT RECIPIENT
    // =========================

    function test_RevertRecipient_EOAReceivesAndWithdraws() public {
        address payable eoa = payable(makeAddr("eoaRecipient"));
        ReadSpec memory spec = defaultSpec;
        spec.revertRecipient = eoa;

        vm.deal(user, DEPOSIT);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: DEPOSIT}(spec, CALLBACK_SEL, 50000);

        _fulfillAndBurn(requestId, "", 0.2 ether);

        uint256 credited = BUDGET - 0.2 ether;
        assertEq(eoa.balance, credited);
        assertEq(user.balance, 0, "funder is not credited");


    }

    function test_RevertRecipient_ReceivesOnExpiry() public {
        address eoa = makeAddr("eoaRecipient");
        ReadSpec memory spec = defaultSpec;
        spec.revertRecipient = eoa;

        vm.deal(user, DEPOSIT);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: DEPOSIT}(spec, CALLBACK_SEL, 50000);

        vm.roll(spec.expiryPushChainHeight);
        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);

        assertEq(eoa.balance, BUDGET);
        assertEq(user.balance, 0);
    }

    /// @dev Proves the invariant assertion has teeth: burning more than the
    ///      contract authorized must break `balance >= withdrawable + escrowed`.
    ///      An invariant check that can never fail is worthless.
    function test_Invariant_OverBurnBreaksBacking() public {
        uint256 requestId = _request();

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, "");
        vm.prank(ucallbackModule);
        uint256 burned = callback.reportCallbackGas(requestId, 0.2 ether);

        // A second request keeps real escrow on the books to measure against.
        ReadSpec memory spec = defaultSpec;
        spec.query = abi.encode("second");
        vm.deal(user, DEPOSIT);
        vm.prank(user);
        callback.requestExternalReadSelf{value: DEPOSIT}(spec, CALLBACK_SEL, 50000);

        assertGe(address(callback).balance, callback.totalEscrowed() + burned);

        // Burn one wei more than the contract sanctioned.
        vm.deal(address(callback), address(callback).balance - burned - 1);

        assertLt(
            address(callback).balance,
            callback.totalEscrowed(),
            "over-burn must leave user funds unbacked"
        );
    }

    function test_RevertRecipient_ChangesRequestId() public {
        vm.deal(user, 10 ether);

        ReadSpec memory a = defaultSpec;
        a.revertRecipient = makeAddr("a");
        ReadSpec memory b = defaultSpec;
        b.revertRecipient = makeAddr("b");

        vm.prank(user);
        uint256 idA = callback.requestExternalReadSelf{value: DEPOSIT}(a, CALLBACK_SEL, 50000);
        vm.prank(user);
        uint256 idB = callback.requestExternalReadSelf{value: DEPOSIT}(b, CALLBACK_SEL, 50000);

        assertTrue(idA != idB);
    }

    receive() external payable {}
}
