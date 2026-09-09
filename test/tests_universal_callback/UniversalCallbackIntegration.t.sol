// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {UniversalCallback} from "../../src/UniversalCallback.sol";
import {CrossLendMock} from "../mocks/CrossLendMock.sol";
import {RevertingReadClient} from "../mocks/RevertingReadClient.sol";
import {ReentrantReadClient} from "../mocks/ReentrantReadClient.sol";
import {MockUniversalCore} from "../mocks/MockUniversalCore.sol";
import {MockVaultPC} from "../mocks/MockVaultPC.sol";
import {RevertingVaultPC} from "../mocks/RevertingVaultPC.sol";
import {ReentrantVaultPC} from "../mocks/ReentrantVaultPC.sol";
import {UniversalCallbackErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {RequestStatus} from "../../src/libraries/ReadTypes.sol";

contract UniversalCallbackIntegrationTest is Test {
    UniversalCallback callback;
    MockUniversalCore mockCore;
    MockVaultPC mockVault;
    CrossLendMock crossLend;
    RevertingReadClient revertingClient;

    address defaultAdmin = address(0xAAAA);
    address ucallbackModule = 0x07a0258D367A4A4cd9d6E4b7eEE8E7eF491CC519;
    address uvAdmin = address(0xBBBB);
    address user = address(0xCCCC);
    address pauser = address(0xDDDD);

    uint256 constant PROTOCOL_FEE = 0.01 ether;
    uint256 constant DEPOSIT_FEE = 1 ether;
    /// @dev Escrowed portion: the protocol fee leaves at request time.
    uint256 constant BUDGET = DEPOSIT_FEE - PROTOCOL_FEE;

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
        vm.stopPrank();

        mockCore.setReadBaseFee("eip155", "1", PROTOCOL_FEE);
        mockCore.setChainHeight("eip155:1", 1000);

        crossLend = new CrossLendMock(address(callback));
        revertingClient = new RevertingReadClient(address(callback));
    }

    function testIntegration_FullFlow_RequestFulfillReportCreditsRemainder() public {
        // Snapshot BEFORE the request: the protocol fee moves at request time.
        uint256 vaultBefore = mockVault.totalReceived();

        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = crossLend.lastRequestId();
        assertGt(requestId, 0);
        assertEq(mockVault.totalReceived(), vaultBefore + PROTOCOL_FEE);

        uint256 balanceBefore = address(crossLend).balance;

        bytes memory result = abi.encode("ethPrice:3500");
        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, result);

        assertTrue(callback.isFulfilled(requestId));
        assertEq(crossLend.lastResultData(), result);
        assertEq(address(crossLend).balance, 0, "no credit before the report");

        uint256 gasBurned = 0.3 ether;
        vm.prank(ucallbackModule);
        uint256 burned = callback.reportCallbackGas(requestId, gasBurned);
        vm.deal(address(callback), address(callback).balance - burned);

        // Pushed on settlement -- no claim step.
        assertEq(address(crossLend).balance, balanceBefore + (BUDGET - gasBurned));
    }

    function testIntegration_FullFlow_CallbackFails_SettlesIdentically() public {
        uint256 vaultBefore = mockVault.totalReceived();

        vm.deal(address(revertingClient), DEPOSIT_FEE);
        vm.prank(address(revertingClient));
        revertingClient.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = revertingClient.lastRequestId();
        bytes memory result = abi.encode("ethPrice:3500");
        uint256 balanceBefore = address(revertingClient).balance;

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, result);

        uint256 gasBurned = 0.3 ether;
        vm.prank(ucallbackModule);
        uint256 burned = callback.reportCallbackGas(requestId, gasBurned);
        vm.deal(address(callback), address(callback).balance - burned);

        assertTrue(callback.isFulfilled(requestId));
        // Identical to the success path: gas was consumed either way, and the fee
        // was already taken at request time.
        assertEq(address(revertingClient).balance, balanceBefore + (BUDGET - gasBurned));
        assertEq(mockVault.totalReceived(), vaultBefore + PROTOCOL_FEE);
    }

    function testIntegration_MultipleRequestsConcurrent() public {
        uint256[] memory ids = new uint256[](3);

        for (uint256 i = 0; i < 3; i++) {
            vm.deal(address(crossLend), 10 ether);
            vm.prank(address(crossLend));
            crossLend.requestSync{value: 2 ether}(100 * (i + 1));
            ids[i] = crossLend.lastRequestId();
        }

        for (uint256 i = 0; i < 3; i++) {
            bytes memory result = abi.encode(ids[i]);
            vm.prank(ucallbackModule);
            callback.fulfillExternalCallback(ids[i], result);
        }

        assertTrue(callback.isFulfilled(ids[0]));
        assertTrue(callback.isFulfilled(ids[1]));
        assertTrue(callback.isFulfilled(ids[2]));
    }

    function testIntegration_PauseBlocksNewRequests_AllowsFulfill() public {
        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: DEPOSIT_FEE}(1000);
        uint256 requestId = crossLend.lastRequestId();

        vm.prank(pauser);
        callback.pause();

        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        vm.expectRevert();
        crossLend.requestSync{value: DEPOSIT_FEE}(2000);

        bytes memory result = abi.encode("ethPrice:3500");
        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, result);

        assertTrue(callback.isFulfilled(requestId));
    }

    function testIntegration_Expiry_CreditsRefund() public {
        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = crossLend.lastRequestId();
        uint256 balanceBefore = address(crossLend).balance;

        vm.roll(block.number + 1000);

        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);

        // Nothing executed, so the full budget is pushed back. Fee not refunded.
        assertEq(address(crossLend).balance, balanceBefore + BUDGET);
    }

    function testIntegration_ExpiryThenFulfill_Reverts() public {
        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = crossLend.lastRequestId();
        vm.roll(block.number + 1000);

        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);

        uint256 creditedOnce = address(crossLend).balance;

        vm.prank(ucallbackModule);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCallbackErrors.InvalidRequestStatus.selector,
                requestId, uint8(RequestStatus.EXPIRED), uint8(RequestStatus.PENDING)
            )
        );
        callback.fulfillExternalCallback(requestId, "");

        assertEq(address(crossLend).balance, creditedOnce);
    }

    function testIntegration_MultipleExpiries_LedgerAccumulates() public {
        uint256[] memory ids = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) {
            vm.deal(address(crossLend), DEPOSIT_FEE);
            vm.prank(address(crossLend));
            crossLend.requestSync{value: DEPOSIT_FEE}(100 * (i + 1));
            ids[i] = crossLend.lastRequestId();
        }

        vm.roll(block.number + 1000);
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(ucallbackModule);
            callback.expireExternalRead(ids[i]);
        }

        assertEq(address(crossLend).balance, 3 * BUDGET, "all three budgets pushed back");
    }

    function testIntegration_AdminCannotRescueCreditedRefunds() public {
        vm.deal(address(crossLend), 3 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 3 ether}(1000);

        uint256 requestId = crossLend.lastRequestId();

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, abi.encode("x"));
        vm.prank(ucallbackModule);
        uint256 burned = callback.reportCallbackGas(requestId, 0);
        vm.deal(address(callback), address(callback).balance - burned);

        // The whole deposit is now at the vault, burned, or already pushed back, so
        // the contract holds nothing sweepable.
        assertEq(address(callback).balance, 0);

        vm.prank(defaultAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCallbackErrors.InsufficientContractBalance.selector, 1, 0
            )
        );
        callback.rescueNativePC(payable(address(mockVault)), 1);
    }

    function testIntegration_AdminRescuesOnlyStrayFunds() public {
        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = crossLend.lastRequestId();
        vm.roll(block.number + 1000);
        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);

        uint256 credited = address(crossLend).balance;
        assertGt(credited, 0);

        uint256 stray = 0.5 ether;
        vm.deal(address(callback), address(callback).balance + stray);

        // Only the stray amount is sweepable; the credited refund is untouchable.
        vm.prank(defaultAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalCallbackErrors.InsufficientContractBalance.selector, stray + 1, stray
            )
        );
        callback.rescueNativePC(payable(address(mockVault)), stray + 1);

        uint256 vaultBefore = mockVault.totalReceived();
        vm.prank(defaultAdmin);
        callback.rescueNativePC(payable(address(mockVault)), stray);
        assertEq(mockVault.totalReceived(), vaultBefore + stray);

        // The client can still claim in full after the sweep.
    }

    function testIntegration_RequestRevertsWhenVaultRejectsFee() public {
        // The fee is pushed at request time now, so a vault that refuses payment
        // fails the request outright instead of trapping already-escrowed funds in
        // an unsettleable state. That is a strict improvement worth pinning.
        RevertingVaultPC badVault = new RevertingVaultPC();
        UniversalCallback impl = new UniversalCallback();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(
                UniversalCallback.initialize.selector,
                address(mockCore),
                address(badVault),
                defaultAdmin
            )
        );
        UniversalCallback cb = UniversalCallback(payable(address(proxy)));
        CrossLendMock client = new CrossLendMock(address(cb));

        vm.deal(address(client), DEPOSIT_FEE);
        vm.prank(address(client));
        vm.expectRevert(abi.encodeWithSelector(CommonErrors.TransferFailed.selector));
        client.requestSync{value: DEPOSIT_FEE}(1000);

        // Nothing escrowed, nothing credited, no request created.
        assertEq(cb.totalEscrowed(), 0);
        assertEq(address(cb).balance, 0);
    }

    /// @dev Pins the escrow-before-push ordering in `requestExternalReadSelf`.
    ///      `rescueNativePC` is not `nonReentrant`, so a vault that re-enters it
    ///      during the fee push sees whatever the contract considers unattributed
    ///      at that instant. With escrow incremented first the budget is already
    ///      protected; reverse the order and it is sweepable, leaving escrow
    ///      permanently unbacked.
    function testIntegration_VaultCannotSweepBudgetDuringFeePush() public {
        ReentrantVaultPC evilVault = new ReentrantVaultPC();
        UniversalCallback impl = new UniversalCallback();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(
                UniversalCallback.initialize.selector,
                address(mockCore),
                address(evilVault),
                address(evilVault)
            )
        );
        UniversalCallback cb = UniversalCallback(payable(address(proxy)));
        address sink = makeAddr("sink");
        evilVault.arm(address(cb), sink);

        CrossLendMock client = new CrossLendMock(address(cb));
        vm.deal(address(client), DEPOSIT_FEE);
        vm.prank(address(client));
        client.requestSync{value: DEPOSIT_FEE}(1000);

        // Escrow was incremented before the push, so at the moment the vault
        // re-entered, the budget was already attributed and unreachable.
        assertEq(evilVault.swept(), 0, "budget must not be sweepable mid-request");
        assertEq(sink.balance, 0);
        assertEq(cb.totalEscrowed(), BUDGET);
        assertGe(address(cb).balance, cb.totalEscrowed());
    }

    function testIntegration_CallbackCannotSeeItsRefund() public {
        ReentrantReadClient reentrant = new ReentrantReadClient(address(callback));

        vm.deal(address(reentrant), DEPOSIT_FEE);
        vm.prank(address(reentrant));
        reentrant.requestSync{value: DEPOSIT_FEE}(1000);
        uint256 requestId = reentrant.lastRequestId();

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, abi.encode("x"));

        // Semantic change integrators must know about: settlement now happens
        // AFTER the callback, so a client reading its own withdrawable balance
        // from inside onUniversalData sees nothing.
        assertEq(reentrant.creditSeenDuringCallback(), 0);

        uint256 gasBurned = 0.2 ether;
        vm.prank(ucallbackModule);
        uint256 burned = callback.reportCallbackGas(requestId, gasBurned);
        vm.deal(address(callback), address(callback).balance - burned);

        uint256 credited = BUDGET - gasBurned;
        assertEq(address(reentrant).balance, credited);
        assertEq(address(reentrant).balance, credited);
    }

    function testIntegration_EstimateFeeIsProtocolFeeOnly() public {
        assertEq(callback.estimateFee("eip155", "1"), PROTOCOL_FEE);
    }

    function testIntegration_ReportWorksWhilePaused() public {
        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: DEPOSIT_FEE}(1000);
        uint256 requestId = crossLend.lastRequestId();

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, "");

        vm.prank(pauser);
        callback.pause();

        // A pause must never trap escrow.
        vm.prank(ucallbackModule);
        uint256 burned = callback.reportCallbackGas(requestId, 0.1 ether);
        vm.deal(address(callback), address(callback).balance - burned);

        assertEq(address(crossLend).balance, BUDGET - 0.1 ether);
    }
}
