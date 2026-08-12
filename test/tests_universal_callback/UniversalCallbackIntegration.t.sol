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
import {UniversalCallbackErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";

contract UniversalCallbackIntegrationTest is Test {
    UniversalCallback callback;
    MockUniversalCore mockCore;
    MockVaultPC mockVault;
    CrossLendMock crossLend;
    RevertingReadClient revertingClient;

    address defaultAdmin = address(0xAAAA);
    address ueModule = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    address uvAdmin = address(0xBBBB);
    address user = address(0xCCCC);
    address pauser = address(0xDDDD);

    uint256 constant PROTOCOL_FEE = 0.01 ether;
    uint256 constant DEPOSIT_FEE = 1 ether;

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
        mockCore.setChainHeight("eip155", 1000);

        crossLend = new CrossLendMock(address(callback));
        revertingClient = new RevertingReadClient(address(callback));
    }

    function testIntegration_FullFlow_RequestFulfillCreditsRefund() public {
        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = crossLend.lastRequestId();
        assertGt(requestId, 0);

        uint256 balanceBefore = address(crossLend).balance;
        uint256 vaultBefore = mockVault.totalReceived();

        bytes memory result = abi.encode("ethPrice:3500");
        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, result, 500, bytes32(uint256(0x123)));

        assertTrue(callback.isFulfilled(requestId));
        assertEq(crossLend.lastResultData(), result);

        uint256 refundAmount = DEPOSIT_FEE - PROTOCOL_FEE;
        // Pull, not push: the balance does not move until withdraw() is called.
        assertEq(address(crossLend).balance, balanceBefore);
        assertEq(callback.withdrawable(address(crossLend)), refundAmount);
        assertEq(mockVault.totalReceived(), vaultBefore + PROTOCOL_FEE);

        crossLend.reclaim();
        assertEq(address(crossLend).balance, balanceBefore + refundAmount);
        assertEq(callback.withdrawable(address(crossLend)), 0);
    }

    function testIntegration_FullFlow_CallbackFails_CreditsRefundMinusProtocolFee() public {
        vm.deal(address(revertingClient), DEPOSIT_FEE);
        vm.prank(address(revertingClient));
        revertingClient.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = revertingClient.lastRequestId();
        bytes memory result = abi.encode("ethPrice:3500");

        uint256 balanceBefore = address(revertingClient).balance;
        uint256 vaultBefore = mockVault.totalReceived();

        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, result, 500, bytes32(uint256(0x123)));

        assertTrue(callback.isFulfilled(requestId));
        // A reverting callback no longer earns a full refund -- the protocol fee is
        // retained because validators still did the work.
        assertEq(address(revertingClient).balance, balanceBefore);
        assertEq(callback.withdrawable(address(revertingClient)), DEPOSIT_FEE - PROTOCOL_FEE);
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
            vm.prank(ueModule);
            callback.fulfillExternalCallback(ids[i], result, uint64(100 + i), bytes32(uint256(i)));
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
        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, result, 500, bytes32(uint256(0x123)));

        assertTrue(callback.isFulfilled(requestId));
    }

    function testIntegration_Expiry_CreditsRefund() public {
        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = crossLend.lastRequestId();
        uint256 balanceBefore = address(crossLend).balance;
        uint256 vaultBefore = mockVault.totalReceived();

        vm.roll(block.number + 1000);

        vm.prank(ueModule);
        callback.expireExternalRead(requestId);

        uint256 refundAmount = DEPOSIT_FEE - PROTOCOL_FEE;
        assertEq(address(crossLend).balance, balanceBefore);
        assertEq(callback.withdrawable(address(crossLend)), refundAmount);
        assertEq(callback.totalWithdrawable(), refundAmount);
        assertEq(mockVault.totalReceived(), vaultBefore + PROTOCOL_FEE);

        crossLend.reclaim();
        assertEq(address(crossLend).balance, balanceBefore + refundAmount);
        assertEq(callback.totalWithdrawable(), 0);
    }

    function testIntegration_ExpiryThenFulfill_Reverts() public {
        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = crossLend.lastRequestId();
        vm.roll(block.number + 1000);

        vm.prank(ueModule);
        callback.expireExternalRead(requestId);

        uint256 creditedOnce = callback.withdrawable(address(crossLend));

        vm.prank(ueModule);
        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.RequestAlreadyFulfilled.selector, requestId)
        );
        callback.fulfillExternalCallback(requestId, "", 0, bytes32(0));

        assertEq(callback.withdrawable(address(crossLend)), creditedOnce);
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
            vm.prank(ueModule);
            callback.expireExternalRead(ids[i]);
        }

        uint256 expected = 3 * (DEPOSIT_FEE - PROTOCOL_FEE);
        assertEq(callback.withdrawable(address(crossLend)), expected);
        assertEq(callback.totalWithdrawable(), expected);

        uint256 balanceBefore = address(crossLend).balance;
        crossLend.reclaim();
        assertEq(address(crossLend).balance, balanceBefore + expected);
    }

    function testIntegration_AdminCannotRescueCreditedRefunds() public {
        vm.deal(address(crossLend), 3 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 3 ether}(1000);

        uint256 requestId = crossLend.lastRequestId();

        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, abi.encode("x"), 500, bytes32(uint256(0x123)));

        // The whole deposit is now either at the vault or owed to the client, so
        // nothing is sweepable.
        uint256 credited = callback.withdrawable(address(crossLend));
        assertEq(address(callback).balance, credited);

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
        vm.prank(ueModule);
        callback.expireExternalRead(requestId);

        uint256 credited = callback.withdrawable(address(crossLend));
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
        crossLend.reclaim();
        assertEq(callback.totalWithdrawable(), 0);
    }

    function testIntegration_SettlementRevertsWhenVaultRejectsFee() public {
        // VaultPC accepts plain transfers unconditionally, so this can only happen
        // if a future vault breaks that contract. Settlement must fail loudly
        // rather than silently converting the fee into an unpayable credit.
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
        client.requestSync{value: DEPOSIT_FEE}(1000);
        uint256 requestId = client.lastRequestId();

        vm.roll(block.number + 1000);

        vm.prank(ueModule);
        vm.expectRevert(abi.encodeWithSelector(CommonErrors.TransferFailed.selector));
        cb.expireExternalRead(requestId);

        // Nothing was credited and the request stays live.
        assertEq(cb.totalWithdrawable(), 0);
        assertFalse(cb.isFulfilled(requestId));
    }

    function testIntegration_CallbackReentersWithdraw_Blocked() public {
        ReentrantReadClient reentrant = new ReentrantReadClient(address(callback));

        vm.deal(address(reentrant), DEPOSIT_FEE);
        vm.prank(address(reentrant));
        reentrant.requestSync{value: DEPOSIT_FEE}(1000);
        uint256 requestId = reentrant.lastRequestId();

        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, abi.encode("x"), 500, bytes32(0));

        uint256 credited = DEPOSIT_FEE - PROTOCOL_FEE;
        // Settlement completed before the callback ran, so the client saw its credit.
        assertEq(reentrant.creditSeenDuringCallback(), credited);
        // ...but re-entering withdraw() from inside the callback was blocked.
        assertFalse(reentrant.reentrySucceeded());
        assertEq(callback.withdrawable(address(reentrant)), credited);

        // The credit survives and is claimable afterwards.
        reentrant.reclaimRefunds();
        assertEq(address(reentrant).balance, credited);
    }

    function testIntegration_EstimateFeePlusDeposit() public {
        uint256 estimated = callback.estimateFee("eip155", "1", 50000);
        assertEq(estimated, PROTOCOL_FEE + 50000 * tx.gasprice);
    }
}
