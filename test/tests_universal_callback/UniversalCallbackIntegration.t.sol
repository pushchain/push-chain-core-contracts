// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {UniversalCallback} from "../../src/UniversalCallback.sol";
import {CrossLendMock} from "../mocks/CrossLendMock.sol";
import {RevertingReadClient} from "../mocks/RevertingReadClient.sol";
import {MockUniversalCore} from "../mocks/MockUniversalCore.sol";
import {MockVaultPC} from "../mocks/MockVaultPC.sol";
import {UniversalCallbackErrors} from "../../src/libraries/Errors.sol";

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

        vm.prank(uvAdmin);
        callback.updateSupportedDomain("eip155", "1", true);

        mockCore.setReadBaseFee("eip155", "1", PROTOCOL_FEE);
        mockCore.setChainHeight("eip155", 1000);

        crossLend = new CrossLendMock(address(callback));
        revertingClient = new RevertingReadClient(address(callback));
    }

    function testIntegration_FullFlow_RequestFulfillRefund() public {
        uint256 balanceBefore = address(crossLend).balance;

        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = crossLend.lastRequestId();
        assertGt(requestId, 0);

        bytes memory result = abi.encode("ethPrice:3500");
        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, result, 500, bytes32(uint256(0x123)));

        assertTrue(callback.isFulfilled(requestId));
        assertEq(crossLend.lastResultData(), result);

        uint256 refundAmount = DEPOSIT_FEE - PROTOCOL_FEE;
        uint256 balanceAfter = address(crossLend).balance;
        assertGe(balanceAfter, balanceBefore + refundAmount);
    }

    function testIntegration_FullFlow_RequestFulfillCallbackFails_Refund() public {
        vm.deal(address(revertingClient), DEPOSIT_FEE);
        vm.prank(address(revertingClient));
        revertingClient.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = revertingClient.lastRequestId();
        bytes memory result = abi.encode("ethPrice:3500");

        uint256 balanceBefore = address(revertingClient).balance;

        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, result, 500, bytes32(uint256(0x123)));

        assertTrue(callback.isFulfilled(requestId));
        uint256 balanceAfter = address(revertingClient).balance;
        assertEq(balanceAfter, balanceBefore + DEPOSIT_FEE);
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

    function testIntegration_Expiry_NoRefund() public {
        vm.deal(address(crossLend), DEPOSIT_FEE);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: DEPOSIT_FEE}(1000);

        uint256 requestId = crossLend.lastRequestId();
        uint256 balanceBefore = address(crossLend).balance;

        vm.roll(block.number + 1000);

        vm.prank(ueModule);
        callback.expireExternalRead(requestId);

        uint256 balanceAfter = address(crossLend).balance;
        assertEq(balanceAfter, balanceBefore);
    }

    function testIntegration_AdminSweepsFees() public {
        vm.deal(address(crossLend), 3 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 3 ether}(1000);

        uint256 requestId = crossLend.lastRequestId();
        bytes memory result = abi.encode("ethPrice:3500");

        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, result, 500, bytes32(uint256(0x123)));

        uint256 vaultBalanceBefore = address(mockVault).balance;

        uint256 sweepable = address(callback).balance;
        vm.prank(defaultAdmin);
        callback.sweepFees(payable(address(mockVault)), sweepable);

        assertEq(mockVault.totalReceived(), vaultBalanceBefore + sweepable);
    }

    function testIntegration_EstimateFeePlusDeposit() public {
        uint256 estimated = callback.estimateFee("eip155", "1", 50000);
        assertEq(estimated, PROTOCOL_FEE + 50000 * tx.gasprice);
    }
}
