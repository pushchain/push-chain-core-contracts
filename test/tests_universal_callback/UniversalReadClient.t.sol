// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {UniversalCallback} from "../../src/UniversalCallback.sol";
import {CrossLendMock} from "../mocks/CrossLendMock.sol";
import {RevertingReadClient} from "../mocks/RevertingReadClient.sol";
import {NoReceiveReadClient} from "../mocks/NoReceiveReadClient.sol";
import {MockUniversalCore} from "../mocks/MockUniversalCore.sol";
import {MockVaultPC} from "../mocks/MockVaultPC.sol";
import {UniversalCallbackErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";

contract UniversalReadClientTest is Test {
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

        mockCore.setReadBaseFee("eip155", "1", 0.01 ether);
        mockCore.setChainHeight("eip155:1", 1000);

        crossLend = new CrossLendMock(address(callback));
        revertingClient = new RevertingReadClient(address(callback));
    }

    function test_Constructor_SetsCallback() public {
        assertEq(address(crossLend.universalCallback()), address(callback));
    }

    function test_RequestRead_CreatesRequest() public {
        vm.deal(address(crossLend), 10 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 1 ether}(1000);

        assertGt(crossLend.lastRequestId(), 0);
    }

    function test_OnReadResult_StoredAfterFulfill() public {
        vm.deal(address(crossLend), 10 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 1 ether}(1000);

        uint256 requestId = crossLend.lastRequestId();
        bytes memory resultData = abi.encode("ethPrice");

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, resultData);

        assertEq(crossLend.lastResultData(), resultData);
        assertTrue(crossLend.lastLocalState().length > 0);
    }

    function test_OnReadResult_MultipleRequests() public {
        vm.deal(address(crossLend), 10 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 1 ether}(100);

        vm.deal(address(crossLend), 10 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 1 ether}(200);

        uint256 firstId = crossLend.lastRequestId();
        bytes memory data1 = abi.encode("data1");

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(firstId, data1);

        assertEq(crossLend.lastResultData(), data1);
    }

    function test_OnReadResult_RevertingClient_EmitsCallbackFailed() public {
        vm.deal(address(revertingClient), 10 ether);
        vm.prank(address(revertingClient));
        revertingClient.requestSync{value: 1 ether}(1000);

        uint256 requestId = revertingClient.lastRequestId();

        vm.prank(ucallbackModule);
        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.CallbackFailed(requestId, abi.encodeWithSelector(RevertingReadClient.IntentionalRevert.selector));
        callback.fulfillExternalCallback(requestId, "");
    }

    function test_GetLocalContext_ReturnsStoredState() public {
        vm.deal(address(crossLend), 10 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 1 ether}(1000);

        uint256 requestId = crossLend.lastRequestId();
        bytes memory ctx = crossLend.getLocalContext(requestId);
        assertGt(ctx.length, 0);
    }

    function test_Refund_PushedToClientOnExpiry() public {
        vm.deal(address(crossLend), 1 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 1 ether}(1000);

        uint256 requestId = crossLend.lastRequestId();
        vm.roll(block.number + 1000);
        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);

        // No claim step: the budget arrives via the client's receive().
        assertEq(address(crossLend).balance, 1 ether - 0.01 ether);
        assertEq(callback.totalEscrowed(), 0);
    }

    /// @dev A client without `receive()` rejects the push. Settlement must still
    ///      complete -- reverting would wedge the request and lock its escrow.
    function test_Refund_ClientWithoutReceive_ForfeitsButSettles() public {
        NoReceiveReadClient noReceive = new NoReceiveReadClient(address(callback));

        vm.deal(address(noReceive), 1 ether);
        vm.prank(address(noReceive));
        noReceive.requestSync{value: 1 ether}(1000);

        uint256 requestId = noReceive.lastRequestId();
        uint256 budget = 1 ether - 0.01 ether;

        vm.roll(block.number + 1000);

        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.RefundFailed(requestId, address(noReceive), budget);

        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);

        // Escrow released and the request settled, even though the push failed.
        assertEq(callback.totalEscrowed(), 0);
        assertEq(address(noReceive).balance, 0, "recipient forfeited its refund");
        // The stranded PC is now unattributed and recoverable by admin.
        assertEq(address(callback).balance, budget);
    }

    function test_GetLocalContext_ClearedAfterCallback() public {
        vm.deal(address(crossLend), 10 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 1 ether}(1000);

        uint256 requestId = crossLend.lastRequestId();

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, "");

        bytes memory ctx = crossLend.getLocalContext(requestId);
        assertEq(ctx.length, 0);
    }
}
