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
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";

contract UniversalReadClientTest is Test {
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
        mockCore.setReadBaseFee("eip155", "1", 0.01 ether);

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

        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, resultData, 500, bytes32(uint256(0x123)));

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

        vm.prank(ueModule);
        callback.fulfillExternalCallback(firstId, data1, 100, bytes32(uint256(0x1)));

        assertEq(crossLend.lastResultData(), data1);
    }

    function test_OnReadResult_RevertingClient_EmitsCallbackFailed() public {
        vm.deal(address(revertingClient), 10 ether);
        vm.prank(address(revertingClient));
        revertingClient.requestSync{value: 1 ether}(1000);

        uint256 requestId = revertingClient.lastRequestId();

        vm.prank(ueModule);
        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.CallbackFailed(requestId, abi.encodeWithSelector(RevertingReadClient.IntentionalRevert.selector));
        callback.fulfillExternalCallback(requestId, "", 0, bytes32(0));
    }

    function test_GetLocalContext_ReturnsStoredState() public {
        vm.deal(address(crossLend), 10 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 1 ether}(1000);

        uint256 requestId = crossLend.lastRequestId();
        bytes memory ctx = crossLend.getLocalContext(requestId);
        assertGt(ctx.length, 0);
    }

    function test_GetLocalContext_ClearedAfterCallback() public {
        vm.deal(address(crossLend), 10 ether);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: 1 ether}(1000);

        uint256 requestId = crossLend.lastRequestId();

        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, "", 0, bytes32(0));

        bytes memory ctx = crossLend.getLocalContext(requestId);
        assertEq(ctx.length, 0);
    }
}
