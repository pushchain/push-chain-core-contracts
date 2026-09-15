// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {UniversalCallback} from "../../src/UniversalCallback.sol";
import {UniversalReadRegistry} from "../../src/UniversalReadRegistry.sol";
import {ReadSpec, RequestStatus} from "../../src/libraries/ReadTypes.sol";
import {UniversalAccountId} from "../../src/libraries/Types.sol";
import {UniversalCallbackErrors} from "../../src/libraries/Errors.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {MockUniversalCore} from "../mocks/MockUniversalCore.sol";
import {MockVaultPC} from "../mocks/MockVaultPC.sol";

contract UniversalReadRegistryTest is Test {
    UniversalCallback callback;
    UniversalReadRegistry registry;
    MockUniversalCore mockCore;
    MockVaultPC mockVault;

    address defaultAdmin = address(0xAAAA);
    address ucallbackModule = 0x07a0258D367A4A4cd9d6E4b7eEE8E7eF491CC519;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    ReadSpec defaultSpec;
    uint256 constant DEPOSIT = 1 ether;
    uint256 constant PROTOCOL_FEE = 0.01 ether;

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
        callback.grantRole(callback.UVCALLBACK_ADMIN_ROLE(), defaultAdmin);
        vm.stopPrank();

        mockCore.setReadBaseFee("eip155", "1", PROTOCOL_FEE);
        mockCore.setChainHeight("eip155:1", 1000);

        UniversalReadRegistry registryImpl = new UniversalReadRegistry(address(callback));
        ERC1967Proxy registryProxy = new ERC1967Proxy(
            address(registryImpl),
            abi.encodeWithSelector(UniversalReadRegistry.initialize.selector)
        );
        registry = UniversalReadRegistry(payable(address(registryProxy)));

        defaultSpec = ReadSpec({
            account: UniversalAccountId({
                chainNamespace: "eip155",
                chainId: "1",
                owner: abi.encode(address(0xdead))
            }),
            query: abi.encode("balanceOf"),
            minConfirmations: 10,
            blockNumber: 100,
            expiryPushChainHeight: uint64(block.number + 1000),
            maxFee: 10 ether,
            revertRecipient: address(0xdead)
        });
    }

    function _read(address reader) internal returns (uint256 requestId) {
        vm.deal(reader, DEPOSIT);
        vm.prank(reader);
        requestId = registry.read{value: DEPOSIT}(defaultSpec, bytes32(0), 500_000);
    }

    function _readWithQueryKey(address reader, bytes32 qk) internal returns (uint256 requestId) {
        vm.deal(reader, DEPOSIT);
        vm.prank(reader);
        requestId = registry.read{value: DEPOSIT}(defaultSpec, qk, 500_000);
    }

    function test_Read_CreatesRequest() public {
        uint256 requestId = _read(alice);

        assertGt(requestId, 0);
        assertEq(uint8(callback.statusOf(requestId)), uint8(RequestStatus.PENDING));
    }

    function test_Read_StoresReader() public {
        uint256 requestId = _read(alice);

        assertEq(registry.readerOf(requestId), alice);
    }

    function test_Read_StoresQueryKey() public {
        uint256 requestId = _read(alice);

        bytes32 expectedQk = keccak256(abi.encode(defaultSpec.account, defaultSpec.query));
        assertEq(registry.queryKeyOf(requestId), expectedQk);
    }

    function test_Read_StoresRequestOrder() public {
        uint256 id1 = _read(alice);
        uint256 id2 = _read(bob);

        assertEq(registry.requestOrderOf(id1), 1);
        assertEq(registry.requestOrderOf(id2), 2);
    }

    function test_Read_RespectsUserRevertRecipient() public {
        uint256 requestId = _read(alice);

        address revertRecipient = callback.getPendingRead(requestId).revertRecipient;
        assertEq(revertRecipient, address(0xdead));
    }

    function test_Read_DefaultsRevertRecipientToSender() public {
        ReadSpec memory spec = defaultSpec;
        spec.revertRecipient = address(0);

        vm.deal(alice, DEPOSIT);
        vm.prank(alice);
        uint256 requestId = registry.read{value: DEPOSIT}(spec, bytes32(0), 500_000);

        address revertRecipient = callback.getPendingRead(requestId).revertRecipient;
        assertEq(revertRecipient, alice);
    }

    function test_Read_CallbackTargetIsRegistry() public {
        uint256 requestId = _read(alice);

        address target = callback.getPendingRead(requestId).callbackTarget;
        assertEq(target, address(registry));
    }

    function test_Read_EmitsRegistryEvent() public {
        bytes32 expectedQk = keccak256(abi.encode(defaultSpec.account, defaultSpec.query));

        vm.deal(alice, DEPOSIT);
        vm.prank(alice);
        vm.expectEmit(false, true, true, true);
        emit UniversalReadRegistry.RegistryReadRequested(0, alice, expectedQk);
        registry.read{value: DEPOSIT}(defaultSpec, bytes32(0), 500_000);
    }

    function test_Read_CustomQueryKey() public {
        bytes32 customQk = keccak256("myLogicalQuery");
        uint256 requestId = _readWithQueryKey(alice, customQk);

        assertEq(registry.queryKeyOf(requestId), customQk);
    }

    function test_Read_CustomQueryKey_LatestResultGroupsCorrectly() public {
        bytes32 logicalQk = keccak256("balanceOf(0xdead)");

        // Two reads with different spec.query but same logical key
        ReadSpec memory spec1 = defaultSpec;
        spec1.query = abi.encode("balanceOf", uint256(100));
        ReadSpec memory spec2 = defaultSpec;
        spec2.query = abi.encode("balanceOf", uint256(200));

        vm.deal(alice, DEPOSIT);
        vm.prank(alice);
        uint256 id1 = registry.read{value: DEPOSIT}(spec1, logicalQk, 500_000);

        vm.deal(alice, DEPOSIT);
        vm.prank(alice);
        uint256 id2 = registry.read{value: DEPOSIT}(spec2, logicalQk, 500_000);

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(id1, "result1");

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(id2, "result2");

        UniversalReadRegistry.StoredResult memory r = registry.latestResult(alice, logicalQk);
        assertEq(r.requestId, id2);
        assertEq(r.resultData, bytes("result2"));
    }

    function test_Callback_StoresResultByRequestId() public {
        uint256 requestId = _read(alice);
        bytes memory resultData = abi.encode("ethPrice", uint256(3000));

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, resultData);

        UniversalReadRegistry.StoredResult memory r = registry.resultByRequestId(requestId);
        assertEq(r.requestId, requestId);
        assertEq(r.resultData, resultData);
        assertEq(r.updatedAtBlock, uint64(block.number));
    }

    function test_Callback_StoresLatestResult() public {
        uint256 requestId = _read(alice);
        bytes memory resultData = abi.encode("ethPrice");
        bytes32 qk = registry.queryKeyOf(requestId);

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, resultData);

        UniversalReadRegistry.StoredResult memory r = registry.latestResult(alice, qk);
        assertEq(r.requestId, requestId);
        assertEq(r.resultData, resultData);
    }

    function test_Callback_EmitsStoredEvent() public {
        uint256 requestId = _read(alice);
        bytes32 qk = registry.queryKeyOf(requestId);

        vm.prank(ucallbackModule);
        vm.expectEmit(true, true, true, true);
        emit UniversalReadRegistry.RegistryReadStored(requestId, alice, qk);
        callback.fulfillExternalCallback(requestId, "data");
    }

    function test_HasResult_FalseBeforeCallback() public {
        uint256 requestId = _read(alice);
        assertFalse(registry.hasResult(requestId));
    }

    function test_HasResult_TrueAfterCallback() public {
        uint256 requestId = _read(alice);

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, "data");

        assertTrue(registry.hasResult(requestId));
    }

    function test_LatestResult_OverwritesOnRepeat() public {
        uint256 id1 = _read(alice);
        bytes32 qk = registry.queryKeyOf(id1);

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(id1, "first");

        uint256 id2 = _read(alice);

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(id2, "second");

        UniversalReadRegistry.StoredResult memory r = registry.latestResult(alice, qk);
        assertEq(r.requestId, id2);
        assertEq(r.resultData, bytes("second"));
    }

    function test_LatestResult_NotOverwrittenByOlderRequest() public {
        uint256 id1 = _read(alice);
        uint256 id2 = _read(alice);
        bytes32 qk = registry.queryKeyOf(id1);

        // Fulfill newer request first
        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(id2, "newer");

        // Fulfill older request second — latestResult must stay on id2
        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(id1, "older");

        UniversalReadRegistry.StoredResult memory r = registry.latestResult(alice, qk);
        assertEq(r.requestId, id2);
        assertEq(r.resultData, bytes("newer"));

        // Both results are still individually accessible
        assertEq(registry.resultByRequestId(id1).resultData, bytes("older"));
        assertEq(registry.resultByRequestId(id2).resultData, bytes("newer"));
    }

    function test_TwoReaders_IndependentResults() public {
        uint256 aliceId = _read(alice);
        uint256 bobId = _read(bob);

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(aliceId, "aliceData");

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(bobId, "bobData");

        bytes32 qk = registry.queryKeyOf(aliceId);

        UniversalReadRegistry.StoredResult memory rAlice = registry.latestResult(alice, qk);
        UniversalReadRegistry.StoredResult memory rBob = registry.latestResult(bob, qk);

        assertEq(rAlice.resultData, bytes("aliceData"));
        assertEq(rBob.resultData, bytes("bobData"));
    }

    function test_RefundGoesToRecipient_NotRegistry() public {
        address recipient = defaultSpec.revertRecipient;
        uint256 recipientBefore = recipient.balance;

        uint256 requestId = _read(alice);

        vm.roll(block.number + 1000);
        vm.prank(ucallbackModule);
        callback.expireExternalRead(requestId);

        assertGt(recipient.balance, recipientBefore);
        assertEq(address(registry).balance, 0);
    }

    function test_RegistryRejectsRawEth() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = address(registry).call{value: 1 ether}("");
        assertFalse(ok);
    }

    function test_Callback_256ByteResult_SucceedsWith500kGas() public {
        bytes memory payload = new bytes(256);
        for (uint256 i; i < 256; i++) {
            payload[i] = bytes1(uint8(i % 256));
        }

        vm.deal(alice, DEPOSIT);
        vm.prank(alice);
        uint256 requestId = registry.read{value: DEPOSIT}(defaultSpec, bytes32(0), 500_000);

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, payload);

        assertTrue(registry.hasResult(requestId));
        assertEq(registry.resultByRequestId(requestId).resultData, payload);
    }
}
