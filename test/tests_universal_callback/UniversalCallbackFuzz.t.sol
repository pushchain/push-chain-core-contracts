// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {UniversalCallback} from "../../src/UniversalCallback.sol";
import {CrossLendMock} from "../mocks/CrossLendMock.sol";
import {MockUniversalCore} from "../mocks/MockUniversalCore.sol";
import {MockVaultPC} from "../mocks/MockVaultPC.sol";
import {ReadSpec, MIN_CONFIRMATIONS_FLOOR} from "../../src/libraries/ReadTypes.sol";
import {UniversalCallbackErrors} from "../../src/libraries/Errors.sol";
import {UniversalAccountId} from "../../src/libraries/Types.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {UniversalCallback} from "../../src/UniversalCallback.sol";

contract UniversalCallbackFuzzTest is Test {
    UniversalCallback callback;
    MockUniversalCore mockCore;
    MockVaultPC mockVault;
    CrossLendMock crossLend;

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
        callback.grantRole(callback.UVCALLBACK_ADMIN_ROLE(), defaultAdmin);
        vm.stopPrank();

        mockCore.setChainHeight("eip155", 1000);

        crossLend = new CrossLendMock(address(callback));
    }

    function testFuzz_RequestWithValidFees(uint256 feeAmount, uint256 readBaseFee) public {
        feeAmount = bound(feeAmount, 0.01 ether, 100 ether);
        readBaseFee = bound(readBaseFee, 0, feeAmount);

        mockCore.setReadBaseFee("eip155", "1", readBaseFee);

        vm.deal(address(crossLend), feeAmount);
        vm.prank(address(crossLend));
        crossLend.requestSync{value: feeAmount}(50000);

        assertGt(crossLend.lastRequestId(), 0);
    }

    function testFuzz_SupportsAnyCallbackGasLimit(uint64 callbackGasLimit) public {
        if (callbackGasLimit == 0 || callbackGasLimit > 500_000) return;

        ReadSpec memory spec = ReadSpec({
            account: UniversalAccountId({
                chainNamespace: "eip155",
                chainId: "1",
                owner: abi.encode(user)
            }),
            query: abi.encode("fuzzQuery"),
            minConfirmations: 10,
            blockNumber: 100,
            expiryPushChainHeight: uint64(block.number + 1000),
            maxFee: 10 ether
        });

        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            spec, bytes4(keccak256("onResponse(uint256,bytes)")), callbackGasLimit
        );

        assertGt(requestId, 0);
    }

    function testFuzz_MultipleUpdatesToDomain(
        string memory chainNamespace,
        string memory chainId
    ) public {
        vm.assume(bytes(chainNamespace).length > 0);
        vm.assume(bytes(chainId).length > 0);

        vm.prank(uvAdmin);
        callback.updateBlockedDomain(chainNamespace, chainId, true);
        assertTrue(callback.isDomainBlocked(chainNamespace, chainId));

        vm.prank(uvAdmin);
        callback.updateBlockedDomain(chainNamespace, chainId, false);
        assertFalse(callback.isDomainBlocked(chainNamespace, chainId));

        vm.prank(uvAdmin);
        callback.updateBlockedDomain(chainNamespace, chainId, true);
        assertTrue(callback.isDomainBlocked(chainNamespace, chainId));
    }

    function testFuzz_RequestThenFulfillReturnsResult(bytes memory resultData) public {
        vm.assume(resultData.length <= 4096);

        vm.deal(user, 10 ether);
        vm.prank(user);

        ReadSpec memory spec = ReadSpec({
            account: UniversalAccountId({
                chainNamespace: "eip155",
                chainId: "1",
                owner: abi.encode(user)
            }),
            query: abi.encode("fuzzQuery"),
            minConfirmations: 10,
            blockNumber: 100,
            expiryPushChainHeight: uint64(block.number + 1000),
            maxFee: 10 ether
        });

        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            spec, bytes4(keccak256("onResponse(uint256,bytes)")), 50000
        );

        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, resultData, 500, bytes32(uint256(0x123)));

        assertTrue(callback.isFulfilled(requestId));
    }
}
