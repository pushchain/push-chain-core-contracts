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
        callback.grantRole(callback.UVCALLBACK_ADMIN_ROLE(), defaultAdmin);
        vm.stopPrank();

        mockCore.setChainHeight("eip155:1", 1000);

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
            maxFee: 10 ether,
            revertRecipient: user
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

    /// @dev The core accounting guarantee: every wei deposited ends up at the
    ///      vault, burned, or owed back -- on every path, for any gas report.
    function testFuzz_SettlementConservesValue(
        uint256 deposit,
        uint256 baseFee,
        uint256 gasBurned,
        bool expire
    ) public {
        deposit = bound(deposit, 0.01 ether, 100 ether);
        baseFee = bound(baseFee, 0, deposit);
        mockCore.setReadBaseFee("eip155", "1", baseFee);

        ReadSpec memory spec = ReadSpec({
            account: UniversalAccountId({
                chainNamespace: "eip155",
                chainId: "1",
                owner: abi.encode(user)
            }),
            query: abi.encode("q"),
            minConfirmations: 10,
            blockNumber: 100,
            expiryPushChainHeight: uint64(block.number + 1000),
            maxFee: 1000 ether,
            revertRecipient: user
        });

        vm.deal(user, deposit);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: deposit}(
            spec, bytes4(keccak256("onResponse(uint256,bytes)")), 50000
        );

        uint256 budget = deposit - baseFee;

        // The fee left at request time; only the budget is escrowed.
        assertEq(callback.totalEscrowed(), budget);
        assertEq(address(mockVault).balance, baseFee, "fee paid at request time");
        assertGe(
            address(callback).balance,
            callback.totalEscrowed(),
            "user funds must be backed while in flight"
        );

        uint256 burned;
        if (expire) {
            vm.roll(spec.expiryPushChainHeight);
            vm.prank(ucallbackModule);
            callback.expireExternalRead(requestId);
        } else {
            vm.prank(ucallbackModule);
            callback.fulfillExternalCallback(requestId, "");

            // Fulfillment settles nothing.
            assertEq(callback.totalEscrowed(), budget, "fulfill released escrow");

            vm.prank(ucallbackModule);
            burned = callback.reportCallbackGas(requestId, gasBurned);
            assertLe(burned, budget, "burn must never exceed the budget");

            // Simulate the module's burn.
            vm.deal(address(callback), address(callback).balance - burned);
        }

        uint256 owed = user.balance;

        assertEq(address(mockVault).balance + burned + owed, deposit, "value must be conserved");
        assertEq(address(mockVault).balance, baseFee, "protocol fee retained on every path");
        assertEq(callback.totalEscrowed(), 0, "escrow released on settlement");
        assertGe(
            address(callback).balance,
            callback.totalEscrowed(),
            "user funds must remain backed after settlement"
        );
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
            maxFee: 10 ether,
            revertRecipient: user
        });

        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            spec, bytes4(keccak256("onResponse(uint256,bytes)")), 50000
        );

        vm.prank(ucallbackModule);
        callback.fulfillExternalCallback(requestId, resultData);

        assertTrue(callback.isFulfilled(requestId));
    }
}
