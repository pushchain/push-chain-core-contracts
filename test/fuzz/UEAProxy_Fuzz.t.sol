// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../src/UEA/UEAProxy.sol";
import {UEAErrors} from "../../src/libraries/Errors.sol";

/// @dev Minimal mock to verify delegatecall forwarding.
contract MockImplementation {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}

contract UEAProxy_Fuzz is Test {
    // =========================================================================
    // 6.1 Initialization Properties
    // =========================================================================

    function testFuzz_initializeUEA_setsImplementation(address logic) public {
        // Skip zero address — that's tested separately
        vm.assume(logic != address(0));
        // Skip precompiles
        vm.assume(logic > address(0x10));

        UEAProxy proxy = new UEAProxy();
        proxy.initializeUEA(logic);

        assertEq(proxy.getImplementation(), logic);
    }

    function testFuzz_initializeUEA_secondCall_reverts(address logic1, address logic2) public {
        vm.assume(logic1 != address(0));
        vm.assume(logic1 > address(0x10));

        UEAProxy proxy = new UEAProxy();
        proxy.initializeUEA(logic1);

        // Second call must revert regardless of logic2 value
        vm.expectRevert();
        proxy.initializeUEA(logic2);
    }

    function testFuzz_initializeUEA_zeroAddress_behavior(bytes calldata) public {
        // initializeUEA(address(0)) stores address(0) in UEA_LOGIC_SLOT.
        // A subsequent delegatecall then reverts because _implementation() checks for zero.
        UEAProxy proxy = new UEAProxy();
        proxy.initializeUEA(address(0));

        assertEq(proxy.getImplementation(), address(0));

        // Any external call to the proxy should revert (no implementation set)
        (bool ok,) = address(proxy).call(abi.encodeWithSignature("getValue()"));
        assertFalse(ok);
    }

    // =========================================================================
    // 6.2 Delegation Properties
    // =========================================================================

    function testFuzz_delegatecall_forwardsToImplementation(uint256 inputValue) public {
        // Deploy a real implementation
        MockImplementation impl = new MockImplementation();

        // Fresh proxy, initialize with implementation
        UEAProxy proxy = new UEAProxy();
        proxy.initializeUEA(address(impl));

        // Call setValue on the proxy — should delegatecall to impl
        (bool ok,) = address(proxy).call(abi.encodeWithSignature("setValue(uint256)", inputValue));
        assertTrue(ok);

        // Read back via proxy — storage lives in proxy
        (bool ok2, bytes memory result) = address(proxy).call(abi.encodeWithSignature("getValue()"));
        assertTrue(ok2);
        uint256 returnedValue = abi.decode(result, (uint256));
        assertEq(returnedValue, inputValue);

        // The implementation's own storage must be unchanged (delegatecall writes to proxy storage)
        assertEq(impl.value(), 0);
    }
}
