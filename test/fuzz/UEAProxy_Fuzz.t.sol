// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../src/UEA/UEAProxy.sol";
import {UEAErrors} from "../../src/libraries/Errors.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

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
    using Clones for address;

    /// @dev The deployed template, locked by its constructor (F-2026-18955).
    address internal template;

    /// @dev Incremented per clone so each gets a unique CREATE2 salt.
    uint256 internal saltNonce;

    function setUp() public {
        template = address(new UEAProxy());
    }

    /// @dev Mirrors UEAFactory.deployUEA: proxies are EIP-1167 clones of the template.
    ///      Clones do not run constructors, so they are initializable exactly once.
    function _newProxy() internal returns (UEAProxy) {
        return UEAProxy(payable(template.cloneDeterministic(bytes32(++saltNonce))));
    }

    // =========================================================================
    // 6.1 Initialization Properties
    // =========================================================================

    function testFuzz_initializeUEA_setsImplementation(address logic) public {
        // Skip zero address — that's tested separately
        vm.assume(logic != address(0));
        // Skip precompiles
        vm.assume(logic > address(0x10));

        UEAProxy proxy = _newProxy();
        proxy.initializeUEA(logic);

        assertEq(proxy.getImplementation(), logic);
    }

    function testFuzz_initializeUEA_secondCall_reverts(address logic1, address logic2) public {
        vm.assume(logic1 != address(0));
        vm.assume(logic1 > address(0x10));

        UEAProxy proxy = _newProxy();
        proxy.initializeUEA(logic1);

        // Second call must revert regardless of logic2 value
        vm.expectRevert();
        proxy.initializeUEA(logic2);
    }

    function testFuzz_initializeUEA_zeroAddress_reverts(bytes calldata) public {
        // initializeUEA(address(0)) now reverts with InvalidCall (matching CEAProxy)
        UEAProxy proxy = _newProxy();
        vm.expectRevert(UEAErrors.InvalidCall.selector);
        proxy.initializeUEA(address(0));
    }

    /// @dev F-2026-18955: the template itself must never be initializable, so it can
    ///      never be claimed by an unprivileged caller. Only its clones initialize.
    function testFuzz_templateIsLocked(address logic) public {
        vm.assume(logic != address(0));
        vm.assume(logic > address(0x10));

        vm.expectRevert(bytes4(keccak256("InvalidInitialization()")));
        UEAProxy(payable(template)).initializeUEA(logic);
    }

    // =========================================================================
    // 6.2 Delegation Properties
    // =========================================================================

    function testFuzz_delegatecall_forwardsToImplementation(uint256 inputValue) public {
        // Deploy a real implementation
        MockImplementation impl = new MockImplementation();

        // Fresh proxy, initialize with implementation
        UEAProxy proxy = _newProxy();
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
