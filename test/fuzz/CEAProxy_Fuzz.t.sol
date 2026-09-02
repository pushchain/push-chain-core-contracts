// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";

import {CEAProxy} from "../../src/cea/CEAProxy.sol";
import {CEA} from "../../src/cea/CEA.sol";
import {CEAErrors} from "../../src/libraries/Errors.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

contract CEAProxy_FuzzTest is Test {
    using Clones for address;

    /// @dev The deployed template, locked by its constructor (F-2026-18955).
    address internal template;

    /// @dev Incremented per clone so each gets a unique CREATE2 salt.
    uint256 internal saltNonce;

    function setUp() public {
        template = address(new CEAProxy());
    }

    /// @dev Mirrors CEAFactory.deployCEA: proxies are EIP-1167 clones of the template.
    ///      Clones do not run constructors, so they are initializable exactly once.
    function _newProxy() internal returns (CEAProxy) {
        return CEAProxy(payable(template.cloneDeterministic(bytes32(++saltNonce))));
    }

    // =========================================================================
    // 10.1 Initialization Properties
    // =========================================================================

    /// @dev After initializeCEAProxy(logic), getImplementation() == logic.
    function testFuzz_initializeCEAProxy_setsImplementation(address logic) public {
        vm.assume(logic != address(0));
        vm.assume(logic > address(0x10));

        CEAProxy proxy = _newProxy();
        proxy.initializeCEAProxy(logic);

        assertEq(proxy.getImplementation(), logic);
    }

    /// @dev Second call to initializeCEAProxy always reverts (OZ Initializable).
    function testFuzz_initializeCEAProxy_secondCall_reverts(address logic1, address logic2) public {
        vm.assume(logic1 != address(0));
        vm.assume(logic1 > address(0x10));
        vm.assume(logic2 != address(0));
        vm.assume(logic2 > address(0x10));

        CEAProxy proxy = _newProxy();
        proxy.initializeCEAProxy(logic1);

        // OZ Initializable reverts with InvalidInitialization on second call
        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        proxy.initializeCEAProxy(logic2);
    }

    /// @dev initializeCEAProxy(address(0)) reverts with CEAErrors.InvalidCall.
    function testFuzz_initializeCEAProxy_zeroAddress_reverts() public {
        CEAProxy proxy = _newProxy();

        vm.expectRevert(CEAErrors.InvalidCall.selector);
        proxy.initializeCEAProxy(address(0));
    }

    /// @dev F-2026-18955: the template itself must never be initializable, so it can
    ///      never be claimed by an unprivileged caller. Only its clones initialize.
    function testFuzz_templateIsLocked(address logic) public {
        vm.assume(logic != address(0));
        vm.assume(logic > address(0x10));

        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        CEAProxy(payable(template)).initializeCEAProxy(logic);
    }
}
