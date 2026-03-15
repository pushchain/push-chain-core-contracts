// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";

import {CEAProxy} from "../../src/cea/CEAProxy.sol";
import {CEA} from "../../src/cea/CEA.sol";
import {CEAErrors} from "../../src/libraries/Errors.sol";

contract CEAProxy_FuzzTest is Test {
    // =========================================================================
    // 10.1 Initialization Properties
    // =========================================================================

    /// @dev After initializeCEAProxy(logic), getImplementation() == logic.
    function testFuzz_initializeCEAProxy_setsImplementation(address logic) public {
        vm.assume(logic != address(0));
        vm.assume(logic > address(0x10));

        CEAProxy proxy = new CEAProxy();
        proxy.initializeCEAProxy(logic);

        assertEq(proxy.getImplementation(), logic);
    }

    /// @dev Second call to initializeCEAProxy always reverts (OZ Initializable).
    function testFuzz_initializeCEAProxy_secondCall_reverts(
        address logic1,
        address logic2
    ) public {
        vm.assume(logic1 != address(0));
        vm.assume(logic1 > address(0x10));
        vm.assume(logic2 != address(0));
        vm.assume(logic2 > address(0x10));

        CEAProxy proxy = new CEAProxy();
        proxy.initializeCEAProxy(logic1);

        // OZ Initializable reverts with InvalidInitialization on second call
        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        proxy.initializeCEAProxy(logic2);
    }

    /// @dev initializeCEAProxy(address(0)) reverts with CEAErrors.InvalidCall.
    function testFuzz_initializeCEAProxy_zeroAddress_reverts() public {
        CEAProxy proxy = new CEAProxy();

        vm.expectRevert(CEAErrors.InvalidCall.selector);
        proxy.initializeCEAProxy(address(0));
    }
}
