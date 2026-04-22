// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";

import {CEA} from "../../src/cea/CEA.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";
import {CEAProxy} from "../../src/cea/CEAProxy.sol";
import {ICEA} from "../../src/interfaces/ICEA.sol";
import {CEAErrors} from "../../src/libraries/Errors.sol";
import {MockUniversalGateway} from "../mocks/MockUniversalGateway.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

contract CEAFactory_FuzzTest is Test {
    CEA public ceaImplementation;
    CEAProxy public ceaProxyImplementation;
    CEAFactory public factory;
    MockUniversalGateway public mockUniversalGateway;

    address public owner;
    address public vault;

    function setUp() public {
        owner = address(this);
        vault = makeAddr("vault");
        mockUniversalGateway = new MockUniversalGateway();
        ceaImplementation = new CEA();
        ceaProxyImplementation = new CEAProxy();

        CEAFactory factoryImpl = new CEAFactory();
        bytes memory initData = abi.encodeWithSelector(
            CEAFactory.initialize.selector,
            owner,
            makeAddr("pauser"),
            vault,
            address(ceaProxyImplementation),
            address(ceaImplementation),
            address(mockUniversalGateway)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = CEAFactory(address(proxy));
    }

    // =========================================================================
    // 9.1 Deterministic Address Properties
    // =========================================================================

    /// @dev computeCEA called twice with same input returns same address.
    function testFuzz_computeCEA_deterministic(address pushAccount) public view {
        vm.assume(pushAccount != address(0));
        vm.assume(pushAccount > address(0x10));

        address addr1 = factory.computeCEA(pushAccount);
        address addr2 = factory.computeCEA(pushAccount);

        assertEq(addr1, addr2);
    }

    /// @dev computeCEA matches the address from deployCEA.
    function testFuzz_computeCEA_matchesDeployCEA(address pushAccount) public {
        vm.assume(pushAccount != address(0));
        vm.assume(pushAccount > address(0x10));

        address predicted = factory.computeCEA(pushAccount);

        vm.prank(vault);
        address deployed = factory.deployCEA(pushAccount);

        assertEq(predicted, deployed);
    }

    /// @dev Different pushAccounts produce different CEA addresses.
    function testFuzz_differentPushAccounts_differentCEAs(address pushAccount1, address pushAccount2) public view {
        vm.assume(pushAccount1 != address(0));
        vm.assume(pushAccount2 != address(0));
        vm.assume(pushAccount1 > address(0x10));
        vm.assume(pushAccount2 > address(0x10));
        vm.assume(pushAccount1 != pushAccount2);

        address cea1 = factory.computeCEA(pushAccount1);
        address cea2 = factory.computeCEA(pushAccount2);

        assertTrue(cea1 != cea2);
    }

    // =========================================================================
    // 9.2 Deployment Properties
    // =========================================================================

    /// @dev After deployCEA, deployed address has code.
    function testFuzz_deployCEA_hasCode(address pushAccount) public {
        vm.assume(pushAccount != address(0));
        vm.assume(pushAccount > address(0x10));

        vm.prank(vault);
        address cea = factory.deployCEA(pushAccount);

        assertGt(cea.code.length, 0);
    }

    /// @dev Second deployCEA with same pushAccount reverts with CEAAlreadyDeployed.
    function testFuzz_deployCEA_doubleDeployReverts(address pushAccount) public {
        vm.assume(pushAccount != address(0));
        vm.assume(pushAccount > address(0x10));

        vm.prank(vault);
        factory.deployCEA(pushAccount);

        vm.expectRevert(CEAErrors.CEAAlreadyDeployed.selector);
        vm.prank(vault);
        factory.deployCEA(pushAccount);
    }

    /// @dev After deploy, bidirectional mappings are correct.
    function testFuzz_deployCEA_mappingBidirectional(address pushAccount) public {
        vm.assume(pushAccount != address(0));
        vm.assume(pushAccount > address(0x10));

        vm.prank(vault);
        address cea = factory.deployCEA(pushAccount);

        assertEq(factory.pushAccountToCEA(pushAccount), cea);
        assertEq(factory.ceaToPushAccount(cea), pushAccount);
    }

    /// @dev deployCEA(address(0)) reverts with ZeroAddress.
    function testFuzz_deployCEA_zeroAddress_reverts() public {
        vm.expectRevert(CEAErrors.ZeroAddress.selector);
        vm.prank(vault);
        factory.deployCEA(address(0));
    }

    // =========================================================================
    // 9.3 Lookup Properties
    // =========================================================================

    /// @dev After deploy, isCEA returns true for the deployed address.
    function testFuzz_isCEA_trueAfterDeploy(address pushAccount) public {
        vm.assume(pushAccount != address(0));
        vm.assume(pushAccount > address(0x10));

        vm.prank(vault);
        address cea = factory.deployCEA(pushAccount);

        assertTrue(factory.isCEA(cea));
    }

    /// @dev For non-deployed addresses, isCEA returns false.
    function testFuzz_isCEA_falseForRandom(address random) public view {
        vm.assume(random != address(0));
        assertFalse(factory.isCEA(random));
    }

    /// @dev After deploy, getCEAForPushAccount returns (cea, true).
    function testFuzz_getCEAForPushAccount_deployed(address pushAccount) public {
        vm.assume(pushAccount != address(0));
        vm.assume(pushAccount > address(0x10));

        vm.prank(vault);
        address deployed = factory.deployCEA(pushAccount);

        (address cea, bool isDeployed) = factory.getCEAForPushAccount(pushAccount);

        assertEq(cea, deployed);
        assertTrue(isDeployed);
    }

    /// @dev Before deploy, getCEAForPushAccount returns predicted address with false.
    function testFuzz_getCEAForPushAccount_notDeployed(address pushAccount) public view {
        vm.assume(pushAccount != address(0));
        vm.assume(pushAccount > address(0x10));

        address predicted = factory.computeCEA(pushAccount);
        (address cea, bool isDeployed) = factory.getCEAForPushAccount(pushAccount);

        assertEq(cea, predicted);
        assertFalse(isDeployed);
    }

    // =========================================================================
    // 9.4 Access Control Properties
    // =========================================================================

    /// @dev Non-vault callers cannot deploy CEAs.
    function testFuzz_deployCEA_nonVault_reverts(address caller, address pushAccount) public {
        vm.assume(caller != vault);
        vm.assume(caller != address(0));
        vm.assume(pushAccount != address(0));
        vm.assume(pushAccount > address(0x10));

        vm.expectRevert(CEAErrors.NotVault.selector);
        vm.prank(caller);
        factory.deployCEA(pushAccount);
    }

    /// @dev Non-owner callers cannot call setVault.
    function testFuzz_setVault_nonOwner_reverts(address caller, address newVault) public {
        vm.assume(caller != owner);
        vm.assume(caller != address(0));
        vm.assume(newVault != address(0));

        bytes32 adminRole = factory.DEFAULT_ADMIN_ROLE();
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, caller, adminRole)
        );
        vm.prank(caller);
        factory.updateVault(newVault);
    }

    /// @dev Non-owner callers cannot call setCEAImplementation.
    function testFuzz_setCEAImplementation_nonOwner_reverts(address caller, address newImpl) public {
        vm.assume(caller != owner);
        vm.assume(caller != address(0));
        vm.assume(newImpl != address(0));

        bytes32 adminRole = factory.DEFAULT_ADMIN_ROLE();
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, caller, adminRole)
        );
        vm.prank(caller);
        factory.setCEAImplementation(newImpl);
    }

    /// @dev Non-owner callers cannot call setCEAMigrationContract.
    function testFuzz_setCEAMigrationContract_nonOwner_reverts(address caller, address newMigration) public {
        vm.assume(caller != owner);
        vm.assume(caller != address(0));
        vm.assume(newMigration != address(0));

        bytes32 adminRole = factory.DEFAULT_ADMIN_ROLE();
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, caller, adminRole)
        );
        vm.prank(caller);
        factory.setCEAMigrationContract(newMigration);
    }

    // =========================================================================
    // 9.5 Setter Validation Properties
    // =========================================================================

    /// @dev setVault(address(0)) reverts with ZeroAddress.
    function testFuzz_setVault_zeroAddress_reverts() public {
        vm.expectRevert(CEAErrors.ZeroAddress.selector);
        factory.updateVault(address(0));
    }

    /// @dev setCEAProxyImplementation(address(0)) reverts with ZeroAddress.
    function testFuzz_setCEAProxyImplementation_zeroAddress_reverts() public {
        vm.expectRevert(CEAErrors.ZeroAddress.selector);
        factory.setCEAProxyImplementation(address(0));
    }

    /// @dev setCEAImplementation(address(0)) reverts with ZeroAddress.
    function testFuzz_setCEAImplementation_zeroAddress_reverts() public {
        vm.expectRevert(CEAErrors.ZeroAddress.selector);
        factory.setCEAImplementation(address(0));
    }

    /// @dev setUniversalGateway(address(0)) reverts with ZeroAddress.
    function testFuzz_setUniversalGateway_zeroAddress_reverts() public {
        vm.expectRevert(CEAErrors.ZeroAddress.selector);
        factory.updateUniversalGateway(address(0));
    }
}
