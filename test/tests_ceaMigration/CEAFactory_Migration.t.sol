// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/cea/CEA.sol";
import "../../src/cea/CEAFactory.sol";
import {ICEAFactory} from "../../src/interfaces/ICEAFactory.sol";
import {CEAErrors} from "../../src/libraries/Errors.sol";
import {CEAProxy} from "../../src/cea/CEAProxy.sol";
import "../../src/cea/CEAMigration.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title CEAFactory_MigrationTest
 * @notice Tests for CEAFactory migration contract management
 */
contract CEAFactory_MigrationTest is Test {
    CEA public ceaImplementation;
    CEAProxy public ceaProxyImplementation;
    CEAFactory public factory;
    CEAMigration public migration;

    address public owner;
    address public vault;
    address public universalGateway;
    address public nonOwner;

    function setUp() public {
        owner = address(this);
        vault = makeAddr("vault");
        universalGateway = makeAddr("universalGateway");
        nonOwner = makeAddr("nonOwner");

        // Deploy implementations
        ceaImplementation = new CEA();
        ceaProxyImplementation = new CEAProxy();

        // Deploy factory
        CEAFactory factoryImpl = new CEAFactory();
        bytes memory initData = abi.encodeWithSelector(
            CEAFactory.initialize.selector,
            owner,
            makeAddr("pauser"),
            vault,
            address(ceaProxyImplementation),
            address(ceaImplementation),
            universalGateway
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = CEAFactory(address(proxy));

        // Deploy migration contract
        CEA ceaV2 = new CEA();
        migration = new CEAMigration(address(ceaV2));
    }

    // =========================================================================
    // setCEAMigrationContract Tests
    // =========================================================================

    function test_setCEAMigrationContract_Success() public {
        // Initially should be zero
        assertEq(factory.CEA_MIGRATION_CONTRACT(), address(0), "Migration contract should be zero initially");

        // Set migration contract
        factory.setCEAMigrationContract(address(migration));

        // Verify set correctly
        assertEq(factory.CEA_MIGRATION_CONTRACT(), address(migration), "Migration contract should be set");
    }

    function test_setCEAMigrationContract_ZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(CEAErrors.ZeroAddress.selector));
        factory.setCEAMigrationContract(address(0));
    }

    function test_setCEAMigrationContract_NonOwner() public {
        vm.prank(nonOwner);
        vm.expectRevert(); // OwnableUnauthorizedAccount
        factory.setCEAMigrationContract(address(migration));
    }

    function test_setCEAMigrationContract_Event() public {
        // Expect CEAMigrationContractUpdated event
        vm.expectEmit(true, true, false, false);
        emit ICEAFactory.CEAMigrationContractUpdated(address(0), address(migration));

        factory.setCEAMigrationContract(address(migration));
    }

    function test_setCEAMigrationContract_UpdateExisting() public {
        // Set initial migration contract
        factory.setCEAMigrationContract(address(migration));

        // Deploy new migration contract
        CEA ceaV3 = new CEA();
        CEAMigration migration2 = new CEAMigration(address(ceaV3));

        // Expect event with old and new addresses
        vm.expectEmit(true, true, false, false);
        emit ICEAFactory.CEAMigrationContractUpdated(address(migration), address(migration2));

        // Update migration contract
        factory.setCEAMigrationContract(address(migration2));

        // Verify updated
        assertEq(factory.CEA_MIGRATION_CONTRACT(), address(migration2), "Migration contract should be updated");
    }

    // =========================================================================
    // deployCEA Integration with Factory Reference
    // =========================================================================

    function test_deployCEA_PassesFactoryAddress() public {
        address ueaOnPush = makeAddr("ueaOnPush");

        // Deploy CEA
        vm.prank(vault);
        address ceaAddress = factory.deployCEA(ueaOnPush);

        // Cast to CEA and verify factory is set
        CEA cea = CEA(payable(ceaAddress));
        assertEq(address(cea.factory()), address(factory), "Factory reference should be set in CEA");
    }

    function test_deployCEA_FactoryCanFetchMigrationContract() public {
        address ueaOnPush = makeAddr("ueaOnPush");

        // Set migration contract in factory
        factory.setCEAMigrationContract(address(migration));

        // Deploy CEA
        vm.prank(vault);
        address ceaAddress = factory.deployCEA(ueaOnPush);

        // Cast to CEA
        CEA cea = CEA(payable(ceaAddress));

        // Verify CEA can fetch migration contract from factory
        address fetchedMigration = cea.factory().CEA_MIGRATION_CONTRACT();
        assertEq(fetchedMigration, address(migration), "CEA should be able to fetch migration contract from factory");
    }
}
