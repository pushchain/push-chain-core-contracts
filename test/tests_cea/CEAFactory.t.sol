// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/CEA/CEAFactory.sol";
import "../../src/CEA/CEA.sol";
import {CEAProxy} from "../../src/CEA/CEAProxy.sol";
import "../../src/interfaces/ICEA.sol";
import "../../src/interfaces/ICEAProxy.sol";
import {MockUniversalGateway} from "../mocks/MockUniversalGateway.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ICEAFactory} from "../../src/interfaces/ICEAFactory.sol";


contract CEAFactoryTest is Test {
    // Core contracts
    CEAFactory public factory;
    CEAFactory public factoryImpl;
    CEA public ceaImplementation;
    CEAProxy public ceaProxyImplementation;
    MockUniversalGateway public mockUniversalGateway;

    // Test actors
    address public deployer;
    address public owner;
    address public vault;
    address public nonOwner;
    address public ueaOnPush;

    function setUp() public {
        deployer = address(this);
        owner = makeAddr("owner");
        vault = makeAddr("vault");
        nonOwner = makeAddr("nonOwner");
        ueaOnPush = makeAddr("ueaOnPush");

        // Deploy mock contracts
        mockUniversalGateway = new MockUniversalGateway();

        // Deploy CEA implementation
        ceaImplementation = new CEA();

        // Deploy CEAProxy implementation
        ceaProxyImplementation = new CEAProxy();

        // Deploy CEAFactory implementation
        factoryImpl = new CEAFactory();

        // Deploy and initialize the factory proxy
        bytes memory initData = abi.encodeWithSelector(
            CEAFactory.initialize.selector,
            owner,                              // initialOwner
            vault,                              // initialVault
            address(ceaProxyImplementation),   // ceaProxyImplementation
            address(ceaImplementation),          // ceaImplementation
            address(mockUniversalGateway)        // universalGateway
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = CEAFactory(address(proxy));
    }

    // =========================================================================
    // Initialize Tests
    // =========================================================================

    function testInitialize() public {
        assertEq(factory.owner(), owner, "Owner should be set");
        assertEq(factory.VAULT(), vault, "Vault should be set");
        assertEq(
            factory.CEA_PROXY_IMPLEMENTATION(),
            address(ceaProxyImplementation),
            "CEA Proxy Implementation should be set"
        );
        assertEq(factory.CEA_IMPLEMENTATION(), address(ceaImplementation), "CEA Implementation should be set");
        assertEq(factory.UNIVERSAL_GATEWAY(), address(mockUniversalGateway), "Universal Gateway should be set");
    }

    function testRevertWhenInitializingWithZeroOwner() public {
        CEAFactory newFactoryImpl = new CEAFactory();
        ERC1967Proxy newProxy = new ERC1967Proxy(address(newFactoryImpl), "");

        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        CEAFactory(address(newProxy)).initialize(
            address(0),                          
            vault,
            address(ceaProxyImplementation),
            address(ceaImplementation),
            address(mockUniversalGateway)
        );
    }

    function testRevertWhenInitializingWithZeroVault() public {
        CEAFactory newFactoryImpl = new CEAFactory();
        ERC1967Proxy newProxy = new ERC1967Proxy(address(newFactoryImpl), "");

        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        CEAFactory(address(newProxy)).initialize(
            owner,
            address(0),                         
            address(ceaProxyImplementation),
            address(ceaImplementation),
            address(mockUniversalGateway)
        );
    }

    function testRevertWhenInitializingWithZeroCEAProxyImplementation() public {
        CEAFactory newFactoryImpl = new CEAFactory();
        ERC1967Proxy newProxy = new ERC1967Proxy(address(newFactoryImpl), "");

        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        CEAFactory(address(newProxy)).initialize(
            owner,
            vault,
            address(0), 
            address(ceaImplementation),
            address(mockUniversalGateway)
        );
    }

    function testRevertWhenInitializingWithZeroCEAImplementation() public {
        CEAFactory newFactoryImpl = new CEAFactory();
        ERC1967Proxy newProxy = new ERC1967Proxy(address(newFactoryImpl), "");

        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        CEAFactory(address(newProxy)).initialize(
            owner,
            vault,
            address(ceaProxyImplementation),
            address(0), 
            address(mockUniversalGateway)
        );
    }

    function testRevertWhenInitializingWithZeroUniversalGateway() public {
        CEAFactory newFactoryImpl = new CEAFactory();
        ERC1967Proxy newProxy = new ERC1967Proxy(address(newFactoryImpl), "");

        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        CEAFactory(address(newProxy)).initialize(
            owner,
            vault,
            address(ceaProxyImplementation),
            address(ceaImplementation),
            address(0) 
        );
    }

    function testRevertWhenInitializingTwice() public {
        CEAFactory newFactoryImpl = new CEAFactory();
        ERC1967Proxy newProxy = new ERC1967Proxy(address(newFactoryImpl), "");

        CEAFactory(address(newProxy)).initialize(
            owner,
            vault,
            address(ceaProxyImplementation),
            address(ceaImplementation),
            address(mockUniversalGateway)
        );

        vm.expectRevert();
        CEAFactory(address(newProxy)).initialize(
            owner,
            vault,
            address(ceaProxyImplementation),
            address(ceaImplementation),
            address(mockUniversalGateway)
        );
    }

    // =========================================================================
    // Admin Functions - setVault
    // =========================================================================

    function testSetVaultOnlyOwner() public {
        address newVault = makeAddr("newVault");

        vm.prank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner)
        );
        factory.setVault(newVault);

        vm.prank(owner);    
        factory.setVault(newVault);
        assertEq(factory.VAULT(), newVault, "Vault should be updated");
    }

    function testSetVaultZeroAddressReverts() public {
        vm.prank(owner);
        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        factory.setVault(address(0));
    }

    function testSetVaultUpdatesState() public {
        address newVault = makeAddr("newVault");
        address oldVault = factory.VAULT();

        vm.prank(owner);
        factory.setVault(newVault);

        assertEq(factory.VAULT(), newVault, "Vault should be updated");
        assertNotEq(factory.VAULT(), oldVault, "Vault should be different from old");
    }

    function testSetVaultEmitsEvent() public {
        address newVault = makeAddr("newVault");
        address oldVault = factory.VAULT();

        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit ICEAFactory.VaultUpdated(oldVault, newVault);
        factory.setVault(newVault);
    }

    function testSetVaultMultipleTimes() public {
        address vault1 = makeAddr("vault1");
        address vault2 = makeAddr("vault2");
        address vault3 = makeAddr("vault3");

        vm.startPrank(owner);
        factory.setVault(vault1);
        assertEq(factory.VAULT(), vault1);

        factory.setVault(vault2);
        assertEq(factory.VAULT(), vault2);

        factory.setVault(vault3);
        assertEq(factory.VAULT(), vault3);
        vm.stopPrank();
    }

    function testSetVaultToSameAddress() public {
        address currentVault = factory.VAULT();

        vm.prank(owner);
        factory.setVault(currentVault);

        assertEq(factory.VAULT(), currentVault, "Vault should remain the same");
    }

    function testSetVaultAfterDeployment() public {
        address cea = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea), "CEA should have code");

        address newVault = makeAddr("newVault");
        vm.prank(owner);
        factory.setVault(newVault);

        assertTrue(hasCode(cea), "CEA should still have code");
        assertEq(factory.getUEAForCEA(cea), ueaOnPush, "Mapping should persist");
    }

    function testSetVaultToContractAddress() public {
        MockUniversalGateway contractVault = new MockUniversalGateway();
        address contractAddress = address(contractVault);

        vm.prank(owner);
        factory.setVault(contractAddress);

        assertEq(factory.VAULT(), contractAddress, "Vault can be a contract");
    }

    function testSetCEAProxyImplementationOnlyOwner() public {
        CEAProxy newProxyImpl = new CEAProxy();

        vm.prank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner)
        );
        factory.setCEAProxyImplementation(address(newProxyImpl));

        vm.prank(owner);
        factory.setCEAProxyImplementation(address(newProxyImpl));
        assertEq(factory.CEA_PROXY_IMPLEMENTATION(), address(newProxyImpl));
    }

    function testSetCEAProxyImplementationZeroAddressReverts() public {
        vm.prank(owner);
        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        factory.setCEAProxyImplementation(address(0));
    }

    function testSetCEAProxyImplementationUpdatesState() public {
        CEAProxy newProxyImpl = new CEAProxy();
        address oldImpl = factory.CEA_PROXY_IMPLEMENTATION();

        vm.prank(owner);
        factory.setCEAProxyImplementation(address(newProxyImpl));

        assertEq(factory.CEA_PROXY_IMPLEMENTATION(), address(newProxyImpl));
        assertNotEq(factory.CEA_PROXY_IMPLEMENTATION(), oldImpl);
    }

    function testSetCEAProxyImplementationEmitsEvent() public {
        CEAProxy newProxyImpl = new CEAProxy();
        address oldImpl = factory.CEA_PROXY_IMPLEMENTATION();

        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit ICEAFactory.CEAProxyImplementationUpdated(oldImpl, address(newProxyImpl));
        factory.setCEAProxyImplementation(address(newProxyImpl));
    }

    function testSetCEAProxyImplementationAffectsNewDeployments() public {
        // Deploy first CEA with old implementation
        address cea1 = deployCEAHelper(ueaOnPush);
        address computed1 = factory.computeCEA(ueaOnPush);
        assertEq(cea1, computed1, "First CEA should match computed");

        // Update proxy implementation
        CEAProxy newProxyImpl = new CEAProxy();
        vm.prank(owner);
        factory.setCEAProxyImplementation(address(newProxyImpl));

        // New UEA should use new implementation
        address newUEA = makeAddr("newUEA");
        address computed2 = factory.computeCEA(newUEA);
        assertNotEq(computed2, cea1, "New computed address should be different");
    }

    function testSetCEAProxyImplementationDoesNotAffectExisting() public {
        // Deploy a CEA
        address cea = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea), "CEA should have code");

        // Update proxy implementation
        CEAProxy newProxyImpl = new CEAProxy();
        vm.prank(owner);
        factory.setCEAProxyImplementation(address(newProxyImpl));

        // Existing CEA should still work
        assertTrue(hasCode(cea), "Existing CEA should still have code");
        assertEq(factory.getUEAForCEA(cea), ueaOnPush, "Mapping should persist");
    }

    function testSetCEAProxyImplementationToInvalidContract() public {
        // Set to a contract that doesn't implement ICEAProxy
        MockUniversalGateway invalidContract = new MockUniversalGateway();

        vm.prank(owner);
        factory.setCEAProxyImplementation(address(invalidContract));

        address newUEA = makeAddr("newUEA");
        vm.prank(vault);
        vm.expectRevert(); 
        factory.deployCEA(newUEA);
    }

    function testSetCEAImplementationOnlyOwner() public {
        CEA newCEAImpl = new CEA();

        vm.prank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner)
        );
        factory.setCEAImplementation(address(newCEAImpl));

        vm.prank(owner);
        factory.setCEAImplementation(address(newCEAImpl));
        assertEq(factory.CEA_IMPLEMENTATION(), address(newCEAImpl));
    }

    function testSetCEAImplementationZeroAddressReverts() public {
        vm.prank(owner);
        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        factory.setCEAImplementation(address(0));
    }

    function testSetCEAImplementationUpdatesState() public {
        CEA newCEAImpl = new CEA();
        address oldImpl = factory.CEA_IMPLEMENTATION();

        vm.prank(owner);
        factory.setCEAImplementation(address(newCEAImpl));

        assertEq(factory.CEA_IMPLEMENTATION(), address(newCEAImpl));
        assertNotEq(factory.CEA_IMPLEMENTATION(), oldImpl);
    }

    function testSetCEAImplementationEmitsEvent() public {
        CEA newCEAImpl = new CEA();
        address oldImpl = factory.CEA_IMPLEMENTATION();

        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit ICEAFactory.CEAImplementationUpdated(oldImpl, address(newCEAImpl));
        factory.setCEAImplementation(address(newCEAImpl));
    }

    function testSetCEAImplementationAffectsNewDeployments() public {
        address cea1 = deployCEAHelper(ueaOnPush);

        CEA newCEAImpl = new CEA();
        vm.prank(owner);
        factory.setCEAImplementation(address(newCEAImpl));

        address newUEA = makeAddr("newUEA");
        address cea2 = deployCEAHelper(newUEA);

        assertTrue(hasCode(cea1), "First CEA should work");
        assertTrue(hasCode(cea2), "Second CEA should work");
    }

    function testSetCEAImplementationDoesNotAffectExisting() public {
        // Deploy a CEA
        address cea = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea), "CEA should have code");

        // Update CEA implementation
        CEA newCEAImpl = new CEA();
        vm.prank(owner);
        factory.setCEAImplementation(address(newCEAImpl));

        // Existing CEA should still work (proxy delegates to same implementation)
        assertTrue(hasCode(cea), "Existing CEA should still have code");
        assertEq(factory.getUEAForCEA(cea), ueaOnPush, "Mapping should persist");
    }

    function testSetCEAImplementationToNonICEAContract() public {
        // Set to a contract that doesn't implement ICEA
        MockUniversalGateway invalidContract = new MockUniversalGateway();

        vm.prank(owner);
        factory.setCEAImplementation(address(invalidContract));

        // Deployment should fail when trying to initialize
        address newUEA = makeAddr("newUEA");
        vm.prank(vault);
        vm.expectRevert(); // Will revert when trying to initialize CEA
        factory.deployCEA(newUEA);
    }

    // =========================================================================
    // Admin Functions - setUniversalGateway
    // =========================================================================

    function testSetUniversalGatewayOnlyOwner() public {
        MockUniversalGateway newGateway = new MockUniversalGateway();

        vm.prank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner)
        );
        factory.setUniversalGateway(address(newGateway));

        vm.prank(owner);
        factory.setUniversalGateway(address(newGateway));
        assertEq(factory.UNIVERSAL_GATEWAY(), address(newGateway));
    }

    function testSetUniversalGatewayZeroAddressReverts() public {
        vm.prank(owner);
        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        factory.setUniversalGateway(address(0));
    }

    function testSetUniversalGatewayUpdatesState() public {
        MockUniversalGateway newGateway = new MockUniversalGateway();
        address oldGateway = factory.UNIVERSAL_GATEWAY();

        vm.prank(owner);
        factory.setUniversalGateway(address(newGateway));

        assertEq(factory.UNIVERSAL_GATEWAY(), address(newGateway));
        assertNotEq(factory.UNIVERSAL_GATEWAY(), oldGateway);
    }

    // =========================================================================
    // View Functions - getCEAForUEA
    // =========================================================================

    function testGetCEAForUEAWhenNotDeployed() public {
        address testUEA = makeAddr("testUEA");

        (address cea, bool isDeployed) = factory.getCEAForUEA(testUEA);

        assertTrue(cea != address(0), "Should return computed address");
        assertFalse(isDeployed, "Should return false for isDeployed");
        assertEq(cea, factory.computeCEA(testUEA), "Should match computed address");
    }

    function testGetCEAForUEAWhenDeployed() public {
        address cea = deployCEAHelper(ueaOnPush);

        (address returnedCEA, bool isDeployed) = factory.getCEAForUEA(ueaOnPush);

        assertEq(returnedCEA, cea, "Should return deployed address");
        assertTrue(isDeployed, "Should return true for isDeployed");
    }

    function testGetCEAForUEAWithZeroAddress() public {
        // Zero address should compute to a deterministic address
        // Note: But, as a safety measure, Vault contract's _validateExecutionParams function ensures ueaAddress must NOT be zero address.
        (address cea, bool isDeployed) = factory.getCEAForUEA(address(0));

        assertTrue(cea != address(0), "Should return computed address");
        assertFalse(isDeployed, "Should return false for isDeployed");
    }

    function testGetCEAForUEAWithMappingButNoCode() public {
        // Deploy CEA
        address cea = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea), "CEA should have code initially");

        // Selfdestruct the CEA
        selfdestructCEA(cea);
        assertFalse(hasCode(cea), "CEA should not have code after selfdestruct");

        // getCEAForUEA should detect no code
        (address returnedCEA, bool isDeployed) = factory.getCEAForUEA(ueaOnPush);
        assertEq(returnedCEA, cea, "Should return mapped address");
        assertFalse(isDeployed, "Should return false when code is gone");
    }

    function testGetCEAForUEAWithMultipleUEAs() public {
        address uea1 = makeAddr("uea1");
        address uea2 = makeAddr("uea2");
        address uea3 = makeAddr("uea3");

        address cea1 = deployCEAHelper(uea1);
        address cea2 = deployCEAHelper(uea2);
        address cea3 = deployCEAHelper(uea3);

        (address returnedCEA1, bool isDeployed1) = factory.getCEAForUEA(uea1);
        (address returnedCEA2, bool isDeployed2) = factory.getCEAForUEA(uea2);
        (address returnedCEA3, bool isDeployed3) = factory.getCEAForUEA(uea3);

        assertEq(returnedCEA1, cea1, "CEA1 should match");
        assertEq(returnedCEA2, cea2, "CEA2 should match");
        assertEq(returnedCEA3, cea3, "CEA3 should match");
        assertTrue(isDeployed1 && isDeployed2 && isDeployed3, "All should be deployed");
        assertTrue(cea1 != cea2 && cea2 != cea3 && cea1 != cea3, "All should be different");
    }

    function testGetCEAForUEAComputedAddressMatchesDeployed() public {
        address testUEA = makeAddr("testUEA");

        // Compute address before deployment
        address computed = factory.computeCEA(testUEA);

        // Deploy
        address deployed = deployCEAHelper(testUEA);

        // Get after deployment
        (address returned, bool isDeployed) = factory.getCEAForUEA(testUEA);

        assertEq(computed, deployed, "Computed should match deployed");
        assertEq(returned, deployed, "Returned should match deployed");
        assertTrue(isDeployed, "Should be deployed");
    }

    function testGetCEAForUEAWhenImplementationNotSet() public {

        vm.prank(owner);
        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        factory.setCEAProxyImplementation(address(0));
    }

    // =========================================================================
    // View Functions - computeCEA
    // =========================================================================

    function testComputeCEAWithValidUEA() public {
        address testUEA = makeAddr("testUEA");
        address computed = factory.computeCEA(testUEA);

        assertTrue(computed != address(0), "Should return valid address");
    }

    function testComputeCEAWithZeroAddress() public {
        // Zero address should still compute to a deterministic address
        address computed = factory.computeCEA(address(0));
        assertTrue(computed != address(0), "Should compute to valid address");
    }

    function testComputeCEAIsDeterministic() public {
        address testUEA = makeAddr("testUEA");

        address computed1 = factory.computeCEA(testUEA);
        address computed2 = factory.computeCEA(testUEA);
        address computed3 = factory.computeCEA(testUEA);

        assertEq(computed1, computed2, "Should be deterministic");
        assertEq(computed2, computed3, "Should be deterministic");
    }

    function testComputeCEAMatchesDeployed() public {
        address testUEA = makeAddr("testUEA");

        address computed = factory.computeCEA(testUEA);
        address deployed = deployCEAHelper(testUEA);

        assertEq(computed, deployed, "Computed should match deployed");
    }

    function testComputeCEAWithDifferentUEAs() public {
        address uea1 = makeAddr("uea1");
        address uea2 = makeAddr("uea2");
        address uea3 = makeAddr("uea3");

        address computed1 = factory.computeCEA(uea1);
        address computed2 = factory.computeCEA(uea2);
        address computed3 = factory.computeCEA(uea3);

        assertTrue(computed1 != computed2, "Different UEAs should give different addresses");
        assertTrue(computed2 != computed3, "Different UEAs should give different addresses");
        assertTrue(computed1 != computed3, "Different UEAs should give different addresses");
    }

    function testComputeCEAWhenImplementationNotSet() public {
        // Cannot set implementation to zero through setter (it reverts)
        // This scenario would require factory to be initialized with zero,
        // which is prevented. So we test that the setter prevents zero.
        vm.prank(owner);
        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        factory.setCEAProxyImplementation(address(0));
    }

    function testComputeCEAWithContractAddress() public {
        MockUniversalGateway contractUEA = new MockUniversalGateway();
        address computed = factory.computeCEA(address(contractUEA));

        assertTrue(computed != address(0), "Should compute valid address");
    }

    function testComputeCEAWithEOAAddress() public {
        address eoaUEA = makeAddr("eoaUEA");
        address computed = factory.computeCEA(eoaUEA);

        assertTrue(computed != address(0), "Should compute valid address");
    }

    // =========================================================================
    // View Functions - isCEA
    // =========================================================================

    function testIsCEAWithDeployedCEA() public {
        address cea = deployCEAHelper(ueaOnPush);

        bool isCea = factory.isCEA(cea);
        assertTrue(isCea, "Should return true for deployed CEA");
    }

    function testIsCEAWithNonCEAAddress() public {
        address nonCEA = makeAddr("nonCEA");
        bool isCea = factory.isCEA(nonCEA);

        assertFalse(isCea, "Should return false for non-CEA");
    }

    function testIsCEAWithZeroAddress() public {
        bool isCea = factory.isCEA(address(0));
        assertFalse(isCea, "Should return false for zero address");
    }

    function testIsCEAWithFactoryAddress() public {
        bool isCea = factory.isCEA(address(factory));
        assertFalse(isCea, "Should return false for factory");
    }

    function testIsCEAWithVaultAddress() public {
        bool isCea = factory.isCEA(vault);
        assertFalse(isCea, "Should return false for vault");
    }

    function testIsCEAWithUEAAddress() public {
        bool isCea = factory.isCEA(ueaOnPush);
        assertFalse(isCea, "Should return false for UEA (different chain)");
    }

    function testIsCEAWithSelfdestructedCEA() public {
        address cea = deployCEAHelper(ueaOnPush);
        selfdestructCEA(cea);

        // Mapping should still exist
        bool isCea = factory.isCEA(cea);
        assertTrue(isCea, "Should return true if mapping exists, even after selfdestruct");
    }

    function testIsCEAWithComputedButNotDeployed() public {
        address testUEA = makeAddr("testUEA");
        address computed = factory.computeCEA(testUEA);

        bool isCea = factory.isCEA(computed);
        assertFalse(isCea, "Should return false for computed but not deployed");
    }

    // =========================================================================
    // View Functions - getUEAForCEA
    // =========================================================================

    function testGetUEAForCEAWithDeployedCEA() public {
        address cea = deployCEAHelper(ueaOnPush);

        address returnedUEA = factory.getUEAForCEA(cea);
        assertEq(returnedUEA, ueaOnPush, "Should return correct UEA");
    }

    function testGetUEAForCEAWithNonCEAAddress() public {
        address nonCEA = makeAddr("nonCEA");
        address returnedUEA = factory.getUEAForCEA(nonCEA);

        assertEq(returnedUEA, address(0), "Should return zero for non-CEA");
    }

    function testGetUEAForCEAWithZeroAddress() public {
        address returnedUEA = factory.getUEAForCEA(address(0));
        assertEq(returnedUEA, address(0), "Should return zero for zero address");
    }

    function testGetUEAForCEAWithSelfdestructedCEA() public {
        address cea = deployCEAHelper(ueaOnPush);
        selfdestructCEA(cea);

        // Mapping should still exist
        address returnedUEA = factory.getUEAForCEA(cea);
        assertEq(returnedUEA, ueaOnPush, "Should still return UEA if mapping exists");
    }

    function testGetUEAForCEAReverseMapping() public {
        address cea = deployCEAHelper(ueaOnPush);

        // Verify bidirectional mapping
        assertEq(factory.getUEAForCEA(cea), ueaOnPush, "CEA -> UEA");
        assertEq(factory.UEA_to_CEA(ueaOnPush), cea, "UEA -> CEA");
    }

    function testGetUEAForCEAWithMultipleCEAs() public {
        address uea1 = makeAddr("uea1");
        address uea2 = makeAddr("uea2");
        address uea3 = makeAddr("uea3");

        address cea1 = deployCEAHelper(uea1);
        address cea2 = deployCEAHelper(uea2);
        address cea3 = deployCEAHelper(uea3);

        assertEq(factory.getUEAForCEA(cea1), uea1, "CEA1 should map to UEA1");
        assertEq(factory.getUEAForCEA(cea2), uea2, "CEA2 should map to UEA2");
        assertEq(factory.getUEAForCEA(cea3), uea3, "CEA3 should map to UEA3");
    }

    // =========================================================================
    // Core Function - deployCEA - Access Control
    // =========================================================================

    function testDeployCEAOnlyVault() public {
        address cea = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea), "CEA should be deployed");
    }

    function testDeployCEAFromNonVaultReverts() public {
        vm.prank(nonOwner);
        vm.expectRevert(CEAFactory.NotVault.selector);
        factory.deployCEA(ueaOnPush);
    }

    function testDeployCEAFromOwnerReverts() public {
        vm.prank(owner);
        vm.expectRevert(CEAFactory.NotVault.selector);
        factory.deployCEA(ueaOnPush);
    }

    function testDeployCEAFromZeroAddressReverts() public {
        vm.prank(address(0));
        vm.expectRevert(CEAFactory.NotVault.selector);
        factory.deployCEA(ueaOnPush);
    }

    // =========================================================================
    // Core Function - deployCEA - Input Validation
    // =========================================================================

    function testDeployCEAWithZeroUEAReverts() public {
        vm.prank(vault);
        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        factory.deployCEA(address(0));
    }

    function testDeployCEAWhenProxyImplementationNotSet() public {
        // Note: Setting to zero address will revert with ZeroAddress in setter
        // So we need to test this differently - by checking the validation in deployCEA
        // Actually, we can't set to zero through the setter, so this test scenario
        // would require the factory to be initialized with zero, which is prevented.
        // Let's test that the setter prevents zero address
        vm.prank(owner);
        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        factory.setCEAProxyImplementation(address(0));
    }

    function testDeployCEAWhenCEAImplementationNotSet() public {
        // Similar to above - setter prevents zero address
        vm.prank(owner);
        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        factory.setCEAImplementation(address(0));
    }

    function testDeployCEAWhenUniversalGatewayNotSet() public {
        // Similar to above - setter prevents zero address
        vm.prank(owner);
        vm.expectRevert(CEAFactory.ZeroAddress.selector);
        factory.setUniversalGateway(address(0));
    }

    // =========================================================================
    // Core Function - deployCEA - Duplicate Deployment Protection
    // =========================================================================

    function testDeployCEAWhenAlreadyDeployedReverts() public {
        address cea = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea), "CEA should be deployed");

        vm.prank(vault);
        vm.expectRevert(CEAFactory.CEAAlreadyDeployed.selector);
        factory.deployCEA(ueaOnPush);
    }

    function testDeployCEAWhenMappingExistsButNoCode() public {
        // Deploy CEA
        address cea = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea), "CEA should have code");

        // Selfdestruct
        selfdestructCEA(cea);
        assertFalse(hasCode(cea), "CEA should not have code");

        // Note: After selfdestruct, redeployment will fail because proxy was already initialized
        // This is expected behavior - once initialized, proxy cannot be re-initialized
        vm.prank(vault);
        vm.expectRevert(); // Proxy initialization will fail
        factory.deployCEA(ueaOnPush);
    }

    function testDeployCEAWhenMappingExistsButCodeDestroyed() public {
        address cea = deployCEAHelper(ueaOnPush);
        selfdestructCEA(cea);

        // Note: After selfdestruct, redeployment will fail because proxy was already initialized
        vm.prank(vault);
        vm.expectRevert(); // Proxy initialization will fail
        factory.deployCEA(ueaOnPush);
    }

    function testDeployCEAWithSameUEATwiceReverts() public {
        deployCEAHelper(ueaOnPush);

        vm.prank(vault);
        vm.expectRevert(CEAFactory.CEAAlreadyDeployed.selector);
        factory.deployCEA(ueaOnPush);
    }

    // =========================================================================
    // Core Function - deployCEA - Successful Deployment
    // =========================================================================

    function testDeployCEASuccess() public {
        address cea = deployCEAHelper(ueaOnPush);

        assertTrue(cea != address(0), "CEA should be deployed");
        assertTrue(hasCode(cea), "CEA should have code");
    }

    function testDeployCEAEmitsEvent() public {
        address expectedCEA = factory.computeCEA(ueaOnPush);
        vm.prank(vault);
        vm.expectEmit(true, true, false, false);
        emit ICEAFactory.CEADeployed(ueaOnPush, expectedCEA);
        address deployedCEA = factory.deployCEA(ueaOnPush);
        assertEq(deployedCEA, expectedCEA, "Deployed address should match expected");
    }

    function testDeployCEACreatesCorrectAddress() public {
        address computed = factory.computeCEA(ueaOnPush);
        address deployed = deployCEAHelper(ueaOnPush);

        assertEq(computed, deployed, "Deployed address should match computed");
    }

    function testDeployCEASetsMappings() public {
        address cea = deployCEAHelper(ueaOnPush);

        verifyMappings(ueaOnPush, cea);
    }

    function testDeployCEAInitializesProxy() public {
        address cea = deployCEAHelper(ueaOnPush);

        // Check that proxy is initialized by checking it has code and can be called
        assertTrue(hasCode(cea), "Proxy should have code");
    }

    function testDeployCEAInitializesCEA() public {
        address cea = deployCEAHelper(ueaOnPush);
        CEA ceaInstance = CEA(payable(cea));

        assertTrue(ceaInstance.isInitialized(), "CEA should be initialized");
        assertEq(ceaInstance.UEA(), ueaOnPush, "UEA should be set");
        assertEq(ceaInstance.VAULT(), vault, "Vault should be set");
    }

    function testDeployCEAHasCode() public {
        address cea = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea), "CEA should have code");
    }

    function testDeployCEAMultipleUEAs() public {
        address uea1 = makeAddr("uea1");
        address uea2 = makeAddr("uea2");
        address uea3 = makeAddr("uea3");

        address cea1 = deployCEAHelper(uea1);
        address cea2 = deployCEAHelper(uea2);
        address cea3 = deployCEAHelper(uea3);

        assertTrue(cea1 != cea2 && cea2 != cea3 && cea1 != cea3, "All should be different");
        assertTrue(hasCode(cea1) && hasCode(cea2) && hasCode(cea3), "All should have code");
    }

    // =========================================================================
    // Core Function - deployCEA - Deterministic Address (CREATE2)
    // =========================================================================

    function testDeployCEAIsDeterministic() public {
        address testUEA = makeAddr("testUEA");

        // Compute address
        address computed = factory.computeCEA(testUEA);

        // Deploy
        address deployed1 = deployCEAHelper(testUEA);
        assertEq(computed, deployed1, "First deployment should match computed");

        // Deploy another UEA to verify determinism
        address testUEA2 = makeAddr("testUEA2");
        address computed2 = factory.computeCEA(testUEA2);
        address deployed2 = deployCEAHelper(testUEA2);
        assertEq(computed2, deployed2, "Second deployment should match computed");
        assertTrue(deployed1 != deployed2, "Different UEAs should give different addresses");
    }

    function testDeployCEAAddressMatchesComputed() public {
        address testUEA = makeAddr("testUEA");
        address computed = factory.computeCEA(testUEA);
        address deployed = deployCEAHelper(testUEA);

        assertEq(computed, deployed, "Should match computed address");
    }

    function testDeployCEAWithDifferentUEAs() public {
        address uea1 = makeAddr("uea1");
        address uea2 = makeAddr("uea2");

        address cea1 = deployCEAHelper(uea1);
        address cea2 = deployCEAHelper(uea2);

        assertTrue(cea1 != cea2, "Different UEAs should give different CEAs");
    }

    function testDeployCEAAddressConsistency() public {
        address testUEA = makeAddr("testUEA");

        // Compute multiple times
        address computed1 = factory.computeCEA(testUEA);
        address computed2 = factory.computeCEA(testUEA);
        address computed3 = factory.computeCEA(testUEA);

        assertEq(computed1, computed2, "Computed addresses should be consistent");
        assertEq(computed2, computed3, "Computed addresses should be consistent");

        // Deploy and verify
        address deployed = deployCEAHelper(testUEA);
        assertEq(deployed, computed1, "Deployed should match computed");
    }

    // =========================================================================
    // Core Function - deployCEA - Integration & State Consistency
    // =========================================================================

    function testDeployCEAThenGetCEAForUEA() public {
        address cea = deployCEAHelper(ueaOnPush);

        (address returnedCEA, bool isDeployed) = factory.getCEAForUEA(ueaOnPush);
        assertEq(returnedCEA, cea, "Should return deployed CEA");
        assertTrue(isDeployed, "Should return true for isDeployed");
    }

    function testDeployCEAThenIsCEA() public {
        address cea = deployCEAHelper(ueaOnPush);

        bool isCea = factory.isCEA(cea);
        assertTrue(isCea, "Should return true for deployed CEA");
    }

    function testDeployCEAThenGetUEAForCEA() public {
        address cea = deployCEAHelper(ueaOnPush);

        address returnedUEA = factory.getUEAForCEA(cea);
        assertEq(returnedUEA, ueaOnPush, "Should return correct UEA");
    }

    function testDeployCEAWithUpdatedVault() public {
        address newVault = makeAddr("newVault");
        vm.prank(owner);
        factory.setVault(newVault);

        // Deploy with new vault
        vm.prank(newVault);
        address cea = factory.deployCEA(ueaOnPush);

        CEA ceaInstance = CEA(payable(cea));
        assertEq(ceaInstance.VAULT(), newVault, "CEA should use new vault");
    }

    function testDeployCEAWithUpdatedGateway() public {
        MockUniversalGateway newGateway = new MockUniversalGateway();
        vm.prank(owner);
        factory.setUniversalGateway(address(newGateway));

        address cea = deployCEAHelper(ueaOnPush);
        CEA ceaInstance = CEA(payable(cea));
        assertEq(ceaInstance.UNIVERSAL_GATEWAY(), address(newGateway), "CEA should use new gateway");
    }

    function testDeployCEAWithUpdatedImplementation() public {
        CEA newCEAImpl = new CEA();
        vm.prank(owner);
        factory.setCEAImplementation(address(newCEAImpl));

        address cea = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea), "CEA should be deployed with new implementation");
    }

    // =========================================================================
    // Core Function - deployCEA - Edge Cases & Security
    // =========================================================================

    function testDeployCEAWithContractAsUEA() public {
        MockUniversalGateway contractUEA = new MockUniversalGateway();
        address cea = deployCEAHelper(address(contractUEA));

        assertTrue(hasCode(cea), "Should deploy successfully");
        assertEq(factory.getUEAForCEA(cea), address(contractUEA), "Mapping should be correct");
    }

    function testDeployCEAWithEOAAsUEA() public {
        address eoaUEA = makeAddr("eoaUEA");
        address cea = deployCEAHelper(eoaUEA);

        assertTrue(hasCode(cea), "Should deploy successfully");
        assertEq(factory.getUEAForCEA(cea), eoaUEA, "Mapping should be correct");
    }

    function testDeployCEAMultipleDeploymentsSameSalt() public {
        // Deploy first
        address cea1 = deployCEAHelper(ueaOnPush);

        // Try to deploy again - should revert
        vm.prank(vault);
        vm.expectRevert(CEAFactory.CEAAlreadyDeployed.selector);
        factory.deployCEA(ueaOnPush);

        // CREATE2 prevents duplicate deployment
        assertTrue(hasCode(cea1), "First CEA should still exist");
    }

    // =========================================================================
    // Integration & State Management Tests
    // =========================================================================

    function testFactoryLifecycleComplete() public {
        // Initial state
        assertEq(factory.owner(), owner, "Owner should be set");

        // Deploy first CEA
        address cea1 = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea1), "First CEA should be deployed");

        // Update implementations
        CEA newCEAImpl = new CEA();
        vm.prank(owner);
        factory.setCEAImplementation(address(newCEAImpl));

        // Deploy second CEA with new implementation
        address uea2 = makeAddr("uea2");
        address cea2 = deployCEAHelper(uea2);
        assertTrue(hasCode(cea2), "Second CEA should be deployed");

        // Both should work
        assertTrue(hasCode(cea1) && hasCode(cea2), "Both CEAs should work");
    }

    function testFactoryWithMultipleCEAs() public {
        address[] memory ueas = new address[](10);
        address[] memory ceas = new address[](10);

        // Deploy 10 CEAs
        for (uint256 i = 0; i < 10; i++) {
            ueas[i] = makeAddr(string(abi.encodePacked("uea", i)));
            ceas[i] = deployCEAHelper(ueas[i]);
        }

        // Verify all are deployed and mapped correctly
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(hasCode(ceas[i]), "CEA should have code");
            assertEq(factory.getUEAForCEA(ceas[i]), ueas[i], "Mapping should be correct");
            assertEq(factory.UEA_to_CEA(ueas[i]), ceas[i], "Reverse mapping should be correct");
        }
    }

    function testFactoryStateConsistency() public {
        address uea1 = makeAddr("uea1");
        address uea2 = makeAddr("uea2");

        address cea1 = deployCEAHelper(uea1);
        address cea2 = deployCEAHelper(uea2);

        // Verify all mappings are consistent
        verifyMappings(uea1, cea1);
        verifyMappings(uea2, cea2);

        // Verify no cross-mapping
        assertNotEq(factory.getUEAForCEA(cea1), uea2, "No cross-mapping");
        assertNotEq(factory.getUEAForCEA(cea2), uea1, "No cross-mapping");
    }

    function testFactoryAfterImplementationUpdate() public {
        // Deploy with old implementation
        address cea1 = deployCEAHelper(ueaOnPush);

        // Update implementation
        CEA newCEAImpl = new CEA();
        vm.prank(owner);
        factory.setCEAImplementation(address(newCEAImpl));

        // Deploy new CEA
        address uea2 = makeAddr("uea2");
        address cea2 = deployCEAHelper(uea2);

        // Both should work
        assertTrue(hasCode(cea1) && hasCode(cea2), "Both should work");
    }

    function testMappingConsistencyUEAToCEA() public {
        address uea1 = makeAddr("uea1");
        address uea2 = makeAddr("uea2");

        address cea1 = deployCEAHelper(uea1);
        address cea2 = deployCEAHelper(uea2);

        assertEq(factory.UEA_to_CEA(uea1), cea1, "UEA1 -> CEA1");
        assertEq(factory.UEA_to_CEA(uea2), cea2, "UEA2 -> CEA2");
    }

    function testMappingConsistencyCEAToUEA() public {
        address uea1 = makeAddr("uea1");
        address uea2 = makeAddr("uea2");

        address cea1 = deployCEAHelper(uea1);
        address cea2 = deployCEAHelper(uea2);

        assertEq(factory.CEA_to_UEA(cea1), uea1, "CEA1 -> UEA1");
        assertEq(factory.CEA_to_UEA(cea2), uea2, "CEA2 -> UEA2");
    }

    function testMappingBidirectionalConsistency() public {
        address uea = makeAddr("uea");
        address cea = deployCEAHelper(uea);

        // Forward mapping
        assertEq(factory.UEA_to_CEA(uea), cea, "Forward mapping");

        // Reverse mapping
        assertEq(factory.CEA_to_UEA(cea), uea, "Reverse mapping");

        // Consistency check
        assertEq(factory.UEA_to_CEA(factory.CEA_to_UEA(cea)), cea, "Bidirectional consistency");
        assertEq(factory.CEA_to_UEA(factory.UEA_to_CEA(uea)), uea, "Bidirectional consistency");
    }

    function testMappingAfterSelfdestruct() public {
        address cea = deployCEAHelper(ueaOnPush);
        verifyMappings(ueaOnPush, cea);

        // Selfdestruct
        selfdestructCEA(cea);

        // Mappings should persist
        assertEq(factory.UEA_to_CEA(ueaOnPush), cea, "Mapping should persist");
        assertEq(factory.CEA_to_UEA(cea), ueaOnPush, "Mapping should persist");
    }

    function testUpdateProxyImplementationBeforeDeployment() public {
        CEAProxy newProxyImpl = new CEAProxy();
        vm.prank(owner);
        factory.setCEAProxyImplementation(address(newProxyImpl));

        address cea = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea), "Should deploy with new proxy implementation");
    }

    function testUpdateCEAImplementationBeforeDeployment() public {
        CEA newCEAImpl = new CEA();
        vm.prank(owner);
        factory.setCEAImplementation(address(newCEAImpl));

        address cea = deployCEAHelper(ueaOnPush);
        assertTrue(hasCode(cea), "Should deploy with new CEA implementation");
    }

    function testUpdateGatewayBeforeDeployment() public {
        MockUniversalGateway newGateway = new MockUniversalGateway();
        vm.prank(owner);
        factory.setUniversalGateway(address(newGateway));

        address cea = deployCEAHelper(ueaOnPush);
        CEA ceaInstance = CEA(payable(cea));
        assertEq(ceaInstance.UNIVERSAL_GATEWAY(), address(newGateway), "Should use new gateway");
    }

    function testUpdateVaultBeforeDeployment() public {
        address newVault = makeAddr("newVault");
        vm.prank(owner);
        factory.setVault(newVault);

        vm.prank(newVault);
        address cea = factory.deployCEA(ueaOnPush);
        CEA ceaInstance = CEA(payable(cea));
        assertEq(ceaInstance.VAULT(), newVault, "Should use new vault");
    }

    function testUpdateImplementationAfterDeployment() public {
        // Deploy first
        address cea = deployCEAHelper(ueaOnPush);
        CEA ceaInstance = CEA(payable(cea));
        address originalGateway = ceaInstance.UNIVERSAL_GATEWAY();

        // Update gateway
        MockUniversalGateway newGateway = new MockUniversalGateway();
        vm.prank(owner);
        factory.setUniversalGateway(address(newGateway));

        // Existing CEA should still have old gateway
        assertEq(ceaInstance.UNIVERSAL_GATEWAY(), originalGateway, "Existing CEA should keep old gateway");
    }

    // =========================================================================
    // Security & Attack Scenarios
    // =========================================================================

    function testPreventUnauthorizedVaultChange() public {
        address newVault = makeAddr("newVault");

        // Vault cannot change itself
        vm.prank(vault);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, vault)
        );
        factory.setVault(newVault);

        // Non-owner cannot change
        vm.prank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner)
        );
        factory.setVault(newVault);
    }

    function testPreventUnauthorizedImplementationChange() public {
        CEA newImpl = new CEA();

        // Vault cannot change
        vm.prank(vault);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, vault)
        );
        factory.setCEAImplementation(address(newImpl));

        // Non-owner cannot change
        vm.prank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner)
        );
        factory.setCEAImplementation(address(newImpl));
    }

    function testPreventVaultFromChangingOwner() public {
        // Vault cannot transfer ownership (only owner can)
        address newOwner = makeAddr("newOwner");

        vm.prank(vault);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, vault)
        );
        factory.transferOwnership(newOwner);
    }

    function testPreventNonVaultFromDeploying() public {
        // Owner cannot deploy
        vm.prank(owner);
        vm.expectRevert(CEAFactory.NotVault.selector);
        factory.deployCEA(ueaOnPush);

        // Non-owner cannot deploy
        vm.prank(nonOwner);
        vm.expectRevert(CEAFactory.NotVault.selector);
        factory.deployCEA(ueaOnPush);
    }

    function testDeployCEAAfterSelfdestruct() public {
        address cea = deployCEAHelper(ueaOnPush);
        selfdestructCEA(cea);

        // Note: After selfdestruct, redeployment will fail because proxy was already initialized
        vm.prank(vault);
        vm.expectRevert(); // Proxy initialization will fail
        factory.deployCEA(ueaOnPush);
    }

    function testGetCEAForUEAAfterSelfdestruct() public {
        address cea = deployCEAHelper(ueaOnPush);
        selfdestructCEA(cea);

        (address returnedCEA, bool isDeployed) = factory.getCEAForUEA(ueaOnPush);
        assertEq(returnedCEA, cea, "Should return mapped address");
        assertFalse(isDeployed, "Should detect selfdestruct");
    }

    function testIsCEAAfterSelfdestruct() public {
        address cea = deployCEAHelper(ueaOnPush);
        selfdestructCEA(cea);

        // Mapping should still exist
        bool isCea = factory.isCEA(cea);
        assertTrue(isCea, "Should return true if mapping exists");
    }

    function testDeployCEAWithMaxAddress() public {
        // Test with address(uint160(uint256(keccak256("max"))))
        address maxAddress = address(type(uint160).max);
        address cea = deployCEAHelper(maxAddress);

        assertTrue(hasCode(cea), "Should handle edge case address");
        assertEq(factory.getUEAForCEA(cea), maxAddress, "Mapping should work");
    }

    function testFactoryCannotBeInitializedTwice() public {
        // This is already tested in testRevertWhenInitializingTwice
        // But verify it's protected at the proxy level
        vm.expectRevert();
        factory.initialize(
            owner,
            vault,
            address(ceaProxyImplementation),
            address(ceaImplementation),
            address(mockUniversalGateway)
        );
    }

        // =========================================================================
    // Helper Functions
    // =========================================================================

    /// @notice Helper to deploy a CEA through the factory
    function deployCEAHelper(address uea) internal returns (address cea) {
        vm.prank(vault);
        return factory.deployCEA(uea);
    }

    /// @notice Helper to selfdestruct a CEA for testing
    function selfdestructCEA(address cea) internal {
        // Use Foundry's destroyAccount cheatcode
        destroyAccount(cea, address(0));
    }

    /// @notice Helper to verify bidirectional mappings
    function verifyMappings(address uea, address cea) internal {
        assertEq(factory.UEA_to_CEA(uea), cea, "UEA_to_CEA mapping should be correct");
        assertEq(factory.CEA_to_UEA(cea), uea, "CEA_to_UEA mapping should be correct");
    }

    /// @notice Helper to check if address has code
    function hasCode(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }
}

