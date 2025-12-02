// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/CEA/CEA.sol";
import "../../src/CEA/CEAFactory.sol";
import {ICEAProxy} from "../../src/interfaces/ICEAProxy.sol";

// Import CEAProxy with explicit path to avoid Initializable conflict
// CEAProxy uses non-upgradeable Initializable, CEAFactory uses upgradeable
import {CEAProxy} from "../../src/CEA/CEAProxy.sol";
import "../../src/interfaces/ICEA.sol";
import {IUniversalGateway, UniversalTxRequest, RevertInstructions} from "../../src/interfaces/IUniversalGateway.sol";
import {CEAErrors as Errors} from "../../src/libraries/Errors.sol";
import {Target} from "../../src/mocks/Target.sol";
import {MockUniversalGateway} from "../mocks/MockUniversalGateway.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";


contract CEATest is Test {
    // Core contracts
    CEA public ceaImplementation;
    CEAProxy public ceaProxyImplementation;
    CEAFactory public factory;
    ICEA public ceaInstance;

    // Mock contracts
    Target public target;
    MockUniversalGateway public mockUniversalGateway;

    // Test actors
    address public owner;
    address public vault;
    address public ueaOnPush;
    address public universalGateway;
    address public nonVault;

    // Constants
    bytes32 private constant CEA_LOGIC_SLOT = 0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;
    
    function setUp() public {
        // Setup test actors
        owner = address(this); // Test contract as owner
        vault = makeAddr("vault");
        ueaOnPush = makeAddr("ueaOnPush");
        universalGateway = makeAddr("universalGateway");
        nonVault = makeAddr("nonVault");
        
        // Deploy mock contracts
        target = new Target();
        mockUniversalGateway = new MockUniversalGateway();
        
        // Deploy CEA implementation
        ceaImplementation = new CEA();
        
        // Deploy CEAProxy implementation
        ceaProxyImplementation = new CEAProxy();
        
        // Deploy CEAFactory implementation
        CEAFactory factoryImpl = new CEAFactory();
        
        // Deploy and initialize the factory proxy
        bytes memory initData = abi.encodeWithSelector(
            CEAFactory.initialize.selector,
            owner,                      // initialOwner
            vault,                      // initialVault
            address(ceaProxyImplementation), // ceaProxyImplementation
            address(ceaImplementation),      // ceaImplementation
            address(mockUniversalGateway)    // universalGateway
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = CEAFactory(address(proxy));
    }
    
    modifier deployCEA() {
        // Deploy CEA through factory (only vault can do this)
        vm.prank(vault);
        address ceaAddress = factory.deployCEA(ueaOnPush);
        ceaInstance = ICEA(ceaAddress);
        _;
    }


    // =========================================================================
    // Initialize and Setup Tests
    // =========================================================================

    function testInitializeCEA() public deployCEA {
        // Verify initialization
        assertTrue(ceaInstance.isInitialized(), "CEA should be initialized");
        assertEq(ceaInstance.UEA(), ueaOnPush, "UEA should match");
        assertEq(ceaInstance.VAULT(), vault, "VAULT should match");
        
        // Verify event was emitted during deployment (factory calls initializeCEA)
        // Note: The event is emitted during factory.deployCEA, so we verify via state
        address cea = address(ceaInstance);
        assertEq(factory.getUEAForCEA(cea), ueaOnPush, "Factory mapping should be correct");
        (address returnedCEA, bool isDeployed) = factory.getCEAForUEA(ueaOnPush);
        assertEq(returnedCEA, cea, "Factory reverse mapping should be correct");
        assertTrue(isDeployed, "CEA should be marked as deployed");
    }
    
    function testRevertWhenInitializingTwice() public {
        // Deploy a CEA implementation directly (not through factory) for testing
        CEA newCEA = new CEA();
        
        // Initialize once
        newCEA.initializeCEA(ueaOnPush, vault, address(mockUniversalGateway));
        
        // Try to initialize again - should revert
        vm.expectRevert(Errors.AlreadyInitialized.selector);
        newCEA.initializeCEA(ueaOnPush, vault, address(mockUniversalGateway));
    }
    
    function testRevertWhenInitializingWithZeroUEA() public {
        CEA newCEA = new CEA();
        
        vm.expectRevert(Errors.ZeroAddress.selector);
        newCEA.initializeCEA(address(0), vault, address(mockUniversalGateway));
    }
    
    function testRevertWhenInitializingWithZeroVault() public {
        CEA newCEA = new CEA();
        
        vm.expectRevert(Errors.ZeroAddress.selector);
        newCEA.initializeCEA(ueaOnPush, address(0), address(mockUniversalGateway));
    }
    
    function testRevertWhenInitializingWithZeroUniversalGateway() public {
        CEA newCEA = new CEA();
        
        vm.expectRevert(Errors.ZeroAddress.selector);
        newCEA.initializeCEA(ueaOnPush, vault, address(0));
    }
    
    function testIsInitializedBeforeInitialization() public {
        // Deploy CEA implementation directly
        CEA newCEA = new CEA();
        
        // Should return false before initialization
        assertFalse(newCEA.isInitialized(), "CEA should not be initialized before initializeCEA is called");
    }
    
    function testFactoryDeployment() public {
        // Deploy CEA through factory
        vm.prank(vault);
        address ceaAddress = factory.deployCEA(ueaOnPush);
        
        // Verify factory mappings
        assertTrue(factory.isCEA(ceaAddress), "Factory should recognize deployed CEA");
        assertEq(factory.getUEAForCEA(ceaAddress), ueaOnPush, "Factory should map CEA to UEA");
        (address mappedCEA, bool isDeployed) = factory.getCEAForUEA(ueaOnPush);
        assertEq(mappedCEA, ceaAddress, "Factory should map UEA to CEA");
        assertTrue(isDeployed, "Factory should mark CEA as deployed");
    }
    
    function testRevertWhenDeployingCEAAsNonVault() public {
        // Try to deploy CEA as non-vault - should revert
        vm.prank(nonVault);
        vm.expectRevert();
        factory.deployCEA(ueaOnPush);
    }
    
    function testRevertWhenDeployingCEAWithZeroUEA() public {
        // Try to deploy CEA with zero UEA address - should revert
        vm.prank(vault);
        vm.expectRevert();
        factory.deployCEA(address(0));
    }
    
    function testRevertWhenDeployingCEATwice() public {
        // Deploy CEA once
        vm.prank(vault);
        factory.deployCEA(ueaOnPush);
        
        // Try to deploy again - should revert
        vm.prank(vault);
        vm.expectRevert();
        factory.deployCEA(ueaOnPush);
    }
}



