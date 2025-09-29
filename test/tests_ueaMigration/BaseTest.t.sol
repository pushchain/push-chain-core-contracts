// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/libraries/Types.sol";
import {UEAErrors as Errors, CommonErrors} from "../../src/libraries/Errors.sol";

import {UEA_EVM} from "../../src/UEA/UEA_EVM.sol";
import {UEA_SVM} from "../../src/UEA/UEA_SVM.sol";
import {UEAProxy} from "../../src/UEA/UEAProxy.sol";
import {UEAMigration} from "../../src/UEA/UEAMigration.sol";
import {UEAFactoryV1} from "../../src/UEA/UEAFactoryV1.sol";
import {IUEA} from "../../src/Interfaces/IUEA.sol";

import {Target} from "../../src/mocks/Target.sol";
import {UEA_EVM_V2} from "../mocks/UEA_EVM_V2.sol";
import {UEA_SVM_V2} from "../mocks/UEA_SVM_V2.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title   BaseTest
 * @dev     Base test contract providing common setup for UEA Migration tests
 */
contract BaseTest is Test {
    // V1 Implementations (original - version 1.0.0)
    UEA_EVM public ueaEVMImplV1;
    UEA_SVM public ueaSVMImplV1;

    // V2 Implementations (mock - version 2.0.0)
    UEA_EVM_V2 public ueaEVMImplV2;
    UEA_SVM_V2 public ueaSVMImplV2;

    // Proxy and Factory
    UEAProxy public ueaProxyImpl;
    UEAFactoryV1 public factory;

    // Migration Contract
    UEAMigration public migration;

    // Helper/Target Contracts
    Target public target;
    RevertingTarget public revertingTarget;
    SilentRevertingTarget public silentRevertingTarget;
    MaliciousMigrationContract public maliciousMigration;

    // Test Actors
    // Primary test actors
    address public deployer;
    address public owner;
    uint256 public ownerPK;
    bytes public ownerBytes;

    // Secondary test actors
    address public nonOwner;
    uint256 public nonOwnerPK;
    bytes public nonOwnerBytes;

    address public unauthorizedUser;
    uint256 public unauthorizedUserPK;

    // ========================================================================
    // STATE VARIABLES - CONSTANTS & CONFIGURATION
    // ========================================================================

    // VM Hash constants
    bytes32 public constant EVM_HASH = keccak256("EVM");
    bytes32 public constant SVM_HASH = keccak256("SVM");

    // Chain configurations
    string public constant EVM_CHAIN_NAMESPACE = "eip155";
    string public constant EVM_CHAIN_ID = "1";
    string public constant SVM_CHAIN_NAMESPACE = "solana";
    string public constant SVM_CHAIN_ID = "mainnet-beta";

    // Storage slot constant (must match UEAProxy and UEAMigration)
    bytes32 public constant UEA_LOGIC_SLOT = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;

    // Deployed UEA instances for testing
    UEA_EVM public deployedEVMUEA;
    UEA_SVM public deployedSVMUEA;

    // Account IDs for testing
    UniversalAccountId public evmAccountId;
    UniversalAccountId public svmAccountId;

    // Core Set up function
    function setUp() public virtual {
        // Set deployer as the test contract itself
        deployer = address(this);

        // Setup test actors with known private keys
        _setupTestActors();

        // Deploy helper/target contracts
        _deployHelperContracts();

        // Deploy UEA implementations (V1 and V2)
        _deployUEAImplementations();

        // Deploy and setup factory
        _deployAndSetupFactory();

        // Deploy migration contract
        _deployMigrationContract();

        // Setup chain registrations
        _setupChainRegistrations();

        // Create test account IDs
        _createTestAccountIds();

        // Deploy test UEA instances
        _deployTestUEAInstances();
    }

    // Internal setup functions
    /**
     * @dev Setup test actors with deterministic addresses and private keys
     */
    function _setupTestActors() internal {
        // Primary owner
        (owner, ownerPK) = makeAddrAndKey("owner");
        ownerBytes = abi.encodePacked(owner);

        // Secondary owner (for cross-testing)
        (nonOwner, nonOwnerPK) = makeAddrAndKey("nonOwner");
        nonOwnerBytes = abi.encodePacked(nonOwner);

        // Unauthorized user
        (unauthorizedUser, unauthorizedUserPK) = makeAddrAndKey("unauthorizedUser");

        // Fund test accounts with ETH
        vm.deal(owner, 100 ether);
        vm.deal(nonOwner, 100 ether);
        vm.deal(unauthorizedUser, 100 ether);
        vm.deal(deployer, 100 ether);
    }

    /**
     * @dev Deploy helper contracts used in tests
     */
    function _deployHelperContracts() internal {
        target = new Target();
        revertingTarget = new RevertingTarget();
        silentRevertingTarget = new SilentRevertingTarget();
        maliciousMigration = new MaliciousMigrationContract();
    }

    /**
     * @dev Deploy all UEA implementations (V1 and V2)
     */
    function _deployUEAImplementations() internal {
        // Deploy V1 implementations
        ueaEVMImplV1 = new UEA_EVM();
        ueaSVMImplV1 = new UEA_SVM();

        // Deploy V2 implementations
        ueaEVMImplV2 = new UEA_EVM_V2();
        ueaSVMImplV2 = new UEA_SVM_V2();

        // Verify versions are correct
        assertEq(ueaEVMImplV1.VERSION(), "1.0.0", "EVM V1 version mismatch");
        assertEq(ueaSVMImplV1.VERSION(), "1.0.0", "SVM V1 version mismatch");
        assertEq(ueaEVMImplV2.VERSION(), "2.0.0", "EVM V2 version mismatch");
        assertEq(ueaSVMImplV2.VERSION(), "2.0.0", "SVM V2 version mismatch");
    }

    function _deployAndSetupFactory() internal {
        ueaProxyImpl = new UEAProxy();

        UEAFactoryV1 factoryImpl = new UEAFactoryV1();

        bytes memory initData = abi.encodeWithSelector(UEAFactoryV1.initialize.selector, deployer);
        ERC1967Proxy factoryProxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = UEAFactoryV1(address(factoryProxy));

        // Set UEA proxy implementation in factory
        factory.setUEAProxyImplementation(address(ueaProxyImpl));
    }

    function _deployMigrationContract() internal {
        migration = new UEAMigration(address(ueaEVMImplV2), address(ueaSVMImplV2));

        assertEq(migration.UEA_EVM_IMPLEMENTATION(), address(ueaEVMImplV2), "Migration EVM implementation mismatch");
        assertEq(migration.UEA_SVM_IMPLEMENTATION(), address(ueaSVMImplV2), "Migration SVM implementation mismatch");
    }

    function _setupChainRegistrations() internal {
        // Register EVM chain
        bytes32 evmChainHash = keccak256(abi.encode(EVM_CHAIN_NAMESPACE, EVM_CHAIN_ID));
        factory.registerNewChain(evmChainHash, EVM_HASH);
        factory.registerUEA(evmChainHash, EVM_HASH, address(ueaEVMImplV1));

        // Register SVM chain
        bytes32 svmChainHash = keccak256(abi.encode(SVM_CHAIN_NAMESPACE, SVM_CHAIN_ID));
        factory.registerNewChain(svmChainHash, SVM_HASH);
        factory.registerUEA(svmChainHash, SVM_HASH, address(ueaSVMImplV1));
    }

    /**
     * @dev Create test account IDs for EVM and SVM
     */
    function _createTestAccountIds() internal {
        evmAccountId =
            UniversalAccountId({chainNamespace: EVM_CHAIN_NAMESPACE, chainId: EVM_CHAIN_ID, owner: ownerBytes});

        // For SVM, we need a 32-byte public key format
        bytes memory svmOwnerBytes = abi.encodePacked(
            bytes32(uint256(uint160(owner))) // Convert address to 32-byte format
        );

        svmAccountId =
            UniversalAccountId({chainNamespace: SVM_CHAIN_NAMESPACE, chainId: SVM_CHAIN_ID, owner: svmOwnerBytes});
    }

    /**
     * @dev Deploy test UEA instances through factory
     */
    function _deployTestUEAInstances() internal {
        // Deploy EVM UEA
        address evmUEAAddress = factory.deployUEA(evmAccountId);
        deployedEVMUEA = UEA_EVM(payable(evmUEAAddress));

        // Deploy SVM UEA
        address svmUEAAddress = factory.deployUEA(svmAccountId);
        deployedSVMUEA = UEA_SVM(payable(svmUEAAddress));

        // Fund deployed UEAs for testing
        vm.deal(address(deployedEVMUEA), 10 ether);
        vm.deal(address(deployedSVMUEA), 10 ether);
    }

    // ========================================================================
    // HELPER FUNCTIONS FOR MIGRATION TESTING
    // ========================================================================

    function createEVMMigrationPayload(uint256 nonce, uint256 deadline) public view returns (MigrationPayload memory) {
        return MigrationPayload({migration: address(migration), nonce: nonce, deadline: deadline});
    }

    function createSVMMigrationPayload(uint256 nonce, uint256 deadline) public view returns (MigrationPayload memory) {
        return MigrationPayload({migration: address(migration), nonce: nonce, deadline: deadline});
    }

    // Helper functions for signing migration payloads
    function signEVMMigrationPayload(UEA_EVM ueaInstance, MigrationPayload memory payload, uint256 signerPK)
        public
        view
        returns (bytes memory signature)
    {
        bytes32 payloadHash = ueaInstance.getMigrationPayloadHash(payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPK, payloadHash);
        return abi.encodePacked(r, s, v);
    }

    function createMockSVMSignature() public pure returns (bytes memory signature) {
        // Return a 64-byte mock signature for Ed25519
        return abi.encodePacked(
            bytes32(0x1111111111111111111111111111111111111111111111111111111111111111),
            bytes32(0x2222222222222222222222222222222222222222222222222222222222222222)
        );
    }

    function getCurrentImplementation(address ueaProxy) public view returns (address impl) {
        bytes32 slot = UEA_LOGIC_SLOT;
        bytes32 raw = vm.load(ueaProxy, slot);
        return address(uint160(uint256(raw)));
    }

    function hasCode(address account) public view returns (bool codeExists) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /**
     * @dev Create a universal payload for testing
     * @param to Target address
     * @param value ETH value to send
     * @param data Call data
     * @param nonce Transaction nonce
     * @param deadline Transaction deadline
     * @param vType Verification type
     * @return payload Universal payload struct
     */
    function createUniversalPayload(
        address to,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 deadline,
        VerificationType vType
    ) public pure returns (UniversalPayload memory payload) {
        return UniversalPayload({
            to: to,
            value: value,
            data: data,
            gasLimit: 1000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: nonce,
            deadline: deadline,
            vType: vType
        });
    }

    // Assertion helpers

    function assertMigrationSuccess(address ueaProxy, address expectedImpl) public {
        address currentImpl = getCurrentImplementation(ueaProxy);
        assertEq(currentImpl, expectedImpl, "Migration did not update implementation correctly");
    }

    function assertStatePreserved(address ueaProxy, UniversalAccountId memory expectedAccount, uint256 expectedNonce)
        public
    {
        IUEA uea = IUEA(ueaProxy);
        UniversalAccountId memory currentAccount = uea.universalAccount();

        assertEq(currentAccount.chainNamespace, expectedAccount.chainNamespace, "Chain namespace not preserved");
        assertEq(currentAccount.chainId, expectedAccount.chainId, "Chain ID not preserved");
        assertEq(keccak256(currentAccount.owner), keccak256(expectedAccount.owner), "Owner not preserved");

        // Note: For nonce checking, we need to call through the specific implementation
        // since the interface might not expose nonce directly
        // This would be verified in the actual test implementations
    }

    // Base setup verification tests

    /**
     * @dev Verify all core contracts are properly deployed
     */
    function testBaseSetupCompleted() public {
        // Verify all core contracts are deployed
        assertTrue(address(ueaEVMImplV1) != address(0), "UEA EVM V1 not deployed");
        assertTrue(address(ueaSVMImplV1) != address(0), "UEA SVM V1 not deployed");
        assertTrue(address(ueaEVMImplV2) != address(0), "UEA EVM V2 not deployed");
        assertTrue(address(ueaSVMImplV2) != address(0), "UEA SVM V2 not deployed");
        assertTrue(address(ueaProxyImpl) != address(0), "UEA Proxy not deployed");
        assertTrue(address(factory) != address(0), "Factory not deployed");
        assertTrue(address(migration) != address(0), "Migration contract not deployed");

        // Verify helper contracts are deployed
        assertTrue(address(target) != address(0), "Target contract not deployed");
        assertTrue(address(revertingTarget) != address(0), "Reverting target not deployed");
        assertTrue(address(silentRevertingTarget) != address(0), "Silent reverting target not deployed");
        assertTrue(address(maliciousMigration) != address(0), "Malicious migration not deployed");
    }

    /**
     * @dev Verify all implementation versions are correct
     */
    function testVersions() public {
        // Verify V1 implementations have correct versions
        assertEq(ueaEVMImplV1.VERSION(), "1.0.0", "EVM V1 version incorrect");
        assertEq(ueaSVMImplV1.VERSION(), "1.0.0", "SVM V1 version incorrect");

        // Verify V2 implementations have correct versions
        assertEq(ueaEVMImplV2.VERSION(), "2.0.0", "EVM V2 version incorrect");
        assertEq(ueaSVMImplV2.VERSION(), "2.0.0", "SVM V2 version incorrect");
    }

    /**
     * @dev Verify migration contract setup and security
     */
    function testMigrationContractSetup() public {
        // Verify migration contract has correct implementations set
        assertEq(migration.UEA_EVM_IMPLEMENTATION(), address(ueaEVMImplV2), "Migration EVM implementation incorrect");
        assertEq(migration.UEA_SVM_IMPLEMENTATION(), address(ueaSVMImplV2), "Migration SVM implementation incorrect");

        // Verify migration contract prevents direct calls
        vm.expectRevert(CommonErrors.Unauthorized.selector);
        migration.migrateUEAEVM();

        vm.expectRevert(CommonErrors.Unauthorized.selector);
        migration.migrateUEASVM();
    }

    /**
     * @dev Verify test actors are properly configured
     */
    function testTestActors() public {
        // Verify test actors are set up
        assertTrue(owner != address(0), "Owner not set");
        assertTrue(nonOwner != address(0), "NonOwner not set");
        assertTrue(unauthorizedUser != address(0), "Unauthorized user not set");
        assertTrue(ownerPK != 0, "Owner PK not set");
        assertTrue(nonOwnerPK != 0, "NonOwner PK not set");
        assertTrue(unauthorizedUserPK != 0, "Unauthorized user PK not set");

        // Verify actors have ETH
        assertGe(owner.balance, 100 ether, "Owner has insufficient balance");
        assertGe(nonOwner.balance, 100 ether, "NonOwner has insufficient balance");
        assertGe(unauthorizedUser.balance, 100 ether, "Unauthorized user has insufficient balance");
    }

    /**
     * @dev Verify deployed UEA instances are properly configured
     */
    function testDeployedUEAs() public {
        // Verify UEA instances are deployed
        assertTrue(address(deployedEVMUEA) != address(0), "EVM UEA not deployed");
        assertTrue(address(deployedSVMUEA) != address(0), "SVM UEA not deployed");

        // Verify UEAs have correct account IDs
        UniversalAccountId memory evmAccount = deployedEVMUEA.universalAccount();
        assertEq(evmAccount.chainNamespace, EVM_CHAIN_NAMESPACE, "EVM chain namespace incorrect");
        assertEq(evmAccount.chainId, EVM_CHAIN_ID, "EVM chain ID incorrect");
        assertEq(keccak256(evmAccount.owner), keccak256(ownerBytes), "EVM owner incorrect");

        UniversalAccountId memory svmAccount = deployedSVMUEA.universalAccount();
        assertEq(svmAccount.chainNamespace, SVM_CHAIN_NAMESPACE, "SVM chain namespace incorrect");
        assertEq(svmAccount.chainId, SVM_CHAIN_ID, "SVM chain ID incorrect");

        // Verify UEAs have ETH
        assertGe(address(deployedEVMUEA).balance, 10 ether, "EVM UEA has insufficient balance");
        assertGe(address(deployedSVMUEA).balance, 10 ether, "SVM UEA has insufficient balance");
    }

    /**
     * @dev Verify factory setup and chain registrations
     */
    function testFactorySetup() public {
        // Verify factory has correct proxy implementation
        bytes32 evmChainHash = keccak256(abi.encode(EVM_CHAIN_NAMESPACE, EVM_CHAIN_ID));
        bytes32 svmChainHash = keccak256(abi.encode(SVM_CHAIN_NAMESPACE, SVM_CHAIN_ID));

        // Verify chain registrations
        assertEq(address(factory.getUEA(evmChainHash)), address(ueaEVMImplV1), "EVM implementation not registered");
        assertEq(address(factory.getUEA(svmChainHash)), address(ueaSVMImplV1), "SVM implementation not registered");
    }

    /**
     * @dev Verify deployed UEAs use correct initial implementations
     */
    function testCurrentImplementations() public {
        // Verify deployed UEAs use V1 implementations
        address evmCurrentImpl = getCurrentImplementation(address(deployedEVMUEA));
        address svmCurrentImpl = getCurrentImplementation(address(deployedSVMUEA));

        assertEq(evmCurrentImpl, address(ueaEVMImplV1), "EVM UEA not using V1 implementation");
        assertEq(svmCurrentImpl, address(ueaSVMImplV1), "SVM UEA not using V1 implementation");
    }

    /**
     * @dev Verify helper functions work correctly
     */
    function testHelperFunctions() public {
        // Test createEVMMigrationPayload
        MigrationPayload memory payload = createEVMMigrationPayload(0, block.timestamp + 1000);
        assertEq(payload.migration, address(migration), "Migration payload address incorrect");
        assertEq(payload.nonce, 0, "Migration payload nonce incorrect");
        assertEq(payload.deadline, block.timestamp + 1000, "Migration payload deadline incorrect");

        // Test hasCode function
        assertTrue(hasCode(address(ueaEVMImplV1)), "Should detect code in implementation");
        assertFalse(hasCode(address(0)), "Should not detect code at zero address");

        // Test mock SVM signature creation
        bytes memory mockSig = createMockSVMSignature();
        assertEq(mockSig.length, 64, "Mock SVM signature should be 64 bytes");
    }

    /**
     * @dev Verify target contract functionality
     */
    function testTargetContract() public {
        // Test target contract functionality
        assertEq(target.getMagicNumber(), 0, "Target should start with magic number 0");

        target.setMagicNumber(42);
        assertEq(target.getMagicNumber(), 42, "Target magic number should be updated");

        // Test target with fee
        vm.deal(address(this), 1 ether);
        target.setMagicNumberWithFee{value: 0.1 ether}(100);
        assertEq(target.getMagicNumber(), 100, "Target magic number should be updated with fee");
    }

    /**
     * @dev Verify reverting helper contracts work correctly
     */
    function testRevertingContracts() public {
        // Test reverting target
        vm.expectRevert("This function always reverts with reason");
        revertingTarget.revertWithReason();

        // Test silent reverting target
        vm.expectRevert();
        silentRevertingTarget.revertSilently();

        // Test malicious migration
        vm.expectRevert("Malicious migration contract");
        maliciousMigration.migrateUEAEVM();

        vm.expectRevert("Malicious migration contract");
        maliciousMigration.migrateUEASVM();
    }

    /**
     * @dev Verify storage slot constant is correct
     */
    function testStorageSlotConstant() public {
        // Verify UEA_LOGIC_SLOT matches between contracts
        bytes32 expectedSlot = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;
        assertEq(UEA_LOGIC_SLOT, expectedSlot, "UEA_LOGIC_SLOT constant incorrect");

        // Verify it matches the calculated value
        bytes32 calculatedSlot = bytes32(uint256(keccak256("uea.proxy.implementation")) - 1);
        assertEq(UEA_LOGIC_SLOT, calculatedSlot, "UEA_LOGIC_SLOT doesn't match calculated value");
    }
}

// ========================================================================
// HELPER CONTRACTS FOR TESTING
// ========================================================================

/**
 * @dev Helper contract that always reverts with a reason
 */
contract RevertingTarget {
    function revertWithReason() external pure {
        revert("This function always reverts with reason");
    }
}

/**
 * @dev Helper contract that reverts silently (no reason)
 */
contract SilentRevertingTarget {
    function revertSilently() external pure {
        assembly {
            revert(0, 0)
        }
    }
}

/**
 * @dev Malicious migration contract for testing security
 */
contract MaliciousMigrationContract {
    function migrateUEAEVM() external {
        revert("Malicious migration contract");
    }

    function migrateUEASVM() external {
        revert("Malicious migration contract");
    }
}
