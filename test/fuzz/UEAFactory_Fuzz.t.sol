// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";

import {UEAFactory} from "../../src/uea/UEAFactory.sol";
import {UEA_EVM} from "../../src/uea/UEA_EVM.sol";
import {UEAProxy} from "../../src/uea/UEAProxy.sol";
import {UEAErrors} from "../../src/libraries/Errors.sol";
import {UniversalAccountId} from "../../src/libraries/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract UEAFactory_Fuzz is Test {
    UEAFactory factory;
    UEA_EVM ueaEVMImpl;
    UEAProxy ueaProxyImpl;

    bytes32 constant EVM_HASH = keccak256("EVM");
    string constant CHAIN_NS = "eip155";
    string constant CHAIN_ID = "1";

    function setUp() public {
        ueaProxyImpl = new UEAProxy();
        UEAFactory factoryImpl = new UEAFactory();
        bytes memory initData = abi.encodeWithSelector(UEAFactory.initialize.selector, address(this));
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = UEAFactory(address(proxy));
        factory.setUEAProxyImplementation(address(ueaProxyImpl));
        ueaEVMImpl = new UEA_EVM();
        bytes32 evmChainHash = keccak256(abi.encode(CHAIN_NS, CHAIN_ID));
        factory.registerNewChain(evmChainHash, EVM_HASH);
        factory.registerUEA(evmChainHash, EVM_HASH, address(ueaEVMImpl));
    }

    // =============================================
    // 5.1 Deterministic Address Properties
    // =============================================

    function testFuzz_computeUEA_deterministic(address fuzzedOwner) public {
        vm.assume(fuzzedOwner != address(0));
        UniversalAccountId memory id = UniversalAccountId({
            chainNamespace: CHAIN_NS,
            chainId: CHAIN_ID,
            owner: abi.encodePacked(fuzzedOwner)
        });

        address result1 = factory.computeUEA(id);
        address result2 = factory.computeUEA(id);

        assertEq(result1, result2);
        assertTrue(result1 != address(0));
    }

    function testFuzz_computeUEA_matchesDeployUEA(address fuzzedOwner) public {
        vm.assume(fuzzedOwner != address(0));
        UniversalAccountId memory id = UniversalAccountId({
            chainNamespace: CHAIN_NS,
            chainId: CHAIN_ID,
            owner: abi.encodePacked(fuzzedOwner)
        });

        address computed = factory.computeUEA(id);
        address deployed = factory.deployUEA(id);

        assertEq(computed, deployed);
    }

    function testFuzz_differentIds_differentAddresses(address owner1, address owner2) public {
        vm.assume(owner1 != owner2);
        vm.assume(owner1 != address(0));
        vm.assume(owner2 != address(0));

        UniversalAccountId memory id1 = UniversalAccountId({
            chainNamespace: CHAIN_NS,
            chainId: CHAIN_ID,
            owner: abi.encodePacked(owner1)
        });
        UniversalAccountId memory id2 = UniversalAccountId({
            chainNamespace: CHAIN_NS,
            chainId: CHAIN_ID,
            owner: abi.encodePacked(owner2)
        });

        address addr1 = factory.computeUEA(id1);
        address addr2 = factory.computeUEA(id2);

        assertNotEq(addr1, addr2);
    }

    // =============================================
    // 5.2 Salt Generation Properties
    // =============================================

    function testFuzz_generateSalt_deterministic(address fuzzedOwner) public {
        vm.assume(fuzzedOwner != address(0));
        UniversalAccountId memory id = UniversalAccountId({
            chainNamespace: CHAIN_NS,
            chainId: CHAIN_ID,
            owner: abi.encodePacked(fuzzedOwner)
        });

        bytes32 salt1 = factory.generateSalt(id);
        bytes32 salt2 = factory.generateSalt(id);

        assertEq(salt1, salt2);
    }

    function testFuzz_generateSalt_uniqueness(address owner1, address owner2) public {
        vm.assume(owner1 != owner2);
        vm.assume(owner1 != address(0));
        vm.assume(owner2 != address(0));

        UniversalAccountId memory id1 = UniversalAccountId({
            chainNamespace: CHAIN_NS,
            chainId: CHAIN_ID,
            owner: abi.encodePacked(owner1)
        });
        UniversalAccountId memory id2 = UniversalAccountId({
            chainNamespace: CHAIN_NS,
            chainId: CHAIN_ID,
            owner: abi.encodePacked(owner2)
        });

        bytes32 salt1 = factory.generateSalt(id1);
        bytes32 salt2 = factory.generateSalt(id2);

        assertNotEq(salt1, salt2);
    }

    // =============================================
    // 5.3 Deployment Properties
    // =============================================

    function testFuzz_deployUEA_hasCode(address fuzzedOwner) public {
        vm.assume(fuzzedOwner != address(0));
        UniversalAccountId memory id = UniversalAccountId({
            chainNamespace: CHAIN_NS,
            chainId: CHAIN_ID,
            owner: abi.encodePacked(fuzzedOwner)
        });

        address deployed = factory.deployUEA(id);

        assertTrue(factory.hasCode(deployed));
    }

    function testFuzz_deployUEA_secondCall_reverts(address fuzzedOwner) public {
        vm.assume(fuzzedOwner != address(0));
        UniversalAccountId memory id = UniversalAccountId({
            chainNamespace: CHAIN_NS,
            chainId: CHAIN_ID,
            owner: abi.encodePacked(fuzzedOwner)
        });

        factory.deployUEA(id);

        // Second call reverts because Clones.cloneDeterministic fails on already-deployed address
        vm.expectRevert();
        factory.deployUEA(id);
    }

    function testFuzz_deployUEA_mappingConsistency(address fuzzedOwner) public {
        vm.assume(fuzzedOwner != address(0));
        UniversalAccountId memory id = UniversalAccountId({
            chainNamespace: CHAIN_NS,
            chainId: CHAIN_ID,
            owner: abi.encodePacked(fuzzedOwner)
        });

        address deployed = factory.deployUEA(id);

        // getOriginForUEA should return isUEA = true
        (, bool isUEA) = factory.getOriginForUEA(deployed);
        assertTrue(isUEA);

        // getUEAForOrigin should return the deployed address and isDeployed = true
        (address ueaAddr, bool isDeployed) = factory.getUEAForOrigin(id);
        assertEq(ueaAddr, deployed);
        assertTrue(isDeployed);
    }

    // =============================================
    // 5.4 Lookup Properties
    // =============================================

    function testFuzz_getOriginForUEA_unknownAddress_returnsFalse(address random) public {
        // Exclude addresses that could be UEAs from factory deployments
        // Since no deployments happened with this address, isUEA must be false
        (, bool isUEA) = factory.getOriginForUEA(random);
        assertFalse(isUEA);
    }

    function testFuzz_getUEAForOrigin_undeployed_returnsNotDeployed(address fuzzedOwner) public {
        vm.assume(fuzzedOwner != address(0));
        UniversalAccountId memory id = UniversalAccountId({
            chainNamespace: CHAIN_NS,
            chainId: CHAIN_ID,
            owner: abi.encodePacked(fuzzedOwner)
        });

        (address uea, bool isDeployed) = factory.getUEAForOrigin(id);

        // Address is still predictable (not zero)
        assertTrue(uea != address(0));
        // But not yet deployed
        assertFalse(isDeployed);
    }

    // =============================================
    // 5.5 Chain Registration Properties
    // =============================================

    function testFuzz_registerNewChain_nonOwner_reverts(address caller) public {
        vm.assume(caller != address(this));
        vm.assume(caller != address(0));

        bytes32 chainHash = keccak256(abi.encode("fuzzchain", "999"));

        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, caller)
        );
        factory.registerNewChain(chainHash, EVM_HASH);
    }

    function testFuzz_deployUEA_unregisteredChain_reverts(address fuzzedOwner) public {
        vm.assume(fuzzedOwner != address(0));

        // Use a chain that is NOT registered in setUp
        UniversalAccountId memory id = UniversalAccountId({
            chainNamespace: "unregistered",
            chainId: "9999",
            owner: abi.encodePacked(fuzzedOwner)
        });

        vm.expectRevert(UEAErrors.InvalidInputArgs.selector);
        factory.deployUEA(id);
    }
}
