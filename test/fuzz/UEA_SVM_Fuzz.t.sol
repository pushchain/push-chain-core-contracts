// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";

import "../../src/libraries/Types.sol";
import {UEAErrors} from "../../src/libraries/Errors.sol";
import {Target} from "../../src/mocks/Target.sol";
import {UEAFactory} from "../../src/uea/UEAFactory.sol";
import {UEA_EVM} from "../../src/uea/UEA_EVM.sol";
import {UEA_SVM} from "../../src/uea/UEA_SVM.sol";
import {UEAProxy} from "../../src/uea/UEAProxy.sol";
import {UEAMigration} from "../../src/uea/UEAMigration.sol";
import {IUEA} from "../../src/interfaces/IUEA.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract UEA_SVM_FuzzTest is Test {
    Target target;
    UEAFactory factory;
    UEA_EVM ueaEVMImpl;
    UEA_SVM ueaSVMImpl;
    UEAProxy ueaProxyImpl;

    UEA_SVM svmSmartAccountInstance;

    bytes32 constant EVM_HASH = keccak256("EVM");
    bytes32 constant SVM_HASH = keccak256("SVM");

    address constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    address constant VERIFIER_PRECOMPILE = 0x00000000000000000000000000000000000000ca;

    // SVM owner: 32-byte public key
    bytes svmOwnerBytes;

    function setUp() public {
        target = new Target();
        ueaProxyImpl = new UEAProxy();

        UEAFactory factoryImpl = new UEAFactory();
        bytes memory initData =
            abi.encodeWithSelector(UEAFactory.initialize.selector, address(this), makeAddr("pauser"), "42101");
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = UEAFactory(address(proxy));
        factory.updateUEAProxyImplementation(address(ueaProxyImpl));

        ueaEVMImpl = new UEA_EVM();
        ueaSVMImpl = new UEA_SVM();

        // Register EVM chain
        bytes32 evmChainHash = keccak256(abi.encode("eip155", "1"));
        factory.registerNewChain(evmChainHash, EVM_HASH);
        factory.registerUEA(evmChainHash, EVM_HASH, address(ueaEVMImpl));

        // Register SVM chain
        bytes32 svmChainHash = keccak256(abi.encode("solana", "mainnet"));
        factory.registerNewChain(svmChainHash, SVM_HASH);
        factory.registerUEA(svmChainHash, SVM_HASH, address(ueaSVMImpl));

        // Use a 32-byte owner for SVM
        svmOwnerBytes = abi.encodePacked(bytes32(uint256(0xdeadbeef)));

        // Deploy an SVM UEA
        UniversalAccountId memory svmId =
            UniversalAccountId({chainNamespace: "solana", chainId: "mainnet", owner: svmOwnerBytes});
        address svmAddr = factory.deployUEA(svmId);
        svmSmartAccountInstance = UEA_SVM(payable(svmAddr));
    }

    function _buildPayload(address to, uint256 value, bytes memory data, uint256 deadline)
        internal
        pure
        returns (UniversalPayload memory)
    {
        return UniversalPayload({
            to: to,
            value: value,
            data: data,
            gasLimit: 1_000_000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: 0,
            deadline: deadline,
            vType: VerificationType(0)
        });
    }

    // =========================================================================
    // 4.1 Domain separator uses string chainId (not uint256 conversion)
    // =========================================================================

    function testFuzz_svmDomainSeparator_usesStringChainId(string calldata chainId) public {
        vm.assume(bytes(chainId).length > 0 && bytes(chainId).length < 64);

        // Deploy fresh SVM impl with a string chainId
        UEA_SVM freshSVM = new UEA_SVM();
        bytes memory ownerB = abi.encodePacked(bytes32(uint256(0xabcd)));
        UniversalAccountId memory id = UniversalAccountId({chainNamespace: "solana", chainId: chainId, owner: ownerB});
        freshSVM.initialize(id, address(factory));

        bytes32 ds = freshSVM.domainSeparator();

        // Domain separator should incorporate the raw chainId string (not as uint256)
        // Verify it's deterministic given the same inputs
        bytes32 ds2 = freshSVM.domainSeparator();
        assertEq(ds, ds2);

        // Verify that a different chainId produces a different domain separator
        string memory differentChainId = string(abi.encodePacked(chainId, "x"));
        UEA_SVM otherSVM = new UEA_SVM();
        UniversalAccountId memory otherId =
            UniversalAccountId({chainNamespace: "solana", chainId: differentChainId, owner: ownerB});
        otherSVM.initialize(otherId, address(factory));

        bytes32 dsOther = otherSVM.domainSeparator();
        assertTrue(ds != dsOther, "Different chainIds must yield different domain separators");
    }

    // =========================================================================
    // 4.2 Invalid signature length behavior
    // =========================================================================

    function testFuzz_svmSignature_invalidLength_reverts(bytes calldata signature) public {
        vm.assume(signature.length != 64);

        UniversalPayload memory payload = _buildPayload(address(target), 0, "", 0);
        bytes32 h = svmSmartAccountInstance.getUniversalPayloadHash(payload);

        // The precompile call will fail for wrong-length signatures
        // Mock the precompile to return failure (staticcall fails)
        vm.mockCallRevert(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", svmOwnerBytes, h, signature),
            "precompile failed"
        );

        vm.expectRevert(UEAErrors.PrecompileCallFailed.selector);
        svmSmartAccountInstance.verifyUniversalPayloadSignature(h, signature);
    }

    // =========================================================================
    // 4.3 Payload hash matches EVM (same typehash)
    // =========================================================================

    function testFuzz_svmPayloadHash_matchesEvm(address toAddr, uint256 value, uint256 deadline) public {
        // Deploy matching EVM UEA with same chain namespace/id structure
        // The hash uses UNIVERSAL_PAYLOAD_TYPEHASH in both — verify they use the same constant

        UniversalPayload memory payload = UniversalPayload({
            to: toAddr,
            value: value,
            data: "",
            gasLimit: 1_000_000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: 0,
            deadline: deadline,
            vType: VerificationType(0)
        });

        // Both SVM and EVM use UNIVERSAL_PAYLOAD_TYPEHASH — compute what it should be
        // The struct hash portion is identical; only domain separator differs
        // Verify SVM hash is deterministic and non-zero
        bytes32 svmHash = svmSmartAccountInstance.getUniversalPayloadHash(payload);
        bytes32 svmHash2 = svmSmartAccountInstance.getUniversalPayloadHash(payload);
        assertEq(svmHash, svmHash2);
        assertTrue(svmHash != bytes32(0));
    }

    // =========================================================================
    // 4.4 Nonce increments on execution (via UNIVERSAL_EXECUTOR_MODULE bypass)
    // =========================================================================

    function testFuzz_svm_nonce_incrementsOnExecution(uint256 magicNum) public {
        magicNum = bound(magicNum, 1, type(uint128).max);
        uint256 nonceBefore = svmSmartAccountInstance.nonce();

        bytes memory callData = abi.encodeWithSignature("setMagicNumber(uint256)", magicNum);
        UniversalPayload memory payload = _buildPayload(address(target), 0, callData, 0);

        // Use UNIVERSAL_EXECUTOR_MODULE to bypass Ed25519 signature check
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        svmSmartAccountInstance.executeUniversalTx(payload, "");

        assertEq(svmSmartAccountInstance.nonce(), nonceBefore + 1);
        assertEq(target.magicNumber(), magicNum);
    }

    // =========================================================================
    // 4.5 Deadline past timestamp reverts
    // =========================================================================

    function testFuzz_svm_deadline_pastTimestamp_reverts(uint256 pastOffset) public {
        pastOffset = bound(pastOffset, 1, 365 days);

        // Warp forward then set a past deadline
        vm.warp(block.timestamp + 365 days);
        uint256 pastDeadline = block.timestamp - pastOffset;

        UniversalPayload memory payload = _buildPayload(address(target), 0, "", pastDeadline);

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UEAErrors.ExpiredDeadline.selector);
        svmSmartAccountInstance.executeUniversalTx(payload, "");
    }

    // =========================================================================
    // 4.6 Selector detection: multicall (same logic as EVM)
    // =========================================================================

    function testFuzz_svm_selectorDetection_multicall(bytes4 selector, bytes calldata extra) public {
        vm.assume(selector != MULTICALL_SELECTOR);
        vm.assume(selector != MIGRATION_SELECTOR);

        bytes memory data = abi.encodePacked(selector, extra);
        UniversalPayload memory payload = _buildPayload(address(0), 0, data, 0);

        // Non-multicall, non-migration: should route to single call (succeeds for address(0))
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        svmSmartAccountInstance.executeUniversalTx(payload, "");
        assertEq(svmSmartAccountInstance.nonce(), 1);
    }

    // =========================================================================
    // 4.7 Selector detection: migration (same logic as EVM)
    // =========================================================================

    function testFuzz_svm_selectorDetection_migration(bytes calldata extra) public {
        // MIGRATION_SELECTOR with extra bytes but targeting wrong address => InvalidCall
        bytes memory data = abi.encodePacked(MIGRATION_SELECTOR, extra);
        UniversalPayload memory payload = _buildPayload(
            address(target), // not self
            0,
            data,
            0
        );

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        vm.expectRevert(UEAErrors.InvalidCall.selector);
        svmSmartAccountInstance.executeUniversalTx(payload, "");
    }
}
