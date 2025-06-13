// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/libraries/Types.sol";
import {Target} from "../src/mocks/Target.sol";
import {UEAFactoryV1} from "../src/UEAFactoryV1.sol";
import {UEA_SVM} from "../src/UEA/UEA_SVM.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {IUEA} from "../src/Interfaces/IUEA.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract UEA_SVMTest is Test {
    Target target;
    UEAFactoryV1 factory;
    UEA_SVM svmSmartAccountImpl;
    UEA_SVM svmSmartAccountInstance;

    // VM Hash constants
    bytes32 constant SVM_HASH = keccak256("SVM");

    // Set up the test environment - SVM
    bytes ownerBytes = hex"e48f4e93ca594d3c5e09c3ad39c599bbd6e6a2937869f3456905f5aeb7c78a60"; // Placeholder Solana public key
    address constant VERIFIER_PRECOMPILE = 0x00000000000000000000000000000000000000ca;

    function setUp() public {
        target = new Target();

        // Deploy the factory implementation
        UEAFactoryV1 factoryImpl = new UEAFactoryV1();
        
        // Deploy and initialize the proxy
        bytes memory initData = abi.encodeWithSelector(UEAFactoryV1.initialize.selector, address(this));
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = UEAFactoryV1(address(proxy));

        // Deploy SVM implementation
        svmSmartAccountImpl = new UEA_SVM();

        // Register SVM chain and implementation
        bytes32 svmChainHash = keccak256(abi.encode("SOLANA"));
        factory.registerNewChain(svmChainHash, SVM_HASH);
        factory.registerUEA(svmChainHash, SVM_HASH, address(svmSmartAccountImpl));
    }

    modifier deploySvmSmartAccount() {
        UniversalAccount memory _owner = UniversalAccount({chain: "SOLANA", owner: ownerBytes});

        address smartAccountAddress = factory.deployUEA(_owner);
        svmSmartAccountInstance = UEA_SVM(payable(smartAccountAddress));
        _;
    }

    function testRegisterChain() public view {
        bytes32 svmChainHash = keccak256(abi.encode("SOLANA"));
        (bytes32 vmHash, bool isRegistered) = factory.getVMType(svmChainHash);
        assertEq(vmHash, SVM_HASH);
        assertTrue(isRegistered);
    }

    function testDeployUEA() public deploySvmSmartAccount {
        assertTrue(factory.hasCode(address(svmSmartAccountInstance)));
    }

    function testUniversalAccount() public deploySvmSmartAccount {
        UniversalAccount memory account = svmSmartAccountInstance.universalAccount();
        assertEq(account.chain, "SOLANA");
        assertEq(account.owner, ownerBytes);
    }

    function testMockVerifySignature() public deploySvmSmartAccount {
        bytes32 messageHash = keccak256("test message");
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verifier precompile to return true for this signature
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, messageHash, signature),
            abi.encode(true)
        );

        bool verified = svmSmartAccountInstance.verifyPayloadSignature(messageHash, signature);
        assertTrue(verified);
    }

    function testVerifySignatureFalse() public deploySvmSmartAccount {
        bytes32 messageHash = keccak256("test message");
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verifier precompile to return false for this signature
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, messageHash, signature),
            abi.encode(false)
        );

        bool verified = svmSmartAccountInstance.verifyPayloadSignature(messageHash, signature);
        assertFalse(verified);
    }

    function testVerifySignatureRevert() public deploySvmSmartAccount {
        bytes32 messageHash = keccak256("test message");
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verifier precompile to revert
        vm.mockCallRevert(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, messageHash, signature),
            "Precompile error"
        );

        vm.expectRevert(Errors.PrecompileCallFailed.selector);
        svmSmartAccountInstance.verifyPayloadSignature(messageHash, signature);
    }

    function testExecutionBasic() public deploySvmSmartAccount {
        uint256 previousNonce = svmSmartAccountInstance.nonce();

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            sigType: SignatureType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(true)
        );

        vm.expectEmit(true, true, true, true);
        emit IUEA.PayloadExecuted(ownerBytes, payload.to, payload.data);

        // Execute the payload
        svmSmartAccountInstance.executePayload(payload, signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
        assertEq(previousNonce + 1, svmSmartAccountInstance.nonce(), "Nonce should have incremented");
    }

    // Helper function for UniversalPayload hash
    function getCrosschainTxhash(UEA_SVM _smartAccountInstance, UniversalPayload memory payload)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                UNIVERSAL_PAYLOAD_TYPEHASH,
                payload.to,
                payload.value,
                keccak256(payload.data),
                payload.gasLimit,
                payload.maxFeePerGas,
                payload.maxPriorityFeePerGas,
                _smartAccountInstance.nonce(),
                payload.deadline,
                uint8(payload.sigType)
            )
        );

        // Calculate the domain separator using EIP-712
        bytes32 _domainSeparator = _smartAccountInstance.domainSeparator();

        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator, structHash));
    }
}