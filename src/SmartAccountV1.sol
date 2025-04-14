// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title SmartAccountV1
 * @dev The contract represents an external user's account on Push Chain. 
 *      It allows for the execution of payloads based on EVM and non-EVM signatures.
 *      It uses a native precompile for signature verification of Non-EVM users.
 * @notice Use this contract as implementation logic of a user's Smart Account on Push Chain.
 */

contract SmartAccountV1 is Initializable, ReentrancyGuard {
    using ECDSA for bytes32;

    enum OwnerType {
        EVM,
        NON_EVM
    }

    bytes public ownerKey;
    OwnerType public ownerType;
    address public verifierPrecompile;

    event PayloadExecuted(bytes caller, address target, bytes data);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract with the given parameters.
     * @param _ownerKey The key of the owner (EVM or NON_EVM).
     * @param _ownerType The type of owner (EVM or NON_EVM).
     * @param _verifierPrecompile The address of the verifier precompile contract.
     */
    function initialize(bytes memory _ownerKey, OwnerType _ownerType, address _verifierPrecompile) external initializer {
        ownerKey = _ownerKey;
        ownerType = _ownerType;
        verifierPrecompile = _verifierPrecompile;
    }

    /**
     * @dev Verifies the EVM signature using the ECDSA library.
     * @param messageHash The hash of the message to verify.
     * @param signature The signature to verify.
     * @return bool indicating whether the signature is valid.
     */
    function verifySignatureEVM(bytes32 messageHash, bytes memory signature) internal view returns (bool) {
        address recoveredSigner = messageHash.recover(signature);
        return recoveredSigner == address(bytes20(ownerKey));
    }

    /**
     * @dev Verifies the NON-EVM signature using the verifier precompile.
     * @param messageHash The hash of the message to verify.
     * @param signature The signature to verify.
     * @return bool indicating whether the signature is valid.
     */
    function verifySignature(bytes32 messageHash, bytes memory signature) internal view returns (bool) {
        (bool success, bytes memory result) = verifierPrecompile.staticcall(
            abi.encodeWithSignature("verify(bytes32,bytes,bytes)", messageHash, signature, ownerKey)
        );
        require(success, "Verifier call failed");
        return abi.decode(result, (bool));
    }
    /**
     * @dev Executes a payload on the target address with the given data and signature.
     * @param target The target address to execute the payload on.
     * @param data The data to send to the target address.
     * @param signature The signature to verify the execution.
     */
    function executePayload(address target, bytes calldata data, bytes calldata signature) external nonReentrant {
        bytes32 messageHash = keccak256(data);

        if (ownerType == OwnerType.EVM) {
            require(verifySignatureEVM(messageHash, signature), "Invalid EVM signature");
        } else {
            require(verifySignature(messageHash, signature), "Invalid NON-EVM signature");
        }

        (bool success, ) = target.call(data);
        require(success, "Execution failed");

        emit PayloadExecuted(ownerKey, target, data);
    }
}
