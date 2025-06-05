// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Errors} from "../libraries/Errors.sol";
import {ISmartAccount} from "../Interfaces/ISmartAccount.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {
    VM_TYPE,
    UniversalAccount,
    CrossChainPayload,
    DOMAIN_SEPARATOR_TYPEHASH,
    PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH
} from "../libraries/Types.sol";

/**
 * @title UEA_SVM
 * @dev The contract represents an external SVM(solana) user's account on Push Chain.
 *      It allows for the execution of payloads based on non-EVM signatures.
 *      It uses a native precompile for signature verification of Non-EVM users.
 * @notice Use this contract as implementation logic of a user's Smart Account on Push Chain.
 */
contract UEA_SVM is Initializable, ReentrancyGuard, ISmartAccount {
    using ECDSA for bytes32;

    UniversalAccount id;
    uint256 public nonce;
    string public constant VERSION = "0.1.0";
    address public constant VERIFIER_PRECOMPILE = 0x0000000000000000000000000000000000000901;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Returns the domain separator for EIP-712 signing.
     * @return bytes32 The domain separator.
     */
    function domainSeparator() public view returns (bytes32) {
        uint256 chainId;
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            chainId := chainid()
        }
        /* solhint-enable no-inline-assembly */

        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, keccak256(bytes(VERSION)), chainId, address(this)));
    }

    /**
     * @dev Initializes the contract with the given parameters.
     * @param _UniversalAccount the UniversalAccount struct
     */
    function initialize(UniversalAccount memory _UniversalAccount) external initializer {
        id = _UniversalAccount;
    }

    /**
     * @notice Must be implemented by all Smart Accounts to return the account identifier.
     * @dev Returns the account ID.
     * @return UniversalAccount The account ID.
     */
    function universalAccount() public view returns (UniversalAccount memory) {
        return id;
    }

    /**
     * @dev Verifies the payload signature.
     * @param messageHash The hash of the message to verify.
     * @param signature The signature to verify.
     * @return bool indicating whether the signature is valid.
     */
    function verifyPayloadSignature(bytes32 messageHash, bytes memory signature) public view returns (bool) {
        return _verifySignatureSVM(messageHash, signature);
    }

    /**
     * @dev Verifies the NON-EVM signature using the verifier precompile.
     * @param message The message to verify.
     * @param signature The signature to verify.
     * @return bool indicating whether the signature is valid.
     */
    function _verifySignatureSVM(bytes32 message, bytes memory signature) internal view returns (bool) {
        (bool success, bytes memory result) = VERIFIER_PRECOMPILE.staticcall(
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", id.ownerKey, message, signature)
        );
        if (!success) {
            revert Errors.PrecompileCallFailed();
        }

        return abi.decode(result, (bool));
    }

    /**
     * @dev Executes a payload on the target(to) address with the given data and signature.
     * @param payload The target(to) address to execute the payload on.
     * @param signature The signature to verify the execution.
     */
    function executePayload(CrossChainPayload calldata payload, bytes calldata signature) external nonReentrant {
        bytes32 txHash = getTransactionHash(payload);

        if (!verifyPayloadSignature(txHash, signature)) {
            revert Errors.InvalidSVMSignature();
        }

        unchecked {
            nonce++;
        }

        (bool success, bytes memory returnData) = payload.to.call{value: payload.value}(payload.data);

        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert Errors.ExecutionFailed();
            }
        }

        emit PayloadExecuted(id.ownerKey, payload.to, payload.data);
    }

    function getTransactionHash(CrossChainPayload calldata payload) public view returns (bytes32) {
        if (payload.deadline > 0) {
            if (block.timestamp > payload.deadline) {
                revert Errors.ExpiredDeadline();
            }
        }
        // Calculate the hash of the payload using EIP-712
        bytes32 structHash = keccak256(
            abi.encode(
                PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH,
                payload.to,
                payload.value,
                keccak256(payload.data),
                payload.gasLimit,
                payload.maxFeePerGas,
                payload.maxPriorityFeePerGas,
                nonce,
                payload.deadline
            )
        );

        // Calculate the domain separator using EIP-712
        bytes32 _domainSeparator = domainSeparator();

        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator, structHash));
    }

    // @dev Fallback function to receive ether.
    receive() external payable {}
}
