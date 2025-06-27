// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Errors} from "../libraries/Errors.sol";
import {IUEA} from "../Interfaces/IUEA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {StringUtils} from "../libraries/Utils.sol";
import {UniversalAccountId, UniversalPayload, VerificationType, UNIVERSAL_PAYLOAD_TYPEHASH} from "../libraries/Types.sol";
/**
 * @title UEA_SVM (Universal Executor Account for SVM)
 * @dev Implementation of the IUEA interface for SVM-based external accounts.
 *      This contract handles verification and execution of cross-chain payloads
 *      using Ed25519 signatures from Solana accounts.
 * @notice Use this contract as implementation logic for SVM-based UEAs.
 */

contract UEA_SVM is ReentrancyGuard, IUEA {
    // @notice The Universal Account information
    UniversalAccountId internal id;
    // @notice Flag to track initialization status
    bool private initialized;
    // @notice The nonce for the UEA
    uint256 public nonce;
    // @notice The version of the UEA
    string public constant VERSION = "0.1.0";
    // @notice The verifier precompile address
    address public constant VERIFIER_PRECOMPILE = 0x00000000000000000000000000000000000000ca;
    // @notice Precompile address for TxHash Based Verification
    address public constant TX_BASED_VERIFIER = 0x0000000000000000000000000000000000000901;
    // @notice Hash of keccak256("EIP712Domain_SVM(string version,string chainId,address verifyingContract)")
    bytes32 constant DOMAIN_SEPARATOR_TYPEHASH_SVM = 0x3aefc31558906b9b2c54de94f82a9b2455c24b4ba2b642ebb545ea2cc64a1e4b;

    /**
     * @dev Returns the domain separator for EIP-712 signing.
     * @return bytes32 The domain separator.
     */
    function domainSeparator() public view returns (bytes32) {
        return
            keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH_SVM, keccak256(bytes(VERSION)), id.chainId, address(this)));
    }

    /**
     * @inheritdoc IUEA
     */
    function initialize(UniversalAccountId memory _id) external {
        if (initialized) {
            revert Errors.AlreadyInitialized();
        }
        initialized = true;

        id = _id;
    }

    /**
     * @inheritdoc IUEA
     */
    function universalAccount() public view returns (UniversalAccountId memory) {
        return id;
    }

    /**
     * @inheritdoc IUEA
     */
    function verifyPayloadSignature(bytes32 messageHash, bytes memory signature) public view returns (bool) {
        return _verifySignatureSVM(messageHash, signature);
    }

    /**
     * @dev Verifies the SVM signature using the verifier precompile.
     * @param message The message to verify.
     * @param signature The signature to verify.
     * @return bool indicating whether the signature is valid.
     */
    function _verifySignatureSVM(bytes32 message, bytes memory signature) internal view returns (bool) {
        (bool success, bytes memory result) = VERIFIER_PRECOMPILE.staticcall(
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", id.owner, message, signature)
        );
        if (!success) {
            revert Errors.PrecompileCallFailed();
        }

        return abi.decode(result, (bool));
    }

    /**
     * @dev Verifies the SVM signature using the verifier precompile.
     *      This function is used to verify the signature of the payload using the verifier precompile.
     *      It is used when the payload is verified using the txHash.
     * @param payload The payload to verify.
     * @param txHash The transaction hash to verify.
     * @return bool indicating whether the signature is valid.
     */
    function verifyPayloadTxHash(UniversalPayload calldata payload, bytes calldata txHash) public view returns (bool) {
        (bool success, bytes memory result) = TX_BASED_VERIFIER.staticcall(
            abi.encodeWithSignature("verifyTxHash(UniversalPayload,bytes)", payload, txHash)
        );
        if (!success) {
            revert Errors.PrecompileCallFailed();
        }

        return abi.decode(result, (bool));
    }

    /**
     * @inheritdoc IUEA
     */
    function executePayload(UniversalPayload calldata payload, bytes calldata signature, bytes calldata payloadTxHash) external nonReentrant {
        bytes32 txHash = getTransactionHash(payload);

        if (payload.vType == VerificationType.universalTxVerification) {
            if (payloadTxHash.length == 0 || !verifyPayloadTxHash(payload, payloadTxHash)) {
                revert Errors.InvalidTxHash();
            }
        } else {
            if (!verifyPayloadSignature(txHash, signature)) {
                revert Errors.InvalidSVMSignature();
            }
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

        emit PayloadExecuted(id.owner, payload.to, payload.data);
    }

    /**
     * @dev Calculates the transaction hash for a given payload.
     * @param payload The payload to calculate the hash for.
     * @return bytes32 The transaction hash.
     */
    function getTransactionHash(UniversalPayload calldata payload) public view returns (bytes32) {
        if (payload.deadline > 0) {
            if (block.timestamp > payload.deadline) {
                revert Errors.ExpiredDeadline();
            }
        }
        // Calculate the hash of the payload using EIP-712
        bytes32 structHash = keccak256(
            abi.encode(
                UNIVERSAL_PAYLOAD_TYPEHASH,
                payload.to,
                payload.value,
                keccak256(payload.data),
                payload.gasLimit,
                payload.maxFeePerGas,
                payload.maxPriorityFeePerGas,
                nonce,
                payload.deadline,
                uint8(payload.vType)
            )
        );

        // Calculate the domain separator using EIP-712
        bytes32 _domainSeparator = domainSeparator();

        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator, structHash));
    }

    /**
     * @dev Fallback function to receive ether.
     */
    receive() external payable {}
}
