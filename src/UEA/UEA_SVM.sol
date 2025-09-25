// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UEAErrors as Errors} from "../libraries/Errors.sol";
import {IUEA} from "../Interfaces/IUEA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {StringUtils} from "../libraries/Utils.sol";
import {
    UniversalAccountId,
    UniversalPayload,
    MigrationPayload,
    VerificationType,
    UNIVERSAL_PAYLOAD_TYPEHASH,
    MIGRATION_PAYLOAD_TYPEHASH,
    MULTICALL_SELECTOR,
    Multicall
} from "../libraries/Types.sol";
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
    address public constant TX_BASED_VERIFIER = 0x00000000000000000000000000000000000000CB;
    // @notice Hash of keccak256("EIP712Domain_SVM(string version,string chainId,address verifyingContract)")
    bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH_SVM =
        0x3aefc31558906b9b2c54de94f82a9b2455c24b4ba2b642ebb545ea2cc64a1e4b;

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
            revert Errors.AccountAlreadyExists();
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
    function verifyPayloadSignature(bytes32 payloadHash, bytes memory signature) public view returns (bool) {
        return _verifySignatureSVM(payloadHash, signature);
    }

    /**
     * @dev Verifies the SVM signature using the verifier precompile.
     * @param payloadHash The payload hash to verify.
     * @param signature The signature to verify.
     * @return bool indicating whether the signature is valid.
     */
    function _verifySignatureSVM(bytes32 payloadHash, bytes memory signature) internal view returns (bool) {
        (bool success, bytes memory result) = VERIFIER_PRECOMPILE.staticcall(
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", id.owner, payloadHash, signature)
        );
        if (!success) {
            revert Errors.PrecompileCallFailed();
        }

        return abi.decode(result, (bool));
    }

    function verifyPayloadTxHash(bytes32 payloadHash, bytes calldata txHash) public view returns (bool) {
        (bool success, bytes memory result) = TX_BASED_VERIFIER.staticcall(
            abi.encodeWithSignature(
                "verifyTxHash(string,string,bytes,bytes32,bytes)",
                id.chainNamespace,
                id.chainId,
                id.owner,
                payloadHash,
                txHash
            )
        );
        if (!success) {
            revert Errors.PrecompileCallFailed();
        }

        return abi.decode(result, (bool));
    }

    /**
     * @dev Checks whether the payload data uses the multicall format by verifying a magic selector prefix.
     * @param data The raw calldata from the UniversalPayload.
     * @return bool Returns true if the data starts with the MULTICALL_SELECTOR, indicating a multicall batch.
     */
    function isMulticall(bytes calldata data) internal pure returns (bool) {
        if (data.length < 4) return false;
        return bytes4(data[:4]) == MULTICALL_SELECTOR;
    }

    /**
     * @dev Decodes the payload data into an array of Call structs, assuming the data uses the multicall format.
     * @notice This function assumes that isMulticall(data) has already returned true.
     * @param data The raw calldata containing the MULTICALL_SELECTOR followed by the ABI-encoded Call[].
     * @return Call[] The decoded array of Call structs to be executed.
     */
    function decodeCalls(bytes calldata data) internal pure returns (Multicall[] memory) {
        return abi.decode(data[4:], (Multicall[])); // Strip selector
    }

    /**
     * @inheritdoc IUEA
     */
    function executePayload(UniversalPayload calldata payload, bytes calldata verificationData) external nonReentrant {
        bytes32 payloadHash = getPayloadHash(payload);

        if (payload.vType == VerificationType.universalTxVerification) {
            if (verificationData.length == 0 || !verifyPayloadTxHash(payloadHash, verificationData)) {
                revert Errors.InvalidTxHash();
            }
        } else {
            if (!verifyPayloadSignature(payloadHash, verificationData)) {
                revert Errors.InvalidSVMSignature();
            }
        }

        unchecked {
            nonce++;
        }

        // flag to overwrite success
        bool success;
        bytes memory returnData;

        // Execute the payload: either single call or multicall batch
        if (isMulticall(payload.data)) {
            Multicall[] memory calls = decodeCalls(payload.data);
            for (uint256 i = 0; i < calls.length; i++) {
                // If any sub-call fails, revert entire multicall
                (success, returnData) = calls[i].to.call{value: calls[i].value}(calls[i].data);
                if (!success) {
                    break;
                }
            }
        } else {
            (success, returnData) = payload.to.call{value: payload.value}(payload.data);
        }

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
     * @inheritdoc IUEA
     */
    function migrateUEA(MigrationPayload calldata payload, bytes calldata signature) external nonReentrant {
        bytes32 payloadHash = getMigrationPayloadHash(payload);

        if (!verifyPayloadSignature(payloadHash, signature)) {
            revert Errors.InvalidSVMSignature();
        }

        unchecked {
            nonce++;
        }

        bytes memory migrateCallData = abi.encodeWithSignature("migrateUEASVM()");

        // delegatecall into the migration contract
        (bool success, bytes memory returnData) = payload.migration.delegatecall(migrateCallData);

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

        emit PayloadExecuted(id.owner, payload.migration, migrateCallData);
    }

    /**
     * @dev Calculates the transaction hash for a given payload.
     * @param payload The payload to calculate the hash for.
     * @return bytes32 The transaction hash.
     */
    function getPayloadHash(UniversalPayload calldata payload) public view returns (bytes32) {
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
     * @dev Calculates the transaction hash for a given migration payload.
     * @param payload The migration payload to calculate the hash for.
     * @return bytes32 The transaction hash.
     */
    function getMigrationPayloadHash(MigrationPayload memory payload) public view returns (bytes32) {
        if (payload.deadline > 0 && block.timestamp > payload.deadline) {
            revert Errors.ExpiredDeadline();
        }

        // Calculate the struct hash of the migration payload
        bytes32 structHash =
            keccak256(abi.encode(MIGRATION_PAYLOAD_TYPEHASH, payload.migration, nonce, payload.deadline));

        // Calculate the domain separator (EIP-712 domain)
        bytes32 _domainSeparator = domainSeparator();

        // Final EIP-712 hash: keccak256("\x19\x01" || domainSeparator || structHash)
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator, structHash));
    }

    /**
     * @dev Fallback function to receive ether.
     */
    receive() external payable {}
}
