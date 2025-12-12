// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UEAErrors as Errors} from "../../src/libraries/Errors.sol";
import {IUEA} from "../../src/Interfaces/IUEA.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {StringUtils} from "../../src/libraries/Utils.sol";
import {
    UniversalAccountId,
    UniversalPayload,
    MigrationPayload,
    UNIVERSAL_PAYLOAD_TYPEHASH,
    MIGRATION_PAYLOAD_TYPEHASH,
    MULTICALL_SELECTOR,
    Multicall
} from "../../src/libraries/Types.sol";

/**
 * @title UEA_EVM_V2 (Universal Executor Account for EVM - Version 2.0.0)
 * @dev Mock implementation of the IUEA interface for EVM-based external accounts - Version 2.
 *      This contract is identical to UEA_EVM except for the version number.
 *      Used for testing migration functionality.
 * @notice Use this contract as implementation logic for EVM-based UEAs V2.
 */
contract UEA_EVM_V2 is ReentrancyGuard, IUEA {
    using ECDSA for bytes32;

    // @notice The Universal Account information
    UniversalAccountId internal id;
    // @notice Flag to track initialization status
    bool private initialized;
    // @notice The nonce for the UEA
    uint256 public nonce;
    // @notice The version of the UEA - Updated to 2.0.0 for V2
    string public constant VERSION = "2.0.0";
    // @notice UEModule address - authorized to execute without signature verification
    address public constant UE_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    // @notice Hash of keccak256("EIP712Domain(string version,uint256 chainId,address verifyingContract)")
    bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH =
        0x2aef22f9d7df5f9d21c56d14029233f3fdaa91917727e1eb68e504d27072d6cd;

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
     * @dev Returns the domain separator for EIP-712 signing.
     * @return bytes32 The domain separator.
     */
    function domainSeparator() public view returns (bytes32) {
        uint256 chainId = StringUtils.stringToExactUInt256(id.chainId);

        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, keccak256(bytes(VERSION)), chainId, address(this)));
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
        address recoveredSigner = payloadHash.recover(signature);
        return recoveredSigner == address(bytes20(id.owner));
    }


    /**
     * @dev Checks whether the payload data uses the multicall format by verifying a magic selector prefix.
     * @param data The raw data from the UniversalPayload.
     * @return bool Returns true if the data starts with the MULTICALL_SELECTOR, indicating a multicall batch.
     */
    function isMulticall(bytes memory data) internal pure returns (bool) {
        if (data.length < 4) return false;
        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }
        return selector == MULTICALL_SELECTOR;
    }

    /**
     * @dev Decodes the payload data into an array of Call structs, assuming the data uses the multicall format.
     * @notice This function assumes that isMulticall(data) has already returned true.
     * @param data The raw data containing the MULTICALL_SELECTOR followed by the ABI-encoded Call[].
     * @return Call[] The decoded array of Call structs to be executed.
     */
    function decodeCalls(bytes memory data) internal pure returns (Multicall[] memory) {
        // Skip the first 4 bytes (MULTICALL_SELECTOR) and decode the rest
        // We need to manually copy because slicing only works with calldata, not memory
        bytes memory strippedData = new bytes(data.length - 4);
        for (uint256 i = 0; i < strippedData.length; i++) {
            strippedData[i] = data[i + 4];
        }
        return abi.decode(strippedData, (Multicall[]));
    }

    /**
     * @inheritdoc IUEA
     */
    function executePayload(bytes calldata rawPayload, bytes calldata verificationData) external nonReentrant {
        // Decode the raw bytes payload into UniversalPayload struct
        UniversalPayload memory payload = abi.decode(rawPayload, (UniversalPayload));
        
        // Caller-based verification: UEModule can execute without signature, others need signature
        if (msg.sender != UE_MODULE) {
            bytes32 payloadHash = getPayloadHash(payload);
            if (!verifyPayloadSignature(payloadHash, verificationData)) {
                revert Errors.InvalidEVMSignature();
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

        emit PayloadExecuted(id.owner, nonce);
    }

    /**
     * @inheritdoc IUEA
     */
    function migrateUEA(MigrationPayload calldata payload, bytes calldata signature) external nonReentrant {
        bytes32 payloadHash = getMigrationPayloadHash(payload);

        if (!verifyPayloadSignature(payloadHash, signature)) {
            revert Errors.InvalidEVMSignature();
        }

        unchecked {
            nonce++;
        }

        bytes memory migrateCallData = abi.encodeWithSignature("migrateUEAEVM()");

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

        emit PayloadExecuted(id.owner, nonce);
    }

    /**
     * @dev Calculates the transaction hash for a given payload.
     * @param payload The payload to calculate the hash for.
     * @return bytes32 The transaction hash.
     */
    function getPayloadHash(UniversalPayload memory payload) public view returns (bytes32) {
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
                payload.deadline
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