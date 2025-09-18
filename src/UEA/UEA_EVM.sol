// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../libraries/Types.sol";
import {UEAErrors as Errors} from "../libraries/Errors.sol";
import {IUEA} from "../Interfaces/IUEA.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {StringUtils} from "../libraries/Utils.sol";
import {UniversalAccountId, UniversalPayload, Multicall, VerificationType, UNIVERSAL_PAYLOAD_TYPEHASH} from "../libraries/Types.sol";
/**
 * @title UEA_EVM (Universal Executor Account for EVM)
 * @dev Implementation of the IUEA interface for EVM-based external accounts.
 *      This contract handles verification and execution of cross-chain payloads
 *      using ECDSA signatures from Ethereum-compatible accounts.
 * @notice Use this contract as implementation logic for EVM-based UEAs.
 */

contract UEA_EVM is ReentrancyGuard, IUEA {
    using ECDSA for bytes32;

    // @notice The Universal Account information
    UniversalAccountId internal id;
    // @notice Flag to track initialization status
    bool private initialized;
    // @notice The nonce for the UEA
    uint256 public nonce;
    // @notice The version of the UEA
    string public constant VERSION = "0.1.0";
    // @notice Precompile address for TxHash Based Verification
    address public constant TX_BASED_VERIFIER = 0x00000000000000000000000000000000000000CB;
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
     * @dev Verifies the EVM signature using the ECDSA library.
     * @param payloadHash The hash of the message to verify.
     * @param signature The signature to verify.
     * @return bool indicating whether the signature is valid.
     */
    function verifyPayloadSignature(bytes32 payloadHash, bytes memory signature) public view returns (bool) {
        address recoveredSigner = payloadHash.recover(signature);
        return recoveredSigner == address(bytes20(id.owner));
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

        emit PayloadExecuted(id.owner, payload.to, payload.data);
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
     * @dev Fallback function to receive ether.
     */
    receive() external payable {}
}
