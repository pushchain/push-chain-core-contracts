// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Errors} from "../libraries/Errors.sol";
import {IUEA} from "../Interfaces/IUEA.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {
    UniversalAccount,
    UniversalPayload,
    DOMAIN_SEPARATOR_TYPEHASH,
    UNIVERSAL_PAYLOAD_TYPEHASH
} from "../libraries/Types.sol";
/**
 * @title UEA_SVM (Universal Executor Account for SVM)
 * @dev Implementation of the IUEA interface for SVM-based external accounts.
 *      This contract handles verification and execution of cross-chain payloads
 *      using Ed25519 signatures from Solana accounts.
 * @notice Use this contract as implementation logic for SVM-based UEAs.
 */
contract UEA_SVM is Initializable, ReentrancyGuard, IUEA {
    UniversalAccount internal id;
    uint256 public nonce;
    string public constant VERSION = "0.1.0";
    address public constant VERIFIER_PRECOMPILE = 0x00000000000000000000000000000000000000ca;

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
     * @inheritdoc IUEA
     */
    function initialize(UniversalAccount memory universalAccount) external initializer {
        id = universalAccount;
    }

    /**
     * @inheritdoc IUEA
     */
    function universalAccount() public view returns (UniversalAccount memory) {
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
     * @inheritdoc IUEA
     */
    function executePayload(UniversalPayload calldata payload, bytes calldata signature) external nonReentrant {
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
                uint8(payload.sigType)
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
