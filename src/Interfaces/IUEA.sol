// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalAccountId, UniversalPayload} from "../libraries/Types.sol";

/**
 * @title IUEA (Interface for Universal Executor Account)
 * @dev Interface that all Universal Executor Accounts (UEA) must implement.
 *      A UEA is a smart contract on the PUSH Chain that acts as a proxy for external
 *      chain users (UOA - Universal Owner Address), allowing them to execute transactions.
 *
 *      Different UEA implementations exist for different virtual machine environments,
 *      such as EVM (Ethereum Virtual Machine) and SVM (Solana Virtual Machine).
 */
interface IUEA {
    //*** Events ***//
    /**
     * @dev Emitted when a payload is successfully executed by a UEA.
     * @param caller The external chain address (UOA) that initiated the execution.
     * @param target The target contract address where the payload was executed.
     * @param data The calldata that was executed on the target contract.
     */
    event PayloadExecuted(bytes caller, address target, bytes data);

    //*** Functions ***//

    /**
     * @dev Initializes the UEA with the Universal Account information.
     * @param universalAccount The UniversalAccountId struct containing:
     *        - chain: The name of the external chain (e.g., "eip155:1", "eip155:900")
     *        - owner: The owner's address/public key from the external chain
     *
     * @notice This function can only be called once during deployment via Factory.
     * The format of the owner field depends on the UEA type:
     * - For EVM-based UEAs: An Ethereum address (20 bytes)
     * - For SVM-based UEAs: A Solana public key (32 bytes)
     */
    function initialize(UniversalAccountId memory universalAccount) external;

    /**
     * @dev Returns the Universal Account information for this UEA.
     * @return The UniversalAccountId struct containing the chain name and owner key.
     */
    function universalAccount() external view returns (UniversalAccountId memory);

    /**
     * @dev Verifies if a signature is valid for a given message hash.
     * @param payloadHash The hash of the payload that was signed.
     * @param signature The signature to verify.
     * @return A boolean indicating whether the signature is valid.
     *
     * @notice Implementation behavior varies by UEA type:
     * - For EVM-based UEAs: Uses ECDSA recovery to verify that the signature was created by the
     *   address stored in the UniversalAccountId.owner field. The owner is expected to be an
     *   Ethereum address represented as bytes.
     *
     * - For SVM-based UEAs: Uses a precompiled contract to verify Ed25519 signatures, where the
     *   UniversalAccountId.owner field contains a Solana public key. The verification is done through
     *   a call to the VERIFIER_PRECOMPILE address.
     */
    function verifyPayloadSignature(bytes32 payloadHash, bytes memory signature) external view returns (bool);

    /**
     * @notice Executes a cross-chain payload with the provided signature.
     * @param payload The UniversalPayload struct containing execution parameters:
     *        - to: Target contract address to call
     *        - value: Native token amount to send
     *        - data: Calldata for the function execution
     *        - gasLimit: Maximum gas to be used for this transaction
     *        - maxFeePerGas: Maximum fee per gas unit
     *        - nonce: Used to prevent replay attacks
     *        - deadline: Timestamp after which the payload is invalid
     * @param verificationData The verificationData is the bytes passed as verifier data for the given payload.
     *        The verificationData can be of 2 different types:
     *        - a. For Signature-based verification: ECDSA signature (r, s, v)
     *        - b. For TxHash-based verification: TxHash of the payload
     *        Additionally, the sig-type verificationData for UEA_EVM vs UEA_SVM differs:
     *        - For UEA_EVM: The verificationData is the ECDSA signature (r, s, v)
     *        - For UEA_SVM: The verificationData is the Ed25519 signature
     *
     * @dev This function performs the following steps:
     * 1. Generates a payload hash from the given payload
     * 2. Checks if verification type is Signature-based or TxHash-based
     * 3. If Signature-based, verifies the signature against the payload hash
     * 4. If TxHash-based, verifies the TxHash against the payload hash
     * 5. Increments the nonce to prevent replay attacks
     * 6. Executes the call to the target contract
     * 5. Handles any errors during execution
     *
     * @dev The function has following reverts:
     * - If signature verification fails, it reverts with InvalidEVMSignature or InvalidSVMSignature.
     * - If TxHash verification fails, it reverts with InvalidTxHash.
     * - If the deadline has passed, it reverts with ExpiredDeadline.
     * - If the target contract execution fails, it reverts with ExecutionFailed or forwards the error message.
     */
    function executePayload(UniversalPayload calldata payload, bytes calldata verificationData) external;
}
