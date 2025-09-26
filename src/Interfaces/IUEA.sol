// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalAccountId, UniversalPayload, MigrationPayload} from "../libraries/Types.sol";

/**
 * @title   IUEA (Interface for Universal Executor Account)
 * @dev     Interface that all Universal Executor Accounts (UEA) must implement.
 *          A UEA is a smart contract that acts as a proxy for external chain users on Push Chain.
 *          External Chain users ( from evm or non-evm chains ) get a UEA auto-deployed for them on Push Chain, during their first tx.
 *          UEA implementation logic may vary based on the type of the user's external chain, i.e., UEA_EVM for Ethereum & UEA_SVM for Solana.
 * 
 *          The UEA includes the provides the users with the following:
 *          - An identity for external chain users on Push Chain. ( UEA acts on behalf of the user)
 *          - EIP-712 compliant transaction signing
 *          - Ability to execute SINGLE or MULTIPLE transactions with a single tx.
 *          - Every trasnaction executed is directly controlled by owner of the UEA.
 *          - Ability to migrate the UEA implementation logic to a new implementation.
 */
interface IUEA {
    //========================
    //           Events
    //========================

    /**
     * @notice        Emitted when a payload is successfully executed by a UEA.
     * @param caller  The external chain address (UOA) that initiated the execution.
     * @param target  The target contract address where the payload was executed.
     * @param data    The calldata that was executed on the target contract.
     */
    event PayloadExecuted(bytes caller, address target, bytes data);

    //========================
    //           Functions
    //========================

    /**
     * @dev    Returns the version of the UEA.
     * @return The version of the UEA.
     */
    function VERSION() external view returns (string memory);

    /**
     * @dev     Returns the Universal Account information for this UEA.
     * @return  The UniversalAccountId struct containing the chain name and owner key.
     */
    function universalAccount() external view returns (UniversalAccountId memory);

    /**
     * @notice                  Initializes the UEA with the Universal Account information.
     * @dev                    This function can only be called once during deployment via Factory.
     * @param universalAccount  The UniversalAccountId struct containing the chain name and owner key.
     * @param universalAccount  The UniversalAccountId struct containing:
     *                          - chain: The name of the external chain (e.g., "eip155:1", "eip155:900")
     *                          - owner: The owner's address/public key from the external chain
     *
     *                          The format of the owner field depends on the UEA type:
     *                          - For EVM-based UEAs: An Ethereum address (20 bytes)
     *                          - For SVM-based UEAs: A Solana public key (32 bytes)
     */
    function initialize(UniversalAccountId memory universalAccount) external;

    /**
     * @notice               Verifies if a signature is valid for a given message hash.
     * @dev                 Implementation behavior varies by UEA type:
     *                      1. For EVM-based UEAs: Uses ECDSA recovery to verify that the signature was created by the
     *                      address stored in the UniversalAccountId.owner field. The owner is expected to be an
     *                      Ethereum address represented as bytes.
     *
     *                      2. For SVM-based UEAs: Uses a precompiled contract to verify Ed25519 signatures, where the
     *                      UniversalAccountId.owner field contains a Solana public key. The verification is done through
     *                      a call to the VERIFIER_PRECOMPILE address.
     * 
     * @param payloadHash   The hash of the payload that was signed.
     * @param signature     The signature to verify.
     * @return              A boolean indicating whether the signature is valid.
     */
    function verifyPayloadSignature(bytes32 payloadHash, bytes memory signature) external view returns (bool);

    /**
     * @notice                  Executes a cross-chain payload with the provided signature.
     * @param payload           The UniversalPayload struct containing execution parameters:
     *                          - to: Target contract address to call
     *                          - value: Native token amount to send
     *                          - data: Calldata for the function execution
     *                          - gasLimit: Maximum gas to be used for this transaction
     *                          - maxFeePerGas: Maximum fee per gas unit
     *                          - nonce: Used to prevent replay attacks
     *                          - deadline: Timestamp after which the payload is invalid
     * 
     * @param verificationData The verificationData is the bytes passed as verifier data for the given payload.
     *                          The verificationData can be of 2 different types:
     *                          1. For Signature-based verification: ECDSA signature (r, s, v)
     *                          2. For TxHash-based verification: TxHash of the payload
     * 
     *                          Additionally, the sig-type verificationData for UEA_EVM vs UEA_SVM differs:
     *                          1. For UEA_EVM: The verificationData is the ECDSA signature (r, s, v)
     *                          2. For UEA_SVM: The verificationData is the Ed25519 signature
     *
     * @dev                     Function can allow SINGLE Payload execution or MULTIPLE Payload execution (Multicall).
     *                         The function has following reverts:
     *                         1. If signature verification fails, it reverts with InvalidEVMSignature or InvalidSVMSignature.
     *                         2. If TxHash verification fails, it reverts with InvalidTxHash.
     *                         3. If the deadline has passed, it reverts with ExpiredDeadline.
     *                         4. In a MultiCall, if any of the sub-calls fails, it reverts with ExecutionFailed.
     *                         5. If the target contract execution fails, it reverts with ExecutionFailed or forwards the error message.
     */
    function executePayload(UniversalPayload calldata payload, bytes calldata verificationData) external;

    /**
     * @notice                  Executes a migration payload for updating UEAs.
     * @param payload           The MigrationPayload struct containing migration parameters:
     *                          - migration: The address of the new migration contract
     *                          - nonce: Used to prevent replay attacks
     *                          - deadline: Timestamp after which the migration is invalid
     * @param signature         The signature is the signature used for verification.
     *                          1. For UEA_EVM: The signature is the ECDSA signature (r, s, v)
     *                          2. For UEA_SVM: The signature is the Ed25519 signature
     *
     * @dev                     Allows UEA Owner to sign and execute a migration of their UEA from old to new implementation.
     */
    function migrateUEA(MigrationPayload calldata payload, bytes calldata signature) external;
}
