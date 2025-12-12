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
     * @param nonce   The nonce of the payload that was executed.
     */
    event PayloadExecuted(bytes caller, uint256 nonce);

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
     * @notice              Verifies if a signature is valid for a given message hash.
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
     * @notice                  Executes a cross-chain payload with the provided verification data.
     * @param payload           The ABI-encoded UniversalPayload struct. Callers must encode the payload as:
     *                          `abi.encode(UniversalPayload({...}))` with the following fields in order:
     *                          - to: Target contract address to call (address)
     *                          - value: Native token amount to send (uint256)
     *                          - data: Calldata for the function execution (bytes)
     *                          - gasLimit: Maximum gas to be used for this transaction (uint256)
     *                          - maxFeePerGas: Maximum fee per gas unit (uint256)
     *                          - maxPriorityFeePerGas: Maximum priority fee per gas unit (uint256)
     *                          - nonce: Used to prevent replay attacks (uint256)
     *                          - deadline: Timestamp after which the payload is invalid (uint256)
     * 
     *                          The function will revert with decoding errors if the payload is not properly encoded.
     * 
     * @param verificationData The verificationData is the signature bytes for verification.
     *                          The signature format differs based on UEA type:
     *                          - For UEA_EVM: ECDSA signature (r, s, v) - 65 bytes
     *                          - For UEA_SVM: Ed25519 signature - 64 bytes
     * 
     *                          Note: If the caller is UE_MODULE, signature verification is skipped.
     *
     * @dev                     Verification behavior:
     *                          - If caller is UE_MODULE: No signature verification required
     *                          - If caller is not UE_MODULE: Signature verification required
     * 
     *                          Function can allow SINGLE Payload execution or MULTIPLE Payload execution (Multicall).
     *                          The function has following reverts:
     *                          1. If signature verification fails, it reverts with InvalidEVMSignature or InvalidSVMSignature.
     *                          2. If the deadline has passed, it reverts with ExpiredDeadline.
     *                          3. In a MultiCall, if any of the sub-calls fails, it reverts with ExecutionFailed.
     *                          4. If the target contract execution fails, it reverts with ExecutionFailed or forwards the error message.
     */
    function executePayload(bytes calldata payload, bytes calldata verificationData) external;

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