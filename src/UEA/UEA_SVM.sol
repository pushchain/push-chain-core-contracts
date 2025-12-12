// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UEAErrors as Errors} from "../libraries/Errors.sol";
import {IUEA} from "../Interfaces/IUEA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {StringUtils} from "../libraries/Utils.sol";
import {
    UniversalAccountId,
    UniversalPayload,
    UNIVERSAL_PAYLOAD_TYPEHASH,
    MULTICALL_SELECTOR,
    MIGRATION_SELECTOR,
    Multicall
} from "../libraries/Types.sol";
/**
 * @title   UEA_SVM (Universal Executor Account for SVM)
 * @notice  UEA_SVM acts as the implementation logic for SVM-based UEAs accounts
 * @dev     Implementation of the IUEA interface for SVM-based external accounts.
 *          This contract handles verification and execution of cross-chain payloads
 *          using Ed25519 signatures from Solana accounts.
 * 
 * Note:    Find detailed natspec in the IUEA interface -> interfaces/IUEA.sol
 */

contract UEA_SVM is ReentrancyGuard, IUEA {
    /// @notice The Universal Account information
    UniversalAccountId internal id;
    /// @notice Flag to track initialization status
    bool private initialized;
    /// @notice The nonce for the UEA
    uint256 public nonce;
    /// @notice The version of the UEA
    string public constant VERSION = "1.0.0";
    /// @notice The verifier precompile address
    address public constant VERIFIER_PRECOMPILE = 0x00000000000000000000000000000000000000ca;
    /// @notice UEModule address - authorized to execute without signature verification
    address public constant UE_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    /// @notice Hash of keccak256("EIP712Domain_SVM(string version,string chainId,address verifyingContract)")
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

    // =========================
    //    UEA_1: Public Getters and Helpers
    // =========================

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
     * @dev                 Verifies the SVM signature using the verifier precompile.
     * @param payloadHash   payload hash to verify.
     * @param signature     signature to verify.
     * @return bool         indicates whether the signature is valid.
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

    // =========================
    //    UEA_2: Execution Handler
    // =========================

    /**
     * @inheritdoc IUEA
     */
    function executePayload(bytes calldata rawPayload, bytes calldata verificationData) external nonReentrant {
        UniversalPayload memory payload = abi.decode(rawPayload, (UniversalPayload));
        
        if (msg.sender != UE_MODULE) {
            bytes32 payloadHash = getPayloadHash(payload);
            if (!verifyPayloadSignature(payloadHash, verificationData)) {
                revert Errors.InvalidSVMSignature();
            }
        }

        _handleExecution(payload);
    }

    // =========================
    //    UEA_3: Internal Execution Helpers
    // =========================

    /**
     * @notice                  Internal handler for executing payloads
     * @dev                     Handles nonce increment, selector-based dispatch, and event emission
     * @param payload           the UniversalPayload to execute
     */
    function _handleExecution(UniversalPayload memory payload) internal {
        if (payload.deadline > 0 && block.timestamp > payload.deadline) {
            revert Errors.ExpiredDeadline();
        }

        unchecked {
            nonce++;
        }

        bool success;
        bytes memory returnData;

        if (isMulticall(payload.data)) {
            (success, returnData) = _handleMulticall(payload);
        } else if (isMigration(payload.data)) {
            (success, returnData) = _handleMigration(payload);
        } else {
            (success, returnData) = _handleSingleCall(payload);
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
     * @notice                  Internal handler for multicall execution
     * @dev                     Executes multiple calls in sequence, reverting if any fails
     * @dev                     Prevents migration selector in subcalls for safety
     * @param payload           the UniversalPayload containing multicall data
     * @return success          whether all calls succeeded
     * @return returnData       return data from the last call or first failed call
     */
    function _handleMulticall(UniversalPayload memory payload) 
        internal 
        returns (bool success, bytes memory returnData) 
    {
        Multicall[] memory calls = decodeCalls(payload.data);

        for (uint256 i = 0; i < calls.length; i++) {
            if (isMigration(calls[i].data)) {
                revert Errors.InvalidCall();
            }

            (success, returnData) = calls[i].to.call{value: calls[i].value}(calls[i].data);
            if (!success) {
                return (success, returnData);
            }
        }

        return (true, "");
    }

    /**
     * @notice                  Internal handler for migration execution
     * @dev                     Executes migration via delegatecall to migration contract
     * @dev                     Enforces safety constraints: must target self, no value transfer
     * @param payload           the UniversalPayload containing migration data
     * @return success          whether the migration succeeded
     * @return returnData       return data from the delegatecall
     */
    function _handleMigration(UniversalPayload memory payload) 
        internal 
        returns (bool success, bytes memory returnData) 
    {
        if (payload.to != address(this)) {
            revert Errors.InvalidCall();
        }
        if (payload.value != 0) {
            revert Errors.InvalidCall();
        }

        // Format: MIGRATION_SELECTOR + abi.encode(migrationContractAddress)
        address migrationContract = decodeMigrationAddress(payload.data);

        bytes memory migrateCallData = abi.encodeWithSignature("migrateUEASVM()");

        (success, returnData) = migrationContract.delegatecall(migrateCallData);
    }

    /**
     * @notice                  Internal handler for single call execution
     * @dev                     Executes a single call to the target address
     * @param payload           the UniversalPayload containing call data
     * @return success          whether the call succeeded
     * @return returnData       return data from the call
     */
    function _handleSingleCall(UniversalPayload memory payload) 
        internal 
        returns (bool success, bytes memory returnData) 
    {
        (success, returnData) = payload.to.call{value: payload.value}(payload.data);
    }



    // =========================
    //    UEA_4: Private Helpers
    // =========================

    /**
     * @notice          Checks whether the payload data uses the multicall format
     * @dev             Determines if the payload data starts with the MULTICALL_SELECTOR magic prefix
     * @dev             Used to distinguish between single call vs multicall batch execution
     * @param data      raw data from the UniversalPayload
     * @return bool     returns true if the data starts with MULTICALL_SELECTOR, indicating a multicall batch
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
     * @notice          Checks whether the payload data uses the migration format
     * @dev             Determines if the payload data starts with the MIGRATION_SELECTOR magic prefix
     * @param data      raw data from the UniversalPayload
     * @return bool     returns true if the data starts with MIGRATION_SELECTOR, indicating a migration request
     */
    function isMigration(bytes memory data) internal pure returns (bool) {
        if (data.length < 4) return false;
        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }
        return selector == MIGRATION_SELECTOR;
    }

    /**
     * @notice              Decodes the payload data into an array of Multicall structs
     * @dev                 Assumes the data uses the multicall format (should be called after isMulticall returns true)
     * @dev                 Strips the MULTICALL_SELECTOR prefix and decodes the remaining data as Multicall[]
     * @param data          raw data containing MULTICALL_SELECTOR followed by ABI-encoded Multicall[]
     * @return Multicall[]  decoded array of Multicall structs to be executed
     */
    function decodeCalls(bytes memory data) internal pure returns (Multicall[] memory) {

        bytes memory strippedData = new bytes(data.length - 4);
        for (uint256 i = 0; i < strippedData.length; i++) {
            strippedData[i] = data[i + 4];
        }
        return abi.decode(strippedData, (Multicall[]));
    }

    /**
     * @notice              Decodes the migration contract address from payload data
     * @dev                 Strips the MIGRATION_SELECTOR prefix and decodes the address
     * @param data          raw data containing MIGRATION_SELECTOR followed by ABI-encoded address
     * @return address      the decoded migration contract address
     */
    function decodeMigrationAddress(bytes memory data) internal pure returns (address) {
        bytes memory strippedData = new bytes(data.length - 4);
        for (uint256 i = 0; i < strippedData.length; i++) {
            strippedData[i] = data[i + 4];
        }
        return abi.decode(strippedData, (address));
    }

    /**
     * @dev             Calculates the transaction hash for a given payload.
     * @param payload   payload to calculate the hash for.
     * @return bytes32  transaction hash.
     */
    function getPayloadHash(UniversalPayload memory payload) public view returns (bytes32) {
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

        bytes32 _domainSeparator = domainSeparator();

        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator, structHash));
    }

    /**
     * @dev Fallback function to receive ether.
     */
    receive() external payable {}
}