// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUEA} from "../interfaces/IUEA.sol";
import {IUEAFactory} from "../interfaces/IUEAFactory.sol";
import {UEAErrors} from "../libraries/Errors.sol";
import {
    UniversalAccountId,
    UniversalPayload,
    UNIVERSAL_PAYLOAD_TYPEHASH,
    MULTICALL_SELECTOR,
    MIGRATION_SELECTOR,
    Multicall
} from "../libraries/Types.sol";

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title   UEA_SVM (Universal Executor Account for SVM)
 * @notice  Implementation logic for SVM-based Universal Executor Accounts.
 * @dev     Handles verification and execution of cross-chain payloads
 *          using Ed25519 signatures from Solana accounts.
 */
contract UEA_SVM is ReentrancyGuard, IUEA {
    // =========================
    //    US: STATE VARIABLES
    // =========================

    /// @notice Universal Account information.
    UniversalAccountId internal _universalAccountId;

    /// @notice Flag to track initialization status.
    bool private _initialized;

    /// @inheritdoc IUEA
    uint256 public nonce;

    /// @notice The version of the UEA.
    string public constant VERSION = "1.0.0";

    /// @notice Ed25519 verifier precompile address.
    address public constant VERIFIER_PRECOMPILE = 0x00000000000000000000000000000000000000ca;

    /// @notice Universal Executor Module — authorized to execute without signature.
    address public constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    /// @notice EIP-712 domain separator typehash for SVM.
    ///         keccak256("EIP712Domain_SVM(string version,string chainId,address verifyingContract,bytes32 salt)")
    /// @dev    Uses only the canonical EIP-712 `EIP712Domain` fields (`version`, `chainId`,
    ///         `verifyingContract`, `salt`) for maximum compatibility with standard signers
    ///         and EIP-712 tooling. The `_SVM` suffix in the type name disambiguates this
    ///         domain from the EVM variant (which encodes `chainId` as `uint256`); here
    ///         `chainId` is a `string` to accommodate Solana cluster identifiers.
    ///
    ///         Field semantics in this protocol:
    ///           - `version`             — UEA implementation version string.
    ///           - `chainId`             — the *source* Solana cluster identifier string,
    ///                                     derived from `UniversalAccountId`. Binds the
    ///                                     signature to the origin chain identity.
    ///           - `verifyingContract`   — this UEA proxy address.
    ///           - `salt`                — `bytes32(block.chainid)` of Push Chain at execution
    ///                                     time. Binds the signature to the specific Push Chain
    ///                                     deployment and prevents cross-deployment replay
    ///                                     across forks or parallel deployments.
    bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH_SVM =
        0x038a4fd0ee5950f0ea6d28f116a885fc5e376a8d1a939f7a9bea48f4f13fabb1;

    /// @notice UEAFactory reference for fetching migration contract.
    IUEAFactory public ueaFactory;

    // =========================
    //    US: INITIALIZER
    // =========================

    /// @inheritdoc IUEA
    function initialize(UniversalAccountId memory _id, address _factory) external {
        if (_initialized) {
            revert UEAErrors.AccountAlreadyExists();
        }
        _initialized = true;

        _universalAccountId = _id;
        ueaFactory = IUEAFactory(_factory);
    }

    // =========================
    //    US_1: VIEW FUNCTIONS
    // =========================

    /// @inheritdoc IUEA
    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_SEPARATOR_TYPEHASH_SVM,
                keccak256(bytes(VERSION)),
                _universalAccountId.chainId,
                address(this),
                bytes32(block.chainid)
            )
        );
    }

    /// @inheritdoc IUEA
    function universalAccount() public view returns (UniversalAccountId memory) {
        return _universalAccountId;
    }

    /// @inheritdoc IUEA
    function verifyUniversalPayloadSignature(bytes32 payloadHash, bytes memory signature) public view returns (bool) {
        return _verifySignatureSVM(payloadHash, signature);
    }

    /// @inheritdoc IUEA
    function getUniversalPayloadHash(UniversalPayload memory payload) public view returns (bytes32) {
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

        bytes32 domainSep = domainSeparator();

        return keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
    }

    // =========================
    //    US_2: EXECUTION
    // =========================

    /// @inheritdoc IUEA
    function executeUniversalTx(UniversalPayload calldata payload, bytes calldata signature) external nonReentrant {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) {
            bytes32 payloadHash = getUniversalPayloadHash(payload);
            if (!verifyUniversalPayloadSignature(payloadHash, signature)) {
                revert UEAErrors.InvalidSVMSignature();
            }
        }

        _handleExecution(payload);
    }

    // =========================
    //    US_3: INTERNAL HELPERS
    // =========================

    /// @dev Verifies an Ed25519 signature via the verifier precompile.
    /// @param payloadHash   Payload hash to verify
    /// @param signature     Ed25519 signature bytes
    /// @return              True if the signature is valid
    function _verifySignatureSVM(bytes32 payloadHash, bytes memory signature) internal view returns (bool) {
        (bool success, bytes memory result) = VERIFIER_PRECOMPILE.staticcall(
            abi.encodeWithSignature(
                "verifyEd25519(bytes,bytes32,bytes)", _universalAccountId.owner, payloadHash, signature
            )
        );
        if (!success) {
            revert UEAErrors.PrecompileCallFailed();
        }

        return abi.decode(result, (bool));
    }

    /// @dev Handles nonce increment, selector-based dispatch, and event emission.
    /// @param payload   The UniversalPayload to execute
    function _handleExecution(UniversalPayload memory payload) internal {
        if (payload.deadline > 0 && block.timestamp > payload.deadline) {
            revert UEAErrors.ExpiredDeadline();
        }

        unchecked {
            nonce++;
        }

        bool success;
        bytes memory returnData;

        if (_isMulticall(payload.data)) {
            (success, returnData) = _handleMulticall(payload);
        } else if (_isMigration(payload.data)) {
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
                revert UEAErrors.ExecutionFailed();
            }
        }

        emit PayloadExecuted(_universalAccountId.owner, nonce);
    }

    /// @dev Executes multiple calls in sequence.
    /// @param payload   The UniversalPayload containing multicall data
    /// @return success  Whether all calls succeeded
    /// @return returnData  Return data from the last or first failed call
    function _handleMulticall(UniversalPayload memory payload)
        internal
        returns (bool success, bytes memory returnData)
    {
        Multicall[] memory calls = _decodeCalls(payload.data);

        for (uint256 i = 0; i < calls.length; i++) {
            (success, returnData) = calls[i].to.call{value: calls[i].value}(calls[i].data);
            if (!success) {
                return (success, returnData);
            }
        }

        return (true, "");
    }

    /// @dev Executes migration via delegatecall to the factory's migration contract.
    ///      Enforces: must target self, no value transfer.
    /// @param payload   The UniversalPayload containing migration data
    /// @return success  Whether the migration succeeded
    /// @return returnData  Return data from the delegatecall
    function _handleMigration(UniversalPayload memory payload)
        internal
        returns (bool success, bytes memory returnData)
    {
        if (payload.to != address(this)) {
            revert UEAErrors.InvalidCall();
        }
        if (payload.value != 0) {
            revert UEAErrors.InvalidCall();
        }

        address migrationContract = ueaFactory.UEA_MIGRATION_CONTRACT();

        if (migrationContract == address(0)) {
            revert UEAErrors.InvalidCall();
        }

        bytes memory migrateCallData = abi.encodeWithSignature("migrateUEASVM()");

        (success, returnData) = migrationContract.delegatecall(migrateCallData);
    }

    /// @dev Executes a single call to the target address.
    /// @param payload   The UniversalPayload containing call data
    /// @return success  Whether the call succeeded
    /// @return returnData  Return data from the call
    function _handleSingleCall(UniversalPayload memory payload)
        internal
        returns (bool success, bytes memory returnData)
    {
        (success, returnData) = payload.to.call{value: payload.value}(payload.data);
    }

    // =========================
    //    US_4: PRIVATE HELPERS
    // =========================

    /// @dev Checks whether the payload data starts with MULTICALL_SELECTOR.
    /// @param data   Raw data from the UniversalPayload
    /// @return       True if multicall format
    function _isMulticall(bytes memory data) private pure returns (bool) {
        if (data.length < 4) return false;
        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }
        return selector == MULTICALL_SELECTOR;
    }

    /// @dev Checks whether the payload data starts with MIGRATION_SELECTOR.
    /// @param data   Raw data from the UniversalPayload
    /// @return       True if migration format
    function _isMigration(bytes memory data) private pure returns (bool) {
        if (data.length < 4) return false;
        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }
        return selector == MIGRATION_SELECTOR;
    }

    /// @dev Strips MULTICALL_SELECTOR prefix and decodes as Multicall[].
    /// @param data   Raw data containing selector + ABI-encoded Multicall[]
    /// @return       Decoded Multicall array
    function _decodeCalls(bytes memory data) private pure returns (Multicall[] memory) {
        bytes memory strippedData = new bytes(data.length - 4);
        for (uint256 i = 0; i < strippedData.length; i++) {
            strippedData[i] = data[i + 4];
        }
        return abi.decode(strippedData, (Multicall[]));
    }

    // =========================
    //    US: RECEIVE
    // =========================

    /// @notice Allows this UEA to receive native tokens.
    receive() external payable {}
}
