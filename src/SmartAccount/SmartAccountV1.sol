// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title SmartAccountV1
 * @dev The contract represents an external user's account on Push Chain. 
 *      It allows for the execution of payloads based on EVM and non-EVM signatures.
 *      It uses a native precompile for signature verification of Non-EVM users.
 * @notice Use this contract as implementation logic of a user's Smart Account on Push Chain.
 */

contract SmartAccountV1 is Initializable, ReentrancyGuard {
    using ECDSA for bytes32;

    enum OwnerType {
        EVM,
        NON_EVM
    }
    // User Struct 
    struct Owner {
     string namespace;
     string chainId;
     bytes ownerKey; 
     OwnerType ownerType;
    }

    // TODO: Confirm the final implementation of the cross-chain payload
    struct CrossChainPayload {
        // Core execution parameters
        address target;               // Target contract address to call
        uint256 value;                // Native token amount to send
        bytes data;                   // Call data for the function execution
        uint256 gasLimit;             // Maximum gas to be used for this tx (caps refund amount)
        uint256 maxFeePerGas;         // Maximum fee per gas unit
        uint256 maxPriorityFeePerGas; // Maximum priority fee per gas unit
        uint256 nonce;                // Chain ID where this should be executed
        uint256 deadline;             // Timestamp after which this payload is invalid
    }

    Owner public owner;
    uint256 public nonce;
    string public constant VERSION = "0.1.0";
    address public constant verifierPrecompile = 0x0000000000000000000000000000000000000902;

    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH = keccak256(
        "EIP712Domain(string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH = keccak256(
        "CrossChainPayload(address target,uint256 value,bytes data,uint256 gasLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 nonce,uint256 deadline)"
    );

    event PayloadExecuted(bytes caller, address target, bytes data);

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
     * @dev Initializes the contract with the given parameters.
     * @param _owner the Owner struct
     */
    function initialize(Owner memory _owner) external initializer {
        owner = _owner;
    }

    /**
     * @dev Verifies the EVM signature using the ECDSA library.
     * @param messageHash The hash of the message to verify.
     * @param signature The signature to verify.
     * @return bool indicating whether the signature is valid.
     */
    function verifySignatureEVM(bytes32 messageHash, bytes memory signature) internal view returns (bool) {
        address recoveredSigner = messageHash.recover(signature);
        return recoveredSigner == address(bytes20(owner.ownerKey));
    }

    /**
     * @dev Verifies the NON-EVM signature using the verifier precompile.
     * @param message The message to verify.
     * @param signature The signature to verify.
     * @return bool indicating whether the signature is valid.
     */
    function verifySignatureNonEVM(bytes32 message, bytes memory signature) internal view returns (bool) {
        (bool success, bytes memory result) = verifierPrecompile.staticcall(
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", owner.ownerKey, message, signature)
        );
        require(success, "Verifier call failed");
        return abi.decode(result, (bool));
    }
    
    /**
     * @dev Executes a payload on the target address with the given data and signature.
     * @param payload The target address to execute the payload on.
     * @param signature The signature to verify the execution.
     */
    function executePayload( CrossChainPayload calldata payload, bytes calldata signature) external nonReentrant {
        bytes32 txHash = getTransactionHash(payload);

        if (owner.ownerType == OwnerType.EVM) {
            require(verifySignatureEVM(txHash, signature), "Invalid EVM signature");
        } else {
            require(verifySignatureNonEVM(txHash, signature), "Invalid NON-EVM signature");
        }

        unchecked {
            nonce++;
        }

        (bool success, bytes memory returnData) = payload.target.call{value: payload.value}(payload.data);

        if(!success) {
            if ( returnData.length > 0 )  {

                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            }else{
                revert("Execution failed without reason");
            }
        }

        emit PayloadExecuted(owner.ownerKey, payload.target, payload.data);
    }
    function getTransactionHash(CrossChainPayload calldata payload) public view returns (bytes32) {        // Calculate the hash of the payload using EIP-712
        bytes32 structHash = keccak256(
            abi.encode(
                PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH,
                payload.target,
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


    // @dev Fallback function to receive ether.
    receive() external payable {}

}
