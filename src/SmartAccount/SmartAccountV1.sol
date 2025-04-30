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

    // @notice Push Cross Chain Payload Struct
    struct CrossChainPayload {
        address target;      // target address to execute the payload on
        uint256 value;       // value to send with the payload
        bytes data;          // data to send with the payload
        uint256 baseGas;     // base gas for the payload execution
        uint256 gasPrice;    // gas price for the payload execution
        uint256 gasLimit;    // gas limit for the payload execution
        uint256 maxFeePerGas;// max fee per gas for the payload execution
        address refundRecp;  // address to refund the gas
        uint256 nonce;       // nonce for the payload execution
    }

    uint256 public nonce;
    bytes public ownerKey;
    OwnerType public ownerType;
    address public verifierPrecompile;
    string public constant VERSION = "0.1.0";


    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH = keccak256(
        "EIP712Domain(string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 private constant PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH = keccak256(
        "CrossChainPayload(address target,uint256 value,bytes data,uint256 baseGas,uint256 gasPrice,uint256 gasLimit,uint256 maxFeePerGas,address refundRecp,uint256 nonce)"
    );
  

    event PayloadExecuted(bytes caller, address target, bytes data);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

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
     * @param _ownerKey The key of the owner (EVM or NON_EVM).
     * @param _ownerType The type of owner (EVM or NON_EVM).
     * @param _verifierPrecompile The address of the verifier precompile contract.
     */
    function initialize(bytes memory _ownerKey, OwnerType _ownerType, address _verifierPrecompile) external initializer {
        ownerKey = _ownerKey;
        ownerType = _ownerType;
        verifierPrecompile = _verifierPrecompile;
    }

    /**
     * @dev Verifies the EVM signature using the ECDSA library.
     * @param messageHash The hash of the message to verify.
     * @param signature The signature to verify.
     * @return bool indicating whether the signature is valid.
     */
    function verifySignatureEVM(bytes32 messageHash, bytes memory signature) internal view returns (bool) {
        address recoveredSigner = messageHash.recover(signature);
        return recoveredSigner == address(bytes20(ownerKey));
    }

    /**
     * @dev Verifies the NON-EVM signature using the verifier precompile.
     * @param message The message to verify.
     * @param signature The signature to verify.
     * @return bool indicating whether the signature is valid.
     */
    function verifySignatureNonEVM(bytes calldata message, bytes memory signature) internal view returns (bool) {
        (bool success, bytes memory result) = verifierPrecompile.staticcall(
            abi.encodeWithSignature("verifyEd25519(bytes,bytes,bytes)", ownerKey, message, signature)
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
        uint256 startGas = gasleft();

        bytes32 txHash = getTransactionHash(payload);

        if (ownerType == OwnerType.EVM) {
            require(verifySignatureEVM(txHash, signature), "Invalid EVM signature");
        } else {
            require(verifySignatureNonEVM(payload.data, signature), "Invalid NON-EVM signature");
        }

        (bool success, ) = payload.target.call{value: payload.value}(payload.data);
        require(success, "Execution failed");

        // Refund gas to the caller

        // Options 1 : Inlcude overhead consumption
        uint256 gasUsed = startGas - gasleft() + 21000 + 5000;

        uint256 gasRefund = gasUsed * tx.gasprice;

        bool sent = payable(msg.sender).send(gasRefund);
        require(sent, "Gas refund failed");

        unchecked {
            nonce++;
        }

        emit PayloadExecuted(ownerKey, payload.target, payload.data);
    }

    function getTransactionHash(CrossChainPayload calldata payload) public view returns (bytes32) {
        // Calculate the hash of the payload using EIP-712
        bytes32 structHash = keccak256(
            abi.encode(
                PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH,
                payload.target,
                payload.value,
                keccak256(payload.data),
                payload.baseGas,
                payload.gasPrice,
                payload.gasLimit,
                payload.maxFeePerGas,
                payload.refundRecp,
                payload.nonce
            )
        );

        // Calculate the domain separator using EIP-712
        bytes32 _domainSeparator = domainSeparator();

        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator, structHash));
    }   


    // @dev Fallback function to receive ether.
    receive() external payable {}

}
