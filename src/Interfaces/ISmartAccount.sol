pragma solidity ^0.8.20;

import {UniversalAccount, CrossChainPayload} from "../libraries/Types.sol";

interface ISmartAccount {
    // Events
    event PayloadExecuted(bytes caller, address target, bytes data);

    // Functions

    function universalAccount() external view returns (UniversalAccount memory);

    function verifyPayloadSignature(bytes32 messageHash, bytes memory signature) external view returns (bool);

    function executePayload(CrossChainPayload calldata payload, bytes calldata signature) external;

    function initialize(UniversalAccount memory _UniversalAccount) external;
}
