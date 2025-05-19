pragma solidity ^0.8.20;

import {AccountId, CrossChainPayload} from "../libraries/Types.sol";

interface ISmartAccount {
    // Events
    event PayloadExecuted(bytes caller, address target, bytes data);

    // Functions

    function accountId() external view returns (AccountId memory);

    function verifyPayloadSignature(bytes32 messageHash, bytes memory signature) external view returns (bool);

    function executePayload(CrossChainPayload calldata payload, bytes calldata signature) external;

    function initialize(AccountId memory _accountId) external;
}
