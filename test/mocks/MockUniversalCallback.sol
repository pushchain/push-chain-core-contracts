// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {ReadSpec} from "../../src/libraries/ReadTypes.sol";

contract MockUniversalCallback is IUniversalCallback {
    uint256 public lastRequestId;

    function requestExternalReadSelf(
        ReadSpec calldata spec,
        bytes4 callbackSelector,
        uint64 callbackGasLimit
    ) external payable returns (uint256 requestId) {
        requestId = uint256(keccak256(abi.encode(spec, callbackSelector, callbackGasLimit, block.timestamp)));
        lastRequestId = requestId;
    }

    function fulfillExternalCallback(
        uint256 requestId,
        bytes calldata resultData,
        uint64 observedBlockHeight,
        bytes32 observedBlockHash
    ) external {}

    function expireExternalRead(uint256 requestId) external {}

    function estimateFee(
        string calldata chainNamespace,
        string calldata chainId,
        uint64 callbackGasLimit
    ) external view returns (uint256) {
        return 0;
    }

    function isFulfilled(uint256 requestId) external view returns (bool) {
        return false;
    }
}
