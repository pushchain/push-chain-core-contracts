// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface IUniversalReadClient {
    function onUniversalData(
        uint256 requestId,
        bytes calldata resultData
    ) external;
}
