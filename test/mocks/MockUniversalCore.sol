// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract MockUniversalCore {
    mapping(string => mapping(string => uint256)) public readBaseFeeByChainNamespace;

    function setReadBaseFee(
        string memory chainNamespace,
        string memory chainId,
        uint256 fee
    ) external {
        readBaseFeeByChainNamespace[chainNamespace][chainId] = fee;
    }
}
