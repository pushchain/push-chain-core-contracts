// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @dev PRC20 mock that returns false instead of reverting on deposit/burn.
contract FalseReturningPRC20 {
    string public SOURCE_CHAIN_NAMESPACE;
    string public SOURCE_TOKEN_ADDRESS;

    constructor(string memory ns, string memory tokenAddr) {
        SOURCE_CHAIN_NAMESPACE = ns;
        SOURCE_TOKEN_ADDRESS = tokenAddr;
    }

    function deposit(address, uint256) external pure returns (bool) {
        return false;
    }

    function burn(uint256) external pure returns (bool) {
        return false;
    }

    function approve(address, uint256) external pure returns (bool) {
        return false;
    }
}
