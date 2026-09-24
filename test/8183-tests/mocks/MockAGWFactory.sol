// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice Answers `isWallet` from a settable map.
contract MockAGWFactory {
    mapping(address => bool) public isWallet;

    function setWallet(address account, bool status) external {
        isWallet[account] = status;
    }
}
