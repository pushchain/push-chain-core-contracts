// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract RevertingPRC20 {
    function deposit(address to, uint256 amount) external returns (bool) {
        revert("Deposit failed");
    }
}
