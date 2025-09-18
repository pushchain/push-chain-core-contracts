// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract MaliciousPRC20 {
    address public handler;
    
    constructor(address _handler) {
        handler = _handler;
    }
    
    function deposit(address to, uint256 amount) external returns (bool) {
        // Try to reenter handler with a function that requires admin role
        (bool success,) = handler.call(abi.encodeWithSignature("setWPCContractAddress(address)", address(0x123)));
        if (!success) {
            revert("Reentry failed");
        }
        return true;
    }
}
