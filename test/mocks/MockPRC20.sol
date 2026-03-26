// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract MockPRC20 {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function deposit(address to, uint256 amount) external returns (bool) {
        balanceOf[to] += amount;
        totalSupply += amount;
        return true;
    }

    function burn(uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
