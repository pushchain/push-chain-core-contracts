// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract MockVaultPC {
    event Received(address indexed from, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);

    address public admin;
    uint256 public totalReceived;

    constructor() {
        admin = msg.sender;
    }

    function withdraw(address payable to, uint256 amount) external {
        require(msg.sender == admin, "not admin");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(to, amount);
    }

    receive() external payable {
        totalReceived += msg.value;
        emit Received(msg.sender, msg.value);
    }
}
