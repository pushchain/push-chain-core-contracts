// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract Target {
    uint256 public magicNumber;

    // Setter function to set the magic number without any cost
    function setMagicNumber(uint256 _magicNumber) public {
        magicNumber = _magicNumber;
    }

    // Setter function to set the magic number with a cost of 0.1 ETH
    function setMagicNumberWithFee(uint256 _magicNumber) public payable {
        require(msg.value == 0.1 ether, "Insufficient fee: 0.1 ETH required");
        magicNumber = _magicNumber;
    }

    // Getter function to retrieve the magic number
    function getMagicNumber() public view returns (uint256) {
        return magicNumber;
    }
}
