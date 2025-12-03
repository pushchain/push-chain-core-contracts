// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./TokenReceiverTarget.sol";

/**
 * @title TokenSpenderTarget
 * @notice Target contract that uses transferFrom to spend approved tokens
 * This is similar to TokenReceiverTarget but focuses on the spending pattern
 */
contract TokenSpenderTarget {
    mapping(address => uint256) public totalReceived;
    uint256 public magicNumber;

    // Function that transfers tokens from CEA using transferFrom
    function spendTokens(address token, uint256 amount) external {
        require(IERC20(token).transferFrom(msg.sender, address(this), amount), "TransferFrom failed");
        totalReceived[token] += amount;
        magicNumber = amount;
    }

    // Function that spends tokens and executes custom logic
    function spendTokensAndExecute(
        address token,
        uint256 amount,
        bytes calldata payload
    ) external {
        require(IERC20(token).transferFrom(msg.sender, address(this), amount), "TransferFrom failed");
        totalReceived[token] += amount;
        
        if (payload.length > 0) {
            (bool success, ) = address(this).call(payload);
            require(success, "Payload execution failed");
        }
        
        magicNumber = amount;
    }

    // Function that sets magic number (for testing empty payload)
    function setMagicNumber(uint256 _magicNumber) external {
        magicNumber = _magicNumber;
    }
}

