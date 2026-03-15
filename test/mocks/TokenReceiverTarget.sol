// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title TokenReceiverTarget
 * @notice Target contract that receives tokens via transferFrom and stores them
 */
contract TokenReceiverTarget {
    mapping(address => uint256) public tokenBalances;
    uint256 public nativeBalance;
    uint256 public magicNumber;

    event TokensReceived(address indexed token, uint256 amount);
    event NativeReceived(uint256 amount);

    // Function that expects to receive tokens via transferFrom
    function receiveTokens(address token, uint256 amount) external {
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        // The caller (CEA) should have approved us, so we transferFrom
        require(IERC20(token).transferFrom(msg.sender, address(this), amount), "Transfer failed");
        uint256 balanceAfter = IERC20(token).balanceOf(address(this));
        
        tokenBalances[token] += amount;
        magicNumber = amount; // Store amount as magic number for testing
        emit TokensReceived(token, amount);
    }

    // Function that receives native tokens
    function receiveNative() external payable {
        nativeBalance += msg.value;
        magicNumber = msg.value;
        emit NativeReceived(msg.value);
    }

    // Function that receives both tokens and executes with payload
    function executeWithTokens(
        address token,
        uint256 amount,
        bytes calldata payload
    ) external {
        if (token != address(0)) {
            require(IERC20(token).transferFrom(msg.sender, address(this), amount), "Transfer failed");
            tokenBalances[token] += amount;
        }
        
        // Execute payload if provided
        if (payload.length > 0) {
            (bool success, ) = address(this).call(payload);
            require(success, "Payload execution failed");
        }
        
        magicNumber = amount;
    }

    // Generic function that receives native tokens and executes payload
    function executeWithNative(bytes calldata payload) external payable {
        nativeBalance += msg.value;
        
        if (payload.length > 0) {
            (bool success, ) = address(this).call(payload);
            require(success, "Payload execution failed");
        }
        
        magicNumber = msg.value;
    }
}

