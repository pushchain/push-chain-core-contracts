// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IWPC} from "./interfaces/IWPC.sol";
import {WPCErrors} from "./libraries/Errors.sol";

/**
 * @title   WPC
 * @notice  Wrapped PC token — ERC-20 wrapper for native PC tokens.
 */
contract WPC is IWPC {
    // =========================
    //    WPC: STATE VARIABLES
    // =========================

    string public name = "Wrapped PC";
    string public symbol = "WPC";
    uint8 public decimals = 18;

    uint256 private _totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // =========================
    //    WPC_1: DEPOSIT / WITHDRAW
    // =========================

    /// @inheritdoc IWPC
    function deposit() public payable {
        _totalSupply += msg.value;
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @inheritdoc IWPC
    function withdraw(uint256 wad) public {
        if (balanceOf[msg.sender] < wad) revert WPCErrors.InsufficientBalance();
        balanceOf[msg.sender] -= wad;
        _totalSupply -= wad;
        (bool ok,) = msg.sender.call{value: wad}("");
        if (!ok) revert WPCErrors.TransferFailed();
        emit Withdrawal(msg.sender, wad);
    }

    // =========================
    //    WPC_2: ERC-20 FUNCTIONS
    // =========================

    /// @inheritdoc IWPC
    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    /// @inheritdoc IWPC
    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    /// @inheritdoc IWPC
    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    /// @inheritdoc IWPC
    function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
        if (balanceOf[src] < wad) revert WPCErrors.InsufficientBalance();

        if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
            if (allowance[src][msg.sender] < wad) revert WPCErrors.InsufficientAllowance();
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);
        return true;
    }

    // =========================
    //    WPC: RECEIVE
    // =========================

    /// @notice Automatically converts sent native PC into WPC tokens.
    receive() external payable {
        deposit();
    }
}
