// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IWPC} from "./Interfaces/IWPC.sol";

/**
 * @title WPC
 * @notice Wrapped PC token - ERC20 wrapper for native PC tokens
 */
contract WPC is IWPC {
    string public name = "Wrapped PC";
    string public symbol = "WPC";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    /**
     * @notice Deposit PC and mint WPC tokens
     */
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw PC by burning WPC tokens
     * @param wad Amount of WPC to burn and PC to withdraw
     */
    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad, "");
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).transfer(wad);
        emit Withdrawal(msg.sender, wad);
    }

    /**
     * @notice Total supply of WPC tokens (equals contract's PC balance)
     * @return Total supply
     */
    function totalSupply() public view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @notice Approve spender to transfer tokens
     * @param guy Spender address
     * @param wad Amount to approve
     * @return Success status
     */
    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    /**
     * @notice Transfer tokens to another address
     * @param dst Destination address
     * @param wad Amount to transfer
     * @return Success status
     */
    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    /**
     * @notice Transfer tokens from one address to another
     * @param src Source address
     * @param dst Destination address
     * @param wad Amount to transfer
     * @return Success status
     */
    function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
        require(balanceOf[src] >= wad, "");

        if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
            require(allowance[src][msg.sender] >= wad, "");
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);
        return true;
    }


    /**
     * @notice Receive function - automatically deposits sent PC
     */
    receive() external payable {
        deposit();
    }

}
