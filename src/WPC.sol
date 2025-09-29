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
     * @notice Deposit native PC tokens and mint WPC tokens
     * @dev Converts native PC to WPC tokens at 1:1 ratio
     * @dev The caller receives WPC tokens equal to the amount of PC sent
     * @dev Emits Deposit event with the depositor address and amount
     */
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw native PC by burning WPC tokens
     * @dev Burns WPC tokens and transfers equivalent amount of native PC to caller
     * @dev Requires caller to have sufficient WPC balance
     * @param wad Amount of WPC tokens to burn and native PC to withdraw
     * @dev Emits Withdrawal event with the withdrawer address and amount
     */
    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad, "");
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).transfer(wad);
        emit Withdrawal(msg.sender, wad);
    }

    /**
     * @notice Get the total supply of WPC tokens
     * @dev Returns the contract's native PC balance, which equals total WPC supply
     * @return Total supply of WPC tokens (equals contract's PC balance)
     */
    function totalSupply() public view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @notice Approve spender to transfer tokens on behalf of caller
     * @dev Sets allowance for spender to transfer caller's WPC tokens
     * @param guy Address of the spender to approve
     * @param wad Amount of WPC tokens to approve for transfer
     * @return Success status (always true)
     * @dev Emits Approval event with caller, spender, and approved amount
     */
    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    /**
     * @notice Transfer WPC tokens to another address
     * @dev Transfers WPC tokens from caller to destination address
     * @dev Requires caller to have sufficient balance
     * @param dst Destination address to receive WPC tokens
     * @param wad Amount of WPC tokens to transfer
     * @return Success status (true if transfer successful)
     * @dev Emits Transfer event with caller, destination, and amount
     */
    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    /**
     * @notice Transfer WPC tokens from one address to another
     * @dev Transfers WPC tokens from source to destination address
     * @dev Requires source to have sufficient balance and caller to have sufficient allowance
     * @dev Supports infinite allowance (type(uint256).max) for gas optimization
     * @param src Source address to transfer WPC tokens from
     * @param dst Destination address to receive WPC tokens
     * @param wad Amount of WPC tokens to transfer
     * @return Success status (true if transfer successful)
     * @dev Emits Transfer event with source, destination, and amount
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
     * @notice Receive function - automatically deposits sent native PC
     * @dev Automatically converts any native PC sent to this contract into WPC tokens
     * @dev Calls deposit() function internally to mint WPC tokens to sender
     */
    receive() external payable {
        deposit();
    }
}
