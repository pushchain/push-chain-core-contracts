// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

/// @title Wrapped PUSH (WPUSH)
/// @notice WPUSH contract for Push Chain - equivalent to WETH9 on Ethereum
/// @dev Implements IWETH9 interface required by Uniswap V3 periphery contracts
contract WPUSH {
    string public name = "Wrapped PUSH";
    string public symbol = "WPUSH";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed src, address indexed guy, uint256 wad);
    event Transfer(address indexed src, address indexed dst, uint256 wad);
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    /// @notice Fallback function to deposit PUSH when sent directly to contract
    receive() external payable {
        deposit();
    }

    /// @notice Deposit PUSH to get WPUSH tokens
    /// @dev Implements IWETH9 interface
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
        emit Transfer(address(0), msg.sender, msg.value);
    }

    /// @notice Withdraw WPUSH tokens to get PUSH
    /// @dev Implements IWETH9 interface
    /// @param wad Amount to withdraw
    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad, "WPUSH: insufficient balance");
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).transfer(wad);
        emit Withdrawal(msg.sender, wad);
        emit Transfer(msg.sender, address(0), wad);
    }

    /// @notice Get total supply of WPUSH tokens
    /// @return Total WPUSH supply (equals contract's PUSH balance)
    function totalSupply() public view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Approve spender to spend tokens on behalf of owner
    /// @param guy Spender address
    /// @param wad Amount to approve
    /// @return Success boolean
    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    /// @notice Transfer tokens to another address
    /// @param dst Destination address
    /// @param wad Amount to transfer
    /// @return Success boolean
    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    /// @notice Transfer tokens from one address to another
    /// @param src Source address
    /// @param dst Destination address
    /// @param wad Amount to transfer
    /// @return Success boolean
    function transferFrom(
        address src,
        address dst,
        uint256 wad
    ) public returns (bool) {
        require(balanceOf[src] >= wad, "WPUSH: insufficient balance");

        if (
            src != msg.sender && allowance[src][msg.sender] != type(uint256).max
        ) {
            require(
                allowance[src][msg.sender] >= wad,
                "WPUSH: insufficient allowance"
            );
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);

        return true;
    }

    /// @notice Increase allowance for spender
    /// @param spender Address to increase allowance for
    /// @param addedValue Amount to increase by
    /// @return Success boolean
    function increaseAllowance(
        address spender,
        uint256 addedValue
    ) public returns (bool) {
        approve(spender, allowance[msg.sender][spender] + addedValue);
        return true;
    }

    /// @notice Decrease allowance for spender
    /// @param spender Address to decrease allowance for
    /// @param subtractedValue Amount to decrease by
    /// @return Success boolean
    function decreaseAllowance(
        address spender,
        uint256 subtractedValue
    ) public returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(
            currentAllowance >= subtractedValue,
            "WPUSH: decreased allowance below zero"
        );
        approve(spender, currentAllowance - subtractedValue);
        return true;
    }
}
