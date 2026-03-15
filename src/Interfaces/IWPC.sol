// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  IWPC
/// @notice Interface for the Wrapped PC token contract.
/// @dev    Defines public-facing functions for the WPC ERC-20 wrapper.
interface IWPC {
    // =========================
    //    WPC: EVENTS
    // =========================

    event Approval(
        address indexed src, address indexed guy, uint256 wad
    );
    event Transfer(
        address indexed src, address indexed dst, uint256 wad
    );
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    // =========================
    //    WPC_1: DEPOSIT / WITHDRAW
    // =========================

    /// @notice             Deposit native PC tokens and mint WPC tokens at 1:1.
    function deposit() external payable;

    /// @notice             Burn WPC tokens and withdraw equivalent native PC.
    /// @param wad          Amount to withdraw
    function withdraw(uint256 wad) external;

    // =========================
    //    WPC_2: ERC-20 FUNCTIONS
    // =========================

    /// @notice             Returns the total supply of WPC tokens.
    /// @return             Total supply (equals contract's PC balance)
    function totalSupply() external view returns (uint256);

    /// @notice             Returns the WPC balance of an account.
    /// @param guy          Account address
    /// @return             Balance of the account
    function balanceOf(address guy) external view returns (uint256);

    /// @notice             Returns the allowance from src to guy.
    /// @param src          Owner address
    /// @param guy          Spender address
    /// @return             Allowance amount
    function allowance(
        address src,
        address guy
    ) external view returns (uint256);

    /// @notice             Approve spender to transfer tokens on behalf of caller.
    /// @param guy          Spender address
    /// @param wad          Amount to approve
    /// @return             Success status
    function approve(address guy, uint256 wad) external returns (bool);

    /// @notice             Transfer WPC tokens to another address.
    /// @param dst          Destination address
    /// @param wad          Amount to transfer
    /// @return             Success status
    function transfer(address dst, uint256 wad) external returns (bool);

    /// @notice             Transfer WPC tokens from one address to another.
    /// @param src          Source address
    /// @param dst          Destination address
    /// @param wad          Amount to transfer
    /// @return             Success status
    function transferFrom(
        address src,
        address dst,
        uint256 wad
    ) external returns (bool);
}
