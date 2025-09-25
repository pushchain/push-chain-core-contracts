// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface IWPC {
    // =========================
    //    Events
    // =========================
    event Approval(address indexed src, address indexed guy, uint256 wad);
    event Transfer(address indexed src, address indexed dst, uint256 wad);
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    // =========================
    //    Functions
    // =========================

    function deposit() external payable;
    function withdraw(uint256 wad) external;
    function totalSupply() external view returns (uint256);
    function balanceOf(address guy) external view returns (uint256);
    function allowance(address src, address guy) external view returns (uint256);
    function approve(address guy, uint256 wad) external returns (bool);
    function transfer(address dst, uint256 wad) external returns (bool);
    function transferFrom(address src, address dst, uint256 wad) external returns (bool);
}
