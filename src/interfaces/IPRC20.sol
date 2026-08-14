// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  IPRC20
/// @notice Interface for PRC20 synthetic tokens on Push Chain.
/// @dev    Defines public-facing functions for the PRC20 token contract.
interface IPRC20 {
    // =========================
    //    PRC20: TYPE DECLARATIONS
    // =========================

    /// @notice Token classification for provenance.
    enum TokenType {
        PC, // Push Chain native PC-origin asset
        NATIVE, // Native coin of the source chain (e.g., ETH on Ethereum)
        ERC20 // ERC-20-origin asset on the source chain
    }

    // =========================
    //    PRC20: EVENTS
    // =========================

    event UpdatedUniversalCore(address universalCore);
    event Deposit(bytes from, address to, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event NameUpdated(string oldName, string newName);
    event SymbolUpdated(string oldSymbol, string newSymbol);

    // =========================
    //    PRC20_1: ERC-20 METADATA
    // =========================

    /// @notice             Returns the token name.
    /// @return             Token name string
    function name() external view returns (string memory);

    /// @notice             Returns the token symbol.
    /// @return             Token symbol string
    function symbol() external view returns (string memory);

    /// @notice             Returns the number of decimals.
    /// @return             Token decimals
    function decimals() external view returns (uint8);

    /// @notice             Returns the source chain namespace this PRC20 mirrors.
    /// @return             Source chain namespace string (e.g. "eip155:1")
    function SOURCE_CHAIN_NAMESPACE() external view returns (string memory);

    // =========================
    //    PRC20_2: ERC-20 FUNCTIONS
    // =========================

    /// @notice             Returns the total supply of the token.
    /// @return             Total supply
    function totalSupply() external view returns (uint256);

    /// @notice             Returns the balance of an account.
    /// @param account      Account address
    /// @return             Balance of the account
    function balanceOf(address account) external view returns (uint256);

    /// @notice             Returns the allowance from owner to spender.
    /// @param owner        Owner address
    /// @param spender      Spender address
    /// @return             Allowance amount
    function allowance(address owner, address spender) external view returns (uint256);

    /// @notice             Approve spender to transfer tokens on behalf of caller.
    /// @param spender      Spender address
    /// @param amount       Amount to approve
    /// @return             Success status
    function approve(address spender, uint256 amount) external returns (bool);

    /// @notice             Transfer tokens to recipient.
    /// @param recipient    Recipient address
    /// @param amount       Amount to transfer
    /// @return             Success status
    function transfer(address recipient, uint256 amount) external returns (bool);

    /// @notice             Transfer tokens using allowance.
    /// @param sender       Source address
    /// @param recipient    Destination address
    /// @param amount       Amount to transfer
    /// @return             Success status
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /// @notice             Burn caller's tokens.
    /// @param amount       Amount to burn
    /// @return             Success status
    function burn(uint256 amount) external returns (bool);

    // =========================
    //    PRC20_3: BRIDGE FUNCTIONS
    // =========================

    /// @notice             Mint PRC20 on inbound bridge (lock on source).
    /// @param to           Recipient on Push EVM
    /// @param amount       Amount to mint
    /// @return             Success status
    function deposit(address to, uint256 amount) external returns (bool);
}
