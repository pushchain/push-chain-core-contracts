// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @dev Interface for PRC20 tokens
 */
interface IPRC20 {
    /// @notice Token classification for provenance
    enum TokenType {
        PC,         // Push Chain native PC-origin asset
        NATIVE,     // Native coin of the source chain (e.g., ETH on Ethereum)
        ERC20       // ERC-20-origin asset on the source chain
    }

    /**
     * @notice ERC-20 metadata
     */
    function decimals() external view returns (uint8);
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function SOURCE_CHAIN_ID() external view returns (string memory);
    function PC_PROTOCOL_FEE() external view returns (uint256);
    
    /**
     * @notice Standard ERC-20 events
     */
    event UpdatedUniversalCore(address universalCore);
    event Deposit(bytes from, address to, uint256 amount);
    event UpdatedProtocolFlatFee(uint256 protocolFlatFee);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    /**
     * @notice ERC-20 standard functions
     */
    function burn(uint256 amount) external returns (bool);
    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);
    function deposit(address to, uint256 amount) external returns (bool);
    
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

}
