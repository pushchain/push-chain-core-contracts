// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @dev Interface for PRC20 tokens
 */
interface IPRC20 {
    /**
     * @notice Standard ERC-20 events
     */
    event UpdatedUniversalCore(address universalCore);
    event UpdatedGasLimit(uint256 gasLimit);
    event UpdatedProtocolFlatFee(uint256 protocolFlatFee);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Deposit(bytes from, address to, uint256 amount);
    event Withdrawal(address from, bytes to, uint256 amount, uint256 gasFee, uint256 protocolFlatFee);

    /**
     * @notice ERC-20 metadata
     */
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);

    /**
     * @notice ERC-20 standard functions
     */
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function deposit(address to, uint256 amount) external returns (bool);
    function burn(uint256 amount) external returns (bool);
    function withdraw(bytes calldata to, uint256 amount) external returns (bool);
    function withdrawGasFee() external view returns (address, uint256);
    function withdrawGasFeeWithGasLimit(uint256 gasLimit) external view returns (address, uint256);

    /**
     * @notice System constants (in upper case to maintain compatibility with ZRC20)
     */
    function UNIVERSAL_EXECUTOR_MODULE() external view returns (address);
    function SOURCE_CHAIN_ID() external view returns (uint256);
    function TOKEN_TYPE() external view returns (TokenType);
    function UNIVERSAL_CORE() external view returns (address);
    function GAS_LIMIT() external view returns (uint256);
    function PC_PROTOCOL_FEE() external view returns (uint256);

    /// @notice Token classification for provenance
    enum TokenType {
        PC, // Push Chain native PC-origin asset
        NATIVE, // Native coin of the source chain (e.g., ETH on Ethereum)
        ERC20 // ERC-20-origin asset on the source chain

    }
}
