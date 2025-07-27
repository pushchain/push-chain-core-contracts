// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../Interfaces/IPRC20.sol";

/**
 * @dev Custom errors for PRC20
 */
interface PRC20Errors {
    error CallerIsNotSyntheticModule();
    error InvalidSender();
    error LowAllowance();
    error LowBalance();
    error ZeroAddress();
}

/**
 * @dev Coin types for different token standards
 */
enum CoinType {
    NOT_SET,
    Gas, // Native Push Chain token
    ERC20 // ERC20 tokens
}

/**
 * @dev Push Chain Wrapped Token (PRC20)
 */
contract PRC20 is IPRC20, PRC20Errors {
    /// @notice Synthetic module address - only this address can mint tokens
    address public syntheticModuleAddress;

    /// @notice Chain ID where this token originates from
    uint256 public immutable CHAIN_ID;

    /// @notice Coin type (Gas, ERC20)
    CoinType public immutable COIN_TYPE;

    /// @notice Protocol flat fee for cross-chain operations
    uint256 public protocolFlatFee;

    /// @notice Gas limit for cross-chain operations
    uint256 public gasLimit;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    string public name;
    string public symbol;
    uint8 public decimals;

    /**
     * @dev Constructor for PRC20 token
     */
    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        uint256 chainId_,
        CoinType coinType_,
        uint256 gasLimit_,
        address initialOwner_
    ) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
        CHAIN_ID = chainId_;
        COIN_TYPE = coinType_;
        gasLimit = gasLimit_;
        syntheticModuleAddress = initialOwner_;
        protocolFlatFee = 1000; // 0.1% = 1000 basis points
    }

    /**
     * @dev Only synthetic module modifier
     */
    modifier onlySyntheticModule() {
        if (msg.sender != syntheticModuleAddress)
            revert CallerIsNotSyntheticModule();
        _;
    }

    /**
     * @dev Standard ERC20 transfer function
     */
    function transfer(address to, uint256 amount) public returns (bool) {
        if (to == address(0)) revert ZeroAddress();
        if (balanceOf[msg.sender] < amount) revert LowBalance();

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @dev Standard ERC20 transferFrom function
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public returns (bool) {
        if (to == address(0)) revert ZeroAddress();
        if (balanceOf[from] < amount) revert LowBalance();
        if (allowance[from][msg.sender] < amount) revert LowAllowance();

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;

        emit Transfer(from, to, amount);
        return true;
    }

    /**
     * @dev Standard ERC20 approve function
     */
    function approve(address spender, uint256 amount) public returns (bool) {
        if (spender == address(0)) revert ZeroAddress();

        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /**
     * @dev Mint tokens - only callable by synthetic module
     */
    function mint(address to, uint256 amount) external onlySyntheticModule {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert LowBalance();

        balanceOf[to] += amount;
        totalSupply += amount;

        emit Transfer(address(0), to, amount);
    }

    /**
     * @dev Burn tokens - callable by users
     */
    function burn(uint256 amount) public returns (bool) {
        if (amount == 0) revert LowBalance();
        if (balanceOf[msg.sender] < amount) revert LowBalance();

        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;

        emit Transfer(msg.sender, address(0), amount);
        return true;
    }

    /**
     * @dev Withdraw function - calls burn internally
     */
    function withdraw(uint256 _amount) external {
        burn(_amount);
    }

    //TODO ADD GAS RELATED FUNCTIONS

    function getGasFee() public view returns (uint256) {
        // return gas fee in ;
    }

    /**
     * @dev Update synthetic module address - only owner
     */
    function setSyntheticModuleAddress(address newSyntheticModule) external {
        if (msg.sender != syntheticModuleAddress)
            revert CallerIsNotSyntheticModule();
        if (newSyntheticModule == address(0)) revert ZeroAddress();

        syntheticModuleAddress = newSyntheticModule;
    }

    /**
     * @dev Update protocol flat fee - only synthetic module
     */
    function setProtocolFlatFee(uint256 newFee) external {
        if (msg.sender != syntheticModuleAddress)
            revert CallerIsNotSyntheticModule();
        protocolFlatFee = newFee;
    }

    /**
     * @dev Update gas limit - only synthetic module
     */
    function setGasLimit(uint256 newGasLimit) external {
        if (msg.sender != syntheticModuleAddress)
            revert CallerIsNotSyntheticModule();
        gasLimit = newGasLimit;
    }
}
