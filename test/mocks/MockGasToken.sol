// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../../src/interfaces/IPRC20.sol";

/**
 * @title MockGasToken
 * @notice Mock implementation of a PRC20 token used as gas token
 */
contract MockGasToken is IPRC20 {
    bool public willSucceed = true;
    bool public willRevert = false;
    address public reentrancyTarget;
    bytes public reentrancyCalldata;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;

    // Mock configuration
    function setWillSucceed(bool success) external {
        willSucceed = success;
    }

    function setWillRevert(bool revert_) external {
        willRevert = revert_;
    }

    function setReentrancyAttack(address target, bytes calldata data) external {
        reentrancyTarget = target;
        reentrancyCalldata = data;
    }

    // Mock minting function
    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
        _totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    // ERC20 core functions
    function transfer(address recipient, uint256 amount) external returns (bool) {
        if (willRevert) revert("MockGasToken: transfer reverted");
        
        if (willSucceed) {
            _balances[msg.sender] -= amount;
            _balances[recipient] += amount;
            emit Transfer(msg.sender, recipient, amount);
        }
        
        return willSucceed;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        if (willRevert) revert("MockGasToken: approve reverted");
        
        if (willSucceed) {
            _allowances[msg.sender][spender] = amount;
            emit Approval(msg.sender, spender, amount);
        }
        
        return willSucceed;
    }

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool) {
        if (willRevert) revert("MockGasToken: transferFrom reverted");
        
        if (willSucceed) {
            uint256 currentAllowance = _allowances[sender][msg.sender];
            require(currentAllowance >= amount, "MockGasToken: insufficient allowance");
            
            _balances[sender] -= amount;
            _balances[recipient] += amount;
            _allowances[sender][msg.sender] = currentAllowance - amount;
            
            emit Transfer(sender, recipient, amount);
            
            // Execute reentrancy attack if configured
            if (reentrancyTarget != address(0) && reentrancyCalldata.length > 0) {
                (bool success,) = reentrancyTarget.call(reentrancyCalldata);
                require(success, "MockGasToken: reentrancy attack failed");
            }
        }
        
        return willSucceed;
    }

    // View functions
    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    // Unimplemented functions required by interface
    function name() external pure returns (string memory) { return "MockGasToken"; }
    function symbol() external pure returns (string memory) { return "MGAS"; }
    function decimals() external pure returns (uint8) { return 18; }
    function deposit(address, uint256) external pure returns (bool) { revert("Not implemented"); }
    function burn(uint256) external pure returns (bool) { revert("Not implemented"); }
    function withdraw(bytes calldata, uint256) external pure returns (bool) { revert("Not implemented"); }
    function withdrawGasFee() external pure returns (address, uint256) { revert("Not implemented"); }
    function withdrawGasFeeWithGasLimit(uint256) external pure returns (address, uint256) { revert("Not implemented"); }
    function UNIVERSAL_EXECUTOR_MODULE() external pure returns (address) { revert("Not implemented"); }
    function SOURCE_CHAIN_ID() external pure returns (uint256) { revert("Not implemented"); }
    function TOKEN_TYPE() external pure returns (TokenType) { revert("Not implemented"); }
    function HANDLER_CONTRACT() external pure returns (address) { revert("Not implemented"); }
    function UNIVERSAL_CORE() external pure returns (address) { revert("Not implemented"); }
    function GAS_LIMIT() external pure returns (uint256) { revert("Not implemented"); }
    function PC_PROTOCOL_FEE() external pure returns (uint256) { revert("Not implemented"); }
}
