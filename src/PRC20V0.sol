// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {IPRC20} from "./interfaces/IPRC20.sol";
import {PRC20Errors, CommonErrors} from "./libraries/Errors.sol";

/**
 * @title   PRC20 (Push Chain Synthetic Token — V0 Testnet)
 * @notice  ERC-20 compatible synthetic token minted/burned by Push Chain protocol.
 * @dev     PRC20 token represents and acts as an alias for an already existing token
 *          of an external chain.
 *          All PRC20 tokens must adhere to the IPRC20 interface.
 */
contract PRC20 is IPRC20, Initializable {
    // =========================
    //    PRC20V0: STATE VARIABLES
    // =========================

    /// @notice The protocol's privileged executor module (auth & fee sink).
    address public immutable UNIVERSAL_EXECUTOR_MODULE =
        0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    /// @notice (Deprecated) Source chain ID this PRC20 mirrors.
    string public SOURCE_CHAIN_ID;

    /// @notice Source chain ERC20 address of the PRC20.
    string public SOURCE_TOKEN_ADDRESS;

    /// @notice Classification of this synthetic.
    TokenType public TOKEN_TYPE;

    /// @notice UniversalCore contract providing gas oracles (gas coin token & gas price).
    address public UNIVERSAL_CORE;

    /// @notice (Deprecated) Gas limit used in fee computation.
    /// @dev    Only included to avoid storage collision in Testnet PRC20.
    uint256 public GAS_LIMIT;

    /// @notice (Deprecated) Flat fee — protocol fees now stored in UniversalCore.
    /// @dev    Only included to avoid storage collision in Testnet PRC20.
    uint256 public PC_PROTOCOL_FEE;

    string private _name;
    string private _symbol;
    uint8 private _decimals;

    uint256 private _totalSupply;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    /// @notice Source chain namespace this PRC20 mirrors (used for oracle lookups).
    string public SOURCE_CHAIN_NAMESPACE;

    // =========================
    //    PRC20V0: MODIFIERS
    // =========================

    /// @notice Restricts to the Universal Executor Module (protocol owner).
    modifier onlyUniversalExecutor() {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) {
            revert PRC20Errors.CallerIsNotUniversalExecutor();
        }
        _;
    }

    // =========================
    //    PRC20V0: CONSTRUCTOR
    // =========================

    constructor() {
        _disableInitializers();
    }

    /// @dev                              Initializer for the upgradeable PRC20 V0 token.
    /// @param name_                      ERC-20 name
    /// @param symbol_                    ERC-20 symbol
    /// @param decimals_                  ERC-20 decimals
    /// @param sourceChainNamespace_      Source chain identifier this PRC20 represents
    /// @param tokenType_                 Token classification (PC, NATIVE, ERC20)
    /// @param protocolFlatFee_           Absolute flat fee (units: gas coin PRC20)
    /// @param universalCore_             UniversalCore contract address
    /// @param sourceTokenAddress_        Source chain token address
    function initialize(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        string memory sourceChainNamespace_,
        TokenType tokenType_,
        uint256 protocolFlatFee_,
        address universalCore_,
        string memory sourceTokenAddress_
    ) public virtual initializer {
        if (universalCore_ == address(0)) revert CommonErrors.ZeroAddress();

        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;

        SOURCE_CHAIN_NAMESPACE = sourceChainNamespace_;
        TOKEN_TYPE = tokenType_;
        PC_PROTOCOL_FEE = protocolFlatFee_;
        UNIVERSAL_CORE = universalCore_;
        SOURCE_TOKEN_ADDRESS = sourceTokenAddress_;
    }

    // =========================
    //    PRC20V0_1: ERC-20 VIEW
    // =========================

    /// @inheritdoc IPRC20
    function name() external view returns (string memory) {
        return _name;
    }

    /// @inheritdoc IPRC20
    function symbol() external view returns (string memory) {
        return _symbol;
    }

    /// @inheritdoc IPRC20
    function decimals() external view returns (uint8) {
        return _decimals;
    }

    /// @inheritdoc IPRC20
    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    /// @inheritdoc IPRC20
    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    /// @inheritdoc IPRC20
    function allowance(
        address owner,
        address spender
    ) external view returns (uint256) {
        return _allowances[owner][spender];
    }

    // =========================
    //    PRC20V0_2: ERC-20 MUTATIVE
    // =========================

    /// @inheritdoc IPRC20
    function transfer(
        address recipient,
        uint256 amount
    ) external returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    /// @inheritdoc IPRC20
    function approve(
        address spender,
        uint256 amount
    ) external returns (bool) {
        if (spender == address(0)) revert CommonErrors.ZeroAddress();
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /// @inheritdoc IPRC20
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool) {
        _transfer(sender, recipient, amount);

        uint256 currentAllowance = _allowances[sender][msg.sender];
        if (currentAllowance < amount) revert PRC20Errors.LowAllowance();
        unchecked {
            _allowances[sender][msg.sender] = currentAllowance - amount;
        }
        emit Approval(
            sender, msg.sender, _allowances[sender][msg.sender]
        );

        return true;
    }

    /// @inheritdoc IPRC20
    function burn(uint256 amount) external returns (bool) {
        _burn(msg.sender, amount);
        return true;
    }

    // =========================
    //    PRC20V0_3: BRIDGE ENTRYPOINTS
    // =========================

    /// @inheritdoc IPRC20
    function deposit(
        address to,
        uint256 amount
    ) external returns (bool) {
        if (
            msg.sender != UNIVERSAL_CORE
                && msg.sender != UNIVERSAL_EXECUTOR_MODULE
        ) {
            revert PRC20Errors.InvalidSender();
        }

        _mint(to, amount);

        emit Deposit(
            abi.encodePacked(UNIVERSAL_EXECUTOR_MODULE), to, amount
        );
        return true;
    }

    // =========================
    //    PRC20V0_4: ADMIN ACTIONS
    // =========================

    /// @notice          Update UniversalCore contract (gas coin & price oracle source).
    /// @param addr      New UniversalCore address
    function updateUniversalCore(
        address addr
    ) external onlyUniversalExecutor {
        if (addr == address(0)) revert CommonErrors.ZeroAddress();
        UNIVERSAL_CORE = addr;
        emit UpdatedUniversalCore(addr);
    }

    /// @notice          Update token name.
    /// @param newName   New name string
    function setName(
        string memory newName
    ) external onlyUniversalExecutor {
        _name = newName;
    }

    /// @notice            Update token symbol.
    /// @param newSymbol   New symbol string
    function setSymbol(
        string memory newSymbol
    ) external onlyUniversalExecutor {
        _symbol = newSymbol;
    }

    // =========================
    //    PRC20V0_5: INTERNAL HELPERS
    // =========================

    /// @dev Internal transfer with balance and zero-address checks.
    /// @param sender      Source address
    /// @param recipient   Destination address
    /// @param amount      Amount to transfer
    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal {
        if (sender == address(0) || recipient == address(0)) {
            revert CommonErrors.ZeroAddress();
        }

        uint256 senderBalance = _balances[sender];
        if (senderBalance < amount) {
            revert CommonErrors.InsufficientBalance();
        }

        unchecked {
            _balances[sender] = senderBalance - amount;
            _balances[recipient] += amount;
        }

        emit Transfer(sender, recipient, amount);
    }

    /// @dev Internal mint — creates tokens and assigns to account.
    /// @param account   Address to mint to
    /// @param amount    Amount to mint
    function _mint(address account, uint256 amount) internal {
        if (account == address(0)) revert CommonErrors.ZeroAddress();
        if (amount == 0) revert CommonErrors.ZeroAmount();

        unchecked {
            _totalSupply += amount;
            _balances[account] += amount;
        }
        emit Transfer(address(0), account, amount);
    }

    /// @dev Internal burn — destroys tokens from account.
    /// @param account   Address to burn from
    /// @param amount    Amount to burn
    function _burn(address account, uint256 amount) internal {
        if (account == address(0)) revert CommonErrors.ZeroAddress();
        if (amount == 0) revert CommonErrors.ZeroAmount();

        uint256 bal = _balances[account];
        if (bal < amount) revert CommonErrors.InsufficientBalance();

        unchecked {
            _balances[account] = bal - amount;
            _totalSupply -= amount;
        }
        emit Transfer(account, address(0), amount);
    }
}
