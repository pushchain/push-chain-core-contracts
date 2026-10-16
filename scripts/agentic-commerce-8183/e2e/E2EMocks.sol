// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title E2E dummies — test-only stand-ins for the evaluator end-to-end run. Never deploy to a real network.

// ───────────────────────────── Base Sepolia ─────────────────────────────

/// @notice USDC stand-in: 6 decimals, anyone can mint.
contract E2EUSDC is ERC20("E2E USD Coin", "eUSDC") {
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @notice aToken stand-in: 1:1 with the asset, minted and burned by its pool only.
contract E2EAToken is ERC20("E2E Aave USDC", "eaUSDC") {
    address public immutable POOL;

    error OnlyPool();

    constructor() {
        POOL = msg.sender;
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        if (msg.sender != POOL) revert OnlyPool();
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        if (msg.sender != POOL) revert OnlyPool();
        _burn(from, amount);
    }
}

/// @notice Aave v3 Pool stand-in, one reserve: `supply` / `withdraw` with Aave's signatures, no interest.
contract E2EAavePool {
    using SafeERC20 for IERC20;

    IERC20 public immutable ASSET;
    E2EAToken public immutable A_TOKEN;

    error WrongAsset(address asset);

    constructor(IERC20 asset) {
        ASSET = asset;
        A_TOKEN = new E2EAToken();
    }

    function supply(address asset, uint256 amount, address onBehalfOf, uint16) external {
        if (asset != address(ASSET)) revert WrongAsset(asset);
        ASSET.safeTransferFrom(msg.sender, address(this), amount);
        A_TOKEN.mint(onBehalfOf, amount);
    }

    function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        if (asset != address(ASSET)) revert WrongAsset(asset);
        A_TOKEN.burn(msg.sender, amount);
        ASSET.safeTransfer(to, amount);
        return amount;
    }
}

/// @notice MetaMorpho vault stand-in: a plain ERC-4626. `maxWithdraw(owner)` is the owner's position in assets.
contract E2EMorphoVault is ERC4626 {
    constructor(IERC20 asset) ERC20("E2E Morpho USDC", "emUSDC") ERC4626(asset) {}
}

// ───────────────────────────── Push Chain ─────────────────────────────

/// @notice The kernel's payment token: 6 decimals, anyone can mint.
contract E2EPaymentToken is ERC20("E2E Test USD", "eUSD") {
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @notice Stands in for both the AGW factory and the SmartSession engine, so an EOA can be a job's client: every
///         account is a wallet and every rules set is live.
contract E2EAllowAll {
    function isWallet(address) external pure returns (bool) {
        return true;
    }

    function isPermissionEnabled(bytes32, address) external pure returns (bool) {
        return true;
    }
}
