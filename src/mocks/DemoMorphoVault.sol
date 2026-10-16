// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC4626Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol";
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/// @title DemoMorphoVault — a Morpho-style ERC-4626 vault for testnet demos
/// @notice Depositors' assets earn a yield at an APY the owner sets. The yield is paid from a reserve the owner funds
///         (`fundYield`), so share value only grows while the reserve lasts.
/// @dev Testnet only: no lending market behind it. Behind a TransparentUpgradeableProxy.
contract DemoMorphoVault is ERC4626Upgradeable, OwnableUpgradeable {
    using SafeERC20 for IERC20;

    /// @notice Depositors' assets, including yield already accrued.
    uint256 public managed;
    /// @notice Yield not yet paid out.
    uint256 public reserve;
    /// @notice Yearly yield, in basis points.
    uint256 public apyBps;
    uint256 public lastAccrual;

    event ApySet(uint256 apyBps);
    event YieldFunded(address indexed from, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(IERC20 asset_, string memory name_, string memory symbol_, address owner_, uint256 apyBps_)
        external
        initializer
    {
        __ERC20_init(name_, symbol_);
        __ERC4626_init(asset_);
        __Ownable_init(owner_);
        apyBps = apyBps_;
        lastAccrual = block.timestamp;
    }

    /// @notice Changes the APY from now on; yield up to now is accrued at the old one.
    function setApy(uint256 apyBps_) external onlyOwner {
        _accrue();
        apyBps = apyBps_;
        emit ApySet(apyBps_);
    }

    /// @notice Adds assets to the yield reserve.
    function fundYield(uint256 amount) external {
        _accrue();
        IERC20(asset()).safeTransferFrom(msg.sender, address(this), amount);
        reserve += amount;
        emit YieldFunded(msg.sender, amount);
    }

    function totalAssets() public view override returns (uint256) {
        return managed + _pending();
    }

    function _pending() internal view returns (uint256 y) {
        y = managed * apyBps * (block.timestamp - lastAccrual) / (10_000 * 365 days);
        if (y > reserve) y = reserve;
    }

    function _accrue() internal {
        uint256 y = _pending();
        managed += y;
        reserve -= y;
        lastAccrual = block.timestamp;
    }

    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal override {
        _accrue();
        managed += assets;
        super._deposit(caller, receiver, assets, shares);
    }

    function _withdraw(address caller, address receiver, address owner_, uint256 assets, uint256 shares)
        internal
        override
    {
        _accrue();
        managed -= assets;
        super._withdraw(caller, receiver, owner_, assets, shares);
    }

    function decimals() public view override(ERC4626Upgradeable) returns (uint8) {
        return super.decimals();
    }
}
