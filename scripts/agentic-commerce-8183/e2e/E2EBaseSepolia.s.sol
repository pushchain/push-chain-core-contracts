// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {E2E} from "./E2EConfig.sol";
import {E2EUSDC, E2EAavePool, E2EMorphoVault} from "./E2EMocks.sol";

/// @title E2EBaseSepolia — the Base Sepolia side of the evaluator end-to-end run (see README.md)
/// @notice `deploy()`: the client key deploys the dummy USDC, Aave pool (with its aToken) and Morpho vault.
///         `allocate()`: the provider's work — mint USDC, supply to Aave and deposit to Morpho, both for the measured
///         account (the client, or in UEA mode the UEA's CEA; see `E2EAccounts`).
///         `fundAccount()`: UEA mode, before `outbound`: the client's USDC, minted into its CEA.
///         `positions()`: the measured account's positions now.
contract E2EBaseSepolia is Script {
    function deploy() external {
        _requireBaseSepolia();
        vm.startBroadcast(E2E.clientKey());
        E2EUSDC usdc = new E2EUSDC();
        E2EAavePool pool = new E2EAavePool(usdc);
        E2EMorphoVault vault = new E2EMorphoVault(usdc);
        vm.stopBroadcast();

        E2E.BaseAddrs memory b = E2E.BaseAddrs({
            usdc: address(usdc), aavePool: address(pool), aToken: address(pool.A_TOKEN()), morphoVault: address(vault)
        });
        E2E.saveBase(b);
        console.log("=== Base Sepolia dummies deployed ===");
        console.log("USDC:        ", b.usdc);
        console.log("Aave pool:   ", b.aavePool);
        console.log("aUSDC:       ", b.aToken);
        console.log("Morpho vault:", b.morphoVault);
    }

    /// @dev ALLOC_AAVE / ALLOC_MORPHO (6 decimals) split the allocation; defaults 600 / 400 USDC.
    function allocate() external {
        _requireBaseSepolia();
        E2E.BaseAddrs memory b = E2E.loadBase();
        address account = E2E.loadAccounts().measured;
        require(account != address(0), "allocate: run `accounts` first");
        address provider = E2E.provider();
        uint256 toAave = vm.envOr("ALLOC_AAVE", uint256(600e6));
        uint256 toMorpho = vm.envOr("ALLOC_MORPHO", uint256(400e6));
        E2EUSDC usdc = E2EUSDC(b.usdc);

        vm.startBroadcast(E2E.providerKey());
        usdc.mint(provider, toAave + toMorpho);
        if (toAave != 0) {
            usdc.approve(b.aavePool, toAave);
            E2EAavePool(b.aavePool).supply(b.usdc, toAave, account, 0);
        }
        if (toMorpho != 0) {
            usdc.approve(b.morphoVault, toMorpho);
            E2EMorphoVault(b.morphoVault).deposit(toMorpho, account);
        }
        vm.stopBroadcast();

        console.log("=== Allocated for", account, "===");
        console.log("to Aave:  ", toAave);
        console.log("to Morpho:", toMorpho);
        _logPositions(b, account);
    }

    /// @dev The dummy token mints freely; this stands for USDC the client already holds in its CEA.
    function fundAccount() external {
        _requireBaseSepolia();
        address account = E2E.loadAccounts().measured;
        require(account != address(0), "fundAccount: run `accounts` first");
        uint256 amount = vm.envOr("ALLOC_AAVE", uint256(600e6)) + vm.envOr("ALLOC_MORPHO", uint256(400e6));
        vm.startBroadcast(E2E.clientKey());
        E2EUSDC(E2E.loadBase().usdc).mint(account, amount);
        vm.stopBroadcast();
        console.log("minted eUSDC to", account, amount);
    }

    function positions() external view {
        _logPositions(E2E.loadBase(), E2E.loadAccounts().measured);
    }

    function _logPositions(E2E.BaseAddrs memory b, address account) internal view {
        console.log("measured aUSDC balance:   ", IERC20(b.aToken).balanceOf(account));
        console.log("measured Morpho position: ", E2EMorphoVault(b.morphoVault).maxWithdraw(account));
    }

    function _requireBaseSepolia() internal view {
        require(block.chainid == E2E.BASE_SEPOLIA_CHAIN_ID, "E2EBaseSepolia: not Base Sepolia (84532)");
    }
}
