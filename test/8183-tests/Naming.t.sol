// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {RulesBindingHook} from "../../src/agentic-commerce-8183/hooks/RulesBindingHook.sol";
import {UniversalMarketplaceTerms} from "../../src/agentic-commerce-8183/UniversalMarketplaceTerms.sol";
import {IUniversalMarketplace} from "../../src/agentic-commerce-8183/interfaces/IUniversalMarketplace.sol";
import {
    UniversalMarketplaceErrors,
    RulesBindingHookErrors,
    ERC8183HookErrors
} from "../../src/agentic-commerce-8183/libraries/Errors.sol";

/// @notice TEST ONLY: exposes the Terms helper's ERC-20 selector constants.
contract TermsSelectorsHarness is UniversalMarketplaceTerms {
    function selectors() external pure returns (bytes4, bytes4, bytes4, bytes4) {
        return (ERC20_TRANSFER, ERC20_APPROVE, ERC20_TRANSFER_FROM, ERC20_INCREASE_ALLOWANCE);
    }
}

/// @title Naming — the AGW naming standard (UM-N PRD §6.2), pinned against LITERAL signatures.
/// @notice A rename that drifts from the standard, or a move that changed a selector, fails here.
contract NamingTest is Test {
    function test_naming_hookTopicsAndErrors() public pure {
        assertEq(RulesBindingHook.RulesBound.selector, keccak256("RulesBound(uint256,address,bytes32)"));
        assertEq(RulesBindingHookErrors.RulesNotLive.selector, bytes4(keccak256("RulesNotLive(address,bytes32)")));
        assertEq(RulesBindingHookErrors.CallerIsNotAGW.selector, bytes4(keccak256("CallerIsNotAGW(address)")));
        assertEq(ERC8183HookErrors.CallerIsNotKernel.selector, bytes4(keccak256("CallerIsNotKernel(address)")));
    }

    function test_naming_marketplaceErrors() public pure {
        assertEq(UniversalMarketplaceErrors.CallerIsNotProvider.selector, bytes4(keccak256("CallerIsNotProvider()")));
        // unrenamed errors keep their selectors: the move changed nothing
        assertEq(UniversalMarketplaceErrors.ZeroAddress.selector, bytes4(keccak256("ZeroAddress()")));
        assertEq(
            UniversalMarketplaceErrors.CardVersionMismatch.selector,
            bytes4(keccak256("CardVersionMismatch(uint256,uint256)"))
        );
        assertEq(
            UniversalMarketplaceErrors.FillOutOfBounds.selector, bytes4(keccak256("FillOutOfBounds(uint256,uint256)"))
        );
    }

    function test_naming_renamedGetters() public {
        assertEq(IUniversalMarketplace.AGW_FACTORY.selector, bytes4(keccak256("AGW_FACTORY()")));
        assertEq(IUniversalMarketplace.KERNEL.selector, bytes4(keccak256("KERNEL()")));
        assertEq(IUniversalMarketplace.TERMS.selector, bytes4(keccak256("TERMS()")));
        assertEq(IUniversalMarketplace.isCardVerified.selector, bytes4(keccak256("isCardVerified(uint256)")));
        assertEq(IUniversalMarketplace.isCardAdminDisabled.selector, bytes4(keccak256("isCardAdminDisabled(uint256)")));
        assertEq(IUniversalMarketplace.isUniversalPaused.selector, bytes4(keccak256("isUniversalPaused(bytes32)")));

        address kernel = makeAddr("kernel");
        address factory = makeAddr("factory");
        address engine = makeAddr("engine");
        RulesBindingHook hook = RulesBindingHook(
            address(
                new TransparentUpgradeableProxy(
                    address(new RulesBindingHook()),
                    makeAddr("hookAdmin"),
                    abi.encodeCall(RulesBindingHook.initialize, (kernel, factory, engine))
                )
            )
        );
        assertEq(hook.rulesOf.selector, bytes4(keccak256("rulesOf(uint256)")));
        assertEq(hook.AGW_FACTORY.selector, bytes4(keccak256("AGW_FACTORY()")));
        assertEq(hook.SESSION_ENGINE.selector, bytes4(keccak256("SESSION_ENGINE()")));
        assertEq(hook.KERNEL.selector, bytes4(keccak256("KERNEL()")));
        assertEq(hook.KERNEL(), kernel);
        assertEq(hook.AGW_FACTORY(), factory);
        assertEq(hook.SESSION_ENGINE(), engine);
        (address agw, bytes32 rulesId) = hook.rulesOf(1);
        assertEq(agw, address(0));
        assertEq(rulesId, bytes32(0));
    }

    function test_naming_derivedErc20Selectors() public {
        (bytes4 transfer, bytes4 approve, bytes4 transferFrom, bytes4 increaseAllowance) =
            new TermsSelectorsHarness().selectors();
        assertEq(transfer, bytes4(0xa9059cbb));
        assertEq(approve, bytes4(0x095ea7b3));
        assertEq(transferFrom, bytes4(0x23b872dd));
        assertEq(increaseAllowance, bytes4(0x39509351));
    }

    function test_naming_noMandateInABIs() public view {
        string[3] memory artifacts = [
            "out/UniversalMarketplace.sol/UniversalMarketplace.json",
            "out/UniversalMarketplaceTerms.sol/UniversalMarketplaceTerms.json",
            "out/RulesBindingHook.sol/RulesBindingHook.json"
        ];
        for (uint256 i; i < artifacts.length; ++i) {
            string memory abiSection = vm.split(vm.readFile(artifacts[i]), '"bytecode"')[0];
            assertEq(vm.indexOf(abiSection, "andate"), type(uint256).max, artifacts[i]);
            assertEq(vm.indexOf(abiSection, "permissionId"), type(uint256).max, artifacts[i]);
        }
    }
}
