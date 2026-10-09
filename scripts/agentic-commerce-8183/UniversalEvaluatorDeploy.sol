// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {UniversalEvaluatorLogic} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluatorLogic.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {IReadStateDomains} from "../../src/agentic-commerce-8183/evaluator/ExternalInterfaces.sol";
import {IUniversalCoreHeights} from "../../src/agentic-commerce-8183/evaluator/ExternalInterfaces.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {ReadConfig} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";

/// @title UniversalEvaluatorDeploy — the in-place route, shared by the deploy script and its test
/// @notice The hook proxy already exists (it runs RulesBindingHook), so nothing has to be predicted:
///         1. anyone deploys the Logic, the evaluator pointing at the existing hook proxy, and the new hook code;
///         2. the ProxyAdmin owner upgrades the proxy and sets its evaluator in one call
///            (`upgradeAndCall` → `UniversalHook.initializeV2`);
///         3. the marketplace admin points new jobs at the evaluator (`UniversalMarketplace.setEvaluator`), but only
///            once the marketplace builds the final JobSpec and the SDK sends the new `fund` params
///            (`abi.encode(rulesId, specHash, newSpec)`). Before that, every marketplace `fund` would revert.
///         Steps 1 and 2 are safe on their own: jobs keep the evaluator they were created with, and the hook only binds
///         rules for jobs with another evaluator.
/// @dev - Precondition: the JobSpec layout is final (`executeBy` / `failFinalAt` removed if they are going, `mutability`
///        in). The evaluator is not upgradeable and decodes the layout it was compiled with.
///      - Every step checks its inputs and its result and reverts on a mismatch.
library UniversalEvaluatorDeploy {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @notice Where `UniversalHook.EVALUATOR` lives (its storage comment); a gap slot in RulesBindingHook, so zero.
    uint256 internal constant EVALUATOR_SLOT = 54;

    struct Params {
        address kernel;
        address hookProxy; // the existing RulesBindingHook proxy
        address expectedHookImpl; // the RulesBindingHook implementation that proxy runs today
        address readState; // UniversalCallback proxy
        address universalCore;
        address feeRecipient;
        ReadConfig config;
    }

    struct Deployed {
        UniversalEvaluatorLogic logic;
        UniversalEvaluator evaluator;
        UniversalHook hookImpl;
    }

    /// @notice Step 1. Deploys the Logic, the evaluator and the new hook implementation, and checks them.
    function deploy(Params memory p) internal returns (Deployed memory d) {
        _requireHookProxy(p);
        _requireDependencies(p);
        d.logic = new UniversalEvaluatorLogic();
        d.evaluator = new UniversalEvaluator(
            p.kernel, p.hookProxy, p.readState, p.universalCore, address(d.logic), p.feeRecipient, p.config
        );
        d.hookImpl = new UniversalHook();
        checkEvaluator(p, d);
    }

    /// @notice The evaluator's fixed settings are the ones asked for.
    function checkEvaluator(Params memory p, Deployed memory d) internal view {
        UniversalEvaluator e = d.evaluator;
        require(address(e.KERNEL()) == p.kernel, "evaluator: kernel");
        require(e.HOOK() == p.hookProxy, "evaluator: hook");
        require(address(e.READ_STATE()) == p.readState, "evaluator: read state");
        require(address(e.UNIVERSAL_CORE()) == p.universalCore, "evaluator: universal core");
        require(address(e.LOGIC()) == address(d.logic), "evaluator: logic");
        require(e.FEE_RECIPIENT() == p.feeRecipient, "evaluator: fee recipient");
        ReadConfig memory c = e.readConfig();
        require(
            c.readTtl == p.config.readTtl && c.callbackGasLimit == p.config.callbackGasLimit
                && c.snapshotCallbackGasLimit == p.config.snapshotCallbackGasLimit
                && c.budgetMultiplier == p.config.budgetMultiplier && c.maxHeightAge == p.config.maxHeightAge
                && c.maxConfirmations == p.config.maxConfirmations,
            "evaluator: config"
        );
    }

    /// @notice The ProxyAdmin that controls the hook proxy, read from its ERC-1967 admin slot.
    function proxyAdminOf(address proxy) internal view returns (address) {
        return address(uint160(uint256(VM.load(proxy, ERC1967Utils.ADMIN_SLOT))));
    }

    /// @notice Step 2's call, for a ProxyAdmin owned by a multisig: send `data` to `target`.
    function upgradeCall(Params memory p, Deployed memory d) internal view returns (address target, bytes memory data) {
        target = proxyAdminOf(p.hookProxy);
        data = abi.encodeCall(
            ProxyAdmin.upgradeAndCall,
            (
                ITransparentUpgradeableProxy(p.hookProxy),
                address(d.hookImpl),
                abi.encodeCall(UniversalHook.initializeV2, (address(d.evaluator)))
            )
        );
    }

    /// @notice Step 2, sent by the ProxyAdmin owner. Upgrades the hook in place and sets its evaluator, then checks the
    ///         evaluator is set and the hook's kernel, factory and engine are unchanged. Whether every wallet binding
    ///         survives is a storage-layout property: the migration test checks it on a populated binding and live
    ///         job; this step can't enumerate bindings.
    function upgrade(Params memory p, Deployed memory d) internal {
        UniversalHook h = UniversalHook(p.hookProxy);
        require(d.evaluator.HOOK() == p.hookProxy, "evaluator is for another hook");
        _requireHookProxy(p); // still the RulesBindingHook it was at step 1
        address factory = h.AGW_FACTORY();
        address engine = h.SESSION_ENGINE();
        ProxyAdmin(proxyAdminOf(p.hookProxy))
            .upgradeAndCall(
                ITransparentUpgradeableProxy(p.hookProxy),
                address(d.hookImpl),
                abi.encodeCall(UniversalHook.initializeV2, (address(d.evaluator)))
            );
        require(h.EVALUATOR() == address(d.evaluator), "hook: evaluator not set");
        require(h.KERNEL() == p.kernel, "hook: kernel changed");
        require(h.AGW_FACTORY() == factory && h.SESSION_ENGINE() == engine, "hook: binding config changed");
    }

    /// @dev The proxy is this kernel's whitelisted hook, has an admin, runs exactly the expected RulesBindingHook
    ///      implementation, and the slot the evaluator will use is still empty.
    function _requireHookProxy(Params memory p) private view {
        require(p.hookProxy.code.length != 0, "hook proxy: no code");
        require(IAgenticCommerce(p.kernel).whitelistedHooks(p.hookProxy), "hook proxy: not whitelisted on kernel");
        require(UniversalHook(p.hookProxy).KERNEL() == p.kernel, "hook proxy: other kernel");
        require(proxyAdminOf(p.hookProxy) != address(0), "hook proxy: no admin");
        address impl = address(uint160(uint256(VM.load(p.hookProxy, ERC1967Utils.IMPLEMENTATION_SLOT))));
        require(impl == p.expectedHookImpl, "hook proxy: not the expected RulesBindingHook implementation");
        require(VM.load(p.hookProxy, bytes32(EVALUATOR_SLOT)) == bytes32(0), "hook proxy: evaluator slot not empty");
    }

    /// @dev The evaluator is bound to these contracts for good, and calls these views on every job, so each must exist:
    ///      a Read State without `isDomainBlocked` (added 2026-08-03) would make every `fund` revert.
    function _requireDependencies(Params memory p) private view {
        try IReadStateDomains(p.readState).isDomainBlocked("", "") returns (bool) {}
        catch {
            revert("read state: no isDomainBlocked");
        }
        try IUniversalCallback(p.readState).estimateFee("", "") returns (uint256) {}
        catch {
            revert("read state: no estimateFee");
        }
        try IUniversalCoreHeights(p.universalCore).chainHeightByChainNamespace("") returns (uint256) {}
        catch {
            revert("universal core: no chainHeightByChainNamespace");
        }
        try IUniversalCoreHeights(p.universalCore).timestampObservedAtByChainNamespace("") returns (uint256) {}
        catch {
            revert("universal core: no timestampObservedAtByChainNamespace");
        }
    }
}
