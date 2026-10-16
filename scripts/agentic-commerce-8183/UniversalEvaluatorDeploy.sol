// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {
    ReadConfig,
    IReadStateDomains,
    IUniversalCoreHeights
} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";

/// @title UniversalEvaluatorDeploy — deploys the UniversalHook and the UniversalEvaluator together, shared by the
///        deploy script and its test
/// @notice Each needs the other's address, so the evaluator's is predicted from the deployer's nonce:
///         1. anyone deploys both implementations, the hook proxy (initialised in its constructor with the predicted
///            evaluator proxy, so nobody can initialise it first) and the evaluator proxy, then checks the wiring;
///         2. the kernel admin whitelists the hook (`setHookWhitelist`);
///         3. the marketplace admin points new jobs at both (`setHook`, `setEvaluator`), but only once the marketplace
///            builds the final JobSpec and the SDK sends the new `fund` params (`abi.encode(rulesId, specHash, newSpec)`).
///            Before that, every marketplace `fund` would revert.
/// @dev - Both proxies' ProxyAdmins are owned by `hookAdminOwner`. The evaluator decodes the JobSpec layout it was
///        compiled with.
///      - Every step checks its inputs and its result and reverts on a mismatch. A wrong prediction reverts in the
///        script's simulation, before anything is sent.
library UniversalEvaluatorDeploy {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct Params {
        address kernel;
        address agwFactory;
        address sessionEngine;
        address hookAdminOwner; // owns both proxies' ProxyAdmins
        address readState; // UniversalCallback proxy
        address universalCore;
        address feeRecipient;
        ReadConfig config;
    }

    struct Deployed {
        UniversalHook hook; // the proxy
        UniversalHook hookImpl;
        UniversalEvaluator evaluator; // the proxy
        UniversalEvaluator evaluatorImpl;
    }

    /// @notice Step 1, from `deployer`: the script's broadcaster, or the calling contract in a test.
    function deploy(Params memory p, address deployer) internal returns (Deployed memory d) {
        require(p.kernel.code.length != 0, "kernel: no code");
        _requireDependencies(p);
        d.hookImpl = new UniversalHook();
        d.evaluatorImpl = new UniversalEvaluator();
        // The hook proxy takes the deployer's next nonce, the evaluator proxy the one after.
        address predicted = VM.computeCreateAddress(deployer, VM.getNonce(deployer) + 1);
        d.hook = UniversalHook(
            address(
                new TransparentUpgradeableProxy(
                    address(d.hookImpl),
                    p.hookAdminOwner,
                    abi.encodeCall(UniversalHook.initialize, (p.kernel, p.agwFactory, p.sessionEngine, predicted))
                )
            )
        );
        d.evaluator = UniversalEvaluator(
            address(
                new TransparentUpgradeableProxy(
                    address(d.evaluatorImpl),
                    p.hookAdminOwner,
                    abi.encodeCall(
                        UniversalEvaluator.initialize,
                        (p.kernel, address(d.hook), p.readState, p.universalCore, p.feeRecipient, p.config)
                    )
                )
            )
        );
        require(address(d.evaluator) == predicted, "evaluator address prediction");
        check(p, d);
    }

    /// @notice The pair is wired as asked: the hook's kernel, binding contracts, evaluator, implementation and admin,
    ///         and the evaluator's fixed settings.
    function check(Params memory p, Deployed memory d) internal view {
        UniversalHook h = d.hook;
        require(h.KERNEL() == p.kernel, "hook: kernel");
        require(h.AGW_FACTORY() == p.agwFactory && h.SESSION_ENGINE() == p.sessionEngine, "hook: binding config");
        require(h.EVALUATOR() == address(d.evaluator), "hook: evaluator");
        require(implementationOf(address(h)) == address(d.hookImpl), "hook: implementation");
        require(ProxyAdmin(proxyAdminOf(address(h))).owner() == p.hookAdminOwner, "hook: proxy admin owner");

        UniversalEvaluator e = d.evaluator;
        require(implementationOf(address(e)) == address(d.evaluatorImpl), "evaluator: implementation");
        require(ProxyAdmin(proxyAdminOf(address(e))).owner() == p.hookAdminOwner, "evaluator: proxy admin owner");
        require(address(e.KERNEL()) == p.kernel, "evaluator: kernel");
        require(e.HOOK() == address(h), "evaluator: hook");
        require(address(e.READ_STATE()) == p.readState, "evaluator: read state");
        require(address(e.UNIVERSAL_CORE()) == p.universalCore, "evaluator: universal core");
        require(e.FEE_RECIPIENT() == p.feeRecipient, "evaluator: fee recipient");
        ReadConfig memory c = p.config;
        require(
            e.READ_TTL() == c.readTtl && e.CALLBACK_GAS_LIMIT() == c.callbackGasLimit
                && e.SNAPSHOT_CALLBACK_GAS_LIMIT() == c.snapshotCallbackGasLimit
                && e.BUDGET_MULTIPLIER() == c.budgetMultiplier && e.MAX_HEIGHT_AGE() == c.maxHeightAge
                && e.MAX_CONFIRMATIONS() == c.maxConfirmations,
            "evaluator: config"
        );
    }

    /// @notice Step 2's call, for a kernel admin that is a multisig: send `data` to `target`.
    function whitelistCall(Params memory p, Deployed memory d)
        internal
        pure
        returns (address target, bytes memory data)
    {
        target = p.kernel;
        data = abi.encodeCall(IAgenticCommerce.setHookWhitelist, (address(d.hook), true));
    }

    /// @notice Step 2, sent by the kernel admin.
    function whitelist(Params memory p, Deployed memory d) internal {
        check(p, d);
        IAgenticCommerce(p.kernel).setHookWhitelist(address(d.hook), true);
        require(IAgenticCommerce(p.kernel).whitelistedHooks(address(d.hook)), "hook: not whitelisted");
    }

    /// @notice The ProxyAdmin that controls a proxy, read from its ERC-1967 admin slot.
    function proxyAdminOf(address proxy) internal view returns (address) {
        return address(uint160(uint256(VM.load(proxy, ERC1967Utils.ADMIN_SLOT))));
    }

    /// @notice The implementation a proxy runs, read from its ERC-1967 implementation slot.
    function implementationOf(address proxy) internal view returns (address) {
        return address(uint160(uint256(VM.load(proxy, ERC1967Utils.IMPLEMENTATION_SLOT))));
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
