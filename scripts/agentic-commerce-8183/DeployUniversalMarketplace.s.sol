// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {UniversalMarketplace} from "../../src/agentic-commerce-8183/UniversalMarketplace.sol";
import {UniversalMarketplaceRules} from "../../src/agentic-commerce-8183/UniversalMarketplaceRules.sol";
import {InitParams} from "../../src/agentic-commerce-8183/libraries/Types.sol";

interface IVaultCEA {
    function CEAFactory() external view returns (address);
}

interface IGatewayCEA {
    function CEA_FACTORY() external view returns (address);
}

interface ICEAFactoryImpl {
    function CEA_PROXY_IMPLEMENTATION() external view returns (address);
}

/// @title DeployUniversalMarketplace
/// @notice Deploys a FRESH UniversalMarketplace (sdk_iterations_v2, v2.1.0) on Push Donut, bound to AGW v6, on the
///         existing kernel and wired to a UniversalHook and UniversalEvaluator already deployed against that kernel:
///         UniversalMarketplaceRules → UniversalMarketplace (JobSpecBuilder linked), then the CEA deployment of each
///         supported chain. `maxRulesPerCard` stays 1 until the hook binds every rules set of a job.
/// @dev - Uses an existing kernel (env KERNEL, default the evaluator team's eUSD kernel); deploys no kernel and no hook.
///      - The hook (env UNIVERSAL_HOOK) must already be whitelisted on that kernel; the evaluator is env
///        UNIVERSAL_EVALUATOR. The evaluator team deploys and owns all three; on Donut, see
///        `docs/addresses/push_donut_universal_marketplace.md`.
///      - The broadcaster is the marketplace admin and the owner of its ProxyAdmin.
///      - CEA factories are read live from each chain's vault (`CEAFactory()`), checked against its gateway
///        (`CEA_FACTORY()`), never hard-coded: the address docs list retired factories too.
///      - Env: DEPLOYER_KEY (broadcaster), KERNEL (optional), UNIVERSAL_HOOK, UNIVERSAL_EVALUATOR, and
///        SEPOLIA_RPC_URL, BASE_TESTNET_RPC_URL, ARB_TESTNET_RPC_URL, BSC_TESTNET_RPC_URL for the CEA reads.
///      - Full deploy: forge script scripts/agentic-commerce-8183/DeployUniversalMarketplace.s.sol \
///             --rpc-url $PUSH_CHAIN_TESTNET_RPC_URL --broadcast --slow
///      - Re-sync an existing marketplace's CEA config: same command plus
///             --sig "syncCEADeployments(address)" <marketplace>
contract DeployUniversalMarketplace is Script {
    /// @dev The evaluator team's kernel on eUSD, which 2.1.0 was deployed on (2026-10-30).
    address internal constant LIVE_KERNEL = 0x449C11cAFe57d8d9079058FeEef8e9E7E1DCBcE0;
    address internal constant AGW_V6_FACTORY = 0xFBBEB6a365178fAaA81A9789a5f64b300c37e5bc;
    uint256 internal constant DONUT_CHAIN_ID = 42101;

    /// @dev Vault and gateway proxies from Push's address registry (push.org/agents/contract-addresses.json).
    struct CEASource {
        string namespace;
        string rpcEnv;
        address vault;
        address gateway;
    }

    struct CEAChain {
        string namespace;
        address ceaFactory;
        address ceaProxyImpl;
    }

    struct Deployed {
        address kernel;
        address hook;
        address evaluator;
        address rules;
        address marketplace;
    }

    function run() external returns (Deployed memory d) {
        require(block.chainid == DONUT_CHAIN_ID, "not Push Donut");
        uint256 key = _envKey("DEPLOYER_KEY");
        address me = vm.addr(key);
        d.kernel = vm.envOr("KERNEL", LIVE_KERNEL);
        d.hook = vm.envAddress("UNIVERSAL_HOOK");
        d.evaluator = vm.envAddress("UNIVERSAL_EVALUATOR");
        require(IAgenticCommerce(d.kernel).whitelistedHooks(d.hook), "UNIVERSAL_HOOK is not whitelisted on KERNEL");
        CEAChain[] memory chains = _readCEAChains();

        vm.startBroadcast(key);
        d.rules = address(new UniversalMarketplaceRules());
        InitParams memory ip = InitParams({
            agwFactory: AGW_V6_FACTORY,
            kernel: d.kernel,
            hook: d.hook,
            evaluator: d.evaluator,
            rules: d.rules,
            admin: me
        });
        d.marketplace =
            _proxy(address(new UniversalMarketplace()), me, abi.encodeCall(UniversalMarketplace.initialize, (ip)));
        _registerCEAChains(UniversalMarketplace(d.marketplace), chains);
        vm.stopBroadcast();

        _log(d, me);
    }

    /// @dev Accepts a private key with or without the 0x prefix.
    function _envKey(string memory name) internal view returns (uint256) {
        string memory raw = vm.envString(name);
        if (bytes(raw).length == 64) raw = string.concat("0x", raw);
        return vm.parseUint(raw);
    }

    function _proxy(address impl, address proxyAdminOwner, bytes memory init) internal returns (address) {
        return address(new TransparentUpgradeableProxy(impl, proxyAdminOwner, init));
    }

    /// @notice Points an already deployed marketplace at the live CEA factories. The broadcaster needs ADMIN_ROLE.
    function syncCEADeployments(address marketplace) external {
        require(block.chainid == DONUT_CHAIN_ID, "not Push Donut");
        CEAChain[] memory chains = _readCEAChains();
        vm.startBroadcast(_envKey("DEPLOYER_KEY"));
        _registerCEAChains(UniversalMarketplace(marketplace), chains);
        vm.stopBroadcast();
    }

    function _registerCEAChains(UniversalMarketplace mkt, CEAChain[] memory chains) internal {
        for (uint256 i; i < chains.length; ++i) {
            mkt.setCEADeployment(keccak256(bytes(chains[i].namespace)), chains[i].ceaFactory, chains[i].ceaProxyImpl);
        }
    }

    /// @dev Forks each chain, reads the factory the vault deploys CEAs with, requires the gateway to agree, reads
    ///      the factory's CEA proxy implementation, then returns to the Donut fork.
    function _readCEAChains() internal returns (CEAChain[] memory c) {
        CEASource[] memory src = _ceaSources();
        uint256 donutFork = vm.activeFork();
        c = new CEAChain[](src.length);
        for (uint256 i; i < src.length; ++i) {
            vm.createSelectFork(vm.envString(src[i].rpcEnv));
            address factory = IVaultCEA(src[i].vault).CEAFactory();
            require(factory == IGatewayCEA(src[i].gateway).CEA_FACTORY(), "vault and gateway disagree on CEAFactory");
            c[i] = CEAChain(src[i].namespace, factory, ICEAFactoryImpl(factory).CEA_PROXY_IMPLEMENTATION());
            console.log(src[i].namespace, factory, c[i].ceaProxyImpl);
        }
        vm.selectFork(donutFork);
    }

    function _ceaSources() internal pure returns (CEASource[] memory s) {
        s = new CEASource[](4);
        s[0] = CEASource(
            "eip155:11155111",
            "SEPOLIA_RPC_URL",
            0xD019Eb12D0d6eF8D299661f22B4B7d262eD4b965,
            0x05bD7a3D18324c1F7e216f7fBF2b15985aE5281A
        );
        s[1] = CEASource(
            "eip155:84532",
            "BASE_TESTNET_RPC_URL",
            0xb4Ba4D5542D1dD48BD3589543660B265B41f16CB,
            0xFD4fef1F43aFEc8b5bcdEEc47f35a1431479aC16
        );
        s[2] = CEASource(
            "eip155:421614",
            "ARB_TESTNET_RPC_URL",
            0x233B1B1B378eb0Aa723097634025A47C4b73A8F7,
            0x2cd870e0166Ba458dEC615168Fd659AacD795f34
        );
        s[3] = CEASource(
            "eip155:97",
            "BSC_TESTNET_RPC_URL",
            0xE52AC4f8DD3e0263bDF748F3390cdFA1f02be881,
            0x44aFFC61983F4348DdddB886349eb992C061EaC0
        );
    }

    function _log(Deployed memory d, address me) internal pure {
        console.log("admin / proxy admin owner:", me);
        console.log("kernel     ", d.kernel);
        console.log("hook       ", d.hook);
        console.log("evaluator  ", d.evaluator);
        console.log("rules      ", d.rules);
        console.log("marketplace", d.marketplace);
    }
}
