# Demo jobs: Aave ETH Supplier, Yield Splitter, Cross-Chain Diversifier

Three UniversalEvaluator jobs run live on Push Donut, Base Sepolia and Ethereum Sepolia. The client is a UEA (a Base
Sepolia key). Its ETH travels to its own CEAs through outbound transactions, and the CEAs do the work: wrap, then
supply to Aave or deposit to the vault. Validators read the result on each chain; the evaluator judges it and the
kernel pays the provider.

| Job | Chains | The CEA's work | Done means |
|---|---|---|---|
| 1 · Aave ETH Supplier | Base | wrap 0.01 ETH, supply to Aave | aWETH +≥99.99% of the principal; no WETH or ETH idle |
| 2 · Yield Splitter | Base | wrap 0.01 ETH, 0.006 to Aave, 0.004 to the vault | Aave + vault +≥99.9% together, each +≥30%; no WETH idle |
| 3 · Cross-Chain Diversifier | Base + Ethereum Sepolia | 0.0055 to Aave on Base, 0.0045 to Aave on Sepolia | both +≥99.9% together, each +≥40% (≤60% on either); no WETH idle on either |

The criteria are in `DemoConfig.sol` (`job1`, `job2`, `job3`), and the CEA's calls are in `supplyPayload`.

## Contracts
- Aave v3 (official testnet deployments) on Base Sepolia and Ethereum Sepolia; WETH is wrapped from native ETH.
- `src/mocks/DemoMorphoVault.sol`: a Morpho-style ERC-4626 WETH vault on Base Sepolia. Its APY is set by the admin
  and paid from a yield reserve. It sits behind a TransparentUpgradeableProxy.
- On Push, deployed by `../e2e/E2EPushDeploy.s.sol`: the kernel, the UniversalHook and the UniversalEvaluator, each
  behind a TransparentUpgradeableProxy owned by the deployer. The hook uses allow-all stand-ins for the AGW checks;
  there is no AGW in this flow.

## Run
```
R=scripts/agentic-commerce-8183/demo/run.sh
$R deploy-push && $R accounts && $R deploy-vault
$R bridge base 26000000000000000          # Base ETH -> pETH.base in the UEA
$R bridge sep 5000000000000000            # Sepolia ETH -> pETH (Sepolia) in the UEA
$R open 1 && $R wait-snapshot && $R outbound base 10000000000000000 && $R submit && $R wait-verdict && $R report && $R claim
$R open 2 && $R wait-snapshot && $R outbound base 6000000000000000 4000000000000000 && $R submit && $R wait-verdict && $R report && $R claim
$R open 3 && $R wait-snapshot && $R outbound base 5500000000000000 && OUTBOUND_GAS_LIMIT=3000000 $R outbound sep 4500000000000000 && $R submit && $R wait-verdict && $R report && $R claim
```
Keys come from `.env`: `CLIENT_PRIVATE_KEY` (client, deployer, admin) and `PROVIDER_PRIVATE_KEY`. State is written
to `deployments/demo-jobs/`.

The first outbound to a chain also deploys that chain's CEA. On Ethereum Sepolia that plus the four calls needs more
than 1M gas, so the first Sepolia outbound needs `OUTBOUND_GAS_LIMIT=3000000`. With 1M it runs out of gas on
Sepolia, and Push refunds the pETH to the UEA.
