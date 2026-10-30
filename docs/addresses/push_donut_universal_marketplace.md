# Push Donut (Chain ID: 42101): UniversalMarketplace stack

## Current: UniversalMarketplace 2.1.0

Deployed 2026-10-30 with `scripts/agentic-commerce-8183/DeployUniversalMarketplace.s.sol` (blocks
24803669–24803686), on the evaluator team's kernel, UniversalHook and UniversalEvaluator. Bound to AGW v6.

### Contracts

| Contract | Proxy | Implementation | ProxyAdmin |
|---|---|---|---|
| UniversalMarketplace (`version()` = `"2.1.0"`) | `0x940744d96b14Bc030163C6084d602d57CE42ba48` | `0xb1d8032F5432D89CF8a67e221960a494A41de1e3` | `0x3b5cD7c5eC3B6344271533518b1dd4F26495a862` |
| UniversalMarketplaceRules (not a proxy) | `0x323FDBF1EC07e56a19225d836566155C93463CcD` | | |
| JobSpecBuilder (linked library) | `0xC84C0056310CBCD89C366E1A339AA7bD91B5d0ba` | | |

The marketplace admin (`DEFAULT_ADMIN_ROLE`, `ADMIN_ROLE`) and the owner of its ProxyAdmin is the deployer
`0x1afC81396f1bb36F91f74506284952b81e4bd47c`. `maxRulesPerCard` = 1.

### Kernel, hook and evaluator (the evaluator team's; not ours)

| Contract | Proxy | Implementation (as of 2026-10-30) | ProxyAdmin |
|---|---|---|---|
| AgenticCommerce (kernel) | `0x449C11cAFe57d8d9079058FeEef8e9E7E1DCBcE0` | `0xDDbD506ce141241DC04564995121683da6f7A131` | `0x7645c0898114101046efB9C6834Cc4309e8eB676` |
| UniversalHook | `0xbee0B01773Dc742887f04bED58BD1B5Aa457ED96` | `0x5fa9cBbcB1434F3cbE84C7F7fD6b07663D437f3f` | `0x3f72d24EE86CA15d175bC56EBE831439669C7906` |
| UniversalEvaluator | `0x2a73944D79E052bAF553F59fA1c7C23f3491845c` | `0xd1d5CD1af6331DF9e83E679E1627BD4966c72c01` | `0xa3ADE3F8Ca1D3a3DEE52C517A364457306a8190E` |

| Item | Value |
|---|---|
| Kernel admin, kernel treasury, evaluator `FEE_RECIPIENT`, owner of all three ProxyAdmins | `0x5496c7e4f5cE04c7c18fe443cD8cA0931099d97D` |
| Kernel payment token (every card's `paymentToken`) | eUSD "E2E Test USD", 6 decimals: `0x8E1eD40770cd197c80048cB3a86D3c8173cd560D` |
| Kernel fees | `platformFeeBP` 0, `evaluatorFeeBP` 0 |
| Hook: AGW factory / session engine | `0xFBBEB6a365178fAaA81A9789a5f64b300c37e5bc` / `0xf63DC0628fe1B25049FE3E3a3585Ef051CB98c1d` (AGW v6, same as the marketplace) |
| Evaluator: Read State / UniversalCore | `0x00000000000000000000000000000000000000c2` / `0x00000000000000000000000000000000000000C0` |
| Evaluator read config | `READ_TTL` 1200, `CALLBACK_GAS_LIMIT` 1 000 000, `SNAPSHOT_CALLBACK_GAS_LIMIT` 300 000, `BUDGET_MULTIPLIER` 3, `MAX_HEIGHT_AGE` 600, `MAX_CONFIRMATIONS` 64 |
| Client UEA shared by the evaluator team (a UEA, not an AGW) | `0x04135Be65b68B3ec51Cf31c9299dAB0f663E499c` |

The three are upgradeable by `0x5496…d97D`, and their implementations are not source-verified. On 2026-10-30 the
evaluator's linked `JobSpecLib` (`0x282fD3DA53D605E0f9AA0a8873ba06999fE16f5C`) accepted every example spec the
marketplace builds, so the live job format is the marketplace's `JobSpecTypes.sol`.

### Supported card chains (`setCEADeployment`)

Each factory is the one Push actually uses on that chain: the vault's `CEAFactory()` and the gateway's
`CEA_FACTORY()` both return it. The address docs also list retired factories; do not take a factory from them.
On 2026-10-30, `computeCEA` equalled each factory's `getCEAForPushAccount` for AGW
`0x8D3deDF167340b86EDff2aF02FD66dfd4F42f3f6` on all four chains.

| Chain | Namespace | CEAFactory (proxy) | CEA proxy implementation |
|---|---|---|---|
| Ethereum Sepolia | `eip155:11155111` | `0x5E191fbBe22F8866C5e4250557664fCE760e8870` | `0x425291f35BA1A94Bd2dcC2dC097c2B55700A1fB6` |
| Base Sepolia | `eip155:84532` | `0x7e8CeeDA043ED1460540616103dD57581a66C856` | `0xe816b67B73c47e51E4B263c9149675b589E8e741` |
| Arbitrum Sepolia | `eip155:421614` | `0x65572FFa81c230360a8a53C1682C7f0Ee321E5E7` | `0xe27c8f93b4e01C9557b41C702Fa2634B9e5728CE` |
| BSC Testnet | `eip155:97` | `0x3f1B16e0B072d472951C4563d29d3da6a3EE3Ce8` | `0x0ff5d8b7d9Ac3ee2Ad420e9b70Ed6Dc465f593e9` |

### Transactions (2026-10-30)

| Step | Transaction |
|---|---|
| JobSpecBuilder | `0xd0ec755de74f18f293a5b3e3ea0182b08969ae255b2cd2c7c0ece5d6cbdf0897` |
| UniversalMarketplaceRules | `0xb1af93660b1c6de7e3ecb659cc931412e47aa80d3376d2457d0b0fa40fec0d5e` |
| UniversalMarketplace implementation | `0xd7c74610a9fe02c5f80e689e6e243d42691152138a8eae8bf7a1ff4e7a2c4f86` |
| Proxy + `initialize` | `0xda96ac05a5660fd11a02c80b090a9ecf806b7d970f28b424d299664068fda0e9` |
| `setCEADeployment` Sepolia | `0xaa9fe66297a2aff3e5e99e1b86f613bfcb88159f1614ec7d0bfa940c19ec5029` |
| `setCEADeployment` Base Sepolia | `0x07ee2673df4983fa3e83181bb4370f34c58a8b5f8c55381e15a529acfd0a461d` |
| `setCEADeployment` Arbitrum Sepolia | `0x045faecdf6db04a91623b6c384cc6ad072674696516f3d7755f966db254191cf` |
| `setCEADeployment` BSC Testnet | `0x13b8c7e748893d84a953e7ecf56edc284ff2e1d982d69b466c83bed28e5fb6c2` |

## Retired: UniversalMarketplace 2.0.0

Deployed 2026-10-20 (last tx in block 24443653). Retired 2026-10-30: not upgraded and not disabled. Its 5 cards and
the jobs it opened stay where they are. Self-contained stack: its own 8183 kernel on pUSDC, bound to AGW v6, fees
zero.

| Contract | Proxy | Implementation | ProxyAdmin |
|---|---|---|---|
| AgenticCommerce (kernel) | `0x977cf1AC973E9eC4332791d531507575006157Ed` | `0x1d631E9d0E0A7a7423743c3076054C784Af8FA40` | `0x5F5Ef9dBbC31d59a28626d1F913A35B5b6eA0Cb9` |
| RulesBindingHook | `0xDe7A94e510b6C571DE7880d441349689F73A32b3` | `0x58bd6951b653B5028Aa77B4904E83Df668Bcef7E` | `0xBa96c7FB588aC17aba00c7aa920E282c088B1746` |
| UniversalMarketplace | `0x9071ebE01B75123A91e88eB6ec4BF163F3fE9BF4` | `0xd683545f84698dF4341b0031C892C53384FF30be` | `0xb7D9315813fE87A13833871ce673073dd4B8c8af` |
| UniversalMarketplaceRules (not a proxy) | `0x5b98A8E0df5b918DF76cD2BE84bA7995B39dfd44` | | |
| JobSpecBuilder (linked library) | `0x2de1e3F053b0bBa0cE0C6953144534a0b055f59e` | | |

| Item | Value |
|---|---|
| Kernel + marketplace admin, owner of every ProxyAdmin, and the marketplace-wide evaluator (an EOA) | `0x1afC81396f1bb36F91f74506284952b81e4bd47c` |
| Kernel payment token (pUSDC, `USDC.eth`, 6 decimals) | `0x7A58048036206bB898008b5bBDA85697DB1e5d66` |
| Kernel platform treasury | `0x2348286F118810521497ADBbF2615D1328aa1630` |

### Change log

| Date | Change | Transactions |
|---|---|---|
| 2026-10-20 | 2.0.0 deployed. Sepolia, Base and Arbitrum were registered with retired factories (`0x8ED5…7029`, `0x0A75…9F55`, `0x88DC…7EA2`), so `computeCEA` returned addresses Push never uses | see `broadcast/` |
| 2026-10-26 | 2.0.0: re-registered Sepolia, Base and Arbitrum with the live factories. Verified: `computeCEA` equals each live factory's `getCEAForPushAccount` on all four chains | `0x7a5cffee…bf68`, `0x97743a1b…ed76`, `0xb8d26064…236e` |
| 2026-10-30 | 2.1.0 deployed on the evaluator team's kernel, hook and evaluator; 2.0.0 retired | above |
