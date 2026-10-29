# Push Donut (Chain ID: 42101): UniversalMarketplace stack

Deployed 2026-10-20 with `scripts/agentic-commerce-8183/DeployUniversalMarketplace.s.sol` (last tx in block 24443653).
Self-contained stack: its own 8183 kernel on pUSDC, bound to AGW v6. Fees are zero.

## Contracts

| Contract | Proxy | Implementation | ProxyAdmin |
|---|---|---|---|
| AgenticCommerce (kernel) | `0x977cf1AC973E9eC4332791d531507575006157Ed` | `0x1d631E9d0E0A7a7423743c3076054C784Af8FA40` | `0x5F5Ef9dBbC31d59a28626d1F913A35B5b6eA0Cb9` |
| RulesBindingHook | `0xDe7A94e510b6C571DE7880d441349689F73A32b3` | `0x58bd6951b653B5028Aa77B4904E83Df668Bcef7E` | `0xBa96c7FB588aC17aba00c7aa920E282c088B1746` |
| UniversalMarketplace | `0x9071ebE01B75123A91e88eB6ec4BF163F3fE9BF4` | `0xd683545f84698dF4341b0031C892C53384FF30be` | `0xb7D9315813fE87A13833871ce673073dd4B8c8af` |
| UniversalMarketplaceRules (not a proxy) | `0x5b98A8E0df5b918DF76cD2BE84bA7995B39dfd44` | | |
| JobSpecBuilder (linked library) | `0x2de1e3F053b0bBa0cE0C6953144534a0b055f59e` | | |

## Roles and settings

| Item | Value |
|---|---|
| Kernel + marketplace admin (`DEFAULT_ADMIN_ROLE`, `ADMIN_ROLE`), owner of every ProxyAdmin | `0x1afC81396f1bb36F91f74506284952b81e4bd47c` |
| Marketplace-wide evaluator (EOA, completes or rejects by hand) | `0x1afC81396f1bb36F91f74506284952b81e4bd47c` |
| Kernel payment token (pUSDC, `USDC.eth`, 6 decimals) | `0x7A58048036206bB898008b5bBDA85697DB1e5d66` |
| Kernel platform treasury | `0x2348286F118810521497ADBbF2615D1328aa1630` |
| AGW v6 factory / session engine | `0xFBBEB6a365178fAaA81A9789a5f64b300c37e5bc` / `0xf63DC0628fe1B25049FE3E3a3585Ef051CB98c1d` |

## Supported card chains (`setCEADeployment`)

Each factory is the one Push actually uses on that chain: the vault's `CEAFactory()` and the gateway's
`CEA_FACTORY()` both return it, and Push's address registry (push.org/agents/contract-addresses.json) lists it.
The address docs also list retired factories; do not take a factory from them.

| Chain | Namespace | CEAFactory (proxy) | CEA proxy implementation |
|---|---|---|---|
| Ethereum Sepolia | `eip155:11155111` | `0x5E191fbBe22F8866C5e4250557664fCE760e8870` | `0x425291f35BA1A94Bd2dcC2dC097c2B55700A1fB6` |
| Base Sepolia | `eip155:84532` | `0x7e8CeeDA043ED1460540616103dD57581a66C856` | `0xe816b67B73c47e51E4B263c9149675b589E8e741` |
| Arbitrum Sepolia | `eip155:421614` | `0x65572FFa81c230360a8a53C1682C7f0Ee321E5E7` | `0xe27c8f93b4e01C9557b41C702Fa2634B9e5728CE` |
| BSC Testnet | `eip155:97` | `0x3f1B16e0B072d472951C4563d29d3da6a3EE3Ce8` | `0x0ff5d8b7d9Ac3ee2Ad420e9b70Ed6Dc465f593e9` |

### Change log

| Date | Change | Transactions |
|---|---|---|
| 2026-10-20 | Initial deploy. Sepolia, Base and Arbitrum were registered with retired factories (`0x8ED5…7029`, `0x0A75…9F55`, `0x88DC…7EA2`), so `computeCEA` returned addresses Push never uses | see `broadcast/` |
| 2026-10-26 | Re-registered Sepolia, Base and Arbitrum with the live factories above. Verified: `computeCEA` equals each live factory's `getCEAForPushAccount` on all four chains | `0x7a5cffee…bf68`, `0x97743a1b…ed76`, `0xb8d26064…236e` |
