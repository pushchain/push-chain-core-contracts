# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Setup
git submodule update --init --recursive
forge build

# Test
forge test                          # all tests
forge test -vvv                     # verbose output
forge test --match-test testName    # single test by name
forge test --match-contract ContractTest  # single contract
forge test --match-path test/tests_uea_and_factory/UEA_EVM.t.sol  # single file
forge test --gas-report             # with gas report

# Fork tests (require RPC)
forge test --match-path test/fork/* --fork-url $PUSH_CHAIN_TESTNET_RPC_URL

# Build with size output (as CI does)
forge build --sizes

# Format
forge fmt

# Coverage
forge coverage --no-match-coverage "(PRC20V0\.sol|UniversalCoreV0\.sol|src/(libraries|[Ii]nterfaces|mocks)/|test/)"

# Deploy (example)
forge script scripts/uea/deployFactory.s.sol --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
```

Compiler: Solidity 0.8.26, EVM target: shanghai, `via_ir = true`, `optimizer_runs = 99999`.

CI uses `FOUNDRY_PROFILE=ci` which raises fuzz runs from 1024 to 4096.

## Architecture

This is a cross-chain interoperability protocol for Push Chain. Two account types bridge external chains to Push Chain:

### UEA (Universal Executor Account) — lives on Push Chain

Represents external-chain users on Push Chain. Each user gets a `UEAProxy` (minimal clone via CREATE2) that delegates to a shared implementation contract. Two implementations exist:

- `UEA_EVM` — ECDSA (secp256k1) for EVM chains
- `UEA_SVM` — Ed25519 via precompile at `0x...ca` for Solana

`UEAFactory` (`src/uea/`) manages deployment and chain→VM→implementation mappings. The salt for CREATE2 is `keccak256(abi.encode(UniversalAccountId))`, where `UniversalAccountId` contains `{chainNamespace, chainId, owner}`. The factory is upgradeable (ERC1967 proxy pattern via OZ).

**UEA execution flow**: `executeUniversalTx(payload, signature)` → verify ECDSA/Ed25519 unless caller is `UNIVERSAL_EXECUTOR_MODULE` → dispatch on payload prefix: `MULTICALL_SELECTOR` (batch calls), `MIGRATION_SELECTOR` (delegatecall migration), or plain single call.

**UEA migration**: `UEAMigration` is a delegatecall-only singleton that updates the implementation slot (`keccak256("uea.proxy.implementation") - 1`) in the proxy. A new `UEAMigration` contract is deployed per version; `UEAFactory.UEA_MIGRATION_CONTRACT` points to the current one.

### CEA (Chain Executor Account) — lives on external chains

Represents a specific UEA on a specific external chain. `CEAFactory` (`src/cea/`) deploys `CEAProxy` clones that delegate to a shared `CEA` implementation. Only the `VAULT` contract can call `executeUniversalTx` on a CEA. The CEA can also initiate outbound transactions back to Push Chain via `sendUniversalTxToUEA` (self-call only, routes through `UniversalGateway`).

CEA migration uses the same delegatecall pattern: `CEAMigration.migrateCEA()` updates the implementation pointer in `CEAProxy`.

### UniversalCore — coordinator on Push Chain

`src/UniversalCore.sol` is upgradeable (OZ `Initializable` + `AccessControlUpgradeable`). Three caller tiers:

- `UNIVERSAL_EXECUTOR_MODULE` (hardcoded: `0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7`) — deposits PRC20 tokens, triggers auto-swaps, refunds unused gas, updates chain metadata
- `universalGatewayPC` — calls `swapAndBurnGas` to pay gas fees by swapping native PC→gasToken via Uniswap V3
- `MANAGER_ROLE` — configures chain metadata, gas tokens, supported tokens, Uniswap pools
- `DEFAULT_ADMIN_ROLE` — configures AMM addresses, slippage, fee tiers, WPC address

Chain namespaces follow CAIP-2 format (e.g., `"eip155:1"` for Ethereum mainnet).

### Token Primitives

- **PRC20** (`src/PRC20.sol`): Upgradeable ERC-20 synthetic representing an external-chain token. Minted via `deposit()` (called by `UniversalCore` or `UNIVERSAL_EXECUTOR_MODULE`), burned via `burn()`. Stores `SOURCE_CHAIN_NAMESPACE` and `SOURCE_TOKEN_ADDRESS`.
- **WPC** (`src/WPC.sol`): Non-upgradeable WETH-style wrapper for native PC. Used by `UniversalCore` for Uniswap V3 swaps.

### Key Shared Types (`src/libraries/Types.sol`)

- `UniversalAccountId` — `{chainNamespace, chainId, owner bytes}`
- `UniversalPayload` — EIP-712 signed struct for UEA execution
- `Multicall` — `{to, value, data}` entry for batch execution
- `MULTICALL_SELECTOR` = `bytes4(keccak256("UEA_MULTICALL"))`
- `MIGRATION_SELECTOR` = `bytes4(keccak256("UEA_MIGRATION"))`

### Access Control Pattern

Both `UEAFactory` and `CEAFactory` and `UniversalCore` use OZ `AccessControlUpgradeable` with:
- `DEFAULT_ADMIN_ROLE`: governance
- `PAUSER_ROLE`: guardian (can pause/unpause only)

`UniversalCore` additionally has `MANAGER_ROLE` for operational config.

### Test Layout

```
test/
├── tests_uea_and_factory/   # UEA_EVM, UEA_SVM, UEAFactory, UEAProxy unit tests
├── tests_ueaMigration/      # UEA migration flow
├── tests_cea/               # CEA, CEAFactory, single/multi/self-call tests
├── tests_ceaMigration/      # CEA migration flow
├── tests_token_and_core/    # PRC20, WPC, UniversalCore unit tests
├── fuzz/                    # Fuzz suites for all major contracts
├── fork/                    # Fork tests against Push Chain Donut Testnet
├── helpers/
│   ├── PushChainAddresses.sol   # Testnet address book (update when addresses change)
│   └── UpgradeableContractHelper.sol
└── mocks/                   # Mock tokens, gateways, Uniswap mocks, V2 implementations
```

Fork tests inherit from `PushChainAddresses` for testnet addresses. Set `PUSH_CHAIN_TESTNET_RPC_URL` to run them.

### Deployment Scripts

```
scripts/
├── uea/    deployFactory.s.sol, upgradeFactory.s.sol
├── cea/    deployCEAFactory.s.sol, upgradeCEAFactory.s.sol
└── uvcore/ deployUniversalCore.s.sol, upgradeUniversalCore.s.sol
```

### Testnet Branch (`core-testnet`)

On the `core-testnet` branch, `src/UniversalCore.sol`, `src/PRC20.sol`, and `src/uea/UEAFactory.sol` are testnet-specific V0 versions (two-phase initialization, deprecated storage slots for upgrade compatibility). They replace the mainnet equivalents. See `docs/TESTNET_BRANCH_SEPARATION.md`.
