# Threat Model — push-chain-core-contracts

## Document Purpose

This document is written for an external security auditor reviewing the
`push-chain-core-contracts` repository. It provides a structured threat model
covering all 12 in-scope contracts, their access control surfaces, STRIDE-categorised
threat tables, external dependencies, and system invariants.

All source contracts use `pragma solidity 0.8.26`. Cross-references below use
repository-root-relative paths (e.g., `src/uea/UEA_EVM.sol`).

`src/mocks/` and `src/testnetV0/` are **excluded** from this analysis.

---

## System Architecture Overview

```
╔══════════════════════════════════════════════════════════════════════════╗
║  PUSH CHAIN                                                              ║
║                                                                          ║
║  ┌─────────────────────────────────────────────────┐                    ║
║  │  UniversalCore (upgradeable)                    │                    ║
║  │  - PRC20 minting/burning                        │                    ║
║  │  - Uniswap V3 gas-swap/burn                     │                    ║
║  │  - Chain oracle / fee config                    │                    ║
║  └───────────┬─────────────────────────────────────┘                    ║
║              │  mints/burns                                              ║
║  ┌───────────▼──────────────────┐  ┌──────────────┐                     ║
║  │  PRC20 ×N (upgradeable)      │  │  WPC         │                     ║
║  │  (synthetic external assets) │  │  (wrapped PC)│                     ║
║  └──────────────────────────────┘  └──────────────┘                     ║
║                                                                          ║
║  ┌─────────────────────────────────────────────────┐                    ║
║  │  UEAFactory (upgradeable, ERC1967)              │                    ║
║  │  - chain → VM → implementation mappings         │                    ║
║  │  - UOA ↔ UEA bidirectional index                │                    ║
║  └───────────┬─────────────────────────────────────┘                    ║
║              │  deploys via CREATE2                                      ║
║  ┌───────────▼──────────────────┐                                        ║
║  │  UEAProxy ×N (minimal clone) │                                        ║
║  │  custom slot: UEA_LOGIC_SLOT │◄──── UEAMigration (singleton)         ║
║  └───────────┬─────────────────┘       (delegatecall only)              ║
║              │  delegatecall                                             ║
║  ┌───────────▼──────────────────┐                                        ║
║  │  UEA_EVM  │  UEA_SVM        │                                        ║
║  │  (ECDSA)  │  (Ed25519)      │                                        ║
║  └──────────────────────────────┘                                        ║
╚══════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════╗
║  EXTERNAL CHAIN                                                          ║
║                                                                          ║
║  [Vault] ──deploys──► CEAFactory (upgradeable)                           ║
║                             │  deploys via CREATE2                       ║
║                    ┌────────▼─────────────────┐                         ║
║                    │  CEAProxy ×N             │◄── CEAMigration          ║
║                    │  custom slot:            │    (singleton,           ║
║                    │  CEA_LOGIC_SLOT          │     delegatecall only)   ║
║                    └────────┬─────────────────┘                         ║
║                             │  delegatecall                             ║
║                    ┌────────▼─────────────────┐                         ║
║                    │  CEA                     │──► [UniversalGateway]   ║
║                    └──────────────────────────┘                         ║
╚══════════════════════════════════════════════════════════════════════════╝

UNIVERSAL_EXECUTOR_MODULE: 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7
```

`UNIVERSAL_EXECUTOR_MODULE` (`0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7`) is
hardcoded in 4 contracts: `UniversalCore`, `PRC20`, `UEA_EVM`, and `UEA_SVM`.
It is the single highest-privilege actor in the system. It bypasses signature
verification on all UEA execution paths, can mint unlimited PRC20 tokens directly,
and drives the core deposit/refund pipeline in UniversalCore. There is no on-chain
setter for this address in any contract — key compromise represents total, irreversible
protocol compromise with no on-chain recovery path.

---

## Scope

| Contract | File | Chain | Upgradeable |
|---|---|---|---|
| UniversalCore | `src/UniversalCore.sol` | Push Chain | Yes (OZ ERC1967) |
| PRC20 | `src/PRC20.sol` | Push Chain | Yes (OZ Initializable) |
| WPC | `src/WPC.sol` | Push Chain | No |
| UEA_EVM | `src/uea/UEA_EVM.sol` | Push Chain | No (logic; proxy is upgradeable via migration) |
| UEA_SVM | `src/uea/UEA_SVM.sol` | Push Chain | No (logic; proxy is upgradeable via migration) |
| UEAFactory | `src/uea/UEAFactory.sol` | Push Chain | Yes (OZ ERC1967) |
| UEAProxy | `src/uea/UEAProxy.sol` | Push Chain | No (upgraded via UEAMigration delegatecall) |
| UEAMigration | `src/uea/UEAMigration.sol` | Push Chain | No |
| CEA | `src/cea/CEA.sol` | External Chain | No (logic; proxy is upgradeable via migration) |
| CEAFactory | `src/cea/CEAFactory.sol` | External Chain | Yes (OZ ERC1967) |
| CEAProxy | `src/cea/CEAProxy.sol` | External Chain | No (upgraded via CEAMigration delegatecall) |
| CEAMigration | `src/cea/CEAMigration.sol` | External Chain | No |

> **Excluded:** `src/mocks/` (test helpers) and `src/testnetV0/` (deprecated v0 contracts)
> are out of scope for this threat model.

---

## Out-of-Scope Trust Boundaries

The following are treated as trusted external systems whose internal security is
not analysed here:

- **Uniswap V3** (Factory, SwapRouter, Quoter) — pool lookup and swap execution
- **UniversalGateway** — cross-chain message bridge on both Push Chain and external chains
- **Vault** — on external chains; sole deployer of CEAs and sole caller of `executeUniversalTx`
- **UNIVERSAL_EXECUTOR_MODULE** (`0x14191...`) — off-chain relay/infrastructure; trust is assumed unconditionally
- **Ed25519 precompile** at `0x00000000000000000000000000000000000000ca` — Push Chain-specific precompile; assumed live and correct
- **Universal Validator set / relayers** — off-chain consensus layer delivering cross-chain messages

---

## Privilege Hierarchy

| Principal | Type | Contracts Affected | Powers |
|---|---|---|---|
| `UNIVERSAL_EXECUTOR_MODULE` (`0x14191...`) | Hardcoded address | `UniversalCore`, `PRC20`, `UEA_EVM`, `UEA_SVM` | Mint PRC20 tokens; deposit/refund/setChainMeta in UniversalCore; bypass all UEA signature checks and execute arbitrary multicall payloads through any UEA |
| `DEFAULT_ADMIN_ROLE` | OZ role (address assigned at init) | `UniversalCore`, `UEAFactory`, `CEAFactory` | Set all protocol config addresses (Uniswap, WPC, gateway, migration contracts); grant/revoke all other roles; upgrade proxy implementations |
| `MANAGER_ROLE` | OZ role | `UniversalCore` | Set per-chain and per-token operational parameters (gas limits, fee tiers, supported tokens, pool addresses) |
| `PAUSER_ROLE` | OZ role | `UniversalCore`, `UEAFactory`, `CEAFactory` | Call `pause()` and `unpause()` only |
| `universalGatewayPC` | Mutable address (admin-settable) | `UniversalCore` | Sole caller of `swapAndBurnGas`; can send arbitrary native value |
| `VAULT` | Mutable address (admin-settable); immutable per-CEA | `CEAFactory`, `CEA` | Sole deployer of CEAs; sole caller of `executeUniversalTx` on every CEA |

---

## UniversalCore

**File:** `src/UniversalCore.sol` | **Chain:** Push Chain | **Upgradeable:** Yes

### Role

Upgradeable coordinator on Push Chain. Hub for PRC20 minting, Uniswap V3 gas-swap
and burn, chain oracle data, and protocol fee configuration. Four privilege tiers
(see Privilege Hierarchy above). Interacts with all PRC20 instances, WPC, and the
Uniswap V3 pool infrastructure.

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `depositPRC20Token` | `UNIVERSAL_EXECUTOR_MODULE` | `onlyUEModule`, `whenNotPaused` |
| `depositPRC20WithAutoSwap` | `UNIVERSAL_EXECUTOR_MODULE` | `onlyUEModule`, `whenNotPaused`, `nonReentrant` |
| `refundUnusedGas` | `UNIVERSAL_EXECUTOR_MODULE` | `onlyUEModule`, `whenNotPaused`, `nonReentrant` |
| `setChainMeta` | `UNIVERSAL_EXECUTOR_MODULE` | `onlyUEModule` (**no** `whenNotPaused`) |
| `swapAndBurnGas` | `universalGatewayPC` | `onlyGatewayPC`, `whenNotPaused`, `nonReentrant`, `payable` |
| `setProtocolFeeByToken` | `MANAGER_ROLE` | `onlyManager` |
| `setSupportedToken` | `MANAGER_ROLE` | `onlyManager` |
| `setGasPCPool` | `MANAGER_ROLE` | `onlyManager` |
| `setGasTokenPRC20` | `MANAGER_ROLE` | `onlyManager` |
| `setBaseGasLimitByChain` | `MANAGER_ROLE` | `onlyManager` |
| `setRescueFundsGasLimitByChain` | `MANAGER_ROLE` | `onlyManager` |
| `setAutoSwapSupported` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setWPC` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setUniversalGatewayPC` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setUniswapV3Addresses` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setDefaultFeeTier` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setSlippageTolerance` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setDefaultDeadlineMins` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setPauserRole` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `pause` | `PAUSER_ROLE` | OZ `Pausable` |
| `unpause` | `PAUSER_ROLE` | OZ `Pausable` |
| `receive()` | Anyone | `payable` |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| UC-T1 | Tampering | `setChainMeta` has no `whenNotPaused` guard — oracle/chain metadata is mutable even while the contract is paused, bypassing the intent of a pause |
| UC-T2 | Elevation of Privilege | `universalGatewayPC` is admin-mutable with no timelock; an attacker who compromises admin can point it to an attacker-controlled address that calls `swapAndBurnGas` with arbitrary native value |
| UC-T3 | Tampering | Uniswap V3 addresses (factory, router, quoter) are admin-mutable; replacement with malicious contracts enables fund diversion in `_autoSwap` and `swapAndBurnGas` |
| UC-T4 | Tampering | `WPC` address is admin-mutable; a malicious WETH-style contract at the new address can redirect or steal native PC during wrap/unwrap operations |
| UC-T5 | Denial of Service | `swapAndBurnGas` sends the native PC refund via `caller.call{value: refund}("")`; if `caller` reverts on ETH receive, the entire swap transaction reverts |
| UC-T6 | Denial of Service | `defaultDeadlineMins` is settable to `0` by admin; `deadline = block.timestamp + 0` makes all new swap transactions immediately expire at the EVM level |
| UC-T7 | Spoofing | `_validateParams` blocks `recipient == UNIVERSAL_EXECUTOR_MODULE` and `recipient == address(this)` but does not block other sensitive addresses (e.g., `universalGatewayPC`) |
| UC-T8 | Information Disclosure | `slippageTolerance` is stored on-chain but `minPCOut` is caller-supplied by the UE Module at call time; auditor should verify that the on-chain tolerance is enforced against the call-time value and not silently ignored |
| UC-T9 | Tampering | `defaultDeadlineMins == 0` path: `deadline = block.timestamp + 0 * 60` makes swaps expire immediately; subtly distinct from UC-T6 (that threat is about setting the var to 0; this is the runtime consequence when the zero value is used) |

### External Dependencies

| Dependency | Mutability | Trust Assumption |
|---|---|---|
| Uniswap V3 Factory | Admin-mutable | Pool lookup; wrong address causes `getPool` to return `address(0)` for all pools |
| Uniswap V3 SwapRouter | Admin-mutable | Executes swaps; a malicious router can steal tokens passed to it |
| Uniswap V3 Quoter | Admin-mutable | View-only; used off-chain for quote estimation |
| WPC | Admin-mutable | Must wrap/unwrap native PC 1:1; uses `.transfer()` for withdrawals |
| PRC20 tokens | Per-call address (from chain config) | Must implement `deposit()` and `burn()` per `IPRC20`; called with external trust |
| `universalGatewayPC` | Admin-mutable | Sole caller of `swapAndBurnGas`; assumed honest |

### Invariants

1. After `swapAndBurnGas`: `msg.value == amountInUsed + refund` (no native PC stranded in contract)
2. After `depositPRC20WithAutoSwap`: no PRC20 tokens remain held by `UniversalCore`
3. `UNIVERSAL_EXECUTOR_MODULE` is immutable — no setter exists in `UniversalCore`

---

## PRC20

**File:** `src/PRC20.sol` | **Chain:** Push Chain | **Upgradeable:** Yes

### Role

Upgradeable synthetic ERC-20. One instance per mirrored external-chain asset.
Minting is gated to `UNIVERSAL_CORE` (mutable) or `UNIVERSAL_EXECUTOR_MODULE`
(immutable). Burning is open to any token holder. Custom ERC-20 implementation
(does not inherit OZ ERC20). Stores `SOURCE_CHAIN_NAMESPACE` and
`SOURCE_TOKEN_ADDRESS` as immutable identity metadata.

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `deposit(to, amount)` | `UNIVERSAL_CORE` or `UNIVERSAL_EXECUTOR_MODULE` | `InvalidSender` custom error check |
| `burn(amount)` | Any address | Balance check only |
| `updateUniversalCore(newCore)` | `UNIVERSAL_EXECUTOR_MODULE` | `onlyUniversalExecutor` |
| `setName(name)` | `UNIVERSAL_EXECUTOR_MODULE` | `onlyUniversalExecutor` |
| `setSymbol(symbol)` | `UNIVERSAL_EXECUTOR_MODULE` | `onlyUniversalExecutor` |
| Standard ERC-20 (`transfer`, `transferFrom`, `approve`, etc.) | Any address | Balance / allowance checks |
| `initialize(...)` | Anyone (once) | OZ `initializer` |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| PRC-T1 | Elevation of Privilege | `UNIVERSAL_EXECUTOR_MODULE` (hardcoded, immutable) can call `deposit()` to mint unlimited tokens to any address; key compromise equals unbounded inflation with no on-chain recovery mechanism |
| PRC-T2 | Tampering | `UNIVERSAL_CORE` is mutable (settable by UE Module); replacing it with an attacker-controlled address opens a second unconstrained `deposit()` call path |
| PRC-T3 | Tampering | `_mint` and `_transfer` use `unchecked` arithmetic; no supply cap — `totalSupply` can reach `type(uint256).max` without reverting |
| PRC-T4 | Spoofing | `name` and `symbol` are mutable by UE Module post-deploy; renaming can mislead off-chain indexers, bridges, and users |
| PRC-T5 | Denial of Service | PRC20 has no pause mechanism; if `UniversalCore` is paused, `UNIVERSAL_EXECUTOR_MODULE` can still mint PRC20 tokens directly, bypassing the pause |
| PRC-T6 | Tampering | `transferFrom` deducts allowance after `_transfer` executes; the revert unwinds both, but confirm no ERC-777-style reentrancy hook is possible via a callback receiver during `_transfer` |

### External Dependencies

None. PRC20 is standalone; it depends only on OZ `Initializable`.

### Invariants

1. `totalSupply == sum(all balanceOf)` at all times
2. Only `UNIVERSAL_CORE` or `UNIVERSAL_EXECUTOR_MODULE` can increase `totalSupply` via `deposit()`
3. `UNIVERSAL_EXECUTOR_MODULE` is immutable — no setter exists in `PRC20`

---

## WPC

**File:** `src/WPC.sol` | **Chain:** Push Chain | **Upgradeable:** No

### Role

Non-upgradeable WETH-style wrapper for native PC. No access control. Holds 1:1
native PC backing for all WPC tokens in circulation. Used by `UniversalCore` for
Uniswap V3 swap paths that require an ERC-20 input.

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `deposit()` | Anyone | `payable` |
| `withdraw(wad)` | Any WPC holder | Balance `require` |
| `transfer`, `transferFrom`, `approve` | Anyone | Balance / allowance checks |
| `receive()` | Anyone | Auto-calls `deposit()` |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| WPC-T1 | Denial of Service | `withdraw` uses `payable(msg.sender).transfer(wad)` (2300 gas stipend); fails for recipients with non-trivial `receive()` logic. `UniversalCore`'s `receive()` is simple (safe), but any future caller contract must be validated |
| WPC-T2 | Tampering | `totalSupply()` returns `address(this).balance`; force-feeding native PC via `selfdestruct` inflates `totalSupply` above `sum(balanceOf)`. Not exploitable as `withdraw` keys on `balanceOf` not `totalSupply`, but breaks the supply/balance equality invariant |
| WPC-T3 | Information Disclosure | `require` reverts use empty strings (`""`); provides no diagnostic context for monitoring or debugging tooling |

### External Dependencies

None.

### Invariants

1. `address(this).balance >= sum(all balanceOf)` always (equality under normal operation; see WPC-T2)
2. `withdraw` only reduces `balanceOf[msg.sender]` and sends the equivalent amount of native PC

---

## UEA_EVM

**File:** `src/uea/UEA_EVM.sol` | **Chain:** Push Chain | **Upgradeable:** No (logic contract; proxy upgraded via migration)

### Role

Logic contract for EVM-origin UEAs. Shared by all EVM-chain `UEAProxy` instances
via delegatecall. Verifies ECDSA (EIP-712) signatures; bypasses verification for
`UNIVERSAL_EXECUTOR_MODULE`. Three execution paths: single call, multicall (batch),
and delegatecall migration.

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `executeUniversalTx` (signature path) | Any address | ECDSA against `_universalAccountId.owner`; `nonReentrant` |
| `executeUniversalTx` (bypass path) | `UNIVERSAL_EXECUTOR_MODULE` | Hardcoded address check; `nonReentrant` |
| `initialize(id, factory)` | Anyone (once) | `_initialized` bool flag (not OZ `initializer`) |
| Multicall sub-calls | Arbitrary `calls[i].to` | No allowlist — any contract address permitted |
| Migration delegatecall | `payload.to == address(this)` and `payload.value == 0` | Inline checks only |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| UEA-EVM-T1 | Spoofing | **Known finding F-02**: domain separator encodes the source chain's `chainId` but not `block.chainid`; CREATE2-deterministic UEA addresses are identical across Push Chain deployments — a valid signature on testnet replays on mainnet |
| UEA-EVM-T2 | Elevation of Privilege | `UNIVERSAL_EXECUTOR_MODULE` bypasses ECDSA entirely; can execute arbitrary multicall payloads through any UEA without owner consent (stated design assumption — document key controls) |
| UEA-EVM-T3 | Tampering | `_handleMigration` fetches `ueaFactory.UEA_MIGRATION_CONTRACT()` at execution time; if factory admin rotates this to a malicious contract, any triggered migration causes full `UEAProxy` storage takeover via delegatecall in the proxy's storage context |
| UEA-EVM-T4 | Tampering | Multicall `calls[i].to` has no allowlist; a user can target the proxy itself, re-entering via the proxy's fallback — confirm `nonReentrant` on `executeUniversalTx` covers this re-entry path |
| UEA-EVM-T5 | Repudiation | `PayloadExecuted` event emits the post-increment nonce; off-chain indexers must subtract 1 to recover the pre-execution nonce — verify alignment with all tooling and explorers |
| UEA-EVM-T6 | Denial of Service | `UNIVERSAL_EXECUTOR_MODULE` can consume any nonce (by executing any payload), invalidating any in-flight user-signed transaction carrying that nonce |
| UEA-EVM-T7 | Tampering | Exactly 4 bytes of multicall data triggers `_decodeCalls` returning an empty `Multicall[]`; nonce increments for a no-op execution, burning the nonce silently |

### External Dependencies

| Dependency | Mutability | Trust Assumption |
|---|---|---|
| OZ ECDSA library | Immutable | `recover` returns `address(0)` on malformed sig; verify `verifyUniversalPayloadSignature` treats `address(0)` as false, not a match |
| `ueaFactory.UEA_MIGRATION_CONTRACT()` | Factory admin-controlled | See UEA-EVM-T3 |
| Target contracts (single-call and multicall) | Untrusted | Arbitrary external calls with arbitrary calldata and value |

### Invariants

1. `_initialized == true` after the first `initialize` call; no re-initialization path exists
2. Nonce strictly increases; no path decrements or resets the nonce
3. Migration delegatecall target must equal `address(this)` — no delegatecall to arbitrary external addresses
4. `UEA_LOGIC_SLOT` written by `UEAMigration` must equal `0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d`

---

## UEA_SVM

**File:** `src/uea/UEA_SVM.sol` | **Chain:** Push Chain | **Upgradeable:** No (logic contract; proxy upgraded via migration)

### Role

Logic contract for Solana-origin UEAs. Identical execution model to `UEA_EVM`
except signature verification uses Ed25519 via `staticcall` to the precompile at
`0x00000000000000000000000000000000000000ca`. The `_universalAccountId.owner`
field is a 32-byte Solana public key (not an Ethereum address).

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `executeUniversalTx` (signature path) | Any address | Ed25519 via precompile against `_universalAccountId.owner`; `nonReentrant` |
| `executeUniversalTx` (bypass path) | `UNIVERSAL_EXECUTOR_MODULE` | Hardcoded address check; `nonReentrant` |
| `initialize(id, factory)` | Anyone (once) | `_initialized` bool flag |
| Multicall sub-calls | Arbitrary `calls[i].to` | No allowlist |
| Migration delegatecall | `payload.to == address(this)` and `payload.value == 0` | Inline checks |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| UEA-SVM-T1 | Spoofing | Same cross-deployment replay as UEA-EVM-T1; domain separator also omits `block.chainid` in the SVM implementation |
| UEA-SVM-T2 | Denial of Service | `staticcall` to `VERIFIER_PRECOMPILE`; if the precompile is unavailable on this chain or network fork, all SVM UEA executions revert with `PrecompileCallFailed` — no fallback path exists |
| UEA-SVM-T3 | Spoofing | `_universalAccountId.owner` is a raw `bytes` field (32-byte Solana pubkey); if the encoding passed to the precompile mismatches the expected format (padded vs. raw), all SVM signature verifications silently return false |
| UEA-SVM-T4 | Elevation of Privilege | Same UE Module bypass as UEA-EVM-T2; applies to Solana-origin accounts identically |
| UEA-SVM-T5 | Tampering | Same migration attack as UEA-EVM-T3; `_handleMigration` reads `ueaFactory.UEA_MIGRATION_CONTRACT()` at execution time |
| UEA-SVM-T6 | Denial of Service | Same nonce-burning as UEA-EVM-T6; UE Module can invalidate any pending user-signed SVM transaction |

### External Dependencies

| Dependency | Mutability | Trust Assumption |
|---|---|---|
| Ed25519 precompile at `0x00...ca` | Hardcoded (Push Chain-specific) | Must be live and implement the expected input/output ABI; no fallback if unavailable |
| `ueaFactory.UEA_MIGRATION_CONTRACT()` | Factory admin-controlled | See UEA-SVM-T5 |
| Target contracts (single-call and multicall) | Untrusted | Arbitrary external calls |

### Invariants

Same as `UEA_EVM`:

1. `_initialized == true` after the first `initialize` call; no re-initialization path exists
2. Nonce strictly increases; no path decrements or resets the nonce
3. Migration delegatecall target must equal `address(this)` — no delegatecall to arbitrary external addresses
4. `UEA_LOGIC_SLOT` written by `UEAMigration` must equal `0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d`

---

## UEAFactory

**File:** `src/uea/UEAFactory.sol` | **Chain:** Push Chain | **Upgradeable:** Yes (OZ ERC1967)

### Role

Upgradeable factory. Deploys `UEAProxy` clones via CREATE2 using
`keccak256(abi.encode(UniversalAccountId))` as salt. Registers chain→VM→implementation
mappings. Maintains bidirectional `UOA ↔ UEA` address index.
`getOriginForUEA` returns a synthetic Push Chain identity for non-UEA addresses.

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `deployUEA(id)` | Anyone | `whenNotPaused` |
| `pause` / `unpause` | `PAUSER_ROLE` | OZ `Pausable` |
| `setPauserRole` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setUEAProxyImplementation` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setUEAMigrationContract` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `registerNewChain` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `registerUEA` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `registerMultipleUEA` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| UF-T1 | Tampering | `setUEAMigrationContract` has no timelock; admin can instantly point all UEAs to a malicious migration contract — any subsequently triggered migration causes full `UEAProxy` storage takeover via delegatecall |
| UF-T2 | Tampering | `setUEAProxyImplementation` changes the clone template for future `deployUEA` calls; does not affect existing deployed UEAs but all new deployments use the replacement template |
| UF-T3 | Spoofing | `getOriginForUEA(addr)` returns a synthetic Push Chain identity `{eip155, 42101, abi.encodePacked(addr)}` for non-UEA addresses; callers using this for authorization may conflate native Push Chain accounts with registered UEAs |
| UF-T4 | Tampering | `registerUEA` updates `UEA_VM[vmHash]` — a shared implementation pointer for all future proxies of that VM type; existing proxy `UEA_LOGIC_SLOT` values are unaffected |
| UF-T5 | Denial of Service | Pausing the factory blocks `deployUEA`; if first-time UEA deployment is required as part of the inbound execution pipeline, a pause prevents all new users from executing their first transaction |
| UF-T6 | Tampering | Salt = `keccak256(abi.encode(_id))` where `_id` contains string fields; auditor should verify that ABI encoding of `UniversalAccountId` is collision-free — two semantically distinct structs with identical byte encoding would share a salt and collide on CREATE2 |

### External Dependencies

| Dependency | Mutability | Trust Assumption |
|---|---|---|
| OZ Clones library | Immutable | `cloneDeterministic` reverts on address collision (existing bytecode at target) |
| `UEA_PROXY_IMPLEMENTATION` template | Admin-mutable | Must be a valid `UEAProxy` with an `initializeUEA` function |

### Invariants

1. A deployed UEA's `UEA_LOGIC_SLOT` is set atomically within `deployUEA` and can only change via a user-triggered migration
2. `UOA_to_UEA[salt]` is written exactly once per salt (CREATE2 collision reverts subsequent attempts)

---

## UEAProxy

**File:** `src/uea/UEAProxy.sol` | **Chain:** Push Chain | **Upgradeable:** No (upgraded only via delegatecall migration)

### Role

Minimal clone deployed per UEA. Stores the logic implementation address in a
custom slot `UEA_LOGIC_SLOT = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d`.
All calls are delegated to the implementation. No post-init admin functions.

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `initializeUEA(_logic)` | Anyone (intended: `UEAFactory` atomically in `deployUEA`) | OZ `initializer` + explicit slot-empty check |
| All other calls | Anyone | Delegated to `_implementation()` |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| UP-T1 | Elevation of Privilege | `initializeUEA` is callable by anyone on the un-cloned template contract; verify whether the template itself is initialized or left uninitialised (an uninitialised template is susceptible to direct hijack) |
| UP-T2 | Tampering | `UEA_LOGIC_SLOT` is non-EIP-1967; any future logic contract that accidentally writes to this storage offset corrupts the implementation pointer — migration contracts write here intentionally, verify exact constant match across all contracts |
| UP-T3 | Tampering | No admin path post-init to rotate implementation; upgrade requires a user-triggered migration payload — users who never trigger migration remain permanently on old logic, even after critical patches |

### Invariants

1. `UEA_LOGIC_SLOT` in `UEAProxy` == value in `UEAMigration` (both `0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d`)
2. `_implementation()` reverts if the slot value is `address(0)` — no delegation to the zero address

---

## UEAMigration

**File:** `src/uea/UEAMigration.sol` | **Chain:** Push Chain | **Upgradeable:** No

### Role

Delegatecall-only singleton. Writes a new implementation address to `UEA_LOGIC_SLOT`
within the calling `UEAProxy`'s storage context. `onlyDelegateCall` is enforced via
immutable `UEA_MIGRATION_IMPLEMENTATION == address(this)`. A single contract covers
both EVM and SVM UEAs via separate `migrateUEAEVM()` and `migrateUEASVM()` functions.

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `migrateUEAEVM()` | Via delegatecall from a `UEAProxy` | `onlyDelegateCall` modifier |
| `migrateUEASVM()` | Via delegatecall from a `UEAProxy` | `onlyDelegateCall` modifier |
| Direct calls to either function | Anyone | Reverts — `onlyDelegateCall` |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| UM-T1 | Elevation of Privilege | `onlyDelegateCall` prevents direct calls to this contract but does not prevent _any other contract_ from delegatecalling `UEAMigration` in its own storage context; any contract that knows this address can corrupt its own slot at `UEA_LOGIC_SLOT`'s storage offset |
| UM-T2 | Tampering | Constructor validates both implementations have `extcodesize > 0`; if either implementation is later `selfdestruct`-ed (on chains where this is still possible), a triggered migration writes a dangling, empty implementation pointer |
| UM-T3 | Tampering | UEA_SVM triggers migration via `abi.encodeWithSignature("migrateUEASVM()")` and UEA_EVM via `"migrateUEAEVM()"` — verify no typos in these string literals; a mismatch causes all migrations to silently revert (function selector not found) |

### Invariants

1. `UEA_LOGIC_SLOT` in `UEAMigration` == `UEAProxy` constant (both `0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d`)
2. `UEA_EVM_IMPLEMENTATION != UEA_SVM_IMPLEMENTATION` enforced in constructor
3. Both `UEA_EVM_IMPLEMENTATION` and `UEA_SVM_IMPLEMENTATION` have `extcodesize > 0` at deploy time

---

## CEA

**File:** `src/cea/CEA.sol` | **Chain:** External Chain | **Upgradeable:** No (logic contract; proxy upgraded via migration)

### Role

Logic contract for external-chain execution accounts. All execution is gated to
the `VAULT` address set at initialization. `isExecuted[txId]` provides per-CEA
replay protection keyed on Vault-supplied transaction IDs. The self-call path
`sendUniversalTxToUEA` allows a CEA to initiate outbound bridging back to Push Chain.

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `initializeCEA(...)` | Anyone (once) | `_initialized` bool flag |
| `executeUniversalTx(txId, ...)` | `VAULT` | `onlyVault`, `nonReentrant`, `payable` |
| `sendUniversalTxToUEA(token, amount, payload)` | `address(this)` only | `msg.sender == address(this)` inline check |
| `receive()` | Anyone | `payable` |
| Multicall sub-calls | Arbitrary `calls[i].to` | `to != address(0)`; self-call with `value != 0` reverts |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| CEA-T1 | Tampering | **Known finding F-01**: the ERC20 path of `sendUniversalTxToUEA` (lines 145-150) calls the gateway without first calling `IERC20(token).approve(UNIVERSAL_GATEWAY, amount)`; any gateway implementation using `transferFrom` will revert, permanently locking ERC20 tokens inside the CEA |
| CEA-T2 | Tampering | `_handleMigration` fetches `factory.CEA_MIGRATION_CONTRACT()` at execution time; factory admin rotating this to a malicious contract enables full `CEAProxy` storage takeover via delegatecall (same pattern as UEA-EVM-T3) |
| CEA-T3 | Elevation of Privilege | `VAULT` is immutable per-CEA (set at `initializeCEA` time); `CEAFactory.setVault` only affects new deployments — existing CEAs cannot rotate their Vault even if it is compromised |
| CEA-T4 | Tampering | `_handleSingleCall` forwards `msg.value` to the target: `recipient.call{value: msg.value}(payload)`; if the target reverts, the EVM refunds the value to the Vault — verify Vault-side accounting correctly handles this partial-execution refund |
| CEA-T5 | Spoofing | `originCaller == pushAccount` is the sole authorization check for outbound calls; an incorrect `pushAccount` set at `initializeCEA` permanently locks or unlocks the CEA to the wrong owner with no rotation path |
| CEA-T6 | Tampering | `isExecuted[txId] = true` is set before `_handleExecution`; a revert unwinds the entire transaction including the flag — replay protection is transaction-atomic (safe), but auditors should confirm this covers all execution paths |
| CEA-T7 | Denial of Service | An entire multicall batch reverts on any single failed sub-call; a crafted batch where an early step transfers value and a late step fails would be fully rolled back — value sent with the `payable` call is refunded by EVM revert |

### External Dependencies

| Dependency | Mutability | Trust Assumption |
|---|---|---|
| `VAULT` | Immutable per-CEA (set at init) | Controls all execution; compromise equals arbitrary execution from any Vault-managed CEA |
| `UNIVERSAL_GATEWAY` | Immutable per-CEA (set at init) | Destination for outbound sends; must not require ERC20 `approve` before `transferFrom` without it being provided (see CEA-T1) |
| `factory.CEA_MIGRATION_CONTRACT()` | Factory admin-controlled | See CEA-T2 |
| Target contracts (multicall / single-call) | Untrusted | Arbitrary external calls |

### Invariants

1. `isExecuted[txId]` transitions only `false → true`, never reset
2. `originCaller == pushAccount` is the sole execution authorization check — no signature verification
3. `sendUniversalTxToUEA` is only reachable via `msg.sender == address(this)` (multicall self-call path inside `nonReentrant` scope)
4. `CEA_LOGIC_SLOT` written by `CEAMigration` must match `CEAProxy.CEA_LOGIC_SLOT`

---

## CEAFactory

**File:** `src/cea/CEAFactory.sol` | **Chain:** External Chain | **Upgradeable:** Yes (OZ ERC1967)

### Role

Upgradeable factory on external chains. Only the `VAULT` address can deploy CEAs.
Maintains bidirectional `pushAccount ↔ CEA` mappings. Stores shared config
(`VAULT`, `UNIVERSAL_GATEWAY`, `CEA_MIGRATION_CONTRACT`) for all newly deployed CEAs.

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `deployCEA(pushAccount)` | `VAULT` | `onlyVault`, `whenNotPaused` |
| `pause` / `unpause` | `PAUSER_ROLE` | OZ `Pausable` |
| `setPauserRole` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setVault` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setCEAProxyImplementation` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setCEAImplementation` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setUniversalGateway` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |
| `setCEAMigrationContract` | `DEFAULT_ADMIN_ROLE` | `onlyAdmin` |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| CF-T1 | Tampering | `setCEAMigrationContract` has no timelock; admin instant rotation to a malicious contract enables storage takeover for all future CEA migrations triggered by any CEA (same criticality as UF-T1) |
| CF-T2 | Tampering | `setVault` changes deployment authority immediately; the old Vault loses `deployCEA` access; existing CEA Vaults are unaffected (they hold the address from init) |
| CF-T3 | Elevation of Privilege | `deployCEA` accepts any non-zero `pushAccount` from the Vault; the factory cannot verify this is a real UEA on Push Chain — the Vault is fully trusted for address correctness |
| CF-T4 | Denial of Service | If a deployed CEA's code is destroyed (e.g., via `selfdestruct` on chains that still support it), `_hasCode` returns false but `pushAccountToCEA[pushAccount]` remains non-zero; a subsequent `deployCEA` for the same `pushAccount` will attempt CREATE2 which reverts (bytecode already at that address) — permanent lock-out for that `pushAccount` |
| CF-T5 | Tampering | `setUniversalGateway` updates the factory's `UNIVERSAL_GATEWAY` for new deployments only; existing CEAs carry their original gateway address, creating state divergence where old and new CEAs use different gateways concurrently |

### Invariants

1. At most one CEA per `pushAccount` (enforced by deployed-code check combined with CREATE2 collision)
2. `pushAccountToCEA` and `ceaToPushAccount` are always set together in `deployCEA` — they are always consistent

---

## CEAProxy

**File:** `src/cea/CEAProxy.sol` | **Chain:** External Chain | **Upgradeable:** No (upgraded only via delegatecall migration)

### Role

Mirrors `UEAProxy` for the external-chain CEA context. Stores logic implementation
address in custom slot
`CEA_LOGIC_SLOT = 0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813`.
All calls are delegated to the implementation.

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `initializeCEAProxy(_logic)` | Anyone (intended: `CEAFactory` atomically in `deployCEA`) | OZ `initializer` + explicit zero-address check on `_logic` |
| All other calls | Anyone | Delegated to `_implementation()` |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| CP-T1 | Tampering | `CEA_LOGIC_SLOT` must match `CEAMigration.CEA_LOGIC_SLOT` exactly; a constant mismatch between the two contracts corrupts the implementation pointer on every migration |
| CP-T2 | Elevation of Privilege | Same template-hijack consideration as UP-T1: `initializeCEAProxy` is callable by anyone on the un-cloned template contract if it is not already initialized |
| CP-T3 | Tampering | No post-init upgrade path other than migration; CEAs that are never triggered for migration remain on old logic indefinitely, even after critical patches |

### Invariants

1. `CEA_LOGIC_SLOT` in `CEAProxy` == value in `CEAMigration` (both `0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813`)
2. `_implementation()` reverts if slot value is `address(0)` — no delegation to zero address

---

## CEAMigration

**File:** `src/cea/CEAMigration.sol` | **Chain:** External Chain | **Upgradeable:** No

### Role

Mirrors `UEAMigration` for the CEA context. Single function `migrateCEA()` writes
`CEA_IMPLEMENTATION` to `CEA_LOGIC_SLOT` within the calling `CEAProxy`'s storage
context. `onlyDelegateCall` is enforced via immutable
`CEA_MIGRATION_IMPLEMENTATION == address(this)`.

### Access Control

| Function | Caller | Guard |
|---|---|---|
| `migrateCEA()` | Via delegatecall from a `CEAProxy` | `onlyDelegateCall` modifier |
| Direct calls to `migrateCEA()` | Anyone | Reverts — `onlyDelegateCall` |

### Threats

| ID | STRIDE | Description |
|---|---|---|
| CM-T1 | Elevation of Privilege | Same as UM-T1: any contract knowing this address can delegatecall `migrateCEA()` to corrupt its own storage at `CEA_LOGIC_SLOT`'s offset |
| CM-T2 | Tampering | Constructor validates `_ceaImplementation` has code at deploy time; if the implementation is later destroyed, a triggered migration writes a dangling empty implementation pointer |
| CM-T3 | Tampering | CEA's `_handleMigration` encodes `abi.encodeWithSignature("migrateCEA()")`; a typo in this string literal causes all CEA migrations to silently revert (function selector not found) |

### Invariants

1. `CEA_LOGIC_SLOT` in `CEAMigration` == `CEAProxy` constant (both `0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813`)
2. `CEA_IMPLEMENTATION` has `extcodesize > 0` at deploy time

---

## Known Issues and Prior Findings

> Source: `docs/SECURITY_ANALYSIS_v1.md` — Pashov Audit Group solidity-auditor skill (v1),
> 4-agent parallel scan, confidence threshold 75.

### Summary

| ID | Confidence | Location | Title | Status |
|---|---|---|---|---|
| F-01 | 80 | `src/cea/CEA.sol` L145-150 | Missing ERC20 approval before gateway call | Open |
| F-02 | 75 | `src/uea/UEA_EVM.sol` L80-93, `src/uea/UEA_SVM.sol` | Domain separator omits Push Chain `chainId` | Open |

---

### F-01 — Missing ERC20 Approval Before Gateway Call in `CEA.sendUniversalTxToUEA`

`CEA.sendUniversalTxToUEA` · Confidence: 80

**Description**

The ERC20 branch of `sendUniversalTxToUEA` (lines 145-150 of `src/cea/CEA.sol`) verifies
the CEA holds sufficient token balance but never calls
`IERC20(token).approve(UNIVERSAL_GATEWAY, amount)` before invoking
`IUniversalGateway(UNIVERSAL_GATEWAY).sendUniversalTxFromCEA(req)`. Any gateway
implementation that pulls tokens via `transferFrom` will revert here, permanently
locking ERC20 funds inside the CEA — the only egress path for ERC20 tokens back to
the UEA.

**Proposed Fix**

```diff
     } else {
         if (IERC20(token).balanceOf(address(this)) < amount) {
             revert CEAErrors.InsufficientBalance();
         }
+        IERC20(token).safeApprove(UNIVERSAL_GATEWAY, amount);
         IUniversalGateway(UNIVERSAL_GATEWAY)
             .sendUniversalTxFromCEA(req);
     }
```

---

### F-02 — Domain Separator Omits Push Chain Network ID, Enabling Cross-Deployment Signature Replay

`UEA_EVM.domainSeparator` · `UEA_SVM.domainSeparator` · Confidence: 75

**Description**

The EIP-712 domain separator in `UEA_EVM` and `UEA_SVM` (lines 80-93 of
`src/uea/UEA_EVM.sol`) encodes only the *source chain's* `chainId` (stored from
`_universalAccountId.chainId`, e.g., `1` for Ethereum mainnet) and `address(this)`,
but never includes `block.chainid` (Push Chain's own network ID). A signed
`UniversalPayload` that is valid on one Push Chain deployment (e.g., testnet) can
therefore be replayed on any other Push Chain deployment (e.g., mainnet) where the
same `UEAProxy` address exists — the only domain separator field that would differ
across deployments is the contract address, which is CREATE2-deterministic from the
same factory.

**Proposed Fix**

```diff
-    bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH =
-        0x2aef22f9d7df5f9d21c56d14029233f3fdaa91917727e1eb68e504d27072d6cd;
-    // keccak256("EIP712Domain(string version,uint256 chainId,address verifyingContract)")
+    bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH =
+        keccak256("EIP712Domain(string version,uint256 chainId,uint256 pushChainId,address verifyingContract)");

     function domainSeparator() public view returns (bytes32) {
         uint256 chainId = StringUtils.stringToExactUInt256(
             _universalAccountId.chainId
         );

         return keccak256(
             abi.encode(
                 DOMAIN_SEPARATOR_TYPEHASH,
                 keccak256(bytes(VERSION)),
                 chainId,
+                block.chainid,
                 address(this)
             )
         );
     }
```

Note: the off-chain signer and `UNIVERSAL_PAYLOAD_TYPEHASH` must be updated to include
the new `pushChainId` field.

---

### Additional Observations (Below Confidence Threshold)

The following patterns were examined and assessed as low-risk or by-design, but are
noted for completeness:

- **`UNIVERSAL_EXECUTOR_MODULE` nonce consumption**: The hardcoded module at `0x14191...`
  bypasses signature verification and can increment any UEA's nonce unconditionally,
  which could cause a pending user-signed transaction (with that nonce) to become
  invalid. This is an inherent trust assumption in the protocol design.

- **UEAProxy / OZ Initializable storage overlap**: `UEAProxy` inherits OZ
  non-upgradeable `Initializable` (slot 0) and then delegates to `UEA_EVM` whose
  `_universalAccountId` also begins at slot 0. After atomic initialization in
  `deployUEA`, the overwrite lands a non-zero value at slot 0, effectively preventing
  re-initialization. No concrete exploit path identified.

- **`WPC.withdraw` uses `transfer`**: The 2300-gas stipend of `address.transfer()`
  blocks reentrancy but may fail for recipients with complex `receive()` logic. WPC
  is a simple WETH-style wrapper with no user accounting beyond `balanceOf`, so the
  practical impact is low.

- **`PRC20.transferFrom` checks allowance after `_transfer`**: The allowance revert is
  placed after `_transfer` executes; however, the revert unwinds all state changes in
  the same transaction, so there is no exploitable window.

- **CEA multicall self-call with `sendUniversalTxToUEA` — no ERC20 approval within
  the call**: Compounds with F-01 above; if F-01 is unfixed, the ERC20 outbound path
  via multicall is also broken.

---

## Cross-Cutting Concerns

### UNIVERSAL_EXECUTOR_MODULE Trust Assumption

`UNIVERSAL_EXECUTOR_MODULE` (`0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7`) is
hardcoded as an immutable constant in `UniversalCore`, `PRC20`, `UEA_EVM`, and
`UEA_SVM`. There is no on-chain setter in any of these contracts.

Its powers span the entire protocol: it can mint unlimited PRC20 tokens to any
address, execute arbitrary multicall payloads through any UEA without owner consent,
and drive all deposit/refund/chain-metadata operations in UniversalCore. Compromise
of the private key controlling this address constitutes total, irreversible protocol
compromise — no on-chain pause or role revocation can halt it.

Auditors should document and review: what hardware/HSM/multisig controls the key
for this address, whether any off-chain circuit-breaker exists, and whether any
monitoring alerts on unexpected activity from this address.

### Admin Privileges and Timelock Absence

Three upgradeable contracts (`UniversalCore`, `UEAFactory`, `CEAFactory`) have
`DEFAULT_ADMIN_ROLE` configured with no on-chain timelock. The following
high-impact operations are therefore instant:

- Rotation of `UEA_MIGRATION_CONTRACT` (UEAFactory) — enables storage takeover
  of all UEAs that subsequently trigger migration
- Rotation of `CEA_MIGRATION_CONTRACT` (CEAFactory) — same for all CEAs
- Rotation of Uniswap V3 addresses (UniversalCore) — enables fund diversion on
  all future swaps
- Rotation of `WPC` address (UniversalCore) — enables native PC theft on wrap/unwrap

A timelock (e.g., 24–48 hours minimum) on migration contract changes would allow
users to observe and exit before a malicious migration is triggered.

### Proxy Storage Layout and Migration Safety

Both proxy clusters (`UEAProxy`/`UEAMigration` and `CEAProxy`/`CEAMigration`) use
non-EIP-1967 custom storage slots for the implementation pointer. These slots were
chosen to avoid collision with standard OZ storage, but this means standard tooling
for upgrade safety checks (e.g., OZ Upgrades plugin) may not detect collisions.

Migration contracts only update the implementation pointer — they perform no data
migration. Therefore, any v2 logic contract must be fully storage-layout compatible
with the v1 state laid down at `initialize` time. Introducing new state variables
in v2 must extend (not reorder) the v1 layout, or proxy storage will be corrupted.
Auditors should verify v2 implementations against v1 storage layout using a
structured storage-layout diff tool.

### CREATE2 Determinism

Both `UEAFactory` and `CEAFactory` use CREATE2 for deterministic proxy addresses.
Proxy initialization (`initializeUEA` / `initializeCEAProxy`) is called atomically
within the same factory transaction as deployment, preventing front-run
initialization of a newly deployed proxy.

However, deterministic addressing means attack pre-positioning is possible:
an adversary who knows the `UniversalAccountId` for a user who has not yet been
deployed can pre-compute the future proxy address and send funds, approvals, or
malicious approvals to it before deployment. Auditors should assess whether any
protocol component trusts a not-yet-deployed address's future behaviour.

### Reentrancy Surface

The following functions are guarded by `nonReentrant`:
- `UEA_EVM.executeUniversalTx` / `UEA_SVM.executeUniversalTx`
- `CEA.executeUniversalTx`
- `UniversalCore.depositPRC20WithAutoSwap`
- `UniversalCore.refundUnusedGas`
- `UniversalCore.swapAndBurnGas`

The following are **not** guarded:
- `UniversalCore.depositPRC20Token` — calls `IPRC20(prc20).deposit(recipient, amount)`
  as an external call; if a malicious PRC20 address is registered (via compromised
  `MANAGER_ROLE`), this call could re-enter `UniversalCore`
- `CEA.sendUniversalTxToUEA` — this function is only reachable via a multicall
  self-call, which is itself inside the `nonReentrant` scope of
  `CEA.executeUniversalTx`; the full call stack must be traced to confirm no
  cross-function re-entry vector exists, particularly for the ERC20 approval path
  once F-01 is patched
