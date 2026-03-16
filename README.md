# Push Chain Core Contracts

This repository contains the core smart contracts powering Push Chain's universal interoperability protocol. The system enables users and applications from any supported chain to interact with Push Chain through deterministic smart accounts, a protocol coordinator, and synthetic token primitives — all without requiring a native Push Chain wallet.

## Getting Started

### Dependencies

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Solidity 0.8.26 (auto-pinned via `foundry.toml`)

### Setup

```bash
forge build
```

### Test

```bash
forge test                                    # all tests
forge test -vvv                               # verbose output
forge test --match-test testName              # single test by name
forge test --match-contract ContractTest      # single contract
forge test --match-path test/tests_uea_and_factory/UEA_EVM.t.sol  # single file
forge test --gas-report                       # with gas report
```

### Coverage

Coverage requires `lcov` for HTML report generation (optional):

```bash
# Ubuntu
sudo apt install lcov

# macOS
brew install lcov
```

```bash
forge coverage --ir-minimum --no-match-coverage "(PRC20V0\.sol|UniversalCoreV0\.sol|ReceiverExample\.sol|src/(libraries|[Ii]nterfaces|mocks)/|test/)"
```

> **Note:** The `--ir-minimum` flag is required because the codebase uses `via_ir = true`. Without it, `forge coverage` disables the optimizer and hits "Stack too deep" errors in some fuzz tests. The `--ir-minimum` flag re-enables `viaIR` with minimal optimization, producing accurate coverage without stack issues.

---

## Docs and Tooling

### Protocol Documentation

- [Push Chain Overview](docs/1_PUSH_CHAIN.md) — what Push Chain is and how cross-chain flows work
- [Universal Executor Accounts (UEA)](docs/2_UEA.md) — UEA architecture, execution model, and migration
- [Chain Executor Accounts (CEA)](docs/3_CEA.md) — CEA architecture, outbound flows, and migration
- [UniversalCore](docs/UniversalCore.md) — protocol coordinator, fee model, and role breakdown
- [CEA + UEA Migration Flow](docs/CEA_UEA_MIGRATION_FLOW.md) — step-by-step proxy migration diagrams
- [Threat Model](docs/THREAT_MODELLING_DOC.md) — STRIDE threat tables, invariants, and trust boundaries

### Deployed Addresses

- [Sepolia Testnet](docs/addresses/sepolia.md)
- [BSC Testnet](docs/addresses/bsc_testnet.md)

### Push Chain Testnet

RPC: `https://rpc.push.org/testnet`

Push Chain Docs: [https://push.org/docs/](https://push.org/docs/)

---

## License

MIT
