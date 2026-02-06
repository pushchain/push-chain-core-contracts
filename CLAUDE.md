# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Push Chain Core Contracts implement a universal interoperability protocol enabling cross-chain interactions through deterministic smart account systems. The protocol bridges external chains (Ethereum, Solana, etc.) with Push Chain through two complementary account types:

- **UEA (Universal Executor Account)**: Deployed on Push Chain, represents external-chain users with native signature verification
- **CEA (Chain Executor Account)**: Deployed on external chains, represents Push Chain UEAs for outbound execution

## Development Commands

### Build and Compilation
```bash
# Build all contracts
forge build

# Clean build artifacts
forge clean

# Update git submodules (required after clone)
git submodule update --init --recursive
```

### Testing
```bash
# Run all tests
forge test

# Run tests with verbosity levels
forge test -vv      # Show stack traces for failing tests
forge test -vvv     # Show stack traces for all tests
forge test -vvvv    # Show stack traces and setup
forge test -vvvvv   # Maximum verbosity with internal calls

# Run specific test file
forge test --match-path test/tests_uea_and_factory/UEA_EVM.t.sol

# Run specific test contract
forge test --match-contract UEA_EVMTest

# Run specific test function
forge test --match-test testExecutePayload

# Run tests with gas reporting
forge test --gas-report

# Run tests with coverage
forge coverage

# Generate detailed coverage report
forge coverage --report lcov
```

### Deployment
```bash
# Deploy UEAFactory (example)
forge script scripts/deployFactory.s.sol --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast

# Deploy UniversalCore
forge script scripts/deployUniversalCore.s.sol --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast

# Upgrade contracts
forge script scripts/upgradeFactory.s.sol --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
```

### Code Quality
```bash
# Format code (if formatter is configured)
forge fmt

# Check code formatting
forge fmt --check
```

## Architecture Overview

### Account System: UEA vs CEA

**Universal Executor Account (UEA)**
- Location: Push Chain
- Purpose: Represents external-chain users on Push Chain
- Control: User-authenticated via native signatures (ECDSA for EVM, Ed25519 for Solana)
- Implementations: `UEA_EVM` (src/UEA/UEA_EVM.sol:28) and `UEA_SVM` (src/UEA/UEA_SVM.sol)
- Deployment: Deterministic via `UEAFactoryV1` using CREATE2 (src/UEA/UEAFactoryV1.sol:35)
- Identity: One external identity → one stable UEA address

**Chain Executor Account (CEA)**
- Location: External chains (Ethereum, Base, etc.)
- Purpose: Represents Push Chain UEAs on external chains
- Control: Vault-driven (no user signatures in v1)
- Implementation: `CEA` (src/CEA/CEA.sol)
- Deployment: Deterministic via `CEAFactory` using CREATE2 (src/CEA/CEAFactory.sol:32)
- Identity: One UEA → one CEA per external chain

### Proxy Pattern Architecture

Both UEA and CEA use minimal proxy (EIP-1167 clone) architecture:

**UEA Proxy Flow:**
1. `UEAFactoryV1` clones `UEAProxy` template using `Clones.cloneDeterministic(salt)`
2. Salt = `keccak256(abi.encode(chainNamespace, chainId, owner))`
3. `UEAProxy.initializeUEA(UEA_IMPLEMENTATION)` sets implementation in custom slot `UEA_LOGIC_SLOT` (src/UEA/UEAProxy.sol:20)
4. Implementation is either `UEA_EVM` or `UEA_SVM` based on VM type
5. All state lives in the proxy, logic is delegatecalled

**CEA Proxy Flow:**
1. `CEAFactory` clones `CEAProxy` template using `Clones.cloneDeterministic(salt)`
2. `CEAProxy.initializeCEAProxy(CEA_IMPLEMENTATION)` sets implementation
3. `CEA.initializeCEA(ueaOnPush, VAULT, UNIVERSAL_GATEWAY)` initializes CEA state
4. All state lives in the proxy, logic is delegatecalled

### Migration System

**UEA Migration:**
- Implemented via `UEAMigration` contract (src/UEA/UEAMigration.sol)
- Allows upgrading UEA implementation logic through delegatecall
- Factory tracks current migration contract at `UEA_MIGRATION_CONTRACT`
- Migration preserves all proxy state while updating logic contract

**CEA Migration:**
- Template addresses can be updated for new deployments via `CEAFactory.setCEAImplementations`
- Existing deployed CEAs maintain their configured implementation
- No in-place upgrade mechanism in v1

### Token Primitives

**PRC20 (src/PRC20.sol)**
- Synthetic token representing external chain assets on Push Chain
- Minted/burned by protocol flows through `UniversalCore`
- Examples: pETH (Ethereum), pBNB (BSC), pUSDC, etc.

**WPC (src/WPC.sol)**
- Wrapped native PC token
- ERC-20 compatible primitive for DEX integrations
- Used in Uniswap V3 pools for gas token swaps

**UniversalCore (src/UniversalCore.sol:26)**
- Protocol coordinator on Push Chain
- Operated by Universal Executor Module at fixed address `0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7`
- Manages PRC20 minting/burning, gas price configuration, and Uniswap V3 integration
- Upgradeable via proxy pattern

### Chain Identification

Uses CAIP-2 standard for chain identifiers:
- Format: `{chainNamespace}:{chainId}`
- Examples: `eip155:1` (Ethereum mainnet), `eip155:8453` (Base), `solana:mainnet`
- Internally hashed: `chainHash = keccak256(abi.encode(chainNamespace, chainId))`
- VM types mapped via `CHAIN_to_VM` in UEAFactoryV1

### Signature Verification

**UEA_EVM Signatures:**
- Uses EIP-712 typed data hashing
- Payload hash: `UNIVERSAL_PAYLOAD_TYPEHASH` (src/libraries/Types.sol:48)
- Domain separator includes version, chainId, and verifying contract
- Recovery via ECDSA `ecrecover`
- Special case: `UE_MODULE` (0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7) can execute without signature

**UEA_SVM Signatures:**
- Uses Ed25519 signature verification
- Verified via precompile at `0x00000000000000000000000000000000000000ca`
- Payload hash: Same `UNIVERSAL_PAYLOAD_TYPEHASH` for consistency
- Special case: Same `UE_MODULE` bypass

### Payload Execution

**UniversalPayload Structure (src/libraries/Types.sol:14):**
```solidity
struct UniversalPayload {
    address to;                     // Target contract
    uint256 value;                  // Native token amount
    bytes data;                     // Call data
    uint256 gasLimit;               // Gas cap
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    uint256 nonce;                  // UEA nonce
    uint256 deadline;               // Expiration timestamp
}
```

**Special Selectors:**
- `MULTICALL_SELECTOR = bytes4(keccak256("UEA_MULTICALL"))` - Batch multiple calls
- `MIGRATION_SELECTOR = bytes4(keccak256("UEA_MIGRATION"))` - Trigger migration

## Key Contracts Reference

### Core Contracts
- `UEAFactoryV1`: src/UEA/UEAFactoryV1.sol:35 - Factory for deploying UEAs
- `UEA_EVM`: src/UEA/UEA_EVM.sol:28 - EVM account implementation
- `UEA_SVM`: src/UEA/UEA_SVM.sol - Solana account implementation
- `UEAProxy`: src/UEA/UEAProxy.sol:17 - Minimal proxy for UEAs
- `CEAFactory`: src/CEA/CEAFactory.sol:32 - Factory for deploying CEAs
- `CEA`: src/CEA/CEA.sol - External chain account implementation
- `CEAProxy`: src/CEA/CEAProxy.sol - Minimal proxy for CEAs
- `UniversalCore`: src/UniversalCore.sol:26 - Protocol coordinator
- `PRC20`: src/PRC20.sol - Synthetic token standard
- `WPC`: src/WPC.sol - Wrapped PC token

### Libraries
- `Types`: src/libraries/Types.sol - Struct definitions and constants
- `Errors`: src/libraries/Errors.sol - Custom error definitions
- `Utils`: src/libraries/Utils.sol - Helper functions

### Interfaces
- `IUEA`: src/Interfaces/IUEA.sol
- `IUEAFactory`: src/Interfaces/IUEAFactory.sol
- `ICEA`: src/Interfaces/ICEA.sol
- `ICEAFactory`: src/Interfaces/ICEAFactory.sol
- `IUniversalCore`: src/Interfaces/IUniversalCore.sol
- `IPRC20`: src/Interfaces/IPRC20.sol

## Test Structure

Tests are organized by component:
- `test/tests_uea_and_factory/` - UEA and factory tests
- `test/tests_cea/` - CEA and factory tests
- `test/tests_token_and_core/` - PRC20, WPC, and UniversalCore tests
- `test/tests_ueaMigration/` - UEA migration tests
- `test/tests_utils/` - Utility function tests
- `test/mocks/` - Mock contracts for testing
- `test/helpers/` - Test helper contracts

Test files follow the pattern `ContractName.t.sol` and use Foundry's testing framework with `forge-std/Test.sol`.

## Important Constants

- **UE_MODULE**: `0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7` - Universal Executor Module (bypasses signature checks)
- **UEA_LOGIC_SLOT**: `0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d` - Storage slot for UEA implementation
- **UNIVERSAL_PAYLOAD_TYPEHASH**: `0x102a0b05d0844e7ea580bbdbe2cfe69c4fa4bfac4cf45919f6b24381a1235844` - EIP-712 payload hash
- **EVM_HASH**: `keccak256("EVM")` - VM type identifier for EVM chains
- **SVM_HASH**: `keccak256("SVM")` - VM type identifier for Solana chains

## Solidity Configuration

- Compiler: Solidity 0.8.26 (exact version, no auto-detection)
- EVM Version: Shanghai
- Optimizer: Enabled with 99,999 runs (optimized for runtime efficiency)
- Dependencies: OpenZeppelin Contracts & Contracts-Upgradeable via git submodules

## Working with Upgradeable Contracts

Most core contracts (`UEAFactoryV1`, `CEAFactory`, `UniversalCore`) use OpenZeppelin's upgradeable proxy pattern:

- Inherit from `Initializable`, `OwnableUpgradeable`, etc.
- Use `initialize()` instead of `constructor()`
- Constructor calls `_disableInitializers()` to prevent direct implementation initialization
- Deploy via `ERC1967Proxy` with initialization data

When modifying upgradeable contracts:
- Never add storage variables before existing ones (breaks storage layout)
- Add new storage at the end
- Use storage gaps (`uint256[50] private __gap`) if implementing inheritance
- Test upgrades with `test/helpers/UpgradeableContractHelper.sol`
