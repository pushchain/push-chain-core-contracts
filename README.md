# Push Chain Core Contracts

This repository contains the core smart contracts powering Push Chain's universal interoperability protocol. The system enables users from any blockchain (EVM or non-EVM) to interact with Push Chain applications without bridging assets or switching networks.

## Architecture Overview

Push Chain's interoperability protocol is built on three foundational pillars:

1. **Universal Executor Accounts (UEAs)** - Smart accounts representing external chain users on Push Chain
2. **UniversalCore** - Core protocol manager handling token minting, swaps, and chain configuration
3. **Token Standards (PRC20 & WPC)** - Synthetic token standard and wrapped native token for DeFi integration

This architecture allows users to stay on their preferred blockchain while seamlessly interacting with Push Chain through deterministically created smart accounts that verify signatures from their native chains.

## Repository Structure

```
push-chain-contracts/
├── src/                        # Source code
│   ├── UEA/                    # Universal Executor Accounts
│   │   ├── UEA_EVM.sol         # EVM implementation (Ethereum, Polygon, etc.)
│   │   ├── UEA_SVM.sol         # SVM implementation (Solana)
│   │   ├── UEAFactoryV1.sol    # Factory for deploying UEAs
│   │   ├── UEAProxy.sol        # Proxy contract for UEAs
│   │   └── UEAMigration.sol    # Migration contract for UEA upgrades
│   ├── UniversalCore.sol       # Core protocol manager (production)
│   ├── UniversalCoreV0.sol     # Core protocol manager (testnet)
│   ├── PRC20.sol               # Push Chain synthetic token standard
│   ├── WPC.sol                 # Wrapped PC token
│   ├── Interfaces/             # Contract interfaces
│   │   ├── IUEA.sol
│   │   ├── IUEAFactory.sol
│   │   ├── IUniversalCore.sol
│   │   ├── IPRC20.sol
│   │   ├── IWPC.sol
│   │   └── IUniswapV3.sol
│   ├── libraries/              # Shared libraries
│   │   ├── Types.sol
│   │   ├── Errors.sol
│   │   └── Utils.sol
│   └── mocks/                  # Mock contracts for testing
├── test/                       # Test files
│   ├── tests_uea_and_factory/  # UEA and Factory tests
│   ├── tests_token_and_core/   # PRC20 and UniversalCore tests
│   ├── tests_ueaMigration/     # UEA migration tests
│   └── tests_utils/            # Utility tests
└── scripts/                    # Deployment scripts
    ├── deployFactory.s.sol
    ├── deployUniversalCore.s.sol
    ├── upgradeFactory.s.sol
    └── upgradeUniversalCore.s.sol
```

## Core System 1: Universal Executor Accounts (UEAs)

### Overview

UEAs are executor smart accounts that represent external chain users on Push Chain. They enable users from any blockchain to interact with Push Chain applications without connecting, bridging, or moving to Push Chain. Users stay on their preferred chain with their own keys while their UEA executes transactions on Push Chain on their behalf.

### Key Objectives

- **Cross-Chain Interaction**: Enable users from external chains (EVM or non-EVM) to interact with Push Chain smart contracts
- **Deterministic Accounts**: Each user gets a dedicated account deterministically created for them
- **Native Signature Verification**: Verify payload execution using signatures from native chain signing mechanisms
- **Account Reusability**: Re-use the same UEA across all future interactions

### UEAFactoryV1: Universal Executor Account Factory

The UEAFactoryV1 is the central contract responsible for deploying and managing Universal Executor Accounts (UEAs) for users from different blockchains. It acts as both a registry and factory for creating deterministic smart accounts.

#### Key Features

- **Multi-Chain Support**: Manages UEAs for users from different blockchains (EVM and non-EVM)
- **VM Type Registry**: Maps chains to their VM types and corresponding UEA implementations
- **Deterministic Deployment**: Creates predictable addresses for UEAs using CREATE2 and minimal proxies
- **Owner-Account Mapping**: Maintains bidirectional mappings between external chain owners and their UEAs
- **Chain Identification**: Follows CAIP-2 standard (e.g., "eip155:1" for Ethereum mainnet)

#### Core Functions

- `registerNewChain(bytes32 _chainHash, bytes32 _vmHash)`: Register a new chain with its VM type
- `registerUEA(bytes32 _chainHash, bytes32 _vmHash, address _UEA)`: Register a UEA implementation for a VM type
- `deployUEA(UniversalAccountId memory _id)`: Deploy a new UEA for an external chain user
- `computeUEA(UniversalAccountId memory _id)`: Compute the address of a UEA before deployment
- `getUEAForOrigin(UniversalAccountId memory _id)`: Get the UEA address for a given external chain user
- `getOriginForUEA(address addr)`: Get the external chain owner information for a UEA address

### UEA Implementations

The repository includes two UEA implementations for different virtual machine types:

#### Common Features

Both implementations share:
- EIP-712 compliant transaction signing
- Payload execution with signature verification
- Nonce management to prevent replay attacks
- Deadline checking for transaction validity
- Support for batch operations (multiple calls in one transaction)

#### UEA_EVM vs UEA_SVM: Key Differences

| Feature | UEA_EVM | UEA_SVM |
|---------|---------|---------|
| **Signature Verification** | ECDSA recovery (secp256k1) | Ed25519 via precompile |
| **Owner Key Format** | 20-byte Ethereum address | 32-byte Solana public key |
| **Verification Method** | Direct cryptographic recovery | Calls to verifier precompile |
| **Error Types** | `InvalidEVMSignature` | `InvalidSVMSignature` |
| **Target Chains** | Ethereum, Polygon, BSC, Avalanche, etc. | Solana |

### UEA Proxy Architecture

UEAs follow a proxy-based architecture for upgradeability and gas efficiency:

```
            +-------------------------------------+
            | UEA Implementation (Logic)          |
            | (UEA_EVM.sol or UEA_SVM.sol)        |
            +-------------------------------------+
                           ^
                           | (delegatecall)
                           |
-------------------------------------------------------
| Proxy1 (Alice) | Proxy2 (Bob) | Proxy3 (Carol) |
| Storage:       | Storage:     | Storage:       |
| ownerKey=...   | ownerKey=... | ownerKey=...   |
| VM_TYPE=...    | VM_TYPE=...  | VM_TYPE=...    |
-------------------------------------------------------
```

**How it works:**

1. UEAFactoryV1 deploys minimal proxies (clones) for each user using CREATE2
2. Each proxy points to the appropriate UEA implementation based on VM type
3. The proxies store user-specific data while sharing implementation logic
4. External chain users interact with their UEAs by signing payloads with their native keys

### UEA Migration & Upgrades

The UEAMigration contract enables safe upgrades of UEA implementations without changing user addresses:

**Key Features:**
- **Delegatecall-Based Migration**: Upgrades implementation via delegatecall to maintain proxy storage
- **VM-Specific Paths**: Separate migration functions for EVM (`migrateUEAEVM()`) and SVM (`migrateUEASVM()`)
- **Immutable Migration Logic**: Each migration contract is deployed for a specific version upgrade
- **Safety Checks**: Validates implementation addresses and prevents direct calls (delegatecall only)

**Migration Pattern:**
```solidity
// User calls their UEA proxy which delegatecalls to UEAMigration
UEAProxy (user address) 
  → delegatecall → UEAMigration.migrateUEAEVM()
  → updates UEA_LOGIC_SLOT to new implementation
```

This allows upgrading UEA logic (bug fixes, new features) while preserving user addresses and storage.

## Core System 2: UniversalCore - The Protocol Manager

### Overview

UniversalCore is the central management contract for Push Chain's interoperability protocol. It handles PRC20 token minting, manages gas pricing and tokens for each supported chain, and provides automatic token swapping via Uniswap V3 integration.

### Key Responsibilities

- **PRC20 Token Minting**: Mint synthetic tokens to target addresses via `depositPRC20Token()`
- **Auto-Swap Functionality**: Automatic PRC20 → PC conversion via `depositPRC20WithAutoSwap()`
- **Gas Price Management**: Per-chain gas price configuration via `gasPriceByChainId`
- **Gas Token Registry**: Maps each chain to its gas token PRC20 via `gasTokenPRC20ByChainId`
- **Uniswap V3 Integration**: Pool management for liquidity operations and swaps
- **Slippage Protection**: Configurable slippage tolerance and swap parameters per token

### Key Features

- **Role-Based Access Control**: 
  - `DEFAULT_ADMIN_ROLE`: Contract owner for critical configurations
  - `MANAGER_ROLE`: Universal Executor Module (0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7)
- **Uniswap V3 Integration**: Integrates with Factory, SwapRouter, and Quoter for DEX operations
- **Configurable Parameters**: Fee tiers (500/3000/10000 bps) and slippage tolerance per token
- **Pausable**: Emergency stop functionality for security incidents
- **Upgradeable**: Proxy pattern for future protocol improvements

### Core Functions

#### Token Minting
```solidity
// Mint PRC20 tokens to target address
depositPRC20Token(address prc20, uint256 amount, address target)

// Mint PRC20 and auto-swap to PC via Uniswap V3
depositPRC20WithAutoSwap(
    address prc20,
    uint256 amount, 
    address target,
    uint24 fee,        // 0 = use default
    uint256 minPCOut,  // 0 = calculate from slippage
    uint256 deadline   // 0 = use default
)
```

#### Chain Configuration
```solidity
// Set gas price for a chain (used in fee calculations)
setGasPrice(string memory chainID, uint256 price)

// Set gas token PRC20 for a chain (e.g., pETH for Ethereum)
setGasTokenPRC20(string memory chainID, address prc20)

// Set Uniswap V3 pool for gas token/PC pair
setGasPCPool(string memory chainID, address gasToken, uint24 fee)
```

#### Swap Configuration
```solidity
// Enable/disable auto-swap support for a token
setAutoSwapSupported(address token, bool supported)

// Set default Uniswap V3 fee tier for a token
setDefaultFeeTier(address token, uint24 feeTier)

// Set slippage tolerance in basis points (e.g., 300 = 3%)
setSlippageTolerance(address token, uint256 tolerance)

// Get swap quote from Uniswap V3 Quoter
getSwapQuote(address tokenIn, address tokenOut, uint24 fee, uint256 amountIn)
```

### Auto-Swap Flow

When `depositPRC20WithAutoSwap()` is called:

1. Validate target address, amount, and auto-swap support
2. Use default fee tier if not provided
3. Verify Uniswap V3 pool exists for the token pair
4. Calculate minimum PC output using slippage tolerance
5. Mint PRC20 tokens to UniversalCore
6. Approve Uniswap V3 SwapRouter
7. Execute swap: PRC20 → WPC (wrapped PC)
8. Transfer WPC to target address
9. Emit `DepositPRC20WithAutoSwap` event

This enables seamless conversion of bridged tokens to native PC for gas or DeFi operations.

## Core System 3: Token Standards - PRC20 & WPC

### PRC20: Push Chain Synthetic Token

PRC20 is Push Chain's ERC-20 compatible synthetic token standard representing assets from external blockchains. Each PRC20 token mirrors a specific external chain token (e.g., pETH for Ethereum's ETH, pBNB for BNB Chain's BNB).

#### Key Features

**Bridge Operations:**
- **Minting via `deposit()`**: Inbound bridge operation (lock on source chain → mint on Push Chain)
- **Burning via `withdraw()`**: Outbound bridge operation (burn on Push Chain → unlock on source chain)

**Source Chain Tracking:**
- `SOURCE_CHAIN_ID`: Identifier of the origin chain (e.g., "1" for Ethereum mainnet)
- `SOURCE_TOKEN_ADDRESS`: Address of the token on the origin chain
- `TOKEN_TYPE`: Classification (PC, NATIVE, ERC20)

**Gas Fee System:**
- Withdrawal fees charged in appropriate gas token PRC20 (e.g., pETH for Ethereum withdrawals)
- Automatic fee calculation via `withdrawGasFee()`
- Integration with UniversalCore for gas price oracles

#### Gas Fee Model

```solidity
// Fee Formula
gasFee = (gasPrice × GAS_LIMIT) + PC_PROTOCOL_FEE

// Where:
// - gasPrice: Current gas price from UniversalCore.gasPriceByChainId
// - GAS_LIMIT: Protocol gas limit configured per PRC20
// - PC_PROTOCOL_FEE: Flat protocol fee in gas token units
```

**Example:** Withdrawing pUSDC to Ethereum
- Gas token: pETH (Ethereum's gas coin on Push Chain)
- User must approve pETH transfer to cover gas fee
- Withdrawal burns pUSDC and charges gas fee in pETH

#### Core Functions

```solidity
// ERC-20 Standard
transfer(address recipient, uint256 amount)
approve(address spender, uint256 amount)
transferFrom(address sender, address recipient, uint256 amount)

// Bridge Operations
deposit(address to, uint256 amount)           // Mint (UNIVERSAL_CORE or UNIVERSAL_EXECUTOR_MODULE only)
withdraw(bytes calldata to, uint256 amount)   // Burn and request unlock on source

// Fee Queries
withdrawGasFee() returns (address gasToken, uint256 gasFee)
withdrawGasFeeWithGasLimit(uint256 gasLimit_) returns (address gasToken, uint256 gasFee)

// Configuration (UNIVERSAL_EXECUTOR_MODULE only)
updateUniversalCore(address addr)
updateGasLimit(uint256 gasLimit_)
updateProtocolFlatFee(uint256 protocolFlatFee_)
```

### WPC: Wrapped PC Token

WPC (Wrapped PC) is an ERC-20 wrapper for Push Chain's native PC token, similar to WETH on Ethereum.

#### Purpose

- **Uniswap V3 Integration**: Native PC cannot be used directly in Uniswap V3 pools; WPC enables DEX trading
- **DeFi Compatibility**: Allows PC to be used in any ERC-20 compatible protocol
- **1:1 Ratio**: Always maintains exact parity with native PC

#### Core Functions

```solidity
// Wrap native PC → WPC
deposit() payable                    // Convert msg.value PC to WPC
receive() external payable           // Automatic wrapping on receive

// Unwrap WPC → native PC
withdraw(uint256 amount)             // Burn WPC and receive PC

// ERC-20 Standard
transfer(address dst, uint256 amount)
approve(address guy, uint256 amount)
transferFrom(address src, address dst, uint256 amount)
totalSupply() returns (uint256)      // Returns contract PC balance
```

## Contract Versions & Upgrades

### UniversalCore vs UniversalCoreV0

- **UniversalCore**: Production version intended for Push Chain mainnet
- **UniversalCoreV0**: Testnet version with identical functionality for testing and validation

Both versions share the same interface and features. The separation allows for safe testnet deployments without affecting mainnet contracts.

### UEA Upgrade Mechanism

UEAs use a sophisticated proxy-based upgrade mechanism:

**Architecture:**
- **UEAProxy**: Minimal proxy contract storing user-specific data and implementation address
- **UEA Implementation**: Logic contract (UEA_EVM or UEA_SVM) containing all functionality
- **UEAMigration**: Upgrade contract for migrating proxies to new implementations

**UEA Upgrade Process:**

1. Deploy new UEA implementation (e.g., UEA_EVM_V2)
2. Deploy UEAMigration contract with new implementation addresses
3. User calls `UEAProxy.execute()` with delegatecall to `UEAMigration.migrateUEAEVM()`
4. Migration updates `UEA_LOGIC_SLOT` to point to new implementation
5. All future calls use new implementation logic

## Getting Started

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) - Ethereum development toolkit
- Git
- Solidity 0.8.26

### Setup

1. Clone the repository:
```bash
git clone https://github.com/your-org/push-chain-contracts.git
cd push-chain-contracts
```

2. Install dependencies:
```bash
git submodule update --init --recursive
# If you encounter issues with submodules, try:
forge install
```

3. Build the project:
```bash
forge build
```

4. Generate coverage report (optional):
```bash
forge coverage --report lcov
genhtml lcov.info -o coverage-report
```

Example deployment:
```bash
forge script scripts/deployFactory.s.sol --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
```

## Running Tests

### Test Organization

Tests are organized by contract system:

- `test/tests_uea_and_factory/` - UEA and UEAFactory tests
  - `UEA_EVM.t.sol` - EVM implementation tests
  - `UEA_SVM.t.sol` - SVM implementation tests
  - `UEAFactory.t.sol` - Factory deployment and management tests
  - `UEAProxyCalls.t.sol` - Proxy pattern tests
  
- `test/tests_token_and_core/` - PRC20 and UniversalCore tests
  - `PRC20.t.sol` - Token standard tests
  - `WPC.t.sol` - Wrapped PC token tests
  - `UniversalCore.t.sol` - Core manager tests
  - `ForkUniversalCoreAMM.t.sol` - Uniswap V3 integration tests
  
- `test/tests_ueaMigration/` - UEA upgrade mechanism tests
  - `UEAMigration.t.sol` - Migration logic tests
  
- `test/tests_utils/` - Utility tests
  - `StringUtils.t.sol` - String utility function tests

### Running Tests

Run all tests:
```bash
forge test
```

Run specific test file:
```bash
forge test --match-path test/tests_uea_and_factory/UEAFactory.t.sol
```

Run tests for a specific contract:
```bash
forge test --match-contract PRC20Test
```

Run with verbosity for debugging:
```bash
forge test -vvv
```

Run with gas reporting:
```bash
forge test --gas-report
```

### Coverage Report

Generate and view coverage report:
```bash
forge coverage --report lcov
genhtml lcov.info -o coverage-report
open coverage-report/index.html
```

## Key Concepts Glossary

- **UEA (Universal Executor Account)**: Smart account deployed on Push Chain representing an external chain user. Verifies signatures from the user's native chain and executes transactions on their behalf.

- **UOA (Universal Owner Address)**: The address/public key of the external chain user who owns a particular UEA. Used for signature verification.

- **PRC20**: Push Chain's synthetic token standard. ERC-20 compatible tokens representing assets from external blockchains (e.g., pETH represents Ethereum's ETH).

- **WPC (Wrapped PC)**: ERC-20 wrapper for Push Chain's native PC token. Enables PC to be used in Uniswap V3 and other DeFi protocols. Maintains 1:1 ratio with PC.

- **UniversalCore**: Central protocol management contract handling PRC20 minting, gas pricing, chain configuration, and Uniswap V3 integration.

- **Universal Executor Module**: Privileged protocol address (`0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7`) with MANAGER_ROLE. Handles cross-chain message processing and authorization.

- **VM Types**: Different blockchain virtual machine environments. Currently supports EVM (Ethereum Virtual Machine) and SVM (Solana Virtual Machine).

- **Chain Hash**: Unique identifier for each supported blockchain, computed from CAIP-2 standard namespace and chain ID (e.g., `keccak256(abi.encode("eip155", "1"))` for Ethereum mainnet).

- **Auto-Swap**: Feature allowing automatic conversion of bridged PRC20 tokens to native PC via Uniswap V3 during minting.

- **Gas Token**: The PRC20 token used to pay gas fees for bridging back to a specific chain (e.g., pETH is the gas token for Ethereum).

- **CREATE2**: Deterministic deployment method using `keccak256(0xff ++ deployerAddress ++ salt ++ keccak256(bytecode))`. Ensures UEAs have predictable addresses.


## Security Considerations

- All contracts use OpenZeppelin's security-audited libraries
- Access control via role-based permissions (AccessControl)
- Reentrancy protection on sensitive functions
- Pausable functionality for emergency stops
- Signature replay protection via nonces
- Deadline checks for time-sensitive operations
- Slippage protection on DEX swaps

## License

This project is licensed under the MIT License.

## Additional Resources

- [Push Protocol Documentation](https://docs.push.org)

---
