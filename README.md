# Push Chain Contracts
This repository contains a set of smart contracts ( UEAs ) that represents external chain users on Push Chain

## Universal Executor Accounts ( UEAs ) 
UEAs are a type of executor smart accounts that represents a external chain users on Push Chain. UEAs are what allows any chain users to interact and use Push Chain apps without having to connect, bridge or move to Push Chain. Instead the user can choose to stay on their own preferred chain with their own keys and still be able to interact with the Push Chain through their UEAs.

The main objective is to enable users from external chains (EVM or NON-EVM) to:
* Interact with smart contracts on PushChain.
* Have a dedicated Account deterministically created for them
* Verify their payload execution using signatures (EVM or NON-EVM signing mechanisms).
* Re-use the same UEAs across future interactions.

## Repository Structure

```
push-chain-contracts/
├── src/                  # Source code
│   ├── UEA/              # UEA implementations for different VM types
│   │   ├── UEA_EVM.sol   # EVM implementation (Ethereum, etc.)
│   │   └── UEA_SVM.sol   # SVM implementation (Solana)
│   ├── Interfaces/       # Contract interfaces
│   ├── libraries/        # Shared libraries and types
│   └── UEAFactoryV1.sol  # Main factory contract
├── test/                 # Test files
└── scripts/              # Deployment scripts
```

## UEAFactoryV1: Universal Executor Account Factory

The UEAFactoryV1 is the central contract responsible for deploying and managing Universal Executor Accounts (UEAs) for users from different blockchains. It acts as a registry and factory for creating deterministic smart accounts.

### Key Features

- **Multi-Chain Support**: Manages UEAs for users from different blockchains (EVM and non-EVM)
- **VM Type Registry**: Maps chains to their VM types and corresponding UEA implementations
- **Deterministic Deployment**: Creates predictable addresses for UEAs using CREATE2 and minimal proxies
- **Owner-Account Mapping**: Maintains bidirectional mappings between external chain owners and their UEAs

### Core Functions

- `registerNewChain(bytes32 _chainHash, bytes32 _vmHash)`: Register a new chain with its VM type
- `registerUEA(bytes32 _chainHash, bytes32 _vmHash, address _UEA)`: Register a UEA implementation for a VM type
- `deployUEA(UniversalAccountInfo memory _id)`: Deploy a new UEA for an external chain user
- `computeUEA(UniversalAccountInfo memory _id)`: Compute the address of a UEA before deployment
- `getUEAForOrigin(UniversalAccountInfo memory _id)`: Get the UEA address for a given external chain user

## UEA Implementations

The repository includes two UEA implementations for different virtual machine types:

### Common Features

Both implementations share:
- EIP-712 compliant transaction signing
- Payload execution with signature verification
- Nonce management to prevent replay attacks
- Deadline checking for transaction validity

### UEA_EVM vs UEA_SVM: Key Differences

| Feature | UEA_EVM | UEA_SVM |
|---------|---------|---------|
| **Signature Verification** | ECDSA recovery (secp256k1) | Ed25519 via precompile |
| **Owner Key Format** | 20-byte Ethereum address | 32-byte Solana public key |
| **Verification Method** | Direct cryptographic recovery | Calls to verifier precompile |
| **Error Types** | `InvalidEVMSignature` | `InvalidSVMSignature` |

## Getting Started

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Git

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

### Running Tests

Run all tests:
```bash
forge test
```

Run specific test file:
```bash
forge test --match-path test/UEAFactory.t.sol -v
```

Run with verbosity for debugging:
```bash
forge test -vvv
```

## Architecture

The UEA system follows a proxy-based architecture:

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

1. UEAFactoryV1 deploys minimal proxies (clones) for each user
2. Each proxy points to the appropriate UEA implementation based on VM type
3. The proxies store user-specific data while sharing implementation logic
4. External chain users interact with their UEAs by signing payloads with their native keys
