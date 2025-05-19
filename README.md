# Push Smart Account V1
This repository contains the implementation of the SmartAccount architecture for PushChain's Fee Abstraction feature.

The main objective is to enable users from external chains (EVM or NON-EVM) to:

* Interact with smart contracts on PushChain.
* Have a dedicated Smart Account deterministically created for them
* Verify their payload execution using signatures (EVM or NON-EVM signing mechanisms).
* Re-use the same Smart Account across future interactions.

The repo has two main contracts

## SmartAccountV1.sol
A lightweight smart contract acting as the user's Smart Account on PushChain.

Core Features:
* OwnerKey	Stored key of user (bytes) — EVM address or Non-EVM pubkey

* VerifierPrecompile	Verifier address to validate NON-EVM signatures

* `executePayload()`	Verify signature, then call target contract
Signature Verification Flow:


## FactoryV1.sol
The contract responsible for deploying and managing Smart Accounts.

Core Features:
* create2 with Clones - Deterministic smart account deployment using userKey as salt.
* tracks the deployed smart accounts for each user
* `computeSmartAccountAddress()` - Returns predicted smart account address before deployment.

> The Factory uses [EIP1167](https://eips.ethereum.org/EIPS/eip-1167) to create proxyies which significantly reduces deployment costs.

### Architectural Flow
Here’s how the system works:

```

            +-------------------------------------+
            | SmartAccountImplementation (Logic) |
            +-------------------------------------+
                           ^
                           | (delegatecall)
                           |
-------------------------------------------------------
| Proxy1 (Alice) | Proxy2 (Bob) | Proxy3 (Carol) |
| Storage:       | Storage:     | Storage:       |
| ownerKey=...   | ownerKey=... | ownerKey=...   |
| VM_TYPE=...  | VM_TYPE=...| VM_TYPE=...  |
-------------------------------------------------------
```

### Deployment Flow:
1. Factory contract is deployed with SmartAccountV1 as implementation.
2. New SmartAccount is deployed per user using Minimal Proxy Contracts ( clones ) for each user.
3. While the logic of SmartAccountV1 is used, the storage of Proxy is used for every specific user.

---
