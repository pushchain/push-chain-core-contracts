# CEA and UEA Migration Flow

## Overview

Both UEA (Universal Executor Account) and CEA (Chain Executor Account) use a delegatecall-based proxy migration pattern. Each proxy stores its logic implementation address in a dedicated custom storage slot — not the standard EIP-1967 slot. Migration only updates this implementation pointer; all proxy state (balances, nonces, mappings, identity) is fully preserved. The factory controls which migration contract is active; users cannot supply an arbitrary delegatecall target.

---

## Shared Concepts

| Constant             | Value                                                                     |
| -------------------- | ------------------------------------------------------------------------- |
| `UEA_LOGIC_SLOT`     | `0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d`      |
| `CEA_LOGIC_SLOT`     | `0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813`      |
| `MIGRATION_SELECTOR` | `bytes4(keccak256("UEA_MIGRATION"))` — same selector for both UEA and CEA |

**Key properties shared by both systems:**

- Migration contracts are `onlyDelegateCall` — they use an immutable self-address check to prevent direct calls.
- The factory (UEAFactory or CEAFactory) controls which migration contract is current. A user or Vault cannot supply an arbitrary target address.
- Migration is not auto-applied. Each proxy migrates only when explicitly triggered. Untriggered proxies continue running on the old logic until migration is invoked.

---

## UEA Migration Flow

### Deploy Phase (admin)

```
1. Deploy new UEA_EVM v2 and/or UEA_SVM v2 implementation contracts
2. Deploy new UEAMigration(UEA_EVM_v2_addr, UEA_SVM_v2_addr)
3. UEAFactory.setUEAMigrationContract(newMigrationAddr)
      └─ updates UEA_MIGRATION_CONTRACT pointer in factory
```

### Execution Phase (per-user)

```
4. User signs UniversalPayload {
       data:  MIGRATION_SELECTOR,
       to:    address(UEA),
       value: 0
   }
   — OR — UE Module submits migration payload on behalf of user

5. UEA.executeUniversalTx(payload, sig) called on Push Chain

6. _handleMigration():
       validates payload.to == address(this)
       validates payload.value == 0

7. Reads UEAFactory.UEA_MIGRATION_CONTRACT() → migrationAddr

8. UEAProxy delegatecalls migrationAddr with "migrateUEAEVM()" or "migrateUEASVM()"
       (selector chosen based on UEA variant)

9. UEAMigration runs in proxy storage context:
       writes new impl address to UEA_LOGIC_SLOT

10. All subsequent calls to the UEAProxy delegate to the new implementation
```

### Proxy Storage Diagram

```text
UEAProxy storage (before migration)         UEAProxy storage (after migration)
──────────────────────────────────         ─────────────────────────────────
UEA_LOGIC_SLOT → UEA_EVM_v1               UEA_LOGIC_SLOT → UEA_EVM_v2
universalAccountId → {...}     (unchanged) universalAccountId → {...}
ueaFactory → 0x...             (unchanged) ueaFactory → 0x...
nonce → N                      (unchanged) nonce → N
```

### Delegatecall Chain

```text
                  Push Chain
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  UEAProxy                                               │
│  ┌─────────────────┐   delegatecall (fallback)          │
│  │ UEA_LOGIC_SLOT  │──────────────────────────────────► │
│  │  → UEA_EVM_v1   │                  UEA_EVM_v1        │
│  └─────────────────┘   executeUniversalTx()             │
│                        _handleMigration()               │
│                              │                          │
│                              │ delegatecall             │
│                              ▼                          │
│                        UEAMigration                     │
│                        migrateUEAEVM()                  │
│                              │                          │
│                              │ writes to UEAProxy storage│
│                              ▼                          │
│  ┌─────────────────┐                                    │
│  │ UEA_LOGIC_SLOT  │ ◄── updated to UEA_EVM_v2          │
│  │  → UEA_EVM_v2   │                                    │
│  └─────────────────┘                                    │
└─────────────────────────────────────────────────────────┘
```

---

## CEA Migration Flow

### Deploy Phase (admin)

```
1. Deploy new CEA v2 implementation contract
2. Deploy new CEAMigration(CEA_v2_addr)
3. CEAFactory.setCEAMigrationContract(newMigrationAddr)
      └─ updates CEA_MIGRATION_CONTRACT pointer in factory
```

### Execution Phase (per-CEA, Vault-driven)

```
4. UEA owner on Push Chain sends outbound tx to CEA with MIGRATION_SELECTOR payload
       UniversalPayload { data: MIGRATION_SELECTOR, to: address(CEA), value: 0 }

5. TSS observes outbound event and relays to external chain

6. Vault.finalizeUniversalTx(subTxId, universalTxId, pushAccount, recipient,
                              token=address(0), amount=0, data=MIGRATION_SELECTOR_payload)

7. Vault → CEA.executeUniversalTx(subTxId, universalTxId, pushAccount, recipient, data)

8. CEA._handleMigration():
       validates payload.to == address(this)
       validates payload.value == 0

9. Reads CEAFactory.CEA_MIGRATION_CONTRACT() → migrationAddr

10. CEAProxy delegatecalls migrationAddr with "migrateCEA()"

11. CEAMigration runs in proxy storage context:
        writes new impl address to CEA_LOGIC_SLOT

12. All subsequent calls to the CEAProxy delegate to the new implementation
```

### Proxy Storage Diagram

```text
CEAProxy storage (before migration)         CEAProxy storage (after migration)
──────────────────────────────────         ─────────────────────────────────
CEA_LOGIC_SLOT → CEA_v1                   CEA_LOGIC_SLOT → CEA_v2
pushAccount → 0x...            (unchanged) pushAccount → 0x...
vault → 0x...                  (unchanged) vault → 0x...
universalGateway → 0x...       (unchanged) universalGateway → 0x...
isExecuted[subTxId] → {...}    (unchanged) isExecuted[subTxId] → {...}
```

### Delegatecall Chain

```text
                  External Chain (e.g. Ethereum)
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  CEAProxy                                               │
│  ┌─────────────────┐   delegatecall (fallback)          │
│  │ CEA_LOGIC_SLOT  │──────────────────────────────────► │
│  │  → CEA_v1       │                  CEA_v1            │
│  └─────────────────┘   executeUniversalTx()             │
│                        _handleMigration()               │
│                              │                          │
│                              │ delegatecall             │
│                              ▼                          │
│                        CEAMigration                     │
│                        migrateCEA()                     │
│                              │                          │
│                              │ writes to CEAProxy storage│
│                              ▼                          │
│  ┌─────────────────┐                                    │
│  │ CEA_LOGIC_SLOT  │ ◄── updated to CEA_v2              │
│  │  → CEA_v2       │                                    │
│  └─────────────────┘                                    │
└─────────────────────────────────────────────────────────┘
```

---

## Security Properties

- **`onlyDelegateCall` guard**: Migration contracts check at construction that their own address is different from the calling context's address. Direct calls revert; only delegatecall contexts (where `address(this)` is the proxy) succeed.
- **Factory-controlled target**: The migration contract address is read from the factory at execution time. Neither the user (UEA) nor the Vault (CEA) can supply an arbitrary delegatecall target, preventing malicious logic injection.
- **State preservation**: Only the implementation slot is updated by migration. All balances, nonces, identity fields, and execution records in the proxy's storage are untouched.
- **No forced migration**: Untriggered proxies remain on their current implementation indefinitely. Migration must be explicitly triggered per-proxy; there is no batch or automatic upgrade path.
