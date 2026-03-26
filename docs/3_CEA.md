# Chain Executor Accounts (CEA)

## Contract Locations

- **CEA Implementation**: [`src/cea/CEA.sol`](../src/cea/CEA.sol)
- **CEAFactory**: [`src/cea/CEAFactory.sol`](../src/cea/CEAFactory.sol)
- **CEAProxy**: [`src/cea/CEAProxy.sol`](../src/cea/CEAProxy.sol)
- **CEAMigration**: [`src/cea/CEAMigration.sol`](../src/cea/CEAMigration.sol)
- **ICEA Interface**: [`src/interfaces/ICEA.sol`](../src/interfaces/ICEA.sol)
- **ICEAFactory Interface**: [`src/interfaces/ICEAFactory.sol`](../src/interfaces/ICEAFactory.sol)
- **ICEAProxy Interface**: [`src/interfaces/ICEAProxy.sol`](../src/interfaces/ICEAProxy.sol)

---

## What is a CEA?

A Chain Executor Account (CEA) is a deterministic, per-user smart contract account deployed on an external EVM chain (e.g., Ethereum) that represents a user's UEA (Universal Executor Account) on Push Chain.

CEAs exist to preserve user identity for outbound execution: instead of the Universal Gateway or Vault becoming the `msg.sender` on the destination chain, the user's own CEA becomes the caller. This enables external protocols to attribute actions (staking, lending, transfers, etc.) to a stable address that uniquely represents the Push user on that chain.

In Push architecture, the Vault is the only trusted on-chain component allowed to deploy CEAs and trigger executions. Each CEA can receive and hold native/ERC20 funds and execute arbitrary payloads on external contracts, ensuring `msg.sender == CEA` for all outbound operations initiated from Push Chain.

---

## Outbound Execution Flow Using CEA (Push Chain → Ethereum)

Consider Bob, who has pETH on Push Chain and wants to execute a function on Ethereum (e.g., `stake()`).

1. **Bob initiates outbound request on Push Chain**
   - Bob calls `UniversalGatewayPC.sendUniversalTxOutbound(req)` to burn pETH and submit the outbound payload (target address + calldata).

2. **Push Chain emits an outbound event**
   - `UniversalGatewayPC` burns PRC20 tokens, pays protocol fee in native PC to VaultPC, swaps PC → gas token, and emits:
     ```solidity
     event UniversalTxOutbound(
         bytes32 indexed subTxId, address indexed sender, string chainNamespace,
         address indexed token, bytes recipient, uint256 amount, address gasToken,
         uint256 gasFee, uint256 gasLimit, bytes payload, uint256 protocolFee,
         address revertRecipient, TX_TYPE txType, uint256 gasPrice
     )
     ```

3. **TSS observes and verifies the event off-chain**
   - The off-chain TSS verification layer confirms the event and prepares an authenticated execution on the external chain.

4. **TSS calls the Vault on Ethereum**
   - TSS calls `Vault.finalizeUniversalTx(subTxId, universalTxId, pushAccount, recipient, token, amount, data)` on the external chain. This function is guarded by `TSS_ROLE`.

5. **Vault ensures Bob's CEA exists**
   - Vault calls `CEAFactory.getCEAForPushAccount(pushAccount)`. If not deployed, it deploys via `deployCEA(pushAccount)`.

6. **Vault funds and triggers execution through the CEA**
   - For ERC20: Vault calls `IERC20.safeTransfer(cea, amount)` then `CEA.executeUniversalTx(subTxId, universalTxId, pushAccount, recipient, data)`.
   - For native: Vault calls `CEA.executeUniversalTx{value: amount}(...)`.

7. **CEA validates and dispatches**
   - CEA verifies `originCaller == pushAccount`, marks `isExecuted[subTxId] = true`, and dispatches `_handleExecution`.

8. **Target contract executes with CEA as caller**
   - The target sees `msg.sender == Bob's CEA` (not Vault, not Gateway).

```text
Push Chain                                         Ethereum (external chain)
─────────                                         ────────────────────────
Bob (origin user)
   |
   | 1) sendUniversalTxOutbound(req) — burn pETH + submit payload
   v
UniversalGatewayPC
   |
   | 2) emit UniversalTxOutbound(subTxId, sender, chainNamespace,
   |         token, recipient, amount, gasToken, gasFee, gasLimit,
   |         payload, protocolFee, revertRecipient, txType, gasPrice)
   v
TSS (off-chain)
   |
   | 3) verify event, relay to Ethereum
   v
Vault (Ethereum)
   |
   | 4) getCEAForPushAccount / deployCEA
   | 5) fund CEA (safeTransfer ERC20 / msg.value for native)
   | 6) CEA.executeUniversalTx(subTxId, universalTxId, pushAccount, recipient, data)
   v
Bob's CEA (Ethereum)
   |
   | 7) verify pushAccount, mark executed, dispatch _handleExecution
   v
Target Contract (Ethereum)
   |
   | msg.sender == Bob's CEA
   v
State updated / action performed
```

---

## Deterministic Creation of CEAs

Each user has exactly one CEA per external chain (v1). A CEA is deployed via `CEAFactory` using deterministic deployment (CREATE2-style semantics through deterministic cloning via OpenZeppelin's `Clones.cloneDeterministic`). The CEA address is derived from the user's UEA identity (on Push Chain) in a way that guarantees:

- The same push account (UEA) always maps to the same CEA address on that chain.
- The mapping is stable and predictable (can be computed ahead of time using `CEAFactory.computeCEA(pushAccount)`).
- The Vault is the only allowed deployer (via `onlyVault` modifier), preventing unauthorized creation or spoofing.

**Deployment flow:**
1. `CEAFactory` clones `CEAProxy` template using `cloneDeterministic(salt)` where `salt = keccak256(abi.encode(pushAccount))`.
2. `CEAFactory` calls `CEAProxy.initializeCEAProxy(CEA_IMPLEMENTATION)` to set the implementation.
3. `CEAFactory` calls `CEA.initializeCEA(pushAccount, VAULT, UNIVERSAL_GATEWAY)` through the proxy.

In practice:
```
UEA (Push identity) → deterministic CEA address (Ethereum identity)
```

---

## Payload Execution

The CEA uses a `_handleExecution` dispatcher identical in structure to the UEA. It reads the first 4 bytes of the payload to select the execution mode:

- **`MULTICALL_SELECTOR`** (`bytes4(keccak256("UEA_MULTICALL"))`) → `_handleMulticall`: iterates a decoded `Multicall[]` array, calling each `{to, value, data}` entry. `to != address(0)` is required. Self-calls (`to == address(this)`) are allowed only with `value == 0`.
- **`MIGRATION_SELECTOR`** (`bytes4(keccak256("UEA_MIGRATION"))`) → `_handleMigration`: must be standalone (not nested in multicall). Requires `to == address(this)` and `value == 0`. Delegatecalls `CEAFactory.CEA_MIGRATION_CONTRACT()` → `migrateCEA()`.
- **Otherwise** → `_handleSingleCall`: `recipient.call{value: msg.value}(data)`.

```text
CEA.executeUniversalTx(subTxId, universalTxId, pushAccount, recipient, data)
        │
        ├─ verify pushAccount, mark isExecuted[subTxId] = true
        │
        └─ _handleExecution(payload)
                   │
    ┌──────────────┼──────────────────────┐
    │              │                      │
MULTICALL_SELECTOR  MIGRATION_SELECTOR   (anything else)
    │              │                      │
_handleMulticall() _handleMigration()  _handleSingleCall()
(batch calls)      (delegatecall to    (single call to
                    migration contract)  recipient)
```

---

## Inbound Calls from CEA (CEA → UEA Calls)

A CEA can initiate a full inbound cross-chain transaction back to Push Chain using `sendUniversalTxToUEA(token, amount, payload)`.

- **Access**: Only callable as a self-call within a multicall (`msg.sender == address(this)`). This prevents external actors from triggering outbound sends on behalf of a CEA.
- **Purpose**: Routes through `UniversalGateway.sendUniversalTxFromCEA(req)` to initiate an authenticated inbound execution on the user's UEA on Push Chain.
- **Native path**: `msg.value > 0`, `token == address(0)` — forwards ETH to the gateway.
- **ERC20 path**: checks balance, calls `safeApprove(UNIVERSAL_GATEWAY, amount)`, then `gateway.sendUniversalTxFromCEA(req)`.
- **Gateway validation**: The gateway verifies that `msg.sender` is a valid CEA registered in `CEA_FACTORY` and that `req.recipient == mappedUEA`.
- **Inbound fee**: There is a protocol fee for inbound calls; the caller (CEA) must supply sufficient `msg.value`. This is a deliberate design choice — the CEA's operator is responsible for funding the fee.

```text
CEA multicall → sendUniversalTxToUEA(token, amount, payload)
    │
    ├─ [native]  UNIVERSAL_GATEWAY.sendUniversalTxFromCEA{value}(req)
    └─ [ERC20]   IERC20(token).safeApprove(UNIVERSAL_GATEWAY, amount)
                 UNIVERSAL_GATEWAY.sendUniversalTxFromCEA(req)
                     │
                     ├─ validates: caller is registered CEA in CEA_FACTORY
                     ├─ validates: req.recipient == mapped UEA
                     └─ emits inbound event → TSS picks up → executes on UEA
```

---

## CEA Migration

CEA uses the same delegatecall-based proxy migration pattern as UEA:

- `CEAProxy` stores the logic implementation address at `CEA_LOGIC_SLOT`.
- Migration is triggered when the Vault routes a `MIGRATION_SELECTOR` payload to the CEA (initiated by the UEA owner on Push Chain via an outbound tx).
- `_handleMigration` reads `CEAFactory.CEA_MIGRATION_CONTRACT()` and delegatecalls `migrateCEA()`, which writes the new `CEA_IMPLEMENTATION` address into `CEA_LOGIC_SLOT`.
- The CEA address, all stored state, and ownership are fully preserved after migration.

See [`docs/CEA_UEA_MIGRATION_FLOW.md`](./CEA_UEA_MIGRATION_FLOW.md) for the complete step-by-step flow with diagrams.
