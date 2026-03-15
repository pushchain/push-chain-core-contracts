# Chain Executor Accounts (CEA)

## Contract Locations

- **CEA Implementation**: [`src/CEA/CEA.sol`](../src/CEA/CEA.sol)
- **CEAFactory**: [`src/CEA/CEAFactory.sol`](../src/CEA/CEAFactory.sol)
- **CEAProxy**: [`src/CEA/CEAProxy.sol`](../src/CEA/CEAProxy.sol)
- **ICEA Interface**: [`src/Interfaces/ICEA.sol`](../src/Interfaces/ICEA.sol)
- **ICEAFactory Interface**: [`src/Interfaces/ICEAFactory.sol`](../src/Interfaces/ICEAFactory.sol)
- **ICEAProxy Interface**: [`src/Interfaces/ICEAProxy.sol`](../src/Interfaces/ICEAProxy.sol)

---

## What is a CEA?

A Chain Executor Account (CEA) is a deterministic, per-user smart contract account deployed on an external EVM chain (e.g., Ethereum) that represents a user's UEA (Universal Executor Account) on Push Chain.

CEAs exist to preserve user identity for outbound execution: instead of the Universal Gateway or Vault becoming the `msg.sender` on the destination chain, the user's own CEA becomes the caller. This enables external protocols to attribute actions (staking, lending, transfers, etc.) to a stable address that uniquely represents the Push user on that chain.

In Push architecture, the Vault is the only trusted on-chain component allowed to deploy CEAs and trigger executions. Each CEA can receive and hold native/ERC20 funds and execute arbitrary payloads on external contracts, ensuring `msg.sender == CEA` for all outbound operations initiated from Push Chain.

---

## Outbound Execution Flow Using CEA (Push Chain → Ethereum)

Consider Bob, who has pETH on Push Chain and wants to execute a function on Ethereum (e.g., `stake()`).

1. **Bob initiates outbound request on Push Chain**
   - Bob calls the Push-side gateway (`UniversalGatewayPC`) to burn pETH and provide the outbound payload (target address + calldata).

2. **Push emits an outbound event**
   - `UniversalGatewayPC` emits the outbound event containing the request details (UEA identity, token, amount, target, payload, txId, etc.).

3. **Validators/TSS relay the request to Ethereum**
   - The off-chain verification layer (Universal Validators / TSS) observes the event and prepares an authenticated execution on Ethereum.

4. **TSS calls the Vault on Ethereum**
   - On Ethereum, the TSS triggers the Vault, which is the single on-chain entrypoint for outbound executions.

5. **Vault ensures Bob's CEA exists**
   - The Vault queries `CEAFactory` for Bob's CEA address. If not deployed, the Vault deploys it deterministically via `CEAFactory.deployCEA(pushAccount)`.

6. **Vault funds the CEA (if needed)**
   - For ERC20: Vault transfers tokens into the CEA.
   - For native ETH: Vault forwards ETH to the CEA as `msg.value` in the execution call.

7. **Vault triggers execution through the CEA**
   - Vault calls `CEA.executeUniversalTx(txID, uea, token, target, amount, payload)` with the target + calldata.

8. **CEA executes the target call on Ethereum**
   - CEA performs the call to the target contract. On Ethereum, the target sees:
   - `msg.sender == Bob's CEA` (not Vault, not Gateway).

```text
Push Chain                                         Ethereum (external chain)
─────────                                         ────────────────────────
Bob (origin user)
   |
   | 1) burn pETH + submit outbound payload
   v
UniversalGatewayPC
   |
   | 2) emit outbound event (txId, UEA, token, amount, target, payload)
   v
Validators / TSS (off-chain)
   |
   | 3) relay authenticated execution to Ethereum
   v
Vault (Ethereum)
   |
   | 4) get or deploy CEA via CEAFactory
   | 5) fund CEA (ERC20 transfer / native msg.value)
   v
Bob's CEA (Ethereum)
   |
   | 6) execute target call as CEA
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

## Withdrawing Funds from CEA Back to Push Chain

CEAs can hold native ETH or ERC20 balances on the external chain (e.g., rewards, leftovers, or funds held for later use). To move these funds back to Push Chain:

1. A withdrawal request is initiated from Push Chain (outbound request targeting the CEA itself via `target == address(CEA)`).
2. Vault routes the request to the user's CEA by calling `CEA.executeUniversalTx(...)` with `target == address(this)`.
3. CEA validates this as an allowed "self-call" (selector must be `withdrawFundsToUEA(address,uint256)`) and triggers `withdrawFundsToUEA(token, amount)`.
4. `withdrawFundsToUEA(...)` uses the external chain's Universal Gateway (`IUniversalGateway.sendUniversalTx`) to send the specified token/native amount back to the user's UEA on Push Chain.

This ensures CEA-held balances can be pulled back to Push Chain safely, using the same authenticated outbound execution pathway.
