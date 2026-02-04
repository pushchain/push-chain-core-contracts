# Universal Executor Accounts (UEA)

## Contract Locations

- **UEA_EVM Implementation**: [`src/UEA/UEA_EVM.sol`](../src/UEA/UEA_EVM.sol)
- **UEA_SVM Implementation**: [`src/UEA/UEA_SVM.sol`](../src/UEA/UEA_SVM.sol)
- **UEAFactoryV1**: [`src/UEA/UEAFactoryV1.sol`](../src/UEA/UEAFactoryV1.sol)
- **UEAProxy**: [`src/UEA/UEAProxy.sol`](../src/UEA/UEAProxy.sol)
- **UEAMigration**: [`src/UEA/UEAMigration.sol`](../src/UEA/UEAMigration.sol)
- **IUEA Interface**: [`src/Interfaces/IUEA.sol`](../src/Interfaces/IUEA.sol)
- **IUEAFactory Interface**: [`src/Interfaces/IUEAFactory.sol`](../src/Interfaces/IUEAFactory.sol)

---

## What is a UEA?

A Universal Executor Account (UEA) is a deterministic smart contract account deployed on Push Chain that represents a user from an external chain and lets them interact with Push apps without "being on Push" natively. Instead of requiring users to create a Push-native wallet/account, Push maps each external identity to a UEA and treats that UEA as the user's on-chain identity within Push execution.

There are currently two UEA implementations:

- **UEA_EVM**: for EVM-based chains (e.g., Ethereum). Ownership is verified using ECDSA signatures (EIP-712-style payload hashing + `ecrecover`).
- **UEA_SVM**: for Solana/SVM-based chains. Ownership is verified using Ed25519 signatures (verified via a verifier precompile at `0x00000000000000000000000000000000000000ca`).

In both cases, the UEA becomes the effective caller on Push: when a payload is executed, apps see `msg.sender == UEA`, giving the user a stable identity on Push that is tied to their external-chain key.

---

## Inbound Flow Using UEA (Ethereum → Push Chain)

Example: Bob is an Ethereum user and wants to deposit funds and execute a Push-chain call.

1. **Bob submits an inbound request on Ethereum**
   - Bob interacts with the Ethereum-side Universal Gateway to send funds + an encoded payload (target address + calldata) destined for Push Chain.

2. **Ethereum-side gateway locks/escrows funds and emits an event**
   - The gateway locks the assets and emits an event that includes the token, amount, destination details, and the encoded call intent.

3. **Validators/relayers observe the event and finalize it for Push**
   - Push's off-chain verification layer (Universal Validators / relayers / TSS depending on the route) confirms the event and prepares an inbound execution on Push.

4. **Push mints the wrapped representation (pTokens) to Bob's UEA**
   - On Push Chain, the inbound pipeline mints the corresponding pToken (e.g., DAI → pDAI) to Bob's UEA.

5. **Push ensures Bob's UEA exists**
   - If Bob is a first-time user, Push deterministically deploys his UEA via `UEAFactory.deployUEA(UniversalAccountId)`.

6. **Push executes the inbound payload through Bob's UEA**
   - The inbound pipeline calls `UEA.executePayload(rawPayload, verificationData)`. If the caller is `UE_MODULE` (address `0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7`), signature verification is skipped. Otherwise, the UEA verifies the signature before execution. The target Push contract is called as if Bob is the actor—i.e. the target sees `msg.sender == Bob's UEA`.

7. **Target contract runs and updates state under Bob's UEA identity**
   - Any balances/positions/state (stake, lend, swap, etc.) are tracked against the UEA as Bob's identity on Push.

```text
Ethereum (external chain)                           Push Chain
──────────────────────────                         ─────────────────────────
Bob (EOA / Smart Account)
   |
   | 1) deposit funds + payload into UniversalGateway (ETH)
   v
UniversalGateway (ETH)
   |
   | 2) lock/escrow funds + emit event (token, amount, payload, origin identity)
   v
Validators / Relayers (off-chain)
   |
   | 3) verify event and submit inbound execution to Push
   v
Push inbound pipeline
   |
   | 4) deploy UEA if needed (via UEAFactory)
   | 5) mint pTokens to Bob's UEA
   | 6) call UEA.executePayload(...)
   v
Bob's UEA (Push Chain)
   |
   | 7) executes target contract call on Push
   v
Target App Contract (Push)
   |
   | msg.sender == Bob's UEA
   v
State updated / action performed
```

---

## Deterministic Creation of UEAs

UEAs are created via `UEAFactoryV1` using deterministic deployment so that a user's UEA address is predictable and stable. The factory derives a salt from the user's `UniversalAccountId` (chain namespace + chain id + owner key), and deploys a per-user `UEAProxy` at a deterministic address using OpenZeppelin's `Clones.cloneDeterministic`. The proxy is then initialized to point to the correct implementation:

- **UEA_EVM** for EVM-origin users
- **UEA_SVM** for Solana-origin users

**Deployment flow:**
1. `UEAFactory` clones `UEAProxy` template using `cloneDeterministic(salt)` where `salt = keccak256(abi.encode(_id.chainNamespace, _id.chainId, _id.owner))`.
2. `UEAFactory` calls `UEAProxy.initializeUEA(UEA_IMPLEMENTATION)` to set the implementation based on the chain's VM type.
3. `UEAFactory` calls `UEA.initialize(UniversalAccountId, factory)` through the proxy.

This guarantees: one external identity ↔ one stable UEA on Push.

---

## Control Model: Only the Owner Can Execute via the UEA

UEAs are controlled by the external user's key:

- **For UEA_EVM**: The UEA verifies an ECDSA signature over an EIP-712-style payload hash derived from the execution request using `domainSeparator()` and `getPayloadHash(payload)`. The signature is recovered using `ECDSA.recover()` and compared to `address(bytes20(id.owner))`.
- **For UEA_SVM**: The UEA verifies an Ed25519 signature via the verifier precompile at `VERIFIER_PRECOMPILE` address.

If the signature is invalid, the call reverts. This ensures no third party can execute arbitrary actions through someone else's UEA.

Additionally, a trusted system component (`UE_MODULE` at address `0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7`) is allowed to call `executePayload` without signature verification, because the inbound execution pipeline is already authenticated at the protocol layer.

**Payload execution modes:**
- **Single call**: Direct execution to a target contract
- **Multicall**: Batch multiple calls in one transaction (identified by `MULTICALL_SELECTOR` prefix)
- **Migration**: Upgrade UEA implementation logic (identified by `MIGRATION_SELECTOR` prefix, cannot be a subcall within multicall)

---

## UEA Migration Overview (Upgrading UEA Logic)

UEAs use a proxy pattern (`UEAProxy`) where the proxy delegates execution to a UEA implementation stored in a fixed storage slot (`UEA_LOGIC_SLOT`). Migration works by updating this implementation pointer to a newer version.

**High-level flow:**
1. A new UEA implementation (e.g., `UEA_EVM` v2 / `UEA_SVM` v2) is deployed.
2. A new `UEAMigration` contract is deployed, configured with the new implementation addresses for both EVM and SVM.
3. The factory is updated to point to the latest migration contract via `UEAFactory.setUEAMigrationContract(migrationAddress)`.
4. A user triggers migration via the UEA execution pathway: the payload data must start with `MIGRATION_SELECTOR`, and `payload.to == address(this)`. This is a dedicated execution mode, not a normal call.
5. The UEA delegates to the migration contract via `delegatecall`, which updates the proxy's implementation slot (`UEA_LOGIC_SLOT`) to the new logic contract. For EVM UEAs, `UEAMigration.migrateUEAEVM()` is called; for SVM UEAs, `UEAMigration.migrateUEASVM()` is called.

**Result**: The UEA keeps the same address (identity) but runs new logic.
