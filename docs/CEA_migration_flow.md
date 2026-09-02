# CEA Migration Flow - Planning Document

## Executive Summary

This document designs a safe, UEA-style migration mechanism for CEAs deployed on external EVM chains. The migration allows users (via their UEA on Push Chain) to upgrade their CEAProxy from CEA v1 → CEA v2 without risking loss of funds or bricking the proxy.

**Current Status:**
- ✅ CEAMigration.sol is ready (implements slot-writing logic)
- ❌ CEA.sol lacks migration detection and routing
- ❌ CEAFactory.sol lacks migration contract tracking

**Goal:** Enable users to safely upgrade their CEA implementation by invoking a migration transaction from their UEA on Push Chain, which routes through the Vault → CEA → CEAMigration delegatecall flow.

---

## 1. Architecture Overview

### What We're Building

A migration system that:
- Mirrors the proven UEA migration pattern (UEA_EVM.sol:186-210, UEAMigration.sol)
- Enables proxy implementation upgrades without changing proxy address or losing state
- Maintains security invariants (vault-driven, UEA-authorized, delegatecall-only)
- Preserves all CEA state (UEA, VAULT, UNIVERSAL_GATEWAY, isExecuted mappings, balances)

### Why Reuse UEA Pattern

The UEA migration pattern has been proven safe through:
- Delegatecall-only enforcement (`onlyDelegateCall()` modifier)
- Factory-controlled migration contract addresses (prevents user-supplied migration exploits)
- Strict validation (self-targeted, zero-value, standalone execution)
- Storage slot isolation (implementation in dedicated slot, state preserved)

CEA migration replicates these guarantees while adapting to CEA's unique characteristics:
- **Vault-driven execution** (no user signatures, `msg.sender == VAULT`)
- **Multicall-based payloads** (migration wrapped in Multicall[] format)
- **Cross-chain authorization** (originCaller == UEA validation)

---

## 2. Current Architecture Analysis

### CEAProxy (src/CEA/CEAProxy.sol)

**Role:** Minimal proxy that delegates all calls to CEA implementation

**Implementation Slot:**
```solidity
bytes32 private constant CEA_LOGIC_SLOT =
    0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;
// bytes32(uint256(keccak256("cea.proxy.implementation")) - 1)
```

**Initialization:**
```solidity
function initializeCEAProxy(address _logic) external initializer {
    // Called once by CEAFactory after clone
    assembly { sstore(CEA_LOGIC_SLOT, _logic) }
}
```

**Current Limitation:**
- Comment on line 22 states: "There is NO upgrade mechanism here"
- This is what we're fixing with migration!

### CEA (src/CEA/CEA.sol)

**Current Execution Flow:**
```
executeUniversalTx(subTxId, universalTxID, originCaller, payload)
  → _handleExecution(...)
      → if isMulticall(payload): _handleMulticall(...)
      → else: _handleSingleCall(...) // backwards compat
```

**Key Functions:**
- `executeUniversalTx()` (line 101): Entry point, validates subTxId and originCaller
- `_handleExecution()` (line 168): Routes based on payload type
- `_handleMulticall()` (line 193): Executes Multicall[] array via `.call()`
- `sendUniversalTxToUEA()` (line 123): Self-call only function for withdrawals

**Missing:**
- No migration detection (`isMigration()` helper)
- No migration routing in `_handleExecution()`
- No migration handler (`_handleMigration()`)
- No factory reference (needed to fetch migration contract address)

### CEAFactory (src/CEA/CEAFactory.sol)

**Current State Variables:**
```solidity
address public VAULT;
address public UNIVERSAL_GATEWAY;
address public CEA_PROXY_IMPLEMENTATION;  // CEAProxy template
address public CEA_IMPLEMENTATION;        // CEA logic
mapping(address => address) public UEA_to_CEA;
mapping(address => address) public CEA_to_UEA;
```

**Deployment Flow (line 195):**
```solidity
deployCEA(ueaOnPush):
  1. Clone CEA_PROXY_IMPLEMENTATION via CREATE2
  2. Call CEAProxy.initializeCEAProxy(CEA_IMPLEMENTATION)
  3. Call CEA.initializeCEA(ueaOnPush, VAULT, UNIVERSAL_GATEWAY)
  4. Store mappings
```

**Missing:**
- No `CEA_MIGRATION_CONTRACT` state variable (needed to track migration contract)
- No setter for migration contract
- No event for migration contract updates
- `initializeCEA()` doesn't receive factory address

### CEAMigration (src/CEA/CEAMigration.sol)

**Status: ✅ COMPLETE AND CORRECT**

**Key Components:**
```solidity
address public immutable CEA_MIGRATION_IMPLEMENTATION;  // This contract's address
address public immutable CEA_IMPLEMENTATION;            // Target CEA v2

bytes32 private constant CEA_LOGIC_SLOT =
    0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;
```

**Constructor Validation:**
```solidity
constructor(address _ceaImplementation) {
    CEA_MIGRATION_IMPLEMENTATION = address(this);
    if (!hasCode(_ceaImplementation)) revert Errors.InvalidInput();
    CEA_IMPLEMENTATION = _ceaImplementation;
}
```

**Migration Function:**
```solidity
function migrateCEA() external onlyDelegateCall {
    assembly { sstore(CEA_LOGIC_SLOT, CEA_IMPLEMENTATION) }
    emit ImplementationUpdated(CEA_IMPLEMENTATION);
}
```

**Safety:**
- `onlyDelegateCall()` modifier prevents direct calls (line 58)
- Constructor validates implementation `hasCode()` (line 75)
- Storage slot matches CEAProxy exactly ✅

**No changes needed to CEAMigration.sol.**

---

## 3. Proposed Migration Flow

### End-to-End Execution Sequence

```
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 1: User initiates migration on Push Chain                         │
│ ─────────────────────────────────────────────────────────────────────── │
│ User (via UEA on Push Chain)                                            │
│   → Signs outbound transaction with migration payload                   │
│   → Payload: Multicall[{                                                │
│        to: ceaProxy,                                                    │
│        value: 0,                                                        │
│        data: MIGRATION_SELECTOR (0xb0c47dc5)                            │
│     }]                                                                  │
│   → Wrapped with MULTICALL_SELECTOR prefix                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 2: Cross-chain relay                                              │
│ ─────────────────────────────────────────────────────────────────────── │
│ TSS/Relayer Service                                                     │
│   → Monitors Push Chain for outbound events                            │
│   → Picks up migration transaction                                     │
│   → Relays to external chain Vault                                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 3: Vault invokes CEA                                              │
│ ─────────────────────────────────────────────────────────────────────── │
│ Vault.executeUniversalTx()                                              │
│   → Calls CEA.executeUniversalTx(                                       │
│        subTxId,                                                            │
│        universalTxID,                                                   │
│        originCaller = UEA address,                                      │
│        payload = MULTICALL_SELECTOR + Multicall[{...}]                  │
│     )                                                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 4: CEA validates and routes                                       │
│ ─────────────────────────────────────────────────────────────────────── │
│ CEA.executeUniversalTx() [NEW LOGIC]                                    │
│   → Validates: msg.sender == VAULT              ✓                       │
│   → Validates: !isExecuted[subTxId]                ✓                       │
│   → Validates: originCaller == UEA               ✓                       │
│   → Sets: isExecuted[subTxId] = true               ✓                       │
│   → Calls: _handleExecution(...)                                        │
│                                                                         │
│ CEA._handleExecution() [NEW LOGIC]                                      │
│   → Detects: isMulticall(payload) = true        ✓                       │
│   → Decodes: Multicall[] memory calls                                   │
│   → Detects: calls.length == 1 && isMigration(calls[0].data) = true    │
│   → Routes to: _handleMigration(calls[0])       ← NEW                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 5: CEA validates migration call                                   │
│ ─────────────────────────────────────────────────────────────────────── │
│ CEA._handleMigration(Multicall memory call) [NEW]                       │
│   → Validates: call.to == address(this)         ✓ (self-targeted)       │
│   → Validates: call.value == 0                  ✓ (no value transfer)   │
│   → Fetches: address migrationContract = factory.CEA_MIGRATION_CONTRACT()│
│   → Validates: migrationContract != address(0)  ✓                       │
│   → Prepares: bytes memory data = abi.encodeWithSignature("migrateCEA()")│
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 6: Delegatecall to migration contract                             │
│ ─────────────────────────────────────────────────────────────────────── │
│ CEA._handleMigration() [continued]                                      │
│   → Delegatecalls: migrationContract.migrateCEA()                       │
│   → Context: address(this) = CEAProxy                                   │
│   → Storage: CEAProxy's storage (preserves all state)                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 7: Migration contract writes new implementation                   │
│ ─────────────────────────────────────────────────────────────────────── │
│ CEAMigration.migrateCEA() [DELEGATECALL CONTEXT]                        │
│   → Validates: onlyDelegateCall()                ✓                       │
│   → Writes: sstore(CEA_LOGIC_SLOT, CEA_IMPLEMENTATION_V2)               │
│   → Emits: ImplementationUpdated(CEA_IMPLEMENTATION_V2)                 │
│   → Returns: success = true                                             │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 8: CEA completes execution                                        │
│ ─────────────────────────────────────────────────────────────────────── │
│ CEA._handleMigration() [returned from delegatecall]                     │
│   → Checks: success == true                      ✓                       │
│   → Emits: UniversalTxExecuted(subTxId, universalTxID, originCaller, ...)  │
│   → Returns to caller                                                   │
│                                                                         │
│ Result: CEAProxy now points to CEA v2 implementation                    │
│         All state preserved (UEA, VAULT, isExecuted, balances)          │
│         Future calls route through CEA v2 logic                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Payload Encoding

**User-side (SDK):**
```javascript
// Step 1: Create single migration multicall
const migrationCall = {
    to: ceaProxyAddress,
    value: 0,
    data: MIGRATION_SELECTOR  // 0xb0c47dc5
};

// Step 2: Wrap in Multicall[] array
const multicallArray = [migrationCall];

// Step 3: Encode as Multicall[] and prefix with MULTICALL_SELECTOR
const payload = ethers.utils.concat([
    MULTICALL_SELECTOR,  // 0xc25b8d90
    ethers.utils.defaultAbiCoder.encode(
        ['tuple(address to, uint256 value, bytes data)[]'],
        [multicallArray]
    )
]);

// Step 4: Submit to UEA on Push Chain for cross-chain relay
```

**On-chain detection (CEA):**
```solidity
// In _handleExecution()
if (isMulticall(payload)) {
    Multicall[] memory calls = decodeCalls(payload);

    // NEW: Detect single-element migration
    if (calls.length == 1 && isMigration(calls[0].data)) {
        _handleMigration(calls[0]);
        return;
    }

    // Normal multicall execution
    _handleMulticall(subTxId, universalTxID, originCaller, calls);
}
```

---

## 4. Contract Change Specifications

### 4.1 CEA.sol Changes

#### New State Variable

**Location:** After line 43 (after `_initialized`)

```solidity
/// @notice Reference to the CEA factory for fetching migration contract
ICEAFactory public factory;
```

#### Modified Initializer

**Location:** Modify `initializeCEA()` function (line 74)

**Before:**
```solidity
function initializeCEA(address _uea, address _vault, address _universalGateway) external {
    if (_initialized) revert CEAErrors.AlreadyInitialized();
    if (_uea == address(0) || _vault == address(0) || _universalGateway == address(0))
        revert CEAErrors.ZeroAddress();

    UEA = _uea;
    VAULT = _vault;
    UNIVERSAL_GATEWAY = _universalGateway;
    _initialized = true;
}
```

**After:**
```solidity
function initializeCEA(
    address _uea,
    address _vault,
    address _universalGateway,
    address _factory  // NEW
) external {
    if (_initialized) revert CEAErrors.AlreadyInitialized();
    if (_uea == address(0) ||
        _vault == address(0) ||
        _universalGateway == address(0) ||
        _factory == address(0))  // NEW
        revert CEAErrors.ZeroAddress();

    UEA = _uea;
    VAULT = _vault;
    UNIVERSAL_GATEWAY = _universalGateway;
    factory = ICEAFactory(_factory);  // NEW
    _initialized = true;
}
```

#### New Import

**Location:** Top of file (after existing imports)

```solidity
import {MIGRATION_SELECTOR} from "../libraries/Types.sol";
import {ICEAFactory} from "../interfaces/ICEAFactory.sol";
```

#### New Helper Function: isMigration()

**Location:** Add to private helpers section (after line 255, before `receive()`)

```solidity
/**
 * @notice          Checks whether the call data is a migration request
 * @dev             Determines if the data starts with MIGRATION_SELECTOR
 * @param data      Call data bytes
 * @return bool     True if data starts with MIGRATION_SELECTOR
 */
function isMigration(bytes memory data) private pure returns (bool) {
    if (data.length < 4) return false;
    bytes4 selector;
    assembly {
        selector := mload(add(data, 32))
    }
    return selector == MIGRATION_SELECTOR;
}
```

**Note:** Uses `bytes memory` (not calldata) because it's called on `Multicall.data` which is memory.

#### New Handler Function: _handleMigration()

**Location:** Add to internal helpers section (after `_handleSingleCall()`, around line 240)

```solidity
/**
 * @notice         Internal handler for migration execution
 * @dev            Validates migration constraints and delegates to migration contract
 * @dev            SAFETY CONSTRAINTS:
 *                 - Must target self (call.to == address(this))
 *                 - Must have zero value (call.value == 0)
 *                 - Migration contract must be set in factory
 *                 - Executed via delegatecall (preserves proxy state)
 * @param call     The migration Multicall struct
 */
function _handleMigration(Multicall memory call) internal {
    // CONSTRAINT: Migration must target self
    if (call.to != address(this)) {
        revert CEAErrors.InvalidTarget();
    }

    // CONSTRAINT: Migration must not include value transfer
    if (call.value != 0) {
        revert CEAErrors.InvalidInput();
    }

    // Fetch migration contract address from factory
    address migrationContract = factory.CEA_MIGRATION_CONTRACT();

    // CONSTRAINT: Migration contract must be set
    if (migrationContract == address(0)) {
        revert CEAErrors.InvalidCall();
    }

    // Prepare delegatecall to migration contract
    bytes memory migrateCallData = abi.encodeWithSignature("migrateCEA()");

    // Execute migration via delegatecall (writes to proxy storage)
    (bool success, bytes memory returnData) = migrationContract.delegatecall(migrateCallData);

    // Bubble revert data on failure
    if (!success) {
        if (returnData.length > 0) {
            assembly {
                let returnDataSize := mload(returnData)
                revert(add(32, returnData), returnDataSize)
            }
        } else {
            revert CEAErrors.ExecutionFailed();
        }
    }
}
```

#### Modified _handleExecution()

**Location:** Modify existing function (line 168)

**Before:**
```solidity
function _handleExecution(
    bytes32 subTxId,
    bytes32 universalTxID,
    address originCaller,
    bytes calldata payload
) internal {
    if (isMulticall(payload)) {
        Multicall[] memory calls = decodeCalls(payload);
        _handleMulticall(subTxId, universalTxID, originCaller, calls);
    } else {
        _handleSingleCall(subTxId, universalTxID, originCaller, payload);
    }
}
```

**After:**
```solidity
function _handleExecution(
    bytes32 subTxId,
    bytes32 universalTxID,
    address originCaller,
    bytes calldata payload
) internal {
    if (isMulticall(payload)) {
        Multicall[] memory calls = decodeCalls(payload);

        // NEW: Detect single-element migration multicall
        if (calls.length == 1 && isMigration(calls[0].data)) {
            _handleMigration(calls[0]);
            // Emit event for migration execution
            emit UniversalTxExecuted(subTxId, universalTxID, originCaller, address(this), calls[0].data);
            return;
        }

        // Normal multicall execution
        _handleMulticall(subTxId, universalTxID, originCaller, calls);
    } else {
        _handleSingleCall(subTxId, universalTxID, originCaller, payload);
    }
}
```

#### Modified _handleMulticall() - Loop Validation

**Location:** Add validation inside loop (line 207, before executing call)

**Current loop:**
```solidity
for (uint256 i = 0; i < calls.length; i++) {
    if (calls[i].to == address(0)) revert CEAErrors.InvalidTarget();

    if (calls[i].to == address(this) && calls[i].value != 0) {
        revert CEAErrors.InvalidInput();
    }

    (bool success, bytes memory returnData) = calls[i].to.call{value: calls[i].value}(calls[i].data);
    // ...
}
```

**Add after line 212 (after self-call value check):**
```solidity
// NEW: Prevent migration selector in batched multicalls (must be standalone)
if (isMigration(calls[i].data)) {
    revert CEAErrors.InvalidCall();
}
```

**Explanation:** Migration MUST be standalone (routed via `_handleMigration()`). If detected in multi-step batch, reject to prevent complexity and ensure safety constraints are enforced.

---

### 4.2 CEAFactory.sol Changes

#### New State Variable

**Location:** After line 49 (after `CEA_IMPLEMENTATION`)

```solidity
/// @notice Address of the CEA migration contract
address public CEA_MIGRATION_CONTRACT;
```

#### New Event

**Location:** After error definitions (around line 64, before modifiers)

```solidity
/// @notice Emitted when the CEA migration contract is updated
event CEAMigrationContractUpdated(address indexed oldContract, address indexed newContract);
```

#### New Setter Function

**Location:** Add to admin/governance section (after `setUniversalGateway()`, around line 156)

```solidity
/**
 * @notice Sets the CEA migration contract address
 * @dev    Only callable by owner (governance)
 * @param  newMigrationContract Address of the CEA migration contract
 */
function setCEAMigrationContract(address newMigrationContract) external onlyOwner {
    if (newMigrationContract == address(0)) revert ZeroAddress();
    address old = CEA_MIGRATION_CONTRACT;
    CEA_MIGRATION_CONTRACT = newMigrationContract;
    emit CEAMigrationContractUpdated(old, newMigrationContract);
}
```

**Note:** Zero address check prevents accidental unset. To disable migration, governance can set to a dummy contract or leave unset.

#### Modified deployCEA()

**Location:** Modify existing function (line 195, specifically line 219)

**Before:**
```solidity
// 3. Initialize the CEA logic through the proxy
ICEA(cea).initializeCEA(ueaOnPush, VAULT, UNIVERSAL_GATEWAY);
```

**After:**
```solidity
// 3. Initialize the CEA logic through the proxy (pass factory address)
ICEA(cea).initializeCEA(ueaOnPush, VAULT, UNIVERSAL_GATEWAY, address(this));
```

**Explanation:** Passes factory address so CEA can fetch migration contract later.

#### Optional: Initialize with Migration Contract

**Location:** Modify `initialize()` function (line 94)

**Current signature:**
```solidity
function initialize(
    address initialOwner,
    address initialVault,
    address ceaProxyImplementation,
    address ceaImplementation,
    address universalGateway
) external initializer
```

**Optional enhancement (not required for v1):**
```solidity
function initialize(
    address initialOwner,
    address initialVault,
    address ceaProxyImplementation,
    address ceaImplementation,
    address universalGateway,
    address ceaMigrationContract  // OPTIONAL: can be set later via setter
) external initializer {
    // ... existing validation ...

    CEA_MIGRATION_CONTRACT = ceaMigrationContract;  // Can be address(0) initially
}
```

**Recommendation:** Leave as-is for v1. Migration contract can be set via `setCEAMigrationContract()` after deployment. This provides flexibility for deploying CEA v2 and migration contract after factory initialization.

---

### 4.3 Types.sol

**No changes needed.**

- `MIGRATION_SELECTOR` already exists (line 46)
- `Multicall` struct already exists (line 31)

---

### 4.4 CEAMigration.sol

**No changes needed.**

Current implementation is complete and correct:
- ✅ Correct storage slot (`CEA_LOGIC_SLOT`)
- ✅ Delegatecall-only enforcement (`onlyDelegateCall()`)
- ✅ Constructor validation (`hasCode()` check)
- ✅ Clean slot write via assembly
- ✅ Event emission

---

### 4.5 CEAProxy.sol

**Optional: Update comment for clarity**

**Location:** Line 22

**Before:**
```solidity
*   - There is NO upgrade mechanism here: once implementation is set, it cannot be changed.
```

**After:**
```solidity
*   - Implementation can be upgraded via migration flow (CEA → CEAMigration delegatecall)
```

**Note:** This is a documentation-only change. No functional code changes needed.

---

### 4.6 ICEAFactory.sol (Interface Update)

**Location:** Add to interface definition

```solidity
/// @notice Returns the address of the CEA migration contract
function CEA_MIGRATION_CONTRACT() external view returns (address);
```

**Explanation:** Required for CEA to fetch migration contract address from factory.

---

### 4.7 ICEA.sol (Interface Update)

**Location:** Modify `initializeCEA()` signature

**Before:**
```solidity
function initializeCEA(address _uea, address _vault, address _universalGateway) external;
```

**After:**
```solidity
function initializeCEA(address _uea, address _vault, address _universalGateway, address _factory) external;
```

---

## 5. Safety Constraints Summary

All migration executions MUST satisfy these constraints (enforced by `_handleMigration()`):

| Constraint                 | Validation                                       | Error           | Rationale                                  |
| -------------------------- | ------------------------------------------------ | --------------- | ------------------------------------------ |
| **Standalone execution**   | `calls.length == 1`                              | `InvalidCall`   | Prevents migration buried in complex batch |
| **Self-targeted**          | `call.to == address(this)`                       | `InvalidTarget` | Migration must target own proxy            |
| **Zero value**             | `call.value == 0`                                | `InvalidInput`  | No funds sent with migration               |
| **Migration contract set** | `factory.CEA_MIGRATION_CONTRACT() != address(0)` | `InvalidCall`   | Prevents uninitialized migration           |
| **Delegatecall context**   | Enforced by CEAMigration.`onlyDelegateCall()`    | `Unauthorized`  | Prevents direct calls to migration         |
| **Valid implementation**   | CEAMigration constructor validates `hasCode()`   | `InvalidInput`  | Prevents bricking proxy                    |

**Additional existing protections:**
- `onlyVault` modifier (line 52): Only Vault can call `executeUniversalTx()`
- `originCaller == UEA` check (line 109): Transaction must originate from correct UEA
- `!isExecuted[subTxId]` check (line 108): Prevents replay attacks
- `nonReentrant` modifier (line 106): Prevents reentrancy

---

## 6. Threat Model & Failure Modes

### 6.1 Storage Collision Risk

**Threat:** CEA v2 adds storage variables that collide with v1's layout → corrupts state

**Impact:** Critical - funds loss, UEA/VAULT references corrupted

**Mitigation:**
1. CEA v2 MUST append new storage at the end (never prepend)
2. Storage layout testing: deploy v1, migrate to v2, verify all v1 state unchanged
3. Use storage gaps if implementing inheritance:
   ```solidity
   uint256[50] private __gap;  // Reserve slots for future use
   ```
4. Document storage layout in comments (slot numbers, order)

**Test coverage:**
- Read UEA, VAULT, UNIVERSAL_GATEWAY before and after migration (must match)
- Read isExecuted mappings before and after (must preserve)
- Read native and ERC20 balances before and after (must preserve)

---

### 6.2 Proxy Bricking

**Threat:** Invalid implementation address written to `CEA_LOGIC_SLOT` → proxy unusable

**Impact:** Critical - CEA permanently bricked, funds stranded

**Mitigation:**
1. **CEAMigration constructor validation:**
   ```solidity
   if (!hasCode(_ceaImplementation)) revert Errors.InvalidInput();
   ```
   - Enforced at migration contract deployment
   - Prevents setting EOA or non-contract address

2. **Delegatecall failure bubbling:**
   ```solidity
   if (!success) {
       // Bubble revert data from migration contract
       assembly { revert(add(32, returnData), returnDataSize) }
   }
   ```
   - If delegatecall fails, entire transaction reverts
   - Proxy implementation unchanged

3. **Factory governance:**
   - Only owner can call `setCEAMigrationContract()`
   - Requires multisig or governance approval
   - Can be tested on testnet before mainnet

**Test coverage:**
- Attempt migration to address(0) → expect revert
- Attempt migration to EOA → expect revert (caught at migration contract deploy)
- Attempt migration to invalid contract → delegatecall fails, expect revert

---

### 6.3 Fund Loss

**Threat:** Migration changes behavior such that funds become inaccessible

**Impact:** Critical - user assets stranded in CEA

**Mitigation:**
1. **State preservation:**
   - Delegatecall only writes to `CEA_LOGIC_SLOT`
   - All other storage untouched (balances, mappings)

2. **Pre-migration balance checks:**
   ```solidity
   // Test: Record balances before migration
   uint256 nativeBalanceBefore = address(ceaProxy).balance;
   uint256 erc20BalanceBefore = IERC20(token).balanceOf(ceaProxy);

   // Execute migration

   // Verify balances unchanged
   assertEq(address(ceaProxy).balance, nativeBalanceBefore);
   assertEq(IERC20(token).balanceOf(ceaProxy), erc20BalanceBefore);
   ```

3. **Post-migration withdrawal test:**
   ```solidity
   // Ensure sendUniversalTxToUEA() still works after migration
   ```

4. **CEA v2 compatibility:**
   - MUST maintain same withdrawal interfaces
   - MUST maintain same self-call patterns

**Test coverage:**
- Migrate CEA with native balance → verify balance preserved → withdraw successfully
- Migrate CEA with ERC20 balance → verify balance preserved → approve + withdraw successfully
- Migrate CEA with pending isExecuted entries → verify replay protection intact

---

### 6.4 Replay Attack

**Threat:** Same subTxId executed twice → double spend or double migration

**Impact:** High - unauthorized execution or wasted gas

**Mitigation:**
- **Existing protection (line 108):**
  ```solidity
  if (isExecuted[subTxId]) revert CEAErrors.PayloadExecuted();
  isExecuted[subTxId] = true;
  ```
- Executed BEFORE routing to migration
- Preserved across migration (storage not touched)

**Test coverage:**
- Execute migration with subTxId = keccak256("migration1")
- Attempt to execute same subTxId again → expect `PayloadExecuted` revert
- Verify isExecuted mapping preserved after migration

---

### 6.5 Unauthorized Migration

**Threat:** Attacker triggers migration without authorization

**Attack vectors:**
1. Non-Vault caller
2. Wrong originCaller
3. Unauthorized UEA

**Mitigation:**
- **Vault enforcement (line 52):**
  ```solidity
  modifier onlyVault() {
      if (msg.sender != VAULT) revert CEAErrors.NotVault();
      _;
  }
  ```

- **UEA authorization (line 109):**
  ```solidity
  if (originCaller != UEA) revert CEAErrors.InvalidUEA();
  ```

- **Cross-chain authorization:**
  - Migration transaction must originate from correct UEA on Push Chain
  - User must sign migration payload with their external key
  - TSS/Relayer verifies signature before relay

**Test coverage:**
- Attempt migration from non-Vault address → expect `NotVault` revert
- Attempt migration with wrong originCaller → expect `InvalidUEA` revert
- Attempt migration with wrong UEA → expect `InvalidUEA` revert

---

### 6.6 Initialization Issues

**Threat:** CEA v2 requires new state initialization → undefined behavior

**Impact:** Medium to High - depends on missing initialization

**Mitigation:**
1. **Storage-compatible upgrades:**
   - CEA v2 should use default values for new storage
   - Example: `mapping(address => bool) public newFeature;` defaults to `false`

2. **No post-migration initialization:**
   - Migration only writes implementation slot
   - No additional `initialize()` call
   - CEA v2 MUST work with existing state

3. **Conditional logic in CEA v2:**
   ```solidity
   // If new state needed, use lazy initialization
   if (newStateVariable == 0) {
       newStateVariable = computeDefaultValue();
   }
   ```

**Test coverage:**
- Deploy CEA v1 → use normally → migrate to v2 → verify v2 functions work
- Deploy CEA v1 with zero balances → migrate to v2 → verify no reverts
- Deploy CEA v1 with many executions → migrate to v2 → verify nonce handling

---

### 6.7 Batched Migration Attack

**Threat:** Attacker includes migration selector in multi-step batch to bypass constraints

**Example payload:**
```javascript
[
  { to: externalContract, value: 100, data: maliciousCall },
  { to: ceaProxy, value: 0, data: MIGRATION_SELECTOR }  // Sneaky migration
]
```

**Impact:** High - could trick validation or execute unauthorized actions alongside migration

**Mitigation:**
- **Early detection in `_handleExecution()` (line 168):**
  ```solidity
  if (calls.length == 1 && isMigration(calls[0].data)) {
      _handleMigration(calls[0]);  // Standalone path
      return;
  }
  ```

- **Loop validation in `_handleMulticall()` (line 207):**
  ```solidity
  if (isMigration(calls[i].data)) {
      revert CEAErrors.InvalidCall();  // Block in batches
  }
  ```

**Result:** Migration can ONLY execute standalone. Any batch containing migration selector reverts.

**Test coverage:**
- Submit [normalCall, migrationCall] → expect `InvalidCall` revert
- Submit [migrationCall, normalCall] → expect `InvalidCall` revert
- Submit [migrationCall] → expect success

---

### 6.8 Wrong Target Attack

**Threat:** Attacker sets `call.to` to wrong address in migration payload

**Example:**
```javascript
{ to: attackerContract, value: 0, data: MIGRATION_SELECTOR }
```

**Impact:** High - could trick CEA into delegatecalling to malicious contract

**Mitigation:**
- **Self-target enforcement in `_handleMigration()`:**
  ```solidity
  if (call.to != address(this)) {
      revert CEAErrors.InvalidTarget();
  }
  ```

**Test coverage:**
- Submit migration with `to = externalContract` → expect `InvalidTarget` revert
- Submit migration with `to = address(0)` → expect `InvalidTarget` revert
- Submit migration with `to = ceaProxy` → expect success

---

### 6.9 Value Transfer Attack

**Threat:** Attacker includes native value in migration call

**Example:**
```javascript
{ to: ceaProxy, value: 1 ether, data: MIGRATION_SELECTOR }
```

**Impact:** Medium - unclear what happens to sent value, potential loss or locked funds

**Mitigation:**
- **Zero value enforcement in `_handleMigration()`:**
  ```solidity
  if (call.value != 0) {
      revert CEAErrors.InvalidInput();
  }
  ```

**Test coverage:**
- Submit migration with `value = 1 wei` → expect `InvalidInput` revert
- Submit migration with `value = 0` → expect success

---

### 6.10 Unset Migration Contract

**Threat:** `factory.CEA_MIGRATION_CONTRACT()` returns `address(0)`

**Impact:** High - migration impossible, blocks legitimate upgrades

**Mitigation:**
- **Zero address check in `_handleMigration()`:**
  ```solidity
  if (migrationContract == address(0)) {
      revert CEAErrors.InvalidCall();
  }
  ```

- **Governance responsibility:**
  - Owner MUST call `setCEAMigrationContract()` before users can migrate
  - Can be set after deploying CEA v2 and CEAMigration

**Test coverage:**
- Call `setCEAMigrationContract(address(0))` → expect `ZeroAddress` revert
- Attempt migration before factory.CEA_MIGRATION_CONTRACT() is set → expect `InvalidCall` revert

---

## 7. Test Plan

### 7.1 Unit Tests: CEAMigration.sol

**File:** `test/tests_ceaMigration/CEAMigration.t.sol`

| Test                                   | Description                   | Expected Result                                      |
| -------------------------------------- | ----------------------------- | ---------------------------------------------------- |
| `test_Constructor_ValidImplementation` | Deploy with valid CEA v2      | Success, immutables set correctly                    |
| `test_Constructor_RevertZeroAddress`   | Deploy with address(0)        | Revert with `InvalidInput`                           |
| `test_Constructor_RevertEOA`           | Deploy with EOA address       | Revert with `InvalidInput`                           |
| `test_migrateCEA_DirectCall`           | Call `migrateCEA()` directly  | Revert with `Unauthorized`                           |
| `test_migrateCEA_Delegatecall`         | Delegatecall from mock proxy  | Success, slot written, event emitted                 |
| `test_migrateCEA_SlotWrite`            | Verify CEA_LOGIC_SLOT updated | Slot contains new implementation address             |
| `test_migrateCEA_EventEmission`        | Check event emission          | `ImplementationUpdated` emitted with correct address |
| `test_hasCode_Contract`                | Check contract address        | Returns true                                         |
| `test_hasCode_EOA`                     | Check EOA address             | Returns false                                        |

---

### 7.2 Unit Tests: CEAFactory.sol

**File:** `test/tests_cea/CEAFactory.t.sol` (add to existing test file)

| Test                                       | Description                                | Expected Result                                      |
| ------------------------------------------ | ------------------------------------------ | ---------------------------------------------------- |
| `test_setCEAMigrationContract_Success`     | Owner sets migration contract              | Success, event emitted                               |
| `test_setCEAMigrationContract_ZeroAddress` | Set to address(0)                          | Revert with `ZeroAddress`                            |
| `test_setCEAMigrationContract_NonOwner`    | Non-owner attempts to set                  | Revert with `OwnableUnauthorizedAccount`             |
| `test_setCEAMigrationContract_Event`       | Verify event emission                      | `CEAMigrationContractUpdated` with old/new addresses |
| `test_initialize_WithMigrationContract`    | Initialize factory with migration contract | Success (if optional param added)                    |
| `test_deployCEA_PassesFactoryAddress`      | Verify factory address passed to CEA       | CEA.factory == factory address                       |

---

### 7.3 Unit Tests: CEA.sol

**File:** `test/tests_cea/CEA_Migration.t.sol` (new test file)

| Test                                       | Description                          | Expected Result                |
| ------------------------------------------ | ------------------------------------ | ------------------------------ |
| `test_initializeCEA_WithFactory`           | Initialize with factory address      | Success, factory set           |
| `test_initializeCEA_ZeroFactory`           | Initialize with address(0) factory   | Revert with `ZeroAddress`      |
| `test_isMigration_True`                    | Check MIGRATION_SELECTOR             | Returns true                   |
| `test_isMigration_False`                   | Check other selector                 | Returns false                  |
| `test_isMigration_ShortData`               | Check data < 4 bytes                 | Returns false                  |
| `test_handleMigration_WrongTarget`         | Migration with `to != address(this)` | Revert with `InvalidTarget`    |
| `test_handleMigration_NonZeroValue`        | Migration with `value > 0`           | Revert with `InvalidInput`     |
| `test_handleMigration_NoMigrationContract` | Factory returns address(0)           | Revert with `InvalidCall`      |
| `test_handleMigration_DelegatecallFailure` | Migration contract reverts           | Revert bubbles up              |
| `test_handleMulticall_MigrationInBatch`    | Batch with migration selector        | Revert with `InvalidCall`      |
| `test_handleExecution_StandaloneMigration` | Single-element migration multicall   | Routes to `_handleMigration()` |

---

### 7.4 Integration Tests: End-to-End Migration

**File:** `test/tests_ceaMigration/CEAMigration_Integration.t.sol`

| Test                                        | Description                           | Expected Result                                |
| ------------------------------------------- | ------------------------------------- | ---------------------------------------------- |
| `test_FullMigrationFlow`                    | Complete Vault → CEA → Migration flow | Success, implementation upgraded               |
| `test_StatePersistence_UEA`                 | Verify UEA unchanged after migration  | `cea.UEA()` == original value                  |
| `test_StatePersistence_VAULT`               | Verify VAULT unchanged                | `cea.VAULT()` == original value                |
| `test_StatePersistence_UNIVERSAL_GATEWAY`   | Verify gateway unchanged              | `cea.UNIVERSAL_GATEWAY()` == original value    |
| `test_StatePersistence_isExecuted`          | Verify executed tx records preserved  | `cea.isExecuted(oldTxID)` == true              |
| `test_FundPersistence_Native`               | Native balance preserved              | Balance unchanged before/after                 |
| `test_FundPersistence_ERC20`                | ERC20 balance preserved               | Balance unchanged before/after                 |
| `test_PostMigration_Withdraw`               | Withdraw funds after migration        | `sendUniversalTxToUEA()` succeeds              |
| `test_PostMigration_Execute`                | Execute new tx after migration        | `executeUniversalTx()` succeeds with new logic |
| `test_PostMigration_Multicall`              | Multicall after migration             | Works normally                                 |
| `test_MultipleProxies_IndependentMigration` | Migrate multiple CEAs independently   | Each migrates without affecting others         |

---

### 7.5 Negative Tests: Revert Conditions

**File:** `test/tests_ceaMigration/CEAMigration_Negative.t.sol`

| Test                                | Description                                           | Expected Result                     |
| ----------------------------------- | ----------------------------------------------------- | ----------------------------------- |
| `testRevert_NotVault`               | Non-Vault calls executeUniversalTx with migration     | Revert with `NotVault`              |
| `testRevert_WrongOriginCaller`      | Wrong originCaller in migration payload               | Revert with `InvalidUEA`            |
| `testRevert_ReplayedTxID`           | Attempt to execute same migration subTxId twice       | Revert with `PayloadExecuted`       |
| `testRevert_WrongTarget`            | Migration with `to != address(this)`                  | Revert with `InvalidTarget`         |
| `testRevert_NonZeroValue`           | Migration with `value > 0`                            | Revert with `InvalidInput`          |
| `testRevert_BatchedMigration`       | Migration in multi-call batch                         | Revert with `InvalidCall`           |
| `testRevert_UnsetMigrationContract` | Migration before factory.CEA_MIGRATION_CONTRACT() set | Revert with `InvalidCall`           |
| `testRevert_InvalidImplementation`  | Migration contract points to invalid address          | Revert (caught at migration deploy) |

---

### 7.6 Edge Cases

**File:** `test/tests_ceaMigration/CEAMigration_EdgeCases.t.sol`

| Test                                | Description                                   | Expected Result                           |
| ----------------------------------- | --------------------------------------------- | ----------------------------------------- |
| `test_MigrationV1toV2toV3`          | Chain migrations: v1 → v2 → v3                | All succeed, state preserved through both |
| `test_MigrationAfterManyExecutions` | Migrate CEA with 1000+ executed txs           | Success, all isExecuted entries preserved |
| `test_MigrationWithMaxBalances`     | Migrate CEA holding max uint256 token amounts | Balances preserved                        |
| `test_MigrationEmptyState`          | Migrate brand new CEA (no executions yet)     | Success, ready for use                    |
| `test_MigrationImmediateReuse`      | Execute normal tx immediately after migration | Works with new implementation             |
| `test_MigrationDuringHighLoad`      | Migrate while other CEAs executing            | No interference, isolated state           |

---

### 7.7 Fuzz Testing

**File:** `test/tests_ceaMigration/CEAMigration_Fuzz.t.sol`

```solidity
/// @notice Fuzz test: Migration preserves all state regardless of prior execution count
function testFuzz_MigrationPreservesState(uint256 executionCount) public {
    executionCount = bound(executionCount, 0, 100);

    // Execute random txs
    for (uint256 i = 0; i < executionCount; i++) {
        bytes32 subTxId = keccak256(abi.encode(i));
        // ... execute normal tx
    }

    // Record state
    address ueaBefore = cea.UEA();
    address vaultBefore = cea.VAULT();

    // Execute migration
    // ...

    // Verify state unchanged
    assertEq(cea.UEA(), ueaBefore);
    assertEq(cea.VAULT(), vaultBefore);
}

/// @notice Fuzz test: Migration with arbitrary balances
function testFuzz_MigrationWithBalances(uint256 nativeBalance, uint256 erc20Balance) public {
    nativeBalance = bound(nativeBalance, 0, 100 ether);
    erc20Balance = bound(erc20Balance, 0, type(uint256).max / 2);

    // Fund CEA
    vm.deal(address(cea), nativeBalance);
    token.mint(address(cea), erc20Balance);

    // Execute migration
    // ...

    // Verify balances unchanged
    assertEq(address(cea).balance, nativeBalance);
    assertEq(token.balanceOf(address(cea)), erc20Balance);
}
```

---

### 7.8 Coverage Target

**Minimum coverage:** 95% for migration-related code paths

**Critical paths requiring 100% coverage:**
- `CEA._handleMigration()` - all branches
- `CEA._handleExecution()` - migration routing
- `CEAMigration.migrateCEA()` - full execution
- Migration validation constraints (target, value, contract checks)

**Tools:**
```bash
forge coverage --report lcov
genhtml lcov.info --output-directory coverage
```

---

## 8. Deployment & Rollout Plan

### 8.1 Pre-Deployment Checklist

**Code validation:**
- [ ] All contract modifications implemented per spec
- [ ] All interfaces updated (ICEA, ICEAFactory)
- [ ] Storage slot constants match exactly (CEA_LOGIC_SLOT)
- [ ] All safety constraints enforced in code

**CEA v2 implementation:**
- [ ] CEA v2 contract written and reviewed
- [ ] Storage layout documented and compatible with v1
- [ ] No new initialization required (or lazy initialization implemented)
- [ ] All v1 functions still work (backwards compatibility)

**Testing:**
- [ ] All unit tests passing (CEA, CEAFactory, CEAMigration)
- [ ] All integration tests passing (end-to-end flow)
- [ ] All negative tests passing (revert conditions)
- [ ] All edge case tests passing
- [ ] Fuzz tests run with 10,000+ runs
- [ ] Coverage > 95% on migration paths

**Documentation:**
- [ ] Migration flow documented (this file)
- [ ] SDK integration guide written
- [ ] User-facing migration guide written
- [ ] Audit report completed and mitigations implemented

---

### 8.2 Deployment Sequence

**Testnet deployment:**

1. Deploy CEA v2 implementation (new contract)
   ```bash
   forge script scripts/deployCEAv2.s.sol --rpc-url $TESTNET_RPC --broadcast
   ```
   - Record address: `CEA_V2_IMPLEMENTATION`

2. Deploy CEAMigration contract (points to CEA v2)
   ```bash
   forge script scripts/deployCEAMigration.s.sol \
     --sig "run(address)" $CEA_V2_IMPLEMENTATION \
     --rpc-url $TESTNET_RPC --broadcast
   ```
   - Record address: `CEA_MIGRATION_CONTRACT`

3. Set migration contract in CEAFactory (governance)
   ```bash
   cast send $CEA_FACTORY \
     "setCEAMigrationContract(address)" $CEA_MIGRATION_CONTRACT \
     --rpc-url $TESTNET_RPC --private-key $OWNER_KEY
   ```

4. Verify factory configuration
   ```bash
   cast call $CEA_FACTORY "CEA_MIGRATION_CONTRACT()" --rpc-url $TESTNET_RPC
   # Should return $CEA_MIGRATION_CONTRACT
   ```

5. Test migration on testnet CEA
   - User signs migration payload on Push Chain testnet
   - Relayer picks up and submits to external chain testnet
   - Verify migration succeeds
   - Verify state and funds preserved
   - Verify post-migration execution works

6. Monitor for 48 hours, gather metrics

**Mainnet deployment:**

1. Review testnet results and metrics
2. Conduct final security review
3. Repeat deployment sequence on mainnet (same steps as testnet)
4. Announce migration availability to users
5. Monitor first migrations closely

---

### 8.3 Migration Contract Validation

**Before setting in factory:**
```bash
# Verify CEAMigration constructor set correctly
cast call $CEA_MIGRATION_CONTRACT "CEA_IMPLEMENTATION()" --rpc-url $RPC
# Should return $CEA_V2_IMPLEMENTATION

# Verify CEA v2 has code
cast code $CEA_V2_IMPLEMENTATION --rpc-url $RPC
# Should return non-empty bytecode

# Verify storage slot constant matches
cast call $CEA_MIGRATION_CONTRACT "hasCode(address)" $CEA_V2_IMPLEMENTATION --rpc-url $RPC
# Should return true (0x0000...0001)
```

---

### 8.4 Rollback Plan

**If critical issue discovered:**

1. **Before migration contract is set:**
   - DO NOT call `setCEAMigrationContract()`
   - Fix issue, redeploy, re-test

2. **After migration contract is set but no migrations executed:**
   - Governance calls `setCEAMigrationContract(address(0))` (disabled)
   - Fix issue, redeploy CEA v2 and migration contract
   - Re-set migration contract after fixes verified

3. **After migrations executed:**
   - **Critical**: Cannot rollback already-migrated CEAs (implementation changed)
   - Options:
     - Deploy CEA v2.1 with fixes
     - Deploy new migration contract (v2 → v2.1)
     - Announce second migration to users
   - Prevention: Thorough testing and gradual rollout

**Gradual rollout strategy:**
- Week 1: Enable on testnet only
- Week 2: Enable on mainnet, announce to 10% of users
- Week 3: Monitor metrics, expand to 50% if stable
- Week 4: Full availability

---

## 9. Go/No-Go Checklist

### Pre-Implementation

- [ ] CEA v2 storage layout designed and documented
- [ ] CEA v2 is storage-compatible with v1 (no collisions)
- [ ] No post-migration initialization required (or lazy init designed)
- [ ] Storage slot constants verified identical:
  ```
  CEAProxy.CEA_LOGIC_SLOT == CEAMigration.CEA_LOGIC_SLOT
  == 0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813
  ```

### Code Validation

- [ ] CEA.sol: Factory reference added
- [ ] CEA.sol: `isMigration()` helper implemented
- [ ] CEA.sol: `_handleMigration()` handler implemented with all safety checks
- [ ] CEA.sol: `_handleExecution()` routes standalone migration correctly
- [ ] CEA.sol: `_handleMulticall()` rejects batched migration
- [ ] CEAFactory.sol: `CEA_MIGRATION_CONTRACT` state variable added
- [ ] CEAFactory.sol: `setCEAMigrationContract()` setter implemented
- [ ] CEAFactory.sol: `deployCEA()` passes factory address to CEA
- [ ] ICEA.sol: Interface updated for new `initializeCEA()` signature
- [ ] ICEAFactory.sol: Interface updated with `CEA_MIGRATION_CONTRACT()` view

### Safety Constraints Enforced

- [ ] Migration must be standalone (single-element multicall)
- [ ] Migration must target self (`call.to == address(this)`)
- [ ] Migration must have zero value (`call.value == 0`)
- [ ] Migration contract must be set in factory (!= address(0))
- [ ] Migration contract validates implementation `hasCode()`
- [ ] Delegatecall-only enforcement via `onlyDelegateCall()` modifier
- [ ] Batched migration rejected in `_handleMulticall()` loop

### Test Coverage

- [ ] All CEAMigration.sol unit tests passing (9 tests)
- [ ] All CEAFactory.sol migration tests passing (6 tests)
- [ ] All CEA.sol migration tests passing (11 tests)
- [ ] All integration tests passing (12 tests)
- [ ] All negative tests passing (8 tests)
- [ ] All edge case tests passing (6 tests)
- [ ] Fuzz tests run with 10,000+ runs (2 fuzz tests)
- [ ] **Total: 54+ tests covering migration flow**
- [ ] Code coverage > 95% on migration paths
- [ ] Coverage report reviewed, critical branches all covered

### State & Fund Preservation

- [ ] Test: UEA address preserved after migration
- [ ] Test: VAULT address preserved after migration
- [ ] Test: UNIVERSAL_GATEWAY address preserved after migration
- [ ] Test: isExecuted mappings preserved after migration
- [ ] Test: Native token balance preserved after migration
- [ ] Test: ERC20 token balance preserved after migration
- [ ] Test: Post-migration withdrawal works (sendUniversalTxToUEA)
- [ ] Test: Post-migration execution works (executeUniversalTx)

### Security Validation

- [ ] Storage collision risk analysis completed
- [ ] Proxy bricking attack vectors blocked
- [ ] Delegatecall safety verified (onlyDelegateCall enforced)
- [ ] Authorization chain validated (Vault → originCaller → UEA)
- [ ] Replay protection verified (isExecuted preserved)
- [ ] Batched migration attack prevented
- [ ] Wrong target attack prevented
- [ ] Value transfer attack prevented
- [ ] Unset migration contract handled gracefully

### Deployment Readiness

- [ ] CEA v2 implementation deployed and verified on testnet
- [ ] CEAMigration contract deployed and verified on testnet
- [ ] Factory.setCEAMigrationContract() called on testnet
- [ ] Test migration executed successfully on testnet
- [ ] 48-hour monitoring period completed on testnet
- [ ] No critical issues found during testnet monitoring
- [ ] Deployment scripts reviewed and tested
- [ ] Rollback plan documented and understood

### Documentation

- [ ] This migration flow document completed and reviewed
- [ ] SDK integration guide written
- [ ] User-facing migration guide written
- [ ] API documentation updated
- [ ] Code comments added to all new functions
- [ ] NatSpec complete for all new functions

### Audit & External Review

- [ ] Internal security review completed
- [ ] External audit report received (if applicable)
- [ ] All audit findings addressed or mitigated
- [ ] Governance approval obtained for migration contract
- [ ] Multisig signers briefed on migration flow

---

## 10. Appendix

### 10.1 Storage Layout Compatibility

**CEA v1 Storage Layout:**
```
Slot 0: address UEA
Slot 1: address VAULT
Slot 2: address UNIVERSAL_GATEWAY
Slot 3: bool _initialized
Slot 4: uint256 _reentrancyStatus (from ReentrancyGuard)
Slot 5: mapping(bytes32 => bool) isExecuted
Slot 6: address factory (NEW in v1.1)
```

**CEA v2 MUST:**
- Keep slots 0-6 unchanged
- Add new storage starting at slot 7+

**Example CEA v2 storage addition:**
```solidity
contract CEA_v2 is CEA {
    // Existing state (slots 0-6) inherited from CEA

    // NEW STATE STARTS AT SLOT 7
    mapping(address => uint256) public newFeature;  // Slot 7
    uint256 public newCounter;                      // Slot 8
}
```

---

### 10.2 Reference: UEA Migration Implementation

**UEA_EVM._handleMigration() (lines 186-210):**
```solidity
function _handleMigration(UniversalPayload memory payload)
    internal
    returns (bool success, bytes memory returnData)
{
    // Validate self-targeted
    if (payload.to != address(this)) {
        revert Errors.InvalidCall();
    }

    // Validate zero value
    if (payload.value != 0) {
        revert Errors.InvalidCall();
    }

    // Fetch migration contract from factory
    address migrationContract = factory.UEA_MIGRATION_CONTRACT();

    // Validate migration contract set
    if (migrationContract == address(0)) {
        revert Errors.InvalidCall();
    }

    // Prepare delegatecall
    bytes memory migrateCallData = abi.encodeWithSignature("migrateUEAEVM()");

    // Execute delegatecall
    (success, returnData) = migrationContract.delegatecall(migrateCallData);
}
```

**CEA implementation follows this pattern exactly**, with only naming differences:
- `UniversalPayload` → `Multicall` (different payload structure)
- `migrateUEAEVM()` → `migrateCEA()` (different function name)

---

### 10.3 Selector Constants

```solidity
// From Types.sol (line 43-46)
bytes4 constant MULTICALL_SELECTOR = bytes4(keccak256("UEA_MULTICALL"));
// 0xc25b8d90

bytes4 constant MIGRATION_SELECTOR = bytes4(keccak256("UEA_MIGRATION"));
// 0xb0c47dc5
```

**Usage in payloads:**
```javascript
// Normal multicall
payload = 0xc25b8d90 + encode([call1, call2, call3])

// Migration multicall
payload = 0xc25b8d90 + encode([{to: ceaProxy, value: 0, data: 0xb0c47dc5}])
           ^             ^
           |             |
    MULTICALL_SELECTOR  MIGRATION_SELECTOR in call.data
```

---

### 10.4 Event Definitions

**CEAMigration (line 47):**
```solidity
event ImplementationUpdated(address indexed implementation);
```

**CEAFactory (new):**
```solidity
event CEAMigrationContractUpdated(address indexed oldContract, address indexed newContract);
```

**CEA (existing, line 219):**
```solidity
event UniversalTxExecuted(
    bytes32 indexed subTxId,
    bytes32 indexed universalTxID,
    address indexed originCaller,
    address to,
    bytes data
);
```

**Emitted during migration:**
1. `CEAMigration.ImplementationUpdated(ceaV2Address)` - inside delegatecall
2. `CEA.UniversalTxExecuted(subTxId, universalTxID, UEA, ceaProxy, migrationSelector)` - in _handleExecution

---

### 10.5 Gas Estimates

**Migration transaction:**
- Base execution: ~100k gas
- Delegatecall: ~5k gas
- Storage write (SSTORE): ~20k gas (warm slot) or ~22.1k gas (cold slot)
- Event emissions: ~2k gas each
- **Total estimated:** ~130k-150k gas

**Normal multicall (for comparison):**
- 2-call batch: ~80k-120k gas (depends on call complexity)

**Implication:** Migration costs slightly more than normal multicall, but well within reasonable limits.

---

### 10.6 Comparison: UEA vs CEA Migration

| Aspect                       | UEA Migration                      | CEA Migration                                    |
| ---------------------------- | ---------------------------------- | ------------------------------------------------ |
| **Initiator**                | User (signs UniversalPayload)      | User (via UEA on Push Chain)                     |
| **Entry point**              | `UEA_EVM.executePayload()`         | `CEA.executeUniversalTx()`                       |
| **Caller**                   | Direct call (or UE_MODULE)         | Vault only                                       |
| **Authorization**            | Signature verification             | originCaller == UEA                              |
| **Payload format**           | `UniversalPayload` struct          | `Multicall[]` array                              |
| **Selector detection**       | `isMigration(payload.data)`        | `isMigration(call.data)` inside multicall        |
| **Migration contract fetch** | `factory.UEA_MIGRATION_CONTRACT()` | `factory.CEA_MIGRATION_CONTRACT()`               |
| **Delegatecall target**      | `migrateUEAEVM()`                  | `migrateCEA()`                                   |
| **Storage slot**             | `UEA_LOGIC_SLOT` (0x868a771a...)   | `CEA_LOGIC_SLOT` (0x8b2ae8ee...)                 |
| **Cross-chain**              | No (UEA lives on Push Chain)       | Yes (CEA on external chain, initiated from Push) |

---

### 10.7 Migration Payload Examples

**TypeScript (SDK side):**
```typescript
import { ethers } from 'ethers';

// Constants
const MULTICALL_SELECTOR = ethers.utils.id("UEA_MULTICALL").slice(0, 10);
const MIGRATION_SELECTOR = ethers.utils.id("UEA_MIGRATION").slice(0, 10);

// Build migration payload
function buildMigrationPayload(ceaProxyAddress: string): string {
    // Single-element multicall targeting self with migration selector
    const migrationCall = {
        to: ceaProxyAddress,
        value: 0,
        data: MIGRATION_SELECTOR
    };

    // Encode as Multicall[]
    const multicallArray = [migrationCall];
    const encodedCalls = ethers.utils.defaultAbiCoder.encode(
        ['tuple(address to, uint256 value, bytes data)[]'],
        [multicallArray]
    );

    // Prefix with MULTICALL_SELECTOR
    return ethers.utils.concat([MULTICALL_SELECTOR, encodedCalls]);
}

// Usage
const ceaProxy = "0x1234...";
const payload = buildMigrationPayload(ceaProxy);

// Submit to UEA on Push Chain
await ueaContract.submitOutboundTransaction(
    ceaProxy,  // target (CEA on external chain)
    0,         // value
    payload,   // migration payload
    // ... other params
);
```

**Solidity (test helper):**
```solidity
function buildMigrationPayload(address ceaProxy) internal pure returns (bytes memory) {
    Multicall[] memory calls = new Multicall[](1);
    calls[0] = Multicall({
        to: ceaProxy,
        value: 0,
        data: abi.encodePacked(MIGRATION_SELECTOR)
    });

    return abi.encodePacked(
        MULTICALL_SELECTOR,
        abi.encode(calls)
    );
}
```

---

### 10.8 Post-Migration Verification Checklist

After executing migration on a CEA:

```bash
# 1. Verify implementation updated
cast call $CEA_PROXY "getImplementation()" --rpc-url $RPC
# Should return $CEA_V2_IMPLEMENTATION

# 2. Verify state preserved
cast call $CEA_PROXY "UEA()" --rpc-url $RPC
# Should return original UEA address

cast call $CEA_PROXY "VAULT()" --rpc-url $RPC
# Should return original VAULT address

cast call $CEA_PROXY "UNIVERSAL_GATEWAY()" --rpc-url $RPC
# Should return original UNIVERSAL_GATEWAY address

# 3. Verify balances preserved
cast balance $CEA_PROXY --rpc-url $RPC
# Should match pre-migration balance

cast call $ERC20_TOKEN "balanceOf(address)" $CEA_PROXY --rpc-url $RPC
# Should match pre-migration balance

# 4. Verify migration transaction marked executed
cast call $CEA_PROXY "isExecuted(bytes32)" $MIGRATION_TX_ID --rpc-url $RPC
# Should return true (0x00...01)

# 5. Test post-migration execution
# Submit a normal transaction through Vault -> CEA
# Should succeed with new implementation logic
```

---

## 11. Conclusion

This document provides a comprehensive blueprint for implementing CEA migration functionality that:

1. ✅ **Reuses proven UEA pattern** - leverages battle-tested migration architecture
2. ✅ **Maintains security invariants** - all authorization and validation constraints preserved
3. ✅ **Preserves state and funds** - delegatecall ensures no data loss
4. ✅ **Prevents common attacks** - extensive threat model and mitigations
5. ✅ **Provides clear implementation path** - detailed contract specifications
6. ✅ **Includes comprehensive testing** - 54+ test cases covering all scenarios
7. ✅ **Documents deployment process** - step-by-step rollout plan

**Key Success Factors:**
- CEAMigration.sol is already complete and correct
- Changes needed are localized (CEA.sol and CEAFactory.sol)
- Pattern is proven safe in production (UEA migration)
- Safety constraints prevent all identified attack vectors
- Comprehensive test coverage catches edge cases

**Next Steps:**
1. Review and approve this document
2. Implement contract changes per Section 4
3. Write test suite per Section 7
4. Deploy to testnet per Section 8
5. Execute checklist per Section 9
6. Deploy to mainnet

**Audit Focus Areas:**
- Storage layout compatibility (CEA v1 → CEA v2)
- Delegatecall safety (onlyDelegateCall enforcement)
- Authorization chain (Vault → originCaller → UEA)
- State preservation across migration
- Attack vector coverage (Section 6)

---

**Document Version:** 1.0
**Last Updated:** 2026-02-13
**Status:** Ready for Implementation
**Approvers:** [To be filled]
