# Smart Contract Tester Memory

## CEA Contract Testing Patterns

### Critical Bug Fixed: _handleSelfCalls Function (2026-02-06)
- **Location**: /Users/mdzaryabafser/Documents/blockchain_begins/all_about_eth/all_about_PUSH/push-chain/pc-core-contracts/synthetic-sprint/pc-core-contracts/pc-core-2nd/push-chain-core-contracts/src/CEA/CEA.sol:153-188
- **Root Cause**: Function selector validation was comparing against full `payload` instead of extracting just the first 4 bytes
- **Symptom**: All withdrawal tests failing with "CEA__InvalidPayload" error
- **Impact**: HIGH - Blocked all withdrawal flows from CEA to UEA
- **Fix Applied**:
  - Line 163: Changed from `if (payload != WITHDRAW_SELECTOR)` to `if (bytes4(payload) != WITHDRAW_SELECTOR)`
  - This ensures proper selector comparison using only the first 4 bytes
- **Security Analysis**:
  - No security vulnerability introduced by the fix
  - Fix aligns with Solidity best practices for function selector extraction
  - Preserves all access controls and validation logic
- **Test Coverage**: All 74 CEA tests pass after fix

### CEA Test Structure
- **Test File**: test/tests_cea/CEA.t.sol (74 tests total)
- **Test Categories**:
  1. Deployment & Initialization (7 tests)
  2. ExecuteUniversalTx Flow (25 tests) - ERC20 and Native token execution
  3. WithdrawFundsToUEA Flow (42 tests) - ERC20 and Native token withdrawals
- **Key Test Patterns**:
  - All CEA operations require vault authentication
  - ERC20 approval flow: reset to 0, then approve exact amount
  - Native token transfers must match msg.value
  - Transaction ID replay protection via `isExecuted` mapping
  - Invalid UEA address validation (must be on Push chain)

### Common Failure Patterns
- **Selector Comparison Issues**: Always use `bytes4(data)` to extract function selectors, never compare raw bytes
- **Approval Resets**: Tokens like USDT require resetting approval to 0 before setting new allowance
- **Access Control**: CEA functions are vault-gated; tests must use vm.prank(VAULT)
- **Payload Validation**: Self-calls (withdrawals) require minimum 36-byte payloads (4 bytes selector + 32 bytes address)

### Gas Optimization Notes
- Average gas for ERC20 withdrawal: ~1.5M gas
- Average gas for native withdrawal: ~450K gas
- Approval reset adds ~5K gas per transaction

### Security-Critical Areas
1. **Reentrancy Protection**: CEA uses checks-effects-interactions pattern
2. **Access Control**: All state-changing functions require msg.sender == VAULT
3. **Replay Protection**: txID tracking prevents duplicate executions
4. **Approval Safety**: Reset-to-zero pattern prevents approval frontrunning
5. **UEA Validation**: Ensures only valid UEA addresses receive withdrawals

## Testing Best Practices for This Codebase
- Always run full suite after fixes to catch regressions
- Use `-vvv` verbosity when debugging new failures
- CEA and UEA tests are independent; can run in parallel
- Factory tests cover deterministic deployment and address computation
- Migration tests verify proxy upgrade paths
