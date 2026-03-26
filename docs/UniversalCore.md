# UniversalCore

## Contract Locations

- **UniversalCore**: [`src/UniversalCore.sol`](../src/UniversalCore.sol)
- **IUniversalCore Interface**: [`src/interfaces/IUniversalCore.sol`](../src/interfaces/IUniversalCore.sol)
- **PRC20**: [`src/PRC20.sol`](../src/PRC20.sol)
- **WPC (Wrapped PC)**: [`src/WPC.sol`](../src/WPC.sol)

---

## What is UniversalCore?

UniversalCore is the central system contract on Push Chain that coordinates cross-chain interoperability. It acts as Push Chain's in-house oracle for external chain state, manages PRC-20 token minting/burning, computes outbound gas fees, and handles the swap-and-burn mechanism that settles fees for outbound transactions.

Every cross-chain interaction on Push Chain flows through UniversalCore in some capacity: inbound deposits mint PRC-20 tokens through it, and outbound transactions query it for gas pricing and route fee settlement through it.

---

## Chain Meta Oracle

UniversalCore maintains an on-chain oracle of external chain state. For each supported chain (identified by CAIP-2 chain namespace, e.g. `"eip155:1"` for Ethereum mainnet), it stores:

| Storage mapping | Description |
|---|---|
| `gasPriceByChainNamespace` | Current gas price on the external chain |
| `chainHeightByChainNamespace` | Latest observed block height on the external chain |
| `timestampObservedAtByChainNamespace` | Timestamp when the observation was recorded |
| `gasTokenPRC20ByChainNamespace` | PRC-20 address of the chain's native gas token (e.g. pETH for Ethereum) |

The Universal Executor Module periodically calls `setChainMeta(chainNamespace, price, chainHeight, observedAt)` to push fresh external chain data on-chain, updating both `gasPriceByChainNamespace` and `chainHeightByChainNamespace` in a single call. This makes UniversalCore the single source of truth for external chain gas pricing and block height within Push Chain's contract layer.

This oracle data drives fee computation: when a user initiates an outbound transaction, the gateway queries `getOutboundTxGasAndFees(prc20, gasLimit)` which reads the stored gas price and multiplies it by the gas limit to produce the fee denominated in the destination chain's gas token.

```text
External chains                          Push Chain
-------------                           ----------
Ethereum  ---+
Base      ---+--> Validators/Relayers --> UE Module --> UniversalCore.setChainMeta()
Arbitrum  ---+                                              |
                                                            v
                                              gasPriceByChainNamespace["eip155:1"] = 25 gwei
                                              chainHeightByChainNamespace["eip155:1"] = 21400000
                                              timestampObservedAtByChainNamespace["eip155:1"] = 1741...
```

---

## Roles: UE Module vs Manager vs Admin vs Gateway vs Pauser

UniversalCore uses OpenZeppelin's `AccessControl` with distinct privilege levels. Each role has a specific trust boundary and operational scope.

### Universal Executor Module (`onlyUEModule`)

Address: `0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7` (protocol-level constant, immutable).

The UE Module is a protocol-level system address that executes on behalf of the Push Chain validator set. It is the only caller allowed to mint PRC-20 tokens for inbound deposits.

| Function | Purpose |
|---|---|
| `depositPRC20Token(prc20, amount, recipient)` | Mint PRC-20 tokens to a recipient address on inbound |
| `depositPRC20WithAutoSwap(prc20, amount, recipient, fee, minPCOut, deadline)` | Mint PRC-20 and swap to native PC in one step |
| `setChainMeta(chainNamespace, price, chainHeight, observedAt)` | Update gas price and block height oracle data for an external chain |
| `refundUnusedGas(recipient, amount)` | Refund unused gas to a recipient after execution |

### Manager Role (`MANAGER_ROLE`)

`keccak256("MANAGER_ROLE")` — can be granted to addresses by the admin.

Managers handle operational configuration that changes with external chain conditions:

| Function | Purpose |
|---|---|
| `setGasTokenPRC20(chainNamespace, prc20)` | Map a chain namespace to its gas token PRC-20 |
| `setGasPCPool(chainNamespace, gasToken, fee)` | Register a Uniswap V3 pool for PC/gas-token swaps |
| `setSupportedToken(prc20, supported)` | Mark a PRC-20 token as officially supported |
| `setBaseGasLimitByChain(chainNamespace, gasLimit)` | Set the minimum base gas limit for TSS execution on a chain |
| `setRescueFundsGasLimitByChain(chainNamespace, gasLimit)` | Set the fixed gas limit for rescue operations on a chain |
| `setProtocolFeeByToken(prc20, fee)` | Set the protocol fee (in native PC) for a PRC-20 token |

### Admin Role (`DEFAULT_ADMIN_ROLE`)

Granted to the deployer at initialization. Controls contract-level configuration and emergency operations.

| Function | Purpose |
|---|---|
| `setAutoSwapSupported(token, supported)` | Enable/disable auto-swap for a PRC-20 token |
| `setWPCContractAddress(addr)` | Update the Wrapped PC token address |
| `setUniswapV3Addresses(factory, swapRouter, quoter)` | Update Uniswap V3 infrastructure addresses |
| `setDefaultFeeTier(token, feeTier)` | Set default Uniswap V3 fee tier for a token |
| `setSlippageTolerance(token, tolerance)` | Set slippage tolerance in basis points |
| `setDefaultDeadlineMins(minutesValue)` | Set default swap deadline |
| `pause()` / `unpause()` | Emergency pause/unpause all deposit operations |

### Gateway (`universalGatewayPC`)

Not an OZ `AccessControl` role. `universalGatewayPC` is a mutable address stored in UniversalCore, checked via the `onlyGatewayPC` modifier. It is updated by the admin and gates the fee settlement function:

| Function | Purpose |
|---|---|
| `swapAndBurnGas(gasToken, vault, fee, gasFee, protocolFee, deadline, caller)` | Swap PC for gas token, burn gas fee, send protocol fee to vault |

### Pauser Role (`PAUSER_ROLE`)

`keccak256("PAUSER_ROLE")` — a guardian role restricted to pause/unpause operations only.

| Function | Purpose |
|---|---|
| `pause()` | Pause all deposit operations |
| `unpause()` | Resume deposit operations |

---

## Outbound Tx and Rescue Tx Fee Computation

### getOutboundTxGasAndFees

When a user initiates an outbound transaction (Push Chain to an external chain), the gateway needs to know how much fee to charge. It calls `getOutboundTxGasAndFees(prc20, gasLimitWithBaseLimit)`:

```
getOutboundTxGasAndFees(prc20, gasLimitWithBaseLimit)
    |
    |--> if gasLimitWithBaseLimit == 0:
    |       use baseGasLimitByChainNamespace[chainNamespace]
    |       (minimum gas for TSS execution on the source chain, set per chain by Manager)
    |--> if gasLimitWithBaseLimit != 0:
    |       caller must pass baseGasLimitByChainNamespace + their own additional gasLimit
    |       as the total value of gasLimitWithBaseLimit
    |
    |--> look up chainNamespace from prc20.SOURCE_CHAIN_NAMESPACE()
    |--> look up gasToken from gasTokenPRC20ByChainNamespace[chainNamespace]
    |--> look up gasPrice from gasPriceByChainNamespace[chainNamespace]
    |
    |--> gasFee = gasPrice * gasLimitWithBaseLimit   (denominated in gas token units)
    |--> protocolFee = protocolFeeByToken[prc20]     (flat fee in native PC)
    |
    '--> returns (gasToken, gasFee, protocolFee, gasPrice, chainNamespace)
```

The returned values are denominated in the destination chain's gas token (e.g. pETH for Ethereum). The gateway then uses these to drive the swap-and-burn settlement.

### getRescueFundsGasLimit

Used when rescuing stuck funds on a source chain. The gas limit for rescue operations is fixed per chain namespace (set by Manager via `setRescueFundsGasLimitByChain`) rather than caller-supplied, because rescue operations have a known, bounded execution cost.

```
getRescueFundsGasLimit(prc20)
    |
    |--> look up chainNamespace from prc20.SOURCE_CHAIN_NAMESPACE()
    |--> look up rescueGasLimit from rescueFundsGasLimitByChainNamespace[chainNamespace]
    |--> look up gasToken, gasPrice, protocolFee (same as outbound)
    |
    '--> returns (gasToken, gasFee, rescueGasLimit, gasPrice, chainNamespace)
```

---

## Swap-and-Burn: Gas Fee vs Protocol Fee

Outbound transactions require fee settlement. The user pays in native PC, which gets swapped to the destination chain's gas token PRC-20 via Uniswap V3. The resulting gas tokens are then split into two portions with different destinations:

### Gas Fee (burned)

The gas fee covers the cost of executing the transaction on the destination chain. This portion is **burned** — permanently removed from supply. It represents the real economic cost of destination-chain execution that the protocol absorbs on the user's behalf.

### Protocol Fee (sent to vault)

The protocol fee is a flat fee per PRC-20 token configured via `protocolFeeByToken` — a mapping in **UniversalCore** (`mapping(address => uint256)`), set per token by `MANAGER_ROLE` via `setProtocolFeeByToken(prc20, fee)`. It is always denominated in **native PC**.

`getOutboundTxGasAndFees` reads `protocolFeeByToken[prc20]` and returns it alongside `gasFee`. In practice, `UniversalGatewayPC` pays the protocol fee directly to VaultPC in native PC before calling `swapAndBurnGas`; only the `gasFee` burn happens inside `swapAndBurnGas`.

### Settlement Flow (`swapAndBurnGas`)

The UniversalGatewayPC (checked via `onlyGatewayPC`) calls `swapAndBurnGas` with native PC as `msg.value`:

```text
User pays native PC
        |
        v
UniversalGatewayPC
        |
        | calls swapAndBurnGas{value: pcAmount}(gasToken, vault, fee, gasFee, protocolFee, deadline, caller)
        v
UniversalCore
        |
        |--> 1. Wrap PC into WPC (deposit to IWPC)
        |--> 2. Approve Uniswap V3 router to spend WPC
        |--> 3. Swap WPC -> gasToken via exactOutputSingle
        |       (swap exactly gasFee worth of gas token)
        |
        |--> 4. BURN gasFee portion:    IPRC20(gasToken).burn(gasFee)
        |
        |--> 5. REFUND unused PC:       unwrap leftover WPC, send native PC back to caller
        |
        '--> emit SwapAndBurnGas(gasToken, vault, pcUsed, gasFee, protocolFee, fee, caller)
```

The swap uses `exactOutputSingle` — the caller specifies exactly how much gas token output is needed (`gasFee`), and any unused PC input is refunded directly to the caller address. This ensures users never overpay.

### Why burn vs transfer?

- **Burn (gas fee)**: The gas fee represents real execution cost on the destination chain. Burning the equivalent PRC-20 on Push Chain keeps the wrapped token supply in sync with actual external-chain liabilities. The protocol (via validators/TSS) covers the real gas on the destination side.
- **Transfer (protocol fee)**: The protocol fee is revenue. It is paid directly to VaultPC in native PC by `UniversalGatewayPC` before `swapAndBurnGas` is called, and can be used for protocol operations, validator rewards, or other governance-directed purposes.
