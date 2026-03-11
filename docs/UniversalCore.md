# UniversalCore

## Contract Locations

- **UniversalCore**: [`src/UniversalCore.sol`](../src/UniversalCore.sol)
- **IUniversalCore Interface**: [`src/Interfaces/IUniversalCore.sol`](../src/Interfaces/IUniversalCore.sol)
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

The Universal Executor Module periodically calls `setChainMeta(chainNamespace, price, chainHeight, observedAt)` to push fresh external chain data on-chain. This makes UniversalCore the single source of truth for external chain gas pricing within Push Chain's contract layer.

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

## Roles: UE Module vs Manager vs Admin

UniversalCore uses OpenZeppelin's `AccessControl` with three distinct privilege levels. Each role has a specific trust boundary and operational scope.

### Universal Executor Module (`onlyUEModule`)

Address: `0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7` (protocol-level constant, immutable).

The UE Module is a protocol-level system address that executes on behalf of the Push Chain validator set. It is the only caller allowed to mint PRC-20 tokens for inbound deposits.

| Function | Purpose |
|---|---|
| `depositPRC20Token(prc20, amount, target)` | Mint PRC-20 tokens to a target address on inbound |
| `depositPRC20WithAutoSwap(prc20, amount, target, fee, minPCOut, deadline)` | Mint PRC-20 and swap to native PC in one step |

The UE Module is also granted `MANAGER_ROLE` during initialization, giving it access to all manager functions as well.

### Manager Role (`MANAGER_ROLE`)

`keccak256("MANAGER_ROLE")` -- granted to the UE Module at initialization and can be granted to additional addresses by the admin.

Managers handle operational configuration that changes with external chain conditions:

| Function | Purpose |
|---|---|
| `setChainMeta(chainNamespace, price, chainHeight, observedAt)` | Update oracle data for an external chain |
| `setGasTokenPRC20(chainNamespace, prc20)` | Map a chain namespace to its gas token PRC-20 |
| `setGasPCPool(chainNamespace, gasToken, fee)` | Register a Uniswap V3 pool for PC/gas-token swaps |
| `setSupportedToken(prc20, supported)` | Mark a PRC-20 token as officially supported |

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
| `updateBaseGasLimit(gasLimit)` | Update the default gas limit for outbound transactions |
| `pause()` / `unpause()` | Emergency pause/unpause all deposit operations |

### Gateway Role (`GATEWAY_ROLE`)

`keccak256("GATEWAY_ROLE")` -- granted to the UniversalGatewayPC contract. Gates the fee settlement function:

| Function | Purpose |
|---|---|
| `swapAndBurnGas(gasToken, vault, fee, gasFee, protocolFee, deadline, caller)` | Swap PC for gas token, burn gas fee, send protocol fee to vault |

---

## Outbound Fee Computation

When a user initiates an outbound transaction (Push Chain to an external chain), the gateway needs to know how much fee to charge. It calls `getOutboundTxGasAndFees(prc20, gasLimit)`:

```
getOutboundTxGasAndFees(prc20, gasLimit)
    |
    |--> if gasLimit == 0, use BASE_GAS_LIMIT (default: 500,000)
    |--> look up chainNamespace from prc20.SOURCE_CHAIN_NAMESPACE()
    |--> look up gasToken from gasTokenPRC20ByChainNamespace[chainNamespace]
    |--> look up price from gasPriceByChainNamespace[chainNamespace]
    |
    |--> gasFee = price * gasLimit          (denominated in gas token units)
    |--> protocolFee = prc20.PC_PROTOCOL_FEE()  (flat fee set per PRC-20)
    |
    '--> returns (gasToken, gasFee, protocolFee, chainNamespace)
```

The returned values are denominated in the destination chain's gas token (e.g. pETH for Ethereum). The gateway then uses these to drive the swap-and-burn settlement.

---

## Swap-and-Burn: Gas Fee vs Protocol Fee

Outbound transactions require fee settlement. The user pays in native PC, which gets swapped to the destination chain's gas token PRC-20 via Uniswap V3. The resulting gas tokens are then split into two portions with different destinations:

### Gas Fee (burned)

The gas fee covers the cost of executing the transaction on the destination chain. This portion is **burned** -- permanently removed from supply. It represents the real economic cost of destination-chain execution that the protocol absorbs on the user's behalf.

### Protocol Fee (sent to vault)

The protocol fee is a flat fee per PRC-20 token (configured via `PRC20.PC_PROTOCOL_FEE()`). This portion is **transferred to the VaultPC address** as protocol revenue.

### Settlement Flow (`swapAndBurnGas`)

The UniversalGatewayPC (which holds `GATEWAY_ROLE`) calls `swapAndBurnGas` with native PC as `msg.value`:

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
        |       (swap exactly gasFee + protocolFee worth of gas token)
        |
        |--> 4. BURN gasFee portion:    IPRC20(gasToken).burn(gasFee)
        |--> 5. TRANSFER protocolFee:   IERC20(gasToken).safeTransfer(vault, protocolFee)
        |
        |--> 6. REFUND unused PC:       unwrap leftover WPC, send native PC back to caller
        |
        '--> emit SwapAndBurnGas(gasToken, vault, pcUsed, gasFee, protocolFee, fee, caller)
```

The swap uses `exactOutputSingle` -- the caller specifies exactly how much gas token output is needed (`gasFee + protocolFee`), and any unused PC input is refunded directly to the caller address. This ensures users never overpay.

### Why burn vs transfer?

- **Burn (gas fee)**: The gas fee represents real execution cost on the destination chain. Burning the equivalent PRC-20 on Push Chain keeps the wrapped token supply in sync with actual external-chain liabilities. The protocol (via validators/TSS) covers the real gas on the destination side.
- **Transfer (protocol fee)**: The protocol fee is revenue. It goes to VaultPC where it can be used for protocol operations, validator rewards, or other governance-directed purposes.
