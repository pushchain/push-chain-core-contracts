# Deployment Guide

## CEAFactory Deployment (External EVM Chains)

This guide explains how to deploy the CEAFactory contract on external EVM chains (Ethereum, Base, Arbitrum, etc.).

### Prerequisites

1. **Foundry installed** - Ensure you have `forge` and `cast` installed
2. **RPC endpoint** - Get an RPC URL for your target chain
3. **Private key** - Have a funded deployer account
4. **Required addresses**:
   - Owner address (governance/admin)
   - Vault address (deployed on the same chain)
   - UniversalGateway address (deployed on the same chain)

### Deployment Steps

#### 1. Set Environment Variables

Create a `.env` file or export the following variables:

```bash
# Deployer private key
export PRIVATE_KEY=0x...

# RPC endpoint for target chain
export RPC_URL=https://...

# Contract addresses
export OWNER_ADDRESS=0x...
export VAULT_ADDRESS=0x...
export UNIVERSAL_GATEWAY_ADDRESS=0x...
```

**Example for Base Sepolia:**
```bash
export PRIVATE_KEY=0x1234567890abcdef...
export RPC_URL=https://sepolia.base.org
export OWNER_ADDRESS=0x778D3206374f8AC265728E18E3fE2Ae6b93E4ce4
export VAULT_ADDRESS=0x... # Vault deployed on Base Sepolia
export UNIVERSAL_GATEWAY_ADDRESS=0x... # UniversalGateway on Base Sepolia
```

#### 2. Run Deployment Script

**Dry run (simulation):**
```bash
forge script scripts/deployCEAFactory.s.sol:DeployCEAFactoryScript \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY
```

**Actual deployment:**
```bash
forge script scripts/deployCEAFactory.s.sol:DeployCEAFactoryScript \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify
```

**With verification (recommended):**
```bash
forge script scripts/deployCEAFactory.s.sol:DeployCEAFactoryScript \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_API_KEY
```

#### 3. Verify Deployment

The script will output deployed addresses:
```
=== Deployment Summary ===
CEA Implementation: 0x...
CEAProxy Implementation: 0x...
CEAFactory Implementation: 0x...
CEAFactory Proxy (use this): 0x...
```

**Save the CEAFactory Proxy address** - this is the main contract you'll interact with.

### Post-Deployment Verification

Verify the deployment using cast:

```bash
# Check owner
cast call $CEA_FACTORY_PROXY "owner()(address)" --rpc-url $RPC_URL

# Check vault
cast call $CEA_FACTORY_PROXY "VAULT()(address)" --rpc-url $RPC_URL

# Check implementations
cast call $CEA_FACTORY_PROXY "CEA_IMPLEMENTATION()(address)" --rpc-url $RPC_URL
cast call $CEA_FACTORY_PROXY "CEA_PROXY_IMPLEMENTATION()(address)" --rpc-url $RPC_URL

# Check universal gateway
cast call $CEA_FACTORY_PROXY "UNIVERSAL_GATEWAY()(address)" --rpc-url $RPC_URL
```

### Testing CEA Deployment

Once CEAFactory is deployed, you can test deploying a CEA:

```bash
# Deploy CEA for a specific UEA address
cast send $CEA_FACTORY_PROXY \
  "deployCEA(address)" \
  $UEA_ADDRESS \
  --rpc-url $RPC_URL \
  --private-key $VAULT_PRIVATE_KEY
```

**Note:** Only the Vault address can call `deployCEA`.

### Multi-Chain Deployment

To deploy on multiple chains, repeat the process for each chain:

1. **Ethereum Mainnet**
2. **Base**
3. **Arbitrum**
4. **Optimism**
5. **Polygon**
... etc.

Each chain will have its own:
- CEAFactory instance
- Vault instance
- UniversalGateway instance

### Upgrading CEAFactory

The CEAFactory is upgradeable. To upgrade:

```bash
# 1. Deploy new implementation
forge create src/CEA/CEAFactory.sol:CEAFactory \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY

# 2. Upgrade proxy (owner only)
cast send $CEA_FACTORY_PROXY \
  "upgradeTo(address)" \
  $NEW_IMPLEMENTATION \
  --rpc-url $RPC_URL \
  --private-key $OWNER_PRIVATE_KEY
```

### Updating Implementations

To update CEA or CEAProxy implementations (affects future deployments only):

```bash
# Update CEA implementation
cast send $CEA_FACTORY_PROXY \
  "setCEAImplementation(address)" \
  $NEW_CEA_IMPL \
  --rpc-url $RPC_URL \
  --private-key $OWNER_PRIVATE_KEY

# Update CEAProxy implementation
cast send $CEA_FACTORY_PROXY \
  "setCEAProxyImplementation(address)" \
  $NEW_CEA_PROXY_IMPL \
  --rpc-url $RPC_URL \
  --private-key $OWNER_PRIVATE_KEY
```

### Security Checklist

- [ ] Owner address is a multi-sig or secure governance contract
- [ ] Vault address is correct and deployed on the same chain
- [ ] UniversalGateway address is correct and deployed on the same chain
- [ ] All deployed contracts are verified on block explorer
- [ ] Test deployment on testnet before mainnet
- [ ] Deployer key is secured/rotated after deployment

### Common Issues

**Issue:** "Invalid owner address" error
- **Solution:** Make sure `OWNER_ADDRESS` environment variable is set and non-zero

**Issue:** Deployment fails with "insufficient funds"
- **Solution:** Ensure deployer account has enough native tokens for gas

**Issue:** Verification fails
- **Solution:** Add `--etherscan-api-key` and ensure correct network in foundry.toml

### Example foundry.toml Configuration

```toml
[rpc_endpoints]
base_sepolia = "https://sepolia.base.org"
ethereum = "https://eth.llamarpc.com"
arbitrum = "https://arb1.arbitrum.io/rpc"

[etherscan]
base_sepolia = { key = "${BASESCAN_API_KEY}", url = "https://api-sepolia.basescan.org/api" }
ethereum = { key = "${ETHERSCAN_API_KEY}" }
arbitrum = { key = "${ARBISCAN_API_KEY}" }
```
