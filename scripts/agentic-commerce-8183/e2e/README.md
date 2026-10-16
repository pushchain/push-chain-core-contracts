# Evaluator end-to-end test: Push Donut + Base Sepolia

Tests the 8183 kernel, the UniversalHook and the UniversalEvaluator against **live Push Read State**, on one job:

> "Allocate my 1000 USDC across Aave and Morpho."

Everything outside the evaluation is a stand-in: no AGW, no marketplace, no real Aave or Morpho. Two modes:

- **EOA mode** (default): two EOAs are the client and the provider; the reads measure the client's own address.
- **UEA mode** (`CLIENT_MODE=uea`): the client is the client key's **UEA** on Push, and the reads measure that
  UEA's **CEA** on Base Sepolia (§5a).

## 1 · What runs where

| Chain | Contract | Real or dummy | Deployed by |
|---|---|---|---|
| Push Donut (42101) | Read State `0x…c2`, UniversalCore `0x…C0` | **real**, live predeploys | — |
| Push Donut | AgenticCommerce (kernel, behind a proxy) | real code, fresh deploy | client key (`deploy-push`) |
| Push Donut | UniversalHook (proxy) + UniversalEvaluator | real code, fresh deploy via `UniversalEvaluatorDeploy` | client key |
| Push Donut | `E2EPaymentToken` (eUSD, open mint) | dummy | client key |
| Push Donut | `E2EAllowAll`: stands in for the AGW factory and the SmartSession engine (every account is a wallet, every rules set is live), so an EOA can be a client | dummy | client key |
| Base Sepolia (84532) | `E2EUSDC` (open mint), `E2EAavePool` + `E2EAToken` (1:1, no interest), `E2EMorphoVault` (plain ERC-4626) | dummy | client key (`deploy-base`) |
| Push Donut | UEA factory `0x…eA` | **real** (UEA mode) | — (`deployUEA` is open to anyone) |
| Base Sepolia | CEA factory `0x7e8C…C856` (`CEA_FACTORY()` of the gateway `0xFD4f…aC16`) | **real** (UEA mode), read only | — |

The evaluator must sit on Push: it reads through Read State, and Push's validators answer the reads from Base Sepolia.

## 2 · The job

The reads measure one account on Base Sepolia, `account`: the client's address in EOA mode, the UEA's CEA in UEA
mode (resolved by the `accounts` step).

| Read | Call on Base Sepolia | When |
|---|---|---|
| 0 | `aUSDC.balanceOf(account)` | POST: at the end block fixed at `submit` |
| 1 | `morphoVault.maxWithdraw(account)` (the position, in USDC) | POST |
| 2 | `aUSDC.balanceOf(account)` | PRE: at the block recorded at `fund` |
| 3 | `morphoVault.maxWithdraw(account)` | PRE |

| Check | Rule | Meaning |
|---|---|---|
| 0 | NUMBER `(r0 + r1) − (r2 + r3) ≥ 999.9e6` | at least 99.99% of the 1000 USDC arrived, across both venues |
| 1 | NUMBER `r0 − r2 > 0` | Aave grew |
| 2 | NUMBER `r1 − r3 > 0` | Morpho grew |

Logic: `ALL(check 0, check 1, check 2)`. Mutability `NONE`. Built in `E2EConfig.allocationSpec`.

Because it measures growth against PRE reads, repeated runs work: positions from earlier jobs are in the "before".

## 3 · The flow

| # | Chain | Signer | What happens | Then wait for |
|---|---|---|---|---|
| 1 | Base Sepolia | client | `deploy-base`: dummy USDC, Aave pool, aUSDC, Morpho vault | — |
| 2 | Push | client | `deploy-push`: payment token, allow-all, kernel; hook + evaluator (address predicted, hook initialised with it); hook whitelisted | Push's tracked Base Sepolia height ≥ the dummies' deploy block |
| 3 | Push, then Base Sepolia | relayer (UEA mode) | `accounts`: the job's client (the client key, or its UEA, deployed if missing) and the measured account (the client, or the UEA's CEA) | — |
| 4 | Push | client, provider | `open`: client `createJob` (description = the spec) → provider `setBudget` → client mints eUSD, approves, `prefund`s the reads (2 rounds) and `fund`s. Inside `fund` the hook binds the job and the evaluator freezes the spec and sends the 2 PRE reads at the tracked height | both PRE reads answered (`ready`) |
| 5 | Base Sepolia | provider | `allocate`: mints 1000 USDC, `supply` 600 to Aave and `deposit` 400 to Morpho, both for the measured account | Push's tracked height ≥ the allocation block |
| 6 | Push | provider | `submit`: the evaluator fixes the end blocks (tracked height now) and sends the 2 POST reads | the verdict |
| 7 | Push | — | the answer that decides applies it: PASS → `complete` (provider paid), FAIL → `reject` (client refunded) | — |

## 4 · Setup

Two keys, in `.env` at the repo root or the environment:

```
CLIENT_PRIVATE_KEY=0x…      # deploys everything, admins the kernel; the job's client (EOA mode) or the UEA's owner
PROVIDER_PRIVATE_KEY=0x…    # prices, allocates and submits
# optional
CLIENT_MODE=uea             # default eoa (§5a)
UEA_ORIGIN_CHAIN_ID=84532   # UEA mode: the origin chain of the client key's UEA (default Base Sepolia)
RELAYER_PRIVATE_KEY=0x…     # UEA mode: sends the UEA's signed payloads and pays for them (default: the client key)
PUSH_CHAIN_TESTNET_RPC_URL=https://evm.rpc-testnet-donut-node1.push.org/   # default
BASE_TESTNET_RPC_URL=https://sepolia.base.org                              # default
DEPLOYER_PRIVATE_KEY=0x…    # deploy-push from another key (it becomes the kernel admin)
```

Funding (measured on forks, with margin):

| | Push Donut (PC) | Base Sepolia (ETH) |
|---|---|---|
| client | 0.2 (the Push deploy is ~16M gas, ~0.035 PC at today's price; each job ~11M gas plus ~0.004 PC of prepaid reads) | 0.005 (dummies ~4.1M gas) |
| provider | 0.05 (`setBudget`, `submit`) | 0.005 (allocation) |

`run.sh check` prints both balances, the tracked height and its age, and whether Read State is paused.

## 5 · Run

```
scripts/agentic-commerce-8183/e2e/run.sh all
```

`all` = check → deploy (skipped if already deployed; `FRESH=1` redeploys) → accounts → open → wait-snapshot →
status → allocate → wait-height → submit → wait-verdict → status. Every step also runs on its own:
`run.sh check | deploy | deploy-base | deploy-push | accounts | open | wait-snapshot | allocate | wait-height |
submit | wait-verdict | status`.

A passing run ends with:

```
VERDICT: PASS (job Completed, provider paid)
  check 0: PASS  check 1: PASS  check 2: PASS
  read 0 aUSDC after  (POST) block <end>  | request EXECUTED | answer 600000000
  read 1 Morpho after (POST) block <end>  | request EXECUTED | answer 400000000
  read 2 aUSDC before (PRE)  block <fund> | request EXECUTED | answer 0
  read 3 Morpho before(PRE)  block <fund> | request EXECUTED | answer 0
```

State goes to `deployments/e2e-evaluator/` (gitignored), written by broadcasting runs only: `base-sepolia.json`,
`push.json`, `accounts.json`, `job.json`, `deploy-block`, `alloc-block`. `JOB_ID=<n>` points any step at another job;
`E2E_STATE_DIR=deployments/<dir>` keeps a separate set.

Dry run first if you like: without `--broadcast` forge only simulates against the live chains, signs nothing and
writes no state:

```
forge script scripts/agentic-commerce-8183/e2e/E2EBaseSepolia.s.sol:E2EBaseSepolia --sig 'deploy()' \
  --rpc-url https://sepolia.base.org
forge script scripts/agentic-commerce-8183/e2e/E2EPushDeploy.s.sol:E2EPushDeploy \
  --rpc-url https://evm.rpc-testnet-donut-node1.push.org/ --private-key "$CLIENT_PRIVATE_KEY"
```

## 5a · UEA + CEA mode

```
CLIENT_MODE=uea scripts/agentic-commerce-8183/e2e/run.sh all
```

- `accounts` finds the client key's UEA through Donut's UEA factory (origin `eip155:UEA_ORIGIN_CHAIN_ID`), deploys
  it if missing (`deployUEA` is open to anyone; the relayer sends it), and resolves its CEA on Base Sepolia with
  `CEAFactory.computeCEA(uea)`. The CEA doesn't need to exist: its balances read as 0 until something arrives.
- The client's calls are UEA payloads: `createJob`, then `approve` + `fund` as one multicall
  (`MULTICALL_SELECTOR ‖ abi.encode(Multicall[])`). The script reads `getUniversalPayloadHash` and `nonce` from the
  UEA, signs with the client key, and the relayer sends `executeUniversalTx(payload, signature)`, which anyone may do
  with the owner's signature. Minting eUSD to the UEA and `prefund` are open to anyone, so the relayer does them;
  unspent PC still goes back to the UEA.
- The provider deposits into Aave and Morpho for the CEA, and the evaluator reads the CEA's positions.
- The hook still uses the allow-all stand-in: a UEA isn't an AGW, so the real AGW factory would refuse it at `fund`.

### The CEA does the work: `ALLOCATE_VIA=outbound`

```
CLIENT_MODE=uea ALLOCATE_VIA=outbound scripts/agentic-commerce-8183/e2e/run.sh all
```

This replaces `allocate` with three steps:

1. `fund-account` (Base Sepolia): mint the client's eUSDC into its CEA (USDC the client already holds there).
2. `outbound` (Push): the UEA calls `UniversalGatewayPC(0x…C1).sendUniversalTxOutbound` with `recipient` = the
   CEA, `token` = pETH.base `0xc700…Fc21` (it names eip155:84532), `amount` 0, `gasLimit` `OUTBOUND_GAS_LIMIT`
   (default 1,000,000), and as `payload` the CEA's multicall: approve + supply to Aave, approve + deposit to Morpho,
   for itself. The UEA pays `OUTBOUND_PC` (default 1 PC) as `msg.value`. The gateway swaps what the gas costs
   (6.6 Mwei × gas limit in pETH; protocol fee 0) and refunds the rest, and the relayer tops the UEA up first if
   needed.
3. `wait-outbound`: Push's TSS has the Base Sepolia Vault `0xb4Ba…16CB` run `finalizeUniversalTx`, which deploys the
   CEA on first use and runs the multicall. The step waits for the CEA's positions to grow, then records the
   Vault's transaction and uses its block as the allocation block for `submit`.

Measured: deploying the CEA takes 222k gas and the multicall 188k (410k used live of the 1M limit). The outbound
reached Base Sepolia in about 50 s and cost the UEA about 0.12 PC net after refunds. In production the agent would
drive the client's account through the AGW and a session permission; here the client key signs the UEA's outbound.

## 6 · Scenarios

| Scenario | How | Expected |
|---|---|---|
| Pass | defaults (600 Aave + 400 Morpho) | Completed; provider gets the budget |
| Too little | `ALLOC_AAVE=500000000 ALLOC_MORPHO=400000000 run.sh allocate` | Rejected (check 0 FAIL) |
| One venue only | `ALLOC_AAVE=1000000000 ALLOC_MORPHO=0` | Rejected (check 2 FAIL) |
| Another target | `ALLOC_TOTAL=…` at `open` (6 decimals) | check 0 uses 99.99% of it |
| Slower finality | `MIN_CONFIRMATIONS=10` at `open` | reads wait for 10 Base Sepolia blocks |

Other knobs: `BUDGET` (eUSD, default 100e6), `JOB_EXPIRY` (s, default 7200), and the evaluator config at
`deploy-push` (`READ_TTL`, `CALLBACK_GAS_LIMIT`, `SNAPSHOT_CALLBACK_GAS_LIMIT`, `BUDGET_MULTIPLIER`,
`MAX_HEIGHT_AGE`, `MAX_CONFIRMATIONS`; defaults in `E2EPushDeploy`).

## 7 · When something stalls

| Symptom | Cause | Do |
|---|---|---|
| `wait-snapshot` times out | the PRE reads aren't answered: validators slow, or an error answer | `run.sh status`; for an unreadable answer `run.sh retry-snapshot` (provider) |
| `submit` refuses: height not reached | Push hasn't tracked the allocation block yet | `run.sh wait-height`, then `submit` |
| "the POST reads did not go out inside submit" | prepaid PC short, or Read State paused | `VALUE=<wei> run.sh send-reads` (provider) |
| `wait-verdict`: INCONCLUSIVE | a read came back unreadable | `run.sh send-reads` (re-sends it at the same block) |
| decided but not applied | the kernel refused it (e.g. paused) | `run.sh settle` |
| `open`: client has a live job | the hook allows one live job per client | finish it, or `run.sh refund` after expiry (+1 h if Submitted), or `FRESH=1 run.sh deploy-push` (a new hook) |
| `open`/`allocate`: accounts.json is for the other mode or key | `CLIENT_MODE` or the client key changed | `run.sh accounts` |
| any time after the job ends | unspent prepaid PC | `run.sh refund` (also `claimRefund` when the job is stuck past expiry) |

## 8 · Shortcuts taken, on purpose

- EOAs instead of AGWs: `E2EAllowAll` answers the hook's `isWallet` and `isPermissionEnabled`. The hook's other rules
  (spec hash at `fund`, one live job per client) still run.
- EOA mode measures the client's own address; UEA mode measures the real CEA address, but the provider fills it.
- No marketplace: `open` writes the JobSpec directly; mutability `NONE`.
- Dummy Aave / Morpho: 1:1, no interest, no caps. Morpho's position is read with `maxWithdraw(owner)`, one call that
  returns assets (a real MetaMorpho vault caps it by liquidity; `convertToAssets(balanceOf)` needs two reads).
- Kernel fees are 0; the payment token mints freely.

## 9 · Local rehearsal (no validators, no real funds)

The same scripts against two anvil forks; `local-relay.sh` plays the validators: it moves UniversalCore's tracked
height and answers each pending read with the real view call on the Base fork, as raw return data (what
`x/ucallback` delivers).

```
anvil --fork-url https://evm.rpc-testnet-donut-node1.push.org/ --port 8645 --timeout 120000 --retries 10 &
anvil --fork-url https://sepolia.base.org --port 8646 --timeout 120000 --retries 10 &
export PUSH_CHAIN_TESTNET_RPC_URL=http://127.0.0.1:8645 BASE_TESTNET_RPC_URL=http://127.0.0.1:8646
export CLIENT_PRIVATE_KEY=<anvil key 0> PROVIDER_PRIVATE_KEY=<anvil key 1>
export E2E_STATE_DIR=deployments/e2e-evaluator-local POLL_SECONDS=2
R=scripts/agentic-commerce-8183/e2e/run.sh; L=scripts/agentic-commerce-8183/e2e/local-relay.sh
$R deploy-base && $R deploy-push && $R accounts && $L height && $R open && $L answer && $R wait-snapshot
$R allocate && $L height && $R submit && $L answer && $R wait-verdict && $R status
```

The same works with `CLIENT_MODE=uea`. The forks fetch state from the public RPCs, which sometimes time out
(`-32002`); re-run the relay step.

## Files

| File | |
|---|---|
| `run.sh` | the runner: steps, waits, status |
| `E2EConfig.sol` | addresses, keys, state files, the job's spec |
| `E2EMocks.sol` | the dummies |
| `E2EBaseSepolia.s.sol` | `deploy()`, `allocate()`, `fundAccount()`, `positions()` |
| `E2EPushDeploy.s.sol` | kernel, token, allow-all, hook + evaluator, whitelist |
| `E2EAccounts.s.sol` | `push()`: the job's client (UEA deployed if needed); `base()`: the measured account (CEA) |
| `E2EJob.s.sol` | `open()`, `outbound()`, `submit()`, `status()`, `retrySnapshot()`, `sendReads()`, `settle()`, `refund()` |
| `local-relay.sh` | local forks only: the validators' part (not the outbound TSS) |
