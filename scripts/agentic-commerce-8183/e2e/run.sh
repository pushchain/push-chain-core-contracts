#!/usr/bin/env bash
# Evaluator end-to-end run on Push Donut + Base Sepolia, with two EOAs. See README.md in this folder.
#
#   scripts/agentic-commerce-8183/e2e/run.sh <step>
#
#   all             check, deploy (unless already deployed; FRESH=1 redeploys), accounts, open, wait-snapshot,
#                   allocate, wait-height, submit, wait-verdict, status
#   check           keys, balances, Read State and the tracked Base Sepolia height
#   deploy          deploy-base + deploy-push
#   deploy-base     dummy USDC, Aave pool + aUSDC, Morpho vault on Base Sepolia (client key)
#   deploy-push     payment token, allow-all, kernel, hook, evaluator on Push Donut (DEPLOYER_PRIVATE_KEY or client key)
#   accounts        who the job is for: CLIENT_MODE=eoa (default) the client key; CLIENT_MODE=uea its UEA on Push
#                   (deployed if needed) and that UEA's CEA on Base Sepolia as the measured account
#   open            client creates, provider prices, client prefunds + funds (PRE reads go out)
#   wait-snapshot   until both PRE reads are answered
#   allocate        provider supplies to Aave and deposits to Morpho for the measured account (ALLOC_AAVE / ALLOC_MORPHO)
#   fund-account    UEA mode: mint the client's eUSDC into its CEA (before outbound)
#   outbound        UEA mode: the UEA sends an outbound tx; the Base Sepolia Vault has the CEA supply + deposit itself
#   wait-outbound   until the CEA's positions grow; records the Vault's execution block for submit
#                   (ALLOCATE_VIA=outbound makes `all` use fund-account + outbound + wait-outbound instead of allocate)
#   wait-height     until Push's tracked Base Sepolia height covers the allocation block
#   submit          provider submits (end blocks fixed, POST reads go out)
#   wait-verdict    until the evaluator decides and the kernel applies it
#   status          the job, evaluation, every read, and the client's positions
#   retry-snapshot | send-reads | settle | refund     recovery (see README.md)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
# .env fills in only what the environment doesn't already set
if [ -f .env ]; then
  while IFS='=' read -r k v; do
    [[ "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    v="${v%\"}"; v="${v#\"}"
    [ -n "${!k:-}" ] || export "$k=$v"
  done < .env
fi
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

PUSH_RPC="${PUSH_CHAIN_TESTNET_RPC_URL:-https://evm.rpc-testnet-donut-node1.push.org/}"
BASE_RPC="${BASE_TESTNET_RPC_URL:-https://sepolia.base.org}"
DIR=scripts/agentic-commerce-8183/e2e
STATE="${E2E_STATE_DIR:-deployments/e2e-evaluator}"
export E2E_STATE_DIR="$STATE"
CORE=0x00000000000000000000000000000000000000C0
READ_STATE=0x00000000000000000000000000000000000000c2
BASE_KEY=eip155:84532
POLL="${POLL_SECONDS:-10}"

jget() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }
first() { awk '{print $1}'; } # cast prints "123 [1.23e2]"
# The highest block among a forge broadcast's receipts: where its last transaction landed. (The RPC's head can
# lag behind it on a load-balanced endpoint.)
last_block() { python3 -c 'import json,sys; print(max(int(r["blockNumber"], 16) for r in json.load(open(sys.argv[1]))["receipts"]))' "$1"; }
need() { [ -n "${!1:-}" ] || { echo "error: set $1 (in .env or the environment)" >&2; exit 1; }; }
job() { if [ -n "${JOB_ID:-}" ]; then echo "$JOB_ID"; else jget "$STATE/job.json" jobId; fi; }
evaluator() { jget "$STATE/push.json" evaluator; }
tracked() { cast call "$CORE" 'chainHeightByChainNamespace(string)(uint256)' "$BASE_KEY" --rpc-url "$PUSH_RPC" | first; }

push_script() { forge script "$@" --rpc-url "$PUSH_RPC" --broadcast --slow --gas-estimate-multiplier 200; }
base_script() { forge script "$@" --rpc-url "$BASE_RPC" --broadcast --slow; }

# Polls `$1` (a function that succeeds when done) every POLL seconds, for at most `$2` seconds.
wait_for() {
  local cond=$1 timeout=$2 label=$3 waited=0
  until $cond; do
    if [ "$waited" -ge "$timeout" ]; then echo "timed out after ${timeout}s waiting for: $label" >&2; return 1; fi
    sleep "$POLL"; waited=$((waited + POLL))
  done
  echo "ok after ~${waited}s: $label"
}

check() {
  need CLIENT_PRIVATE_KEY; need PROVIDER_PRIVATE_KEY
  local client provider
  client=$(cast wallet address --private-key "$CLIENT_PRIVATE_KEY")
  provider=$(cast wallet address --private-key "$PROVIDER_PRIVATE_KEY")
  echo "client key: $client (CLIENT_MODE=${CLIENT_MODE:-eoa})"
  echo "provider:   $provider"
  echo "Push Donut  ($PUSH_RPC) chain $(cast chain-id --rpc-url "$PUSH_RPC")"
  echo "  client PC:   $(cast balance "$client" --ether --rpc-url "$PUSH_RPC")"
  echo "  provider PC: $(cast balance "$provider" --ether --rpc-url "$PUSH_RPC")"
  echo "  Read State paused: $(cast call "$READ_STATE" 'paused()(bool)' --rpc-url "$PUSH_RPC")"
  echo "  Base Sepolia blocked: $(cast call "$READ_STATE" 'isDomainBlocked(string,string)(bool)' eip155 84532 --rpc-url "$PUSH_RPC")"
  local observed now
  observed=$(cast call "$CORE" 'timestampObservedAtByChainNamespace(string)(uint256)' "$BASE_KEY" --rpc-url "$PUSH_RPC" | first)
  now=$(cast block latest --field timestamp --rpc-url "$PUSH_RPC")
  echo "  tracked Base Sepolia height: $(tracked) (observed $((now - observed))s ago)"
  echo "Base Sepolia ($BASE_RPC) chain $(cast chain-id --rpc-url "$BASE_RPC") at block $(cast block-number --rpc-url "$BASE_RPC")"
  echo "  client ETH:   $(cast balance "$client" --ether --rpc-url "$BASE_RPC")"
  echo "  provider ETH: $(cast balance "$provider" --ether --rpc-url "$BASE_RPC")"
}

deploy_base() {
  need CLIENT_PRIVATE_KEY
  base_script "$DIR/E2EBaseSepolia.s.sol:E2EBaseSepolia" --sig 'deploy()'
  last_block broadcast/E2EBaseSepolia.s.sol/84532/deploy-latest.json > "$STATE/deploy-block" # the dummies exist from here on
}
deploy_push() {
  need CLIENT_PRIVATE_KEY
  push_script "$DIR/E2EPushDeploy.s.sol:E2EPushDeploy" --private-key "${DEPLOYER_PRIVATE_KEY:-$CLIENT_PRIVATE_KEY}"
}

# PRE reads are taken at the tracked height at fund: it must already include the dummies' deployment
height_covers_deploy() { [ "$(tracked)" -ge "$(cat "$STATE/deploy-block" 2>/dev/null || echo 0)" ]; }
accounts() {
  need CLIENT_PRIVATE_KEY
  push_script "$DIR/E2EAccounts.s.sol:E2EAccounts" --sig 'push()'
  base_script "$DIR/E2EAccounts.s.sol:E2EAccounts" --sig 'base()'
}

open_job() {
  need CLIENT_PRIVATE_KEY; need PROVIDER_PRIVATE_KEY
  wait_for height_covers_deploy "${HEIGHT_TIMEOUT:-600}" "tracked Base Sepolia height >= the dummies' deploy block"
  MIN_FUND_HEIGHT="$(cat "$STATE/deploy-block" 2>/dev/null || echo 0)" push_script "$DIR/E2EJob.s.sol:E2EJob" --sig 'open()'
}

snapshot_ready() { [ "$(cast call "$(evaluator)" 'ready(uint256)(bool)' "$(job)" --rpc-url "$PUSH_RPC")" = true ]; }
wait_snapshot() { wait_for snapshot_ready "${SNAPSHOT_TIMEOUT:-900}" "the PRE reads of job $(job)"; }

allocate() {
  need PROVIDER_PRIVATE_KEY
  base_script "$DIR/E2EBaseSepolia.s.sol:E2EBaseSepolia" --sig 'allocate()'
  last_block broadcast/E2EBaseSepolia.s.sol/84532/allocate-latest.json > "$STATE/alloc-block"
  echo "allocation's last transaction is in Base Sepolia block $(cat "$STATE/alloc-block")"
}

# The measured account's aUSDC balance and Morpho position, as "aUSDC morpho"
positions_now() {
  local account atoken vault
  account=$(jget "$STATE/accounts.json" measured)
  atoken=$(jget "$STATE/base-sepolia.json" aToken); vault=$(jget "$STATE/base-sepolia.json" morphoVault)
  echo "$(cast call "$atoken" 'balanceOf(address)(uint256)' "$account" --rpc-url "$BASE_RPC" | first)" \
    "$(cast call "$vault" 'maxWithdraw(address)(uint256)' "$account" --rpc-url "$BASE_RPC" | first)"
}

fund_account() { need CLIENT_PRIVATE_KEY; base_script "$DIR/E2EBaseSepolia.s.sol:E2EBaseSepolia" --sig 'fundAccount()'; }

outbound() {
  need CLIENT_PRIVATE_KEY
  cast block-number --rpc-url "$BASE_RPC" > "$STATE/outbound-from-block" # the Vault executes after this
  positions_now > "$STATE/outbound-before"
  push_script "$DIR/E2EJob.s.sol:E2EJob" --sig 'outbound()'
}

outbound_landed() {
  local before now
  read -r -a before < "$STATE/outbound-before"
  read -r -a now <<< "$(positions_now)"
  [ "${now[0]}" -ge $((before[0] + ${ALLOC_AAVE:-600000000})) ] && [ "${now[1]}" -ge $((before[1] + ${ALLOC_MORPHO:-400000000})) ]
}

# Waits for the CEA's positions to grow, then records the Vault's execution transaction and block.
wait_outbound() {
  wait_for outbound_landed "${OUTBOUND_TIMEOUT:-900}" "the outbound to run on Base Sepolia"
  local vault from head uea
  vault="${BASE_VAULT:-0xb4Ba4D5542D1dD48BD3589543660B265B41f16CB}" # the gateway's VAULT() on Base Sepolia
  from=$(cat "$STATE/outbound-from-block"); head=$(cast block-number --rpc-url "$BASE_RPC")
  uea=$(jget "$STATE/accounts.json" client)
  python3 - "$BASE_RPC" "$vault" "$from" "$head" "$uea" "$STATE/outbound-exec.json" <<'PY'
import json, subprocess, sys
rpc, vault, lo, hi, uea, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5].lower(), sys.argv[6]
topic = "0xc0e5bfaee884bc9755121a066f66b7b8b025de87a1784e37731ca5a93f2f5b28"  # Vault UniversalTxFinalized
body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getLogs",
                   "params": [{"address": vault, "fromBlock": hex(lo), "toBlock": hex(hi), "topics": [topic]}]})
logs = json.loads(subprocess.run(["curl", "-s", "-m", "30", "-X", "POST", "-H", "content-type: application/json",
                                  "--data", body, rpc], capture_output=True, text=True).stdout)["result"]
mine = [l for l in logs if uea[2:] in l["data"].lower()]
if not mine:
    sys.exit("no Vault UniversalTxFinalized for the UEA in blocks %d-%d" % (lo, hi))
l = mine[-1]
json.dump({"tx": l["transactionHash"], "block": int(l["blockNumber"], 16)}, open(out, "w"))
print("Vault executed it in Base Sepolia tx", l["transactionHash"], "block", int(l["blockNumber"], 16))
PY
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["block"])' "$STATE/outbound-exec.json" > "$STATE/alloc-block"
}

height_covers_allocation() { [ "$(tracked)" -ge "$(cat "$STATE/alloc-block")" ]; }
wait_height() {
  wait_for height_covers_allocation "${HEIGHT_TIMEOUT:-600}" "tracked Base Sepolia height >= $(cat "$STATE/alloc-block")"
}

submit() {
  need PROVIDER_PRIVATE_KEY
  MIN_END_HEIGHT="$(cat "$STATE/alloc-block" 2>/dev/null || echo 0)" push_script "$DIR/E2EJob.s.sol:E2EJob" --sig 'submit()'
}

# evaluationOf: endFixed, started, reads, pending, done, verdict, applied, ownerCheck, checkRes, answered
evaluation() {
  cast call "$(evaluator)" 'evaluationOf(uint256)((bool,bool,uint8,uint8,bool,uint8,bool,uint8,uint32,uint32))' \
    "$(job)" --rpc-url "$PUSH_RPC" | tr -d '() ' | tr ',' ' '
}
decided() { local e; read -r -a e <<< "$(evaluation)"; [ "${e[4]}" = true ]; }
wait_verdict() {
  wait_for decided "${VERDICT_TIMEOUT:-900}" "the verdict of job $(job)"
  local e; read -r -a e <<< "$(evaluation)"
  case "${e[5]}:${e[6]}" in
    1:true) echo "VERDICT: PASS (job Completed, provider paid)" ;;
    2:true) echo "VERDICT: FAIL (job Rejected, client refunded)" ;;
    1:false | 2:false) echo "VERDICT: decided (${e[5]}) but the kernel refused it (paused?): run settle" ;;
    *) echo "VERDICT: INCONCLUSIVE (a read was unreadable): run send-reads" ;;
  esac
}

status() {
  forge script "$DIR/E2EJob.s.sol:E2EJob" --sig 'status()' --rpc-url "$PUSH_RPC" 2>&1 | sed -n '/== Logs ==/,$p'
  forge script "$DIR/E2EBaseSepolia.s.sol:E2EBaseSepolia" --sig 'positions()' --rpc-url "$BASE_RPC" 2>&1 \
    | sed -n '/== Logs ==/,$p' | tail -n +2
}

recover() { push_script "$DIR/E2EJob.s.sol:E2EJob" --sig "$1"; }

all() {
  check
  if [ "${FRESH:-0}" = 1 ] || [ ! -f "$STATE/base-sepolia.json" ]; then deploy_base; fi
  if [ "${FRESH:-0}" = 1 ] || [ ! -f "$STATE/push.json" ]; then deploy_push; fi
  accounts
  open_job
  wait_snapshot
  status
  if [ "${ALLOCATE_VIA:-provider}" = outbound ]; then fund_account; outbound; wait_outbound; else allocate; fi
  wait_height
  submit
  wait_verdict
  status
}

case "${1:-}" in
  all) all ;;
  check) check ;;
  deploy) deploy_base; deploy_push ;;
  deploy-base) deploy_base ;;
  deploy-push) deploy_push ;;
  accounts) accounts ;;
  open) open_job ;;
  wait-snapshot) wait_snapshot ;;
  allocate) allocate ;;
  fund-account) fund_account ;;
  outbound) outbound ;;
  wait-outbound) wait_outbound ;;
  wait-height) wait_height ;;
  submit) submit ;;
  wait-verdict) wait_verdict ;;
  status) status ;;
  retry-snapshot) recover 'retrySnapshot()' ;;
  send-reads) recover 'sendReads()' ;;
  settle) recover 'settle()' ;;
  refund) recover 'refund()' ;;
  *) sed -n '2,26p' "$0"; exit 1 ;;
esac
