#!/usr/bin/env bash
# The three demo jobs on Push Donut + Base Sepolia + Ethereum Sepolia, with the client's UEA and its CEAs.
# See README.md in this folder.
#
#   scripts/agentic-commerce-8183/demo/run.sh <step> [args]
#
#   deploy-push               payment token, allow-all, kernel, hook, evaluator on Push Donut (fresh, all proxies)
#   accounts                  resolve (or deploy) the client's UEA; compute its CEAs on both chains -> state
#   deploy-vault              the Morpho-style WETH vault on Base Sepolia
#   bridge <base|sep> <wei>   send ETH through that chain's gateway to the UEA; waits until the pETH arrives
#   open <1|2|3>              the UEA creates the job, the provider prices it, the UEA funds it (PRE reads go out)
#   wait-snapshot             until every PRE read is answered
#   outbound <base|sep> <toAave> [toVault]
#                             the UEA bridges toAave+toVault ETH to its CEA with the CEA's work; waits until it lands
#                             and records the block
#   submit                    waits for Push's tracked heights to cover the recorded blocks, then the provider submits
#   wait-verdict              until the evaluator decides and the kernel applies it
#   report | claim            the job and every read · claimPrepaid
#   job <1|2|3>               the whole job: open, wait-snapshot, outbound(s), submit, wait-verdict, report
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
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
SEP_RPC="${SEPOLIA_RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"
DIR=scripts/agentic-commerce-8183/demo
STATE="${E2E_STATE_DIR:-deployments/demo-jobs}"
export E2E_STATE_DIR="$STATE" CLIENT_MODE=uea UEA_ORIGIN_CHAIN_ID="${UEA_ORIGIN_CHAIN_ID:-84532}"
mkdir -p "$STATE"
CORE=0x00000000000000000000000000000000000000C0
PETH_BASE=0xc7007af2B24D4eb963fc9633B0c66e1d2D90Fc21
PETH_SEP=0x2971824Db68229D087931155C2b8bB820B275809
GW_BASE=0xFD4fef1F43aFEc8b5bcdEEc47f35a1431479aC16
GW_SEP=0x05bD7a3D18324c1F7e216f7fBF2b15985aE5281A
CEAF_BASE=0x7e8CeeDA043ED1460540616103dD57581a66C856
CEAF_SEP=0x5E191fbBe22F8866C5e4250557664fCE760e8870
AWETH_BASE=0x73a5bB60b0B0fc35710DDc0ea9c407031E31Bdbb
AWETH_SEP=0x5b071b590a59395fe4025a0ccc1fcc931aac1830
POLL="${POLL_SECONDS:-10}"

jget() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }
jset() { python3 -c 'import json,sys,os; p=sys.argv[1]; d=json.load(open(p)) if os.path.exists(p) else {}; d[sys.argv[2]]=sys.argv[3]; json.dump(d,open(p,"w"),indent=2)' "$STATE/demo.json" "$1" "$2"; }
dget() { jget "$STATE/demo.json" "$1"; }
jdel() { python3 -c 'import json,sys,os; p=sys.argv[1]; d=json.load(open(p)) if os.path.exists(p) else {}; [d.pop(k,None) for k in sys.argv[2:]]; json.dump(d,open(p,"w"),indent=2)' "$STATE/demo.json" "$@"; }
first() { awk '{print $1}'; }
last_block() { python3 -c 'import json,sys; print(max(int(r["blockNumber"], 16) for r in json.load(open(sys.argv[1]))["receipts"]))' "$1"; }
tracked() { cast call "$CORE" 'chainHeightByChainNamespace(string)(uint256)' "$1" --rpc-url "$PUSH_RPC" | first; }
uea() { jget "$STATE/accounts.json" client; }
job_env() { export CEA_BASE="$(dget ceaBase)" CEA_SEP="$(dget ceaSep)" VAULT="$(dget vault 2>/dev/null || echo 0x0000000000000000000000000000000000000000)"; }

push_script() { forge script "$@" --rpc-url "$PUSH_RPC" --broadcast --slow --gas-estimate-multiplier 200; }

wait_for() {
  local cond=$1 timeout=$2 label=$3 waited=0
  until $cond; do
    if [ "$waited" -ge "$timeout" ]; then echo "timed out after ${timeout}s waiting for: $label" >&2; return 1; fi
    sleep "$POLL"; waited=$((waited + POLL))
  done
  echo "ok after ~${waited}s: $label"
}

deploy_push() { push_script scripts/agentic-commerce-8183/e2e/E2EPushDeploy.s.sol --private-key "$CLIENT_PRIVATE_KEY"; }

accounts() {
  push_script scripts/agentic-commerce-8183/e2e/E2EAccounts.s.sol --sig 'push()'
  local u; u=$(uea)
  jset ceaBase "$(cast call $CEAF_BASE 'computeCEA(address)(address)' "$u" --rpc-url "$BASE_RPC")"
  jset ceaSep "$(cast call $CEAF_SEP 'computeCEA(address)(address)' "$u" --rpc-url "$SEP_RPC")"
  echo "UEA $u · CEA Base $(dget ceaBase) · CEA Sepolia $(dget ceaSep)"
}

deploy_vault() {
  forge script $DIR/DemoChains.s.sol --sig 'deployVault()' --rpc-url "$BASE_RPC" --broadcast --slow
  local run=broadcast/DemoChains.s.sol/84532/deployVault-latest.json
  jset vault "$(python3 -c 'import json,sys; t=[x for x in json.load(open(sys.argv[1]))["transactions"] if (x.get("contractName") or "").startswith("TransparentUpgradeableProxy")]; print(t[0]["contractAddress"])' $run)"
  echo "vault $(dget vault)"
}

bridge() {
  local chain=$1 amount=$2 rpc gw peth id before
  if [ "$chain" = sep ]; then rpc=$SEP_RPC; gw=$GW_SEP; peth=$PETH_SEP; id=11155111; else rpc=$BASE_RPC; gw=$GW_BASE; peth=$PETH_BASE; id=84532; fi
  before=$(cast call $peth 'balanceOf(address)(uint256)' "$(uea)" --rpc-url "$PUSH_RPC" | first)
  GATEWAY=$gw AMOUNT=$amount RECIPIENT=$(uea) forge script $DIR/DemoChains.s.sol --sig 'bridge()' --rpc-url "$rpc" --broadcast --slow
  jset "bridgeTx_$chain" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["receipts"][-1]["transactionHash"])' broadcast/DemoChains.s.sol/$id/bridge-latest.json)"
  arrived() { [ "$(cast call $peth 'balanceOf(address)(uint256)' "$(uea)" --rpc-url "$PUSH_RPC" | first)" -gt "$before" ]; }
  wait_for arrived 1800 "pETH from $chain credited to the UEA"
}

open_job() {
  job_env
  jdel execBlock_base execBlock_sep execTx_base execTx_sep outboundTx_base outboundTx_sep submitTx
  JOB=$1 push_script $DIR/DemoJob.s.sol --sig 'openJob()'
  jset job "$1"
  jset jobId "$(jget "$STATE/demo-job.json" jobId)"
}

wait_snapshot() {
  local ev; ev=$(jget "$STATE/push.json" evaluator)
  ready() { [ "$(cast call "$ev" 'ready(uint256)(bool)' "$(dget jobId)" --rpc-url "$PUSH_RPC")" = true ]; }
  wait_for ready 1800 "PRE reads answered"
}

outbound() {
  job_env
  local chain=$1 rpc aweth cea start blk
  if [ "$chain" = sep ]; then rpc=$SEP_RPC; aweth=$AWETH_SEP; cea=$CEA_SEP; c=1; else rpc=$BASE_RPC; aweth=$AWETH_BASE; cea=$CEA_BASE; c=0; fi
  start=$(cast block-number --rpc-url "$rpc")
  CHAIN=$c TO_AAVE=$2 TO_VAULT=${3:-0} push_script $DIR/DemoJob.s.sol --sig 'bridgeOut()'
  jset "outboundTx_$chain" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["receipts"][-1]["transactionHash"])' broadcast/DemoJob.s.sol/42101/bridgeOut-latest.json)"
  # A mint of aWETH to exactly this CEA, after `start`: the Vault's execution of this outbound.
  mint_log() {
    cast rpc eth_getLogs "{\"fromBlock\":\"$(printf '0x%x' "$start")\",\"toBlock\":\"latest\",\"address\":\"$aweth\",\"topics\":[\"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\",\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"0x000000000000000000000000${cea#0x}\"]}" --rpc-url "$rpc" 2>/dev/null
  }
  landed() {
    blk=$(mint_log | python3 -c 'import json,sys; l=json.load(sys.stdin); print(int(l[-1]["blockNumber"],16) if l else "")')
    [ -n "$blk" ]
  }
  wait_for landed 1800 "the CEA's work landed on $chain"
  local tx; tx=$(mint_log | python3 -c 'import json,sys; print(json.load(sys.stdin)[-1]["transactionHash"])')
  jset "execBlock_$chain" "$blk"; jset "execTx_$chain" "$tx"
  echo "landed in block $blk ($tx)"
}

submit() {
  local mb ms; mb=$(dget execBlock_base 2>/dev/null || echo 0); ms=$(dget execBlock_sep 2>/dev/null || echo 0)
  covered() { [ "$(tracked eip155:84532)" -ge "$mb" ] && [ "$(tracked eip155:11155111)" -ge "$ms" ]; }
  wait_for covered 1800 "tracked heights cover the work (Base $mb, Sepolia $ms)"
  MIN_BASE=$mb MIN_SEP=$ms push_script $DIR/DemoJob.s.sol --sig 'submitJob()'
  jset submitTx "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["receipts"][-1]["transactionHash"])' broadcast/DemoJob.s.sol/42101/submitJob-latest.json)"
}

wait_verdict() {
  local k; k=$(jget "$STATE/push.json" kernel)
  settled() { local s; s=$(cast call "$k" 'getJob(uint256)((address,uint8,address,uint48,address,address,uint256,string))' "$(dget jobId)" --rpc-url "$PUSH_RPC" | python3 -c 'import sys; print(sys.stdin.read().split(",")[1].strip())'); [ "$s" = 3 ] || [ "$s" = 4 ]; }
  wait_for settled 1800 "the verdict applied"
}

report() { forge script $DIR/DemoJob.s.sol --sig 'report()' --rpc-url "$PUSH_RPC"; }
claim() { push_script $DIR/DemoJob.s.sol --sig 'claim()'; }

case "${1:-}" in
  deploy-push) deploy_push ;;
  accounts) accounts ;;
  deploy-vault) deploy_vault ;;
  bridge) bridge "$2" "$3" ;;
  open) open_job "$2" ;;
  wait-snapshot) wait_snapshot ;;
  outbound) outbound "$2" "$3" "${4:-0}" ;;
  submit) submit ;;
  wait-verdict) wait_verdict ;;
  report) report ;;
  claim) claim ;;
  *) sed -n '2,20p' "$0"; exit 1 ;;
esac
