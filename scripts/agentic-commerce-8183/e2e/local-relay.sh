#!/usr/bin/env bash
# LOCAL FORKS ONLY: plays Push's validators when both chains are anvil forks (see README.md, "Local rehearsal").
#
#   local-relay.sh height   set UniversalCore's tracked Base Sepolia height to the Base fork's head
#   local-relay.sh answer   answer every PENDING read of the job: the real view call on the Base fork at the read's
#                           block, delivered as raw return data, the way x/ucallback does
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1
P="${PUSH_CHAIN_TESTNET_RPC_URL:?set PUSH_CHAIN_TESTNET_RPC_URL to the Donut fork}"
B="${BASE_TESTNET_RPC_URL:?set BASE_TESTNET_RPC_URL to the Base Sepolia fork}"
for url in "$P" "$B"; do
  [[ "$url" =~ ^http://(127\.0\.0\.1|localhost): ]] || { echo "error: $url is not a local fork" >&2; exit 1; }
done
STATE="$ROOT/${E2E_STATE_DIR:-deployments/e2e-evaluator}"
CORE=0x00000000000000000000000000000000000000C0
READ_STATE=0x00000000000000000000000000000000000000c2
UE_MODULE=0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7    # writes UniversalCore's chain heights
READ_MODULE=0x07a0258D367A4A4cd9d6E4b7eEE8E7eF491CC519  # delivers Read State answers

jget() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }
first() { awk '{print $1}'; }
unlock() {
  cast rpc anvil_impersonateAccount "$1" --rpc-url "$P" > /dev/null
  cast rpc anvil_setBalance "$1" 0x56BC75E2D63100000 --rpc-url "$P" > /dev/null
}

case "${1:-}" in
  height)
    unlock "$UE_MODULE"
    h=$(cast block-number --rpc-url "$B")
    price=$(cast call "$CORE" 'gasPriceByChainNamespace(string)(uint256)' eip155:84532 --rpc-url "$P" | first)
    cast send "$CORE" 'setChainMeta(string,uint256,uint256)' eip155:84532 "${price:-1}" "$h" \
      --from "$UE_MODULE" --unlocked --rpc-url "$P" > /dev/null
    echo "tracked Base Sepolia height -> $h"
    ;;
  answer)
    unlock "$READ_MODULE"
    evaluator=$(jget "$STATE/push.json" evaluator)
    job=$(jget "$STATE/job.json" jobId)
    account=$(jget "$STATE/job.json" measured) # the client, or in UEA mode its CEA
    for i in 0 1 2 3; do # the allocation job: 0 aUSDC after, 1 Morpho after, 2 aUSDC before, 3 Morpho before
      req=$(cast call "$evaluator" 'requestOf(uint256,uint256)(uint256)' "$job" "$i" --rpc-url "$P" | first)
      [ "$req" = 0 ] && continue
      [ "$(cast call "$READ_STATE" 'statusOf(uint256)(uint8)' "$req" --rpc-url "$P")" = 1 ] || continue # PENDING
      if [ "$i" -ge 2 ]; then fn=fundHeightOf; else fn=endHeightOf; fi
      blk=$(cast call "$evaluator" "$fn(uint256,uint256)(uint64)" "$job" "$i" --rpc-url "$P" | first)
      if [ $((i % 2)) = 0 ]; then
        target=$(jget "$STATE/base-sepolia.json" aToken); data=$(cast calldata 'balanceOf(address)' "$account")
      else
        target=$(jget "$STATE/base-sepolia.json" morphoVault); data=$(cast calldata 'maxWithdraw(address)' "$account")
      fi
      res=$(cast call "$target" "$data" --block "$blk" --rpc-url "$B")
      cast send "$READ_STATE" 'fulfillExternalCallback(uint256,bytes)' "$req" "$res" \
        --from "$READ_MODULE" --unlocked --gas-limit 5000000 --rpc-url "$P" > /dev/null
      echo "answered read $i at Base block $blk: $(cast to-dec "$res")"
    done
    ;;
  *) sed -n '2,7p' "$0"; exit 1 ;;
esac
