#!/usr/bin/env bash
set -euo pipefail

# Fetches all CEADeployed events from an old CEAFactory and saves
# the pushAccount↔CEA pairs to a JSON file for bulk registration.
#
# Usage:
#   source .env && ./scripts/cea/fetchOldCEAs.sh \
#     --factory <OLD_CEA_FACTORY_PROXY> \
#     --rpc-var <RPC_ENV_VAR_NAME> \
#     --chain-id <CHAIN_ID> \
#     [--from-block <START_BLOCK>] \
#     [--batch-size <BLOCK_RANGE_PER_QUERY>]
#
# Example (ETH Sepolia):
#   source .env && ./scripts/cea/fetchOldCEAs.sh \
#     --factory 0x8ED594A83301FEc545fC6c19fc12cF7111777029 \
#     --rpc-var SEPOLIA_RPC_URL \
#     --chain-id 11155111
#
# Output: migrations/<chainId>_old_ceas.json

FACTORY=""
RPC_VAR=""
CHAIN_ID=""
FROM_BLOCK=0
BATCH_SIZE=5000

while [[ $# -gt 0 ]]; do
    case $1 in
        --factory) FACTORY="$2"; shift 2 ;;
        --rpc-var) RPC_VAR="$2"; shift 2 ;;
        --chain-id) CHAIN_ID="$2"; shift 2 ;;
        --from-block) FROM_BLOCK="$2"; shift 2 ;;
        --batch-size) BATCH_SIZE="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if [[ -z "$FACTORY" || -z "$RPC_VAR" || -z "$CHAIN_ID" ]]; then
    echo "Error: --factory, --rpc-var, and --chain-id are required"
    exit 1
fi

RPC="${!RPC_VAR:-}"
if [[ -z "$RPC" ]]; then
    echo "Error: env var $RPC_VAR is not set"
    exit 1
fi

TOPIC=$(cast keccak "CEADeployed(address,address)" 2>/dev/null)
LATEST=$(cast block-number --rpc-url "$RPC" 2>/dev/null)

echo "=== Fetch Old CEAs ==="
echo "Chain ID:    $CHAIN_ID"
echo "Factory:     $FACTORY"
echo "Topic:       $TOPIC"
echo "Block range: $FROM_BLOCK → $LATEST"
echo "Batch size:  $BATCH_SIZE"
echo ""

mkdir -p migrations
OUTFILE="migrations/${CHAIN_ID}_old_ceas.json"
TMPFILE=$(mktemp)

echo -n "" > "$TMPFILE"

TOTAL=0
from=$FROM_BLOCK
while (( from <= LATEST )); do
    to=$(( from + BATCH_SIZE - 1 ))
    if (( to > LATEST )); then
        to=$LATEST
    fi

    result=$(cast logs \
        --from-block "$from" \
        --to-block "$to" \
        --address "$FACTORY" \
        "$TOPIC" \
        --rpc-url "$RPC" 2>/dev/null || true)

    if [[ -n "$result" ]]; then
        # Each CEADeployed event has 2 indexed topics (after the event sig):
        #   topic1 = pushAccount (address, left-padded to 32 bytes)
        #   topic2 = cea (address, left-padded to 32 bytes)
        while IFS= read -r line; do
            if [[ "$line" =~ ^-\ address: ]]; then
                current_block=""
            fi
            if [[ "$line" =~ blockNumber:\ ([0-9]+) ]]; then
                current_block="${BASH_REMATCH[1]}"
            fi
            if [[ "$line" =~ topics:\ \[ ]]; then
                read -r topic_line
                # topic_line contains the topics array content
                :
            fi
        done <<< "$result"

        # Simpler: parse topic lines directly
        # Each log block has topics: [eventSig, pushAccount, cea]
        topics_raw=$(echo "$result" | grep -A3 "topics:" | grep "0x" | grep -v "CEADeployed" || true)

        # Extract pairs: every 3 topics = 1 event (sig, pushAccount, cea)
        mapfile -t all_topics < <(echo "$result" | grep -oP '0x[0-9a-fA-F]{64}' || true)

        idx=0
        while (( idx < ${#all_topics[@]} )); do
            sig="${all_topics[$idx]}"
            if [[ "$sig" == "$TOPIC" ]] && (( idx + 2 < ${#all_topics[@]} )); then
                push_raw="${all_topics[$((idx+1))]}"
                cea_raw="${all_topics[$((idx+2))]}"
                push_addr="0x${push_raw:26}"
                cea_addr="0x${cea_raw:26}"
                echo "${push_addr},${cea_addr}" >> "$TMPFILE"
                TOTAL=$((TOTAL + 1))
                idx=$((idx + 3))
            else
                idx=$((idx + 1))
            fi
        done

        echo "  Blocks $from-$to: found events (total so far: $TOTAL)"
    fi

    from=$((to + 1))
done

echo ""
echo "Total CEADeployed events found: $TOTAL"

# Deduplicate by pushAccount (keep first occurrence)
DEDUP_FILE=$(mktemp)
sort -t',' -k1,1 -u "$TMPFILE" > "$DEDUP_FILE"
UNIQUE=$(wc -l < "$DEDUP_FILE" | tr -d ' ')
echo "Unique pushAccounts: $UNIQUE"

# Build JSON
{
    echo "{"
    echo "  \"chainId\": $CHAIN_ID,"
    echo "  \"oldFactory\": \"$FACTORY\","
    echo "  \"totalEvents\": $TOTAL,"
    echo "  \"uniquePairs\": $UNIQUE,"
    echo "  \"fetchedAtBlock\": $LATEST,"
    echo "  \"pairs\": ["

    first=true
    while IFS=',' read -r push_addr cea_addr; do
        if [[ -z "$push_addr" ]]; then continue; fi
        if $first; then
            first=false
        else
            echo ","
        fi
        # Checksum the addresses
        push_cs=$(cast to-check-sum-address "$push_addr" 2>/dev/null || echo "$push_addr")
        cea_cs=$(cast to-check-sum-address "$cea_addr" 2>/dev/null || echo "$cea_addr")
        printf '    { "pushAccount": "%s", "cea": "%s" }' "$push_cs" "$cea_cs"
    done < "$DEDUP_FILE"

    echo ""
    echo "  ]"
    echo "}"
} > "$OUTFILE"

rm -f "$TMPFILE" "$DEDUP_FILE"

echo ""
echo "Saved to: $OUTFILE"
echo ""
echo "Next steps:"
echo "  1. Review $OUTFILE to verify the pushAccount↔CEA pairs"
echo "  2. Run the bulk registration script:"
echo "     source .env && forge script scripts/cea/registerOldCEAs.s.sol:RegisterOldCEAsScript \\"
echo "       --rpc-url \"\$${RPC_VAR}\" --broadcast -vvvv"
