# Universal Marketplace — Job criteria

How a card says what counts as "done", and how `startJob` turns that into one job's criteria. For where this fits
in the whole flow, see [`README.md`](./README.md) §7.

- [Two formats: template and JobSpec](#two-formats-template-and-jobspec)
- [The JobSpec](#the-jobspec)
- [The template](#the-template)
- [Building a JobSpec](#building-a-jobspec)
- [Worked example: a lending card](#worked-example-a-lending-card)
- [Worked example: a swap card with a user param](#worked-example-a-swap-card-with-a-user-param)
- [What the SDK must do](#what-the-sdk-must-do)

---

## Two formats: template and JobSpec

| | Template (`EvaluationTemplate`) | Criteria (`JobSpec`) |
|---|---|---|
| Where | stored on the card (`abi.encode`d, as given) | the 8183 job's `description` (`abi.encode(JobSpec)`) |
| Written by | the provider, once per card version | `JobSpecBuilder`, once per job |
| Holds | everything that is the same for every job, plus **holes** | concrete values for this job |
| Read by | the marketplace, at `startJob` / previews | the hook (at `fund`) and the evaluator (at verify) |
| Defined in | [`libraries/Types.sol`](../../src/agentic-commerce-8183/libraries/Types.sol) | [`libraries/JobSpecTypes.sol`](../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol) |

JobSpecTypes is the one definition shared by everything that writes or reads a job's criteria: the marketplace
builds a `JobSpec`, the UniversalHook freezes it at `fund`, and the UniversalEvaluator judges it. Its field order is
ABI: reordering or inserting a field changes every description.

---

## The JobSpec

```solidity
struct JobSpec {
    uint64 executeBy;               // the provider must execute before this
    uint64 failFinalAt;             // a FAIL only counts from a verify started after this
    Read[] reads;
    Check[] checks;
    Logic[] logic;                  // logic[0] is the root: the job passes if it passes
    AllowedMutability allowedMutability;  // who may replace these criteria before `fund`; marketplace jobs are NONE
    bytes32 origin;                 // keccak256(abi.encode(marketplace, cardId, cardVersion, principal))
}
```

### Reads: what to look at

```solidity
struct Read {
    string chainNamespace;    // namespace only, "eip155"
    string chainId;           // decimal, e.g. "11155111"
    uint16 minConfirmations;  // confirmations before the answer counts
    address target;           // the contract to call
    bytes4 selector;          // the view function
    bytes args;               // abi-encoded arguments
    bytes outputs;            // the function's return types, as type codes
    uint8[] field;            // which returned value, by ABI position
    ReadAt at;                // POST_EXECUTION (the zero value) or PRE_EXECUTION
}
```

A read is one view call on one chain, at one moment. **`chainNamespace` here is the namespace only** (`"eip155"`),
with `chainId` separate: the Read State split of the V2 design. That differs from `AgentCard.chainNamespace`, which
is the full CAIP-2 string `"eip155:<id>"`.

`at` says when the read is taken:

| `at` | Read at |
|---|---|
| `POST_EXECUTION` (the zero value) | its end block: the chain's tracked height, fixed inside `submit` |
| `PRE_EXECUTION` | the block recorded at `fund`: the chain's tracked height then |

A spec needs at least one POST_EXECUTION read. A change over the job is a POST read against a PRE read of the same
call (a `NUMBER` or `PERCENTAGE` check, below). An unreadable PRE answer counts as answered: the evaluation still starts, the
checks that need it are UNKNOWN, and the evaluator sends it again, at its `fund` block, with the POST reads.

`outputs` describes the return types so the evaluator can find one value in the answer. Codes:

| Code | Type | Code | Type |
|---|---|---|---|
| 1 `T_UINT` | `uintN` | 6 `T_BYTES` | `bytes` |
| 2 `T_INT` | `intN` | 7 `T_STRING` | `string` |
| 3 `T_BOOL` | `bool` | 8 `T_TUPLE` | tuple / struct: followed by its field count, then each field's type |
| 4 `T_ADDRESS` | `address` | 9 `T_ARRAY` | `T[]`: followed by the element type |
| 5 `T_BYTESN` | `bytesN` | 10 `T_FIXED_ARRAY` | `T[k]`: followed by `k`, then the element type |

The top level is always a tuple of the return values. For example, `balanceOf(address) returns (uint256)` is
`[T_TUPLE, 1, T_UINT]`.

`field` is the path to the value: at a tuple, the field index; at an array, the element index. `[0]` is the first
return value; `[0, 2]` is the first return value's third field.

How the evaluator turns the selected value into a number
([`EvmReadLib.decode`](../../src/agentic-commerce-8183/evaluator/EvmReadLib.sol); a test-only copy of the V2
design's decoder is [`test/8183-tests/helpers/V2Decoder.sol`](../../test/8183-tests/helpers/V2Decoder.sol)):

| Leaf | Value compared |
|---|---|
| uint / int | the number (a uint above `int256.max` is "can't tell") |
| bool | 0 or 1 |
| address, bytesN | the raw word (compare with EQUAL / NOT_EQUAL) |
| bytes, string | `keccak256` of the content |
| array | its length |

### Checks: what to compare

```solidity
struct Check {
    uint8[] left;       // indexes into reads, increasing · BOOLEAN: exactly one
    uint8[] right;      // indexes into reads, increasing, none in `left` · NUMBER / PERCENTAGE: at least one · BOOLEAN / COMPARE: none
    Evaluation evaluation;
    Operation operation;              // EQUAL, NOT_EQUAL, GREATER_THAN, GREATER_OR_EQUAL, LESS_THAN, LESS_OR_EQUAL
    int256 target;      // in the contract's own units
}
```

Each side is the sum of its reads: L = Σ`left`, R = Σ`right`.

| `Evaluation` | Passes when | Sides |
|---|---|---|
| `BOOLEAN` | `L == target` (`op` must be `EQUAL`, `target` 0 or 1) | one `left` read, no `right` |
| `COMPARE` | `L op target` | `left` only |
| `NUMBER` | `(L − R) op target` | both |
| `PERCENTAGE` | `(L − R) × 10 000 op target × R`: the change in basis points, compared without dividing; `R ≤ 0` fails | both |

A side with a missing or unreadable read, or a sum that overflows, makes the check UNKNOWN. With a PRE read on the
right, `NUMBER` and `PERCENTAGE` measure the change over the job: `left [after], right [before], NUMBER, GREATER_OR_EQUAL, x` is "grew by at
least x". Sums compare totals, for example Aave plus Morpho holdings after the job against the same two before.

### Logic: the pass logic

```solidity
struct Logic {
    LogicKind kind;     // COMPARE, ALL, ANY, AT_LEAST
    uint8 check;        // COMPARE only: index into checks
    uint8[] children;   // ALL / ANY / AT_LEAST: indexes into logic, each greater than this entry's own
    uint8 k;            // AT_LEAST only: how many children must pass
}
```

`logic[0]` is the root. `ALL` is AND, `ANY` is OR, `AT_LEAST k` is any `k` of the children. Children always have
a higher index than their parent, so the tree has no cycles and can be evaluated from the last entry to the first.
Each check comes out PASS, FAIL or UNKNOWN, and the entries combine them in three-valued logic, so a job can be
decided while some checks are still UNKNOWN.

### `allowedMutability`

Who may replace the criteria before the job is funded:

| `AllowedMutability` | May replace |
|---|---|
| `BOTH` (the zero value) | the provider in `setBudget`, or the client in `fund` |
| `NONE` | nobody |
| `CLIENT` | the client, in `fund` |
| `PROVIDER` | the provider, in `setBudget` |

The flag in the `createJob` description governs, and a replacement must carry the same flag. The builder always
writes `NONE`: a marketplace job's criteria are exactly the card's.

### Timing

- **`executeBy`**: the provider must have executed by then.
- **`failFinalAt = executeBy + card.settleWindow`**: a FAIL verdict only counts from a verify started after this,
  so slow settlement on the destination chain is not misread as failure.

The marketplace guarantees `executeBy ≥ now + minExecuteWindow` and `failFinalAt ≤ expiredAt` (`startJob` step 5).

### `origin`

`keccak256(abi.encode(marketplace, cardId, cardVersion, principal))`. The hook and evaluator ignore it. It ties
the job to the card version it was started from, and it is what makes an intent signed against one version
unusable on another: the version is inside the signed calldata.

---

## The template

```solidity
struct EvaluationTemplate {
    ReadTemplate[] reads;
    CheckTemplate[] checks;
    Logic[] logic;         // copied verbatim
    ParamBounds[] params;  // one entry per per-job number the user supplies
}
```

### ReadTemplate: a Read with fills

```solidity
struct ReadTemplate {
    string chainNamespace;   // "eip155"
    string chainId;
    uint16 minConfirmations;
    address target;
    bytes4 selector;
    bytes args;              // with placeholder words
    Fill[] fills;            // what to write into args per job
    bytes outputs;
    uint8[] field;
    ReadAt at;               // copied
}

enum FillSource { CEA, PARAM }

struct Fill {
    uint8 word;          // overwrites args[32·word : 32·word + 32]
    FillSource source;
    uint8 param;         // PARAM only: index into the job's params
}
```

| Fill source | Word written |
|---|---|
| `CEA` | the AGW's CEA **on this read's chain**, as a 32-byte word |
| `PARAM` | the job's `params[param]`, as a 32-byte word (two's complement for negatives) |

A CEA fill is how criteria name "this user's account": `balanceOf(CEA)`, `ownerOf(tokenId) == CEA`, and so on.
The CEA is derived per read chain, so one template can read two chains, each with that chain's CEA.

### CheckTemplate: a Check with a target source

```solidity
enum TargetSource { FIXED, PRINCIPAL_BPS, PARAM, CEA }

struct CheckTemplate {
    uint8[] left;        // copied
    uint8[] right;       // copied
    Evaluation evaluation;
    Operation operation;
    TargetSource source;
    int256 value;
}
```

| Source | `value` means | Target |
|---|---|---|
| `FIXED` | the target | `value` |
| `PRINCIPAL_BPS` | basis points of the principal | `principal × value / 10 000`, rounded down |
| `PARAM` | an index into the job's params | `params[value]` |
| `CEA` | unused | the AGW's CEA on the chain of the check's first `left` read, as `int256(uint160(cea))` |

`PRINCIPAL_BPS` is how criteria scale with the job's size ("at least 99.99% of the principal arrived").

### ParamBounds: per-job numbers

```solidity
struct ParamBounds { int256 min; int256 max; }   // inclusive
```

A template may declare numbers the user picks per job (a minimum swap output, a tick range, …). The job supplies
exactly one value per entry, each inside its bounds. The values feed `PARAM` fills and `PARAM` targets. Units are
the provider's, described in the card's metadata.

---

## Building a JobSpec

[`JobSpecBuilder.build`](../../src/agentic-commerce-8183/libraries/JobSpecBuilder.sol), called at `startJob`
step 9 and by both preview views:

1. **Decode** the template. Undecodable bytes revert in `abi.decode`.
2. **Params**: `params.length == template.params.length`, else `ParamCountMismatch(expected, actual)`; each
   `min ≤ params[i] ≤ max`, else `ParamOutOfRange(i, value)`.
3. **CEAs**: for each read with a CEA fill, and the first `left` read of each `CEA`-target check, get
   `expectedCEAOf(agw, keccak256(namespace ":" chainId))` from the marketplace, once per read. A chain without a
   CEA deployment reverts `ChainNotSupported(chainHash)`.
4. **Reads**: copy each read, `at` included; copy its `args` into a fresh buffer; apply each fill. A fill must
   satisfy `32·word + 32 ≤ args.length`, else `FillOutOfBounds(read, fill)`. This bound check is what makes the one
   inline-assembly `mstore` safe.
5. **Checks**: copy `left`, `right`, `evaluation`, `op`; resolve the target. For `PRINCIPAL_BPS`, if
   `principal > type(uint256).max / bps`, revert `TargetOverflow(check)`. Once the product fits, the quotient is at
   most `uint256.max / 10 000`, which always fits in `int256`, so the cast cannot truncate.
6. **Logic** copied verbatim. `executeBy`, `failFinalAt = executeBy + settleWindow`, `origin`, and
   `mutability = NONE`.
7. Return `abi.encode(spec)`.

**Not checked:** whether the criteria make sense or can be run. That covers caps on the number of reads, checks,
logic entries or side terms; check sides that don't fit their type, point past the reads, are out of order or
overlap; outputs that are not valid type codes; fields that point nowhere; reads no check uses; unreachable logic
entries; and trivially true criteria. All of these build as given (`test_JB08_doesNotJudgeTheTemplate`), except
where building needs an index: an empty `left` panics, as does an out-of-range fill `param`, `PARAM` target, or
first `left` read of a `CEA`-target check. The caps `MAX_READS` (32), `MAX_CHECKS` (16) and `MAX_LOGIC` (32)
in JobSpecTypes are the evaluator's, not enforced here: `JobSpecLib.validate` refuses a spec that
breaks them, or any rule above, when the UniversalEvaluator freezes it at `fund` (`JobSpecErrors`). Anything that
reverts here makes `startJob` and both previews of that card revert.

The result is deterministic for a given card version, job inputs and CEA configuration
(`testFuzz_JB11_deterministic`).

---

## Worked example: a lending card

"Deposit the principal into Aave v3 on Sepolia, at a supply rate of at least 4%." This is the test fixture's card
(`_lendingTemplate` in [`UniversalMarketplace.t.sol`](../../test/8183-tests/UniversalMarketplace.t.sol)) and the V2
design doc's lending example.

**Card:** `chainNamespace = "eip155:11155111"`, `settleWindow = 2 h`.

**Rules:** asset pUSDC (Sepolia); one allowed call `Pool.supply(address,uint256,address,uint16)` with the
beneficiary (`onBehalfOf`) pinned at offset 68; one approval, USDC → Pool, `capIsPrincipal`.

**Template:**

```
reads[0]  eip155 / 11155111, 12 confirmations, POST_EXECUTION
          aUSDC.balanceOf(address)          args = 32 zero bytes   fills = [word 0 ← CEA]
          outputs = [TUPLE 1, UINT]         field = [0]
reads[1]  eip155 / 11155111, 12 confirmations, POST_EXECUTION
          Pool.getReserveData(address)      args = abi.encode(USDC) fills = []
          outputs = [TUPLE 1, TUPLE 15, (TUPLE 1, UINT), UINT×7, ADDRESS×4, UINT×3]
          field = [0, 2]                    (the struct's 3rd field: currentLiquidityRate)
checks[0] left [0], COMPARE, GREATER_OR_EQUAL, PRINCIPAL_BPS, 9999     "deposited ≥ 99.99% of principal"
checks[1] left [1], COMPARE, GREATER_OR_EQUAL, FIXED, 0.04e27          "rate ≥ 4% (ray)"
logic     [ ALL(1, 2), COMPARE 0, COMPARE 1 ]
params    []
```

**A job:** principal 500 USDC (`500e6`), `executeBy = now + 1 h`, for wallet 0 of the user.

**Built JobSpec:**

```
reads[0].args    = abi.encode(CEA(agw, "eip155:11155111"))
checks[0].target = 500e6 × 9999 / 10 000 = 499 950 000
checks[1].target = 0.04e27
logic            = [ ALL(1, 2), COMPARE 0, COMPARE 1 ]
mutability       = NONE
executeBy        = now + 1 h
failFinalAt      = now + 3 h
origin           = keccak256(abi.encode(marketplace, cardId, 1, 500e6))
```

The evaluator later passes the job if both checks pass at the end blocks fixed at `submit`: the CEA's aUSDC
balance is at least 499.95 USDC, and Aave's current supply rate is at least 4%.

`test_MC01_lendingExample_equalsV2Doc` builds the same template on Ethereum (the design doc's chain) and compares
the result, field by field, with the V2 design doc's hand-written JobSpec.

## Worked example: a swap card with a user param

"The CEA receives at least `minOut` WETH." `minOut` is chosen by the user per job.

```
reads[0]  eip155 / 11155111, 3 confirmations, POST_EXECUTION
          WETH.balanceOf(address)   args = 32 zero bytes   fills = [word 0 ← CEA]
          outputs = [TUPLE 1, UINT]  field = [0]
reads[1]  as reads[0], but PRE_EXECUTION                "the balance at fund"
checks[0] left [0], right [1], NUMBER, GREATER_OR_EQUAL, PARAM, 0     "balance grew by ≥ params[0]"
logic     [ COMPARE 0 ]
params    [ {min: 1, max: 1e30} ]
```

A job with `params = [0.38e18]` gets `checks[0].target = 0.38e18`. `NUMBER` subtracts read 1 (the CEA's WETH at
`fund`) from read 0 (after the provider's execution), so WETH the CEA already held doesn't count. A job with
`params = [0]` reverts `ParamOutOfRange(0, 0)`; one with no params reverts `ParamCountMismatch(1, 0)`.

---

## What the SDK must do

- **Build templates from ABIs**: `outputs` and `field` from the function's ABI and the chosen return field, and
  CEA fills where the CEA appears in the arguments.
- **Render every check in words before the user signs.** The template is not judged on-chain; what the user sees
  is their protection, together with the verified tag.
- **Use `previewIntent`** to get the exact intent to sign, so the signed calldata hash covers the built criteria.
- **Derive the CEA independently** from the destination `CEAFactory` for the session's `expectedCEA`, and treat a
  disagreement with `expectedCEAOf` as an error.
