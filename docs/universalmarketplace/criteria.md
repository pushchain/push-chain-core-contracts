# Universal Marketplace — Job criteria

How a card says what counts as "done", and how `openJob` turns that into one job's criteria. For where this fits
in the whole flow, see [`README.md`](./README.md) §7.

- [Two formats: template and JobSpec](#two-formats-template-and-jobspec)
- [The JobSpec](#the-jobspec)
- [The template](#the-template)
- [Building a JobSpec](#building-a-jobspec)
- [What the evaluator accepts](#what-the-evaluator-accepts)
- [Worked example: a lending card](#worked-example-a-lending-card)
- [Worked example: a swap card with a user param](#worked-example-a-swap-card-with-a-user-param)
- [Two-rule cards and logic trees](#two-rule-cards-and-logic-trees)
- [What the SDK must do](#what-the-sdk-must-do)

---

## Two formats: template and JobSpec

| | Template (`JobSpecTemplate`) | Criteria (`JobSpec`) |
|---|---|---|
| Where | stored on the card as `jobSpecTemplate` (`abi.encode`d, as given) | the 8183 job's `description` (`abi.encode(JobSpec)`) |
| Written by | the provider, once per card version | `JobSpecBuilder`, once per job |
| Holds | everything that is the same for every job, plus **holes** | concrete values for this job |
| Read by | the marketplace, at `openJob` / previews | the UniversalHook (validated and frozen at `fund`) and the UniversalEvaluator (judged after `submit`) |
| Defined in | [`libraries/Types.sol`](../../src/agentic-commerce-8183/libraries/Types.sol) | [`libraries/JobSpecTypes.sol`](../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol) |

**`JobSpecTypes.sol` is a byte-for-byte copy of the UniversalEvaluator's** at commit `8666c2a` of
`feat/universal-evaluator-pre-post-reads` (decision D1). `git diff 8666c2a -- src/agentic-commerce-8183/libraries/JobSpecTypes.sol`
must print nothing; a difference is a defect. Its field order is ABI: reordering or inserting a field changes
every description. To change the format, change the evaluator first, then re-copy.

---

## The JobSpec

```solidity
struct JobSpec {
    Read[] reads;
    Check[] checks;
    Logic[] logic;                        // logic[0] is the root: the job passes if it passes
    AllowedMutability allowedMutability;  // marketplace jobs are always NONE
    bytes32 origin;                       // keccak256(abi.encode(marketplace, cardId, cardVersion, principal))
}
```

The ABI head is five words: three offsets (reads, checks, logic), then `allowedMutability`, `origin`. Nothing
follows: **there is no timing in the criteria** (no `executeBy`, no `failFinalAt`; decision D3). The evaluator
doesn't read any, so nothing would enforce them (`test_MC05_fieldOrder`: head word 3 is `1` = `NONE`, word 4 is
`origin`, the reads tail starts right after the five words).

### Reads: what to look at, and when

```solidity
enum ReadAt { POST_EXECUTION, PRE_EXECUTION }

struct Read {
    string chainNamespace;    // namespace only, "eip155"
    string chainId;           // decimal, e.g. "11155111"
    uint16 minConfirmations;  // confirmations before the answer counts
    address target;           // the contract to call
    bytes4 selector;          // the view function
    bytes args;               // abi-encoded arguments
    bytes outputs;            // the function's return types, as type codes
    uint8[] field;            // which returned value, by ABI position
    ReadAt at;                // POST: at the block fixed at `submit` · PRE: at the block recorded at `fund`
}
```

A read is one view call on one chain at one moment. `POST_EXECUTION` (0, the default) measures the state after the
provider's work; `PRE_EXECUTION` (1) measures the state before it, at the block the hook records at `fund`. A
"change since funding" check reads the same call twice, once at each moment.

**`chainNamespace` here is the namespace only** (`"eip155"`), with `chainId` separate: the Read State split. That
differs from `CardRule.chainNamespace`, which is the full CAIP-2 string `"eip155:<id>"`.

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

How the evaluator turns the selected value into a number (a test-only copy of its decoder is
[`test/8183-tests/helpers/V2Decoder.sol`](../../test/8183-tests/helpers/V2Decoder.sol)):

| Leaf | Value compared |
|---|---|
| uint / int | the number (a uint above `int256.max` is "can't tell") |
| bool | 0 or 1 |
| address, bytesN | the raw word (compare with `EQUAL` / `NOT_EQUAL`) |
| bytes, string | `keccak256` of the content |
| array | its length |

### Checks: what to compare

```solidity
struct Check {
    uint8[] left;          // indexes into reads, strictly increasing
    uint8[] right;         // indexes into reads, strictly increasing, none also in left
    Evaluation evaluation; // BOOLEAN, COMPARE, NUMBER, PERCENTAGE
    Operation operation;   // EQUAL, NOT_EQUAL, GREATER_THAN, GREATER_OR_EQUAL, LESS_THAN, LESS_OR_EQUAL
    int256 target;         // in the contract's own units (basis points for PERCENTAGE)
}
```

Each side is the **sum** of its reads' values. There is no implicit baseline: a change is always `left` minus an
explicit `right`.

| `Evaluation` | Sides | Passes when |
|---|---|---|
| `BOOLEAN` | exactly 1 left, 0 right; operation `EQUAL`; target 0 or 1 | `left == target` |
| `COMPARE` | ≥ 1 left, 0 right | `Σleft op target` |
| `NUMBER` | ≥ 1 left, ≥ 1 right | `(Σleft − Σright) op target` |
| `PERCENTAGE` | ≥ 1 left, ≥ 1 right | `(Σleft − Σright) × 10 000 / Σright op target` (basis points) |

"Grew by at least X since funding" is `NUMBER` with a `POST_EXECUTION` read in `left` and a `PRE_EXECUTION` read
of the same call in `right`.

### Logic: the pass logic

```solidity
enum LogicKind { CHECK, ALL, ANY, AT_LEAST }

struct Logic {
    LogicKind kind;
    uint8 check;        // CHECK only: index into checks
    uint8[] children;   // ALL / ANY / AT_LEAST: indexes into logic, each greater than this entry's own
    uint8 k;            // AT_LEAST only: how many children must pass
}
```

`logic[0]` is the root. A `CHECK` entry is a leaf naming one check; `ALL` (AND), `ANY` (OR) and `AT_LEAST k`
combine child entries. **Every check enters the tree through a `CHECK` leaf**: an `ALL` over checks 0 and 1 is
`[ {ALL, children [1, 2]}, {CHECK 0}, {CHECK 1} ]`. Children always have a higher index than their parent, so the
tree has no cycles. A single-check job may use `[ {CHECK 0} ]` as its whole tree.

The ordinals are the evaluator's: `CHECK` 0, `ALL` 1, `ANY` 2, `AT_LEAST` 3. `LogicKind.CHECK` is the evaluator's
name; renaming it waits for the evaluator to rename first (D15).

**The marketplace never evaluates `logic`.** It copies the template's array verbatim; the semantics above are
the evaluator's, stated here so a card can be read.

### `allowedMutability`

```solidity
enum AllowedMutability { BOTH, NONE, CLIENT, PROVIDER }   // BOTH = 0
```

Who may replace a job's criteria before it is funded (the provider in `setBudget`, the client in `fund`). **The
builder always writes `NONE` (ordinal 1)**: the owner signs these exact criteria, so nobody may replace them (D2).
The template has no mutability field. `BOTH` is the zero value, so a spec that never set the flag would be
replaceable by either side; that is why it is written explicitly (`test_JB12_mutabilityAlwaysNone_logicCopied`).

### `origin`

`keccak256(abi.encode(marketplace, cardId, cardVersion, principal))`. The hook and evaluator treat it as opaque.
It ties the job to the card version it was opened from, and it is what makes an intent signed against one version
unusable on another: the version is inside the signed calldata.

---

## The template

```solidity
struct JobSpecTemplate {
    ReadTemplate[] reads;
    CheckTemplate[] checks;
    Logic[] logic;          // copied verbatim
    ParamBounds[] params;   // one entry per per-job number the user supplies
}
```

No `allowedMutability` (always `NONE`) and no timing.

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
    ReadAt at;               // last field; copied verbatim into Read.at
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

Fills apply to `PRE_EXECUTION` and `POST_EXECUTION` reads alike (`test_JB13_copiesReadAt`). A CEA fill is how
criteria name "this user's account": `balanceOf(CEA)`, `ownerOf(tokenId) == CEA`, and so on. The CEA is derived
per read chain, so one template can read two chains, each with that chain's CEA. (The SDK maps its word `WALLET`
to `FillSource.CEA` / `TargetSource.CEA`.)

### CheckTemplate: a Check with a target source

```solidity
enum TargetSource { FIXED, PRINCIPAL_BPS, PARAM, CEA }

struct CheckTemplate {
    uint8[] left;        // copied verbatim
    uint8[] right;       // copied verbatim
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
| `CEA` | unused | the AGW's CEA on the chain of the `left[0]` read, as `int256(uint160(cea))` |

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

[`JobSpecBuilder.build`](../../src/agentic-commerce-8183/libraries/JobSpecBuilder.sol), called at `openJob`
step 7 (building the batch) and by both preview views:

1. **Decode** the `JobSpecTemplate`. Undecodable bytes revert in `abi.decode`.
2. **Params**: `params.length == template.params.length`, else `ParamCountMismatch(expected, actual)`; each
   `min ≤ params[i] ≤ max`, else `ParamOutOfRange(i, value)`.
3. **CEAs**: for each read with a CEA fill, and the `left[0]` read of each `CEA`-target check, get
   `computeCEA(agw, keccak256(namespace ":" chainId))` from the marketplace, once per read. A chain without a
   CEA deployment reverts `ChainNotSupported(chainHash)`. `left[0]` is read only for a `CEA` source: a check with
   an empty `left` and another source builds (`test_JB16_emptyLeftNonCeaSource_builds`); with a `CEA` source it
   panics.
4. **Reads**: copy each read, `at` included; copy its `args` into a fresh buffer; apply each fill. A fill must
   satisfy `32·word + 32 ≤ args.length`, else `FillOutOfBounds(read, fill)`. This bound check is what makes the one
   inline-assembly `mstore` safe.
5. **Checks**: copy `left`, `right`, `evaluation`, `operation` verbatim; resolve the target. For `PRINCIPAL_BPS`,
   if `principal > type(uint256).max / bps`, revert `TargetOverflow(check)`. Once the product fits, the quotient is
   at most `uint256.max / 10 000`, which always fits in `int256`, so the cast cannot truncate.
6. **`logic`** copied verbatim; **`allowedMutability = NONE`**; **`origin`**.
7. Return `abi.encode(spec)`.

**Not checked:** whether the evaluator can run the result (decision D5, PRD 09 Z6). None of the rules in the next
section is enforced here: counts, read shapes, side indexes, the POST-read requirement, logic shape, unused reads,
checks or entries all build as given (`test_JB08_doesNotJudgeTheTemplate`). The caps `MAX_READS` (32),
`MAX_CHECKS` (16) and `MAX_LOGIC` (32) in JobSpecTypes are the evaluator's. An out-of-range index (a fill's
`param`, a `PARAM` target, a `CEA` target's `left[0]`) panics. Anything that reverts here makes `openJob` and both
previews of that card revert.

The result is deterministic for a given card version, job inputs and CEA configuration
(`testFuzz_JB11_deterministic`).

---

## What the evaluator accepts

The marketplace does not judge templates on-chain, but the UniversalHook does judge the built spec: it runs the
evaluator's `JobSpecLib.validate` inside `fund`, and a spec it refuses **reverts the funding** (the job stays
Open). A provider must therefore register only templates whose built specs pass these rules, and the SDK should
check a template against them before registering it.

From `JobSpecLib.validate` at `8666c2a`, in this order (the first failure reverts):

| Area | Rule | Evaluator error |
|---|---|---|
| Counts | reads 1–32 · checks 1–16 · logic 1–32 | `ReadCount` / `CheckCount` / `LogicCount` |
| Read chain | `chainNamespace == "eip155"`; namespace and `chainId` each 1–32 bytes | `ReadChain(read)` |
| Read confirmations | `1 ≤ minConfirmations ≤` the evaluator's `maxConfirmations` (64 in the demo configuration) | `ReadConfirmations(read)` |
| Read target | `target ≠ 0` | `ReadTarget(read)` |
| Read args | `args` ≤ 512 bytes | `ReadArgs(read)` |
| Read shape | `outputs` is exactly one `T_TUPLE` (the return list), 3–128 bytes, every code known, every tuple and fixed array non-empty, nesting ≤ 8; `field` has 1–8 indexes, each inside every tuple / fixed array it passes, and lands on a value that is not a tuple or fixed array; the return list's head fits 4 096 bytes | `ReadShape(read)` |
| Reads overall | at least one `POST_EXECUTION` read | `NoPostExecutionRead()` |
| Check sides | each side's indexes strictly increasing and `< nReads`; `left` and `right` share no read | `CheckRead(check)` |
| Check type | `BOOLEAN`: 1 left, 0 right · `COMPARE`: ≥ 1 left, 0 right · `NUMBER` / `PERCENTAGE`: ≥ 1 left, ≥ 1 right | `CheckSides(check)` |
| `BOOLEAN` | operation `EQUAL`; target 0 or 1 | `CheckOp(check)` / `CheckTarget(check)` |
| `Logic` `CHECK` | `check < nChecks`, no children | `LogicShape(entry)` |
| `Logic` `ALL` / `ANY` / `AT_LEAST` | ≥ 1 child; children strictly increasing, each `>` the entry's own index and `< nLogic`; `AT_LEAST`: `1 ≤ k ≤ children` | `LogicShape(entry)` |
| Everything used | every logic entry reachable from `logic[0]`; every check used by a reachable `CHECK`; every read used by some check | `LogicUnreachable` / `CheckUnused` / `ReadUnused` |
| Size | the description ≤ 32 768 bytes (`MAX_DESCRIPTION_LENGTH`; the evaluator checks it before `validate`, in `setSpec` and `startSnapshot`, `UniversalEvaluator.sol:215, 234` at `8666c2a`) | `SpecTooLong(length)` |

The conformance suite holds every built example to a test-only copy of this function,
[`test/8183-tests/helpers/EvaluatorSpecCheck.sol`](../../test/8183-tests/helpers/EvaluatorSpecCheck.sol) (copied
verbatim from `8666c2a`; a divergence is a finding, not something to fix there).
`test_MC06_builtSpecsPassEvaluatorValidate` builds every example template and validates it;
`test_MC07_badTemplateFailsEvaluatorValidate` shows a template with an unused read, or with no POST read, builds
but fails validation.

---

## Worked example: a lending card

"Deposit the principal into Aave v3 on Sepolia, at a supply rate of at least 4%." This is the unit fixture's card
(`_card`, `_rules` and `_lendingTemplate` in
[`UniversalMarketplace.t.sol`](../../test/8183-tests/UniversalMarketplace.t.sol)).

**Card:** jobs of 3 h to 30 days, `paymentToken` = the kernel's token. No chain on the card: it is in the rule.

**Rules:** one `CardRule` (`_cardRules` in [`helpers/RulesFixtures.sol`](../../test/8183-tests/helpers/RulesFixtures.sol)):

```
chainNamespace  "eip155:11155111"
terms.validUntil 0, terms.expectedCEA 0
assets          [ {pUSDC (Sepolia PRC20), maxPerCall: MARKER_PRINCIPAL, maxTotal: MARKER_PRINCIPAL} ]
maxGasPerCall   1e18
allowedCalls[0] USDC.approve       pins [ {4, EQ, Pool}, {36, MAX, MARKER_PRINCIPAL} ]
allowedCalls[1] Pool.supply(address,uint256,address,uint16)   pins [ {68, EQ, MARKER_WALLET} ]
allowedCalls[2] USDC.transfer      beneficiary at offset 4, no pins
```

The pUSDC asset is the card's principal: its `maxTotal` is `MARKER_PRINCIPAL`. For a 500 USDC job, the signed
session holds `{pUSDC, 500e6, 500e6}`, `validUntil = expiredAt`, `expectedCEA` = the Sepolia CEA, the approve amount
pin `bytes32(500e6)`, and the supply pin the CEA word.

**Template:**

```
reads[0]  eip155 / 11155111, 12 confirmations, POST
          aUSDC.balanceOf(address)          args = 32 zero bytes   fills = [word 0 ← CEA]
          outputs = [TUPLE 1, UINT]         field = [0]
reads[1]  eip155 / 11155111, 12 confirmations, POST
          Pool.getReserveData(address)      args = abi.encode(USDC) fills = []
          outputs = [TUPLE 1, TUPLE 15, (TUPLE 1, UINT), UINT×7, ADDRESS×4, UINT×3]
          field = [0, 2]                    (the struct's 3rd field: currentLiquidityRate)
checks[0] left [0], right [], COMPARE, GREATER_OR_EQUAL, PRINCIPAL_BPS 9999   "aUSDC ≥ 99.99% of principal"
checks[1] left [1], right [], COMPARE, GREATER_OR_EQUAL, FIXED 0.04e27        "rate ≥ 4% (ray)"
logic     [ {ALL, children [1, 2]}, {CHECK 0}, {CHECK 1} ]
params    []
```

**A job:** principal 500 USDC (`500e6`), `expiredAt` inside the card's 3 h – 30 days, for wallet 0 of the user.

**Built JobSpec:**

```
reads[0].args     = abi.encode(CEA(agw, "eip155:11155111"))
reads[*].at       = POST_EXECUTION
checks[0].target  = 500e6 × 9999 / 10 000 = 499 950 000
checks[1].target  = 0.04e27
logic             = [ {ALL, children [1, 2]}, {CHECK 0}, {CHECK 1} ]
allowedMutability = NONE
origin            = keccak256(abi.encode(marketplace, cardId, 1, 500e6))
```

The evaluator later passes the job if both checks pass: the CEA's aUSDC balance is at least 499.95 USDC, and
Aave's current supply rate is at least 4%.

`test_MC01_lendingExample_equalsV2Doc` builds the same template on Ethereum (chain `"1"`, principal 100 USDC) and
compares the result, field by field and byte for byte, with the spec written by hand. The fork test
`test_fork_openJob_realAGWv6` decodes the description of a job opened through the real AGW v6 and checks this
`logic`, `allowedMutability == NONE`, `origin`, and that the description is exactly `abi.encode(JobSpec)` with
nothing after it.

## Worked example: a swap card with a user param

"The CEA's WETH grows by at least `minOut` between funding and submission." `minOut` is chosen by the user per
job (`_swapTemplate` in the unit suite; `_swap` in [`JobSpecBuilder.t.sol`](../../test/8183-tests/JobSpecBuilder.t.sol)
on Base).

```
reads[0]  eip155 / 11155111, 3 confirmations, POST
          WETH.balanceOf(address)   args = 32 zero bytes   fills = [word 0 ← CEA]
          outputs = [TUPLE 1, UINT]  field = [0]
reads[1]  the same call, PRE
checks[0] left [0], right [1], NUMBER, GREATER_OR_EQUAL, PARAM 0     "post − pre ≥ params[0]"
logic     [ {ALL, children [1]}, {CHECK 0} ]
params    [ {min: 1, max: 1e30} ]
```

A job with `params = [0.38e18]` gets `checks[0].target = 0.38e18`; both reads get the CEA in their args
(`test_MC02_swapExample_equalsV2Doc`). Because the `right` side is a `PRE_EXECUTION` read taken at `fund`, WETH the
CEA already held doesn't count. A one-entry tree `[ {CHECK 0} ]` would be equally valid. A job with
`params = [0]` reverts `ParamOutOfRange(0, 0)`; one with no params reverts `ParamCountMismatch(1, 0)`.

## Two-rule cards and logic trees

**A two-rule card (Sepolia + Base)**, once `maxRulesPerCard ≥ 2` (README §6):
- rule 0 = the Sepolia lending rule above, which holds the principal;
- rule 1 = `eip155:84532`, with assets from Base only (no principal marker) and its calls pinned to
  `MARKER_WALLET`, which resolves to the **Base** CEA;
- the template's reads name their own chains, and CEA fills and `CEA` targets resolve per read chain
  (`test_JB15_ceaTargetUsesLeftFirstRead`).

**Logic trees** (`test_MC03_orAndAtLeastExamples`):
- Aave OR Morpho: `[ {ANY, [1, 2]}, {CHECK 0}, {CHECK 1} ]`
- (Aave deposited AND Aave ≥ 4%) OR (Morpho deposited AND Morpho ≥ 4%):
  `[ {ANY, [1, 2]}, {ALL, [3, 4]}, {ALL, [5, 6]}, {CHECK 0}, {CHECK 1}, {CHECK 2}, {CHECK 3} ]`
- at least 2 of Aave, Morpho, Spark: `[ {AT_LEAST, [1, 2, 3], k 2}, {CHECK 0}, {CHECK 1}, {CHECK 2} ]`

---

## What the SDK must do

- **Build templates from ABIs**: `outputs` and `field` from the function's ABI and the chosen return field, CEA
  fills where the CEA appears in the arguments, and `at` per read.
- **Write checks with explicit sides**: `left` / `right` instead of a single read. A "change since funding"
  check needs a `PRE_EXECUTION` read of the same call in `right`.
- **Write the logic as a tree of `CHECK` leaves**: every check is a `CHECK` entry (kind 0); `ALL` = 1, `ANY` = 2,
  `AT_LEAST` = 3.
- **Validate the template against [What the evaluator accepts](#what-the-evaluator-accepts) before registering.**
  The marketplace doesn't, and a spec the evaluator refuses can be opened but never funded.
- **Render every check and the `logic` tree in words before the user signs.** What the user sees is their
  protection, together with the verified tag.
- **Decode a job** as `JobSpec {reads, checks, logic, allowedMutability, origin}`. `allowedMutability` is always
  `NONE` (1), and there is no timing.
- **Fill the card's markers into each session** exactly as README §6.1 tables them, one session per card rule in
  rule order, and wrap each rule's terms in the v6 envelope `abi.encode(uint16 1, chain, abi.encode(UniversalTerms))`.
- **Compute `expiredAt = now + duration`** before signing; the contract checks it against the card's
  `minDuration` / `maxDuration`.
- **Use `previewIntent(request, sessions)`** to get the exact intent to sign, so the signed batch hash covers the
  built criteria and every grant.
- **Derive each CEA independently** from the destination `CEAFactory` for each session's `expectedCEA` and
  `MARKER_WALLET` pins, and treat a disagreement with `computeCEA` as an error.
