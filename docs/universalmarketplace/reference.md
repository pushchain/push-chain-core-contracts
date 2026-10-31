# Universal Marketplace — Reference

Every function, event, error, type, constant and storage slot of the Universal Marketplace package. For how they
fit together, read [`README.md`](./README.md) first. Section numbers like "§8" refer to that file. "Changed in
2.1.0" marks what differs from the retired 2.0.0 deployment.

- [UniversalMarketplace](#universalmarketplace)
  - [Initialization](#initialization)
  - [Admin functions](#admin-functions)
  - [Card functions](#card-functions)
  - [openJob](#openjob)
  - [Views](#views)
  - [Constants](#constants)
  - [Storage layout](#storage-layout)
- [UniversalMarketplaceRules](#universalmarketplacerules)
- [JobSpecBuilder](#jobspecbuilder)
- [RulesBindingHook (interim hook)](#rulesbindinghook-interim-hook)
- [Types](#types)
- [Markers and limits](#markers-and-limits)
- [Events](#events)
- [Errors](#errors)

---

## UniversalMarketplace

[`src/agentic-commerce-8183/UniversalMarketplace.sol`](../../src/agentic-commerce-8183/UniversalMarketplace.sol).
Inherits OZ `Initializable`, `AccessControlUpgradeable`, `PausableUpgradeable`, `ReentrancyGuardUpgradeable` and
`IUniversalMarketplace`. Deployed behind a `TransparentUpgradeableProxy`. It has no payable function and holds
no funds. `version()` returns `"2.1.0"`.

### Initialization

#### `constructor()`
Calls `_disableInitializers()`, so the implementation itself can never be initialized.

#### `initialize(InitParams calldata p)` — `initializer`

| Step | Effect |
|---|---|
| 1 | Reverts `ZeroAddress()` if `agwFactory`, `kernel`, `rules` or `admin` is zero. |
| 2 | Initializes AccessControl, Pausable and ReentrancyGuard. |
| 3 | Stores `AGW_FACTORY`, `KERNEL`, `RULES`. |
| 4 | `PUSH_CHAIN_HASH = keccak256("eip155:" ‖ decimal(block.chainid))`. |
| 5 | `_setHook(p.hook)`: `ZeroAddress()` if zero, `HookNotWhitelisted()` unless `KERNEL.whitelistedHooks(hook)`; emits `HookUpdated`. |
| 6 | `_setEvaluator(p.evaluator)`: `ZeroAddress()` if zero; emits `EvaluatorUpdated`. |
| 7 | `maxRulesPerCard = 1`; emits `MaxRulesPerCardUpdated(1)`. |
| 8 | Grants `DEFAULT_ADMIN_ROLE` and `ADMIN_ROLE` to `p.admin`. |

A second call reverts `InvalidInitialization()` (OZ).

### Admin functions

All are `onlyRole(ADMIN_ROLE)`; a non-admin caller gets `AccessControlUnauthorizedAccount(caller, ADMIN_ROLE)`.
None is pausable.

#### `setHook(address hook)`
Sets the hook every **new** job is created with. Reverts `ZeroAddress()` or `HookNotWhitelisted()`. Emits
`HookUpdated(hook)`. Existing jobs keep the hook the kernel recorded at creation.

#### `setEvaluator(address evaluator)`
Sets the evaluator every **new** job is created with. Reverts `ZeroAddress()`. Emits `EvaluatorUpdated(evaluator)`.
Not checked against providers: a card whose provider is now the evaluator is refused at `openJob`
(`ProviderIsEvaluator()`).

#### `setCEADeployment(bytes32 chainHash, address ceaFactory, address ceaProxyImpl)`
Records a destination chain's CEA factory and proxy implementation, which enables the chain for card rules and
for criteria reads and sets the CEA derivation (§9).

| Arguments | Effect |
|---|---|
| both zero | `delete ceaDeployment[chainHash]`: the chain then reports `ChainNotSupported(chainHash)` everywhere |
| exactly one zero | reverts `ZeroAddress()` |
| both non-zero | sets the entry |

Emits `CEADeploymentSet(chainHash, ceaFactory, ceaProxyImpl)` when it does not revert. Rotation runbook:
`pause()` → rotate on the destination → `setCEADeployment` → `unpause()`.

#### `setMaxRulesPerCard(uint8 n)` — new in 2.1.0
Sets the live cap on rules per card. Reverts `InvalidMaxRules(n)` unless `1 ≤ n ≤ MAX_RULES` (4). Emits
`MaxRulesPerCardUpdated(n)`. Applies at `registerAgentCard` and `updateAgentCard` only: lowering it leaves cards
already registered untouched (`test_MR16_setMaxRulesPerCard`). Initialized to 1; raise it only once the job hook
binds every rules set of a job at `fund` (§13.4).

#### `setAgentRating(address agent, uint256 rating)`
`_agentRating[agent] = rating`; emits `AgentRatingSet(agent, rating)`. No validation. A placeholder until
VerifiedRatings is wired.

#### `pause()` / `unpause()`
OZ Pausable. While paused, `registerAgentCard`, `updateAgentCard` and `openJob` revert `EnforcedPause()`. Admin
functions, `setAgentCardActive` and every view stay live.

#### `disableAgentCard(uint256 cardId)`
Permanently disables a card: `isAgentCardDisabled = true`, `active = false`, verified tag cleared. Reverts
`AgentCardInactive()` for an unknown card. Emits `AgentCardVerificationRevoked(cardId)` (only if it was verified),
then `AgentCardDisabled(cardId)`. Nothing re-enables it. `agentCardOf[provider]` is kept, so the provider cannot
register again.

#### `verifyAgentCard(uint256 cardId, uint256 cardVersion)`
Sets the verified tag for the card's current version.

| Revert | When |
|---|---|
| `AgentCardInactive()` | unknown card |
| `AgentCardDisabled(cardId)` | disabled card |
| `AgentCardVersionMismatch(cardVersion, current)` | `cardVersion` is not the current version, e.g. the card changed after review |

Allowed for a card its provider switched off. Emits `AgentCardVerified(cardId, cardVersion)`.

#### `revokeAgentCardVerification(uint256 cardId)`
Clears the tag. Reverts `AgentCardInactive()` for an unknown card. Idempotent: emits
`AgentCardVerificationRevoked(cardId)` only if the card was verified.

### Card functions

#### `registerAgentCard(AgentCard calldata c, bytes calldata rules, bytes calldata jobSpecTemplate) returns (uint256 cardId)` — `whenNotPaused`

| Step | Effect |
|---|---|
| 1 | `AgentCardAlreadyRegistered(msg.sender)` if `agentCardOf[msg.sender] != 0`. |
| 2 | `_validateCard(c, rules)`: the checks of README §4.2, in order; returns each rule's chain hash. |
| 3 | `cardId = ++agentCardCount` (ids start at 1). |
| 4 | Stores the card, then overwrites `provider = msg.sender` and `active = true`. |
| 5 | Stores both blobs as given and the rules' chain hashes (`_cardChainHashes`); `agentCardVersion = 1`; `agentCardOf[msg.sender] = cardId`. |
| 6 | Emits `AgentCardRegistered(cardId, msg.sender, jobType, keccak256(rules), keccak256(jobSpecTemplate), metadataHash, providerFee)`. |

`jobSpecTemplate` is **not** checked (§7.3). `rules` must decode as `CardRule[]`; undecodable bytes revert in
`abi.decode` with no data.

#### `updateAgentCard(uint256 cardId, AgentCard calldata c, bytes calldata rules, bytes calldata jobSpecTemplate)` — `whenNotPaused`

| Step | Effect / revert |
|---|---|
| 1 | `CallerIsNotProvider()` unless the card exists and `msg.sender` is its provider. |
| 2 | `AgentCardDisabled(cardId)` if disabled. |
| 3 | `_validateCard(c, rules)`, as at registration (against the current `maxRulesPerCard`). |
| 4 | Writes `jobType`, `metadataURI`, `metadataHash`, `providerFee`, `paymentToken`, `minDuration`, `maxDuration`; replaces both blobs and the chain hashes. `provider` and `active` stay. |
| 5 | `version = ++agentCardVersion[cardId]`; clears the verified tag (emits `AgentCardVerificationRevoked` if there was one). |
| 6 | Emits `AgentCardUpdated(cardId, version, keccak256(rules), keccak256(jobSpecTemplate), metadataHash, providerFee)`. |

Changed in 2.1.0: **the chains may change** (`AgentCardIdentityImmutable` is gone): the version bump voids every
intent signed against the old version (`test_ML09_update_mayMoveChains`). Opened jobs are untouched
(`test_ML12`).

#### `setAgentCardActive(uint256 cardId, bool active)`
Provider only (`CallerIsNotProvider()`, also for an unknown card). Switching on a disabled card reverts
`AgentCardDisabled(cardId)`; switching it off is allowed. Emits `AgentCardStatusChanged(cardId, active)`. Not
pausable.

### openJob

#### `openJob(OpenJobParams calldata p) returns (uint256 jobId, address agw, bytes32[] memory rulesIds)` — `whenNotPaused nonReentrant`

Deploys the AGW if needed, then, in one owner-signed batch, grants it every card rule and creates the job. The
steps, checks and errors are in §8. Records the wallet's last job, `cardOfJob`, `agwOfJob`, `_rulesOfJob` and
`cardVersionOfJob`. Emits `JobOpened(cardId, intent.owner, agw, jobId, rulesIds, principal, cardVersion)`.
`rulesIds[i]` is the rules set granted for card rule `i`.

`OpenJobParams`:

| Field | Meaning |
|---|---|
| `cardId` | the card |
| `cardVersion` | the version the owner signed against; must equal the current version |
| `job` | `JobInputs{principal, expiredAt, params}`; `principal > 0`; `expiredAt − now` inside the card's duration bounds |
| `sessions` | one SmartSession `Session` per card rule, same order, markers filled |
| `intent` | the owner-signed `OwnerIntent` (from `previewIntent`) |
| `sig` | the owner's signature over the intent |
| `label` | wallet label, used only when deploying a new wallet |

Calls made after every check, in order: `AGW_FACTORY.deployWalletWithSig` (new wallet) or `AGW_FACTORY.ownerOf`
(existing wallet); `KERNEL.jobCounter`; `AGW.executeWithSig(MODE_BATCH, batch, intent, sig)` (inside which the
wallet self-calls `grantRules` per rule, then calls `KERNEL.createJob`); `KERNEL.jobCounter`; `KERNEL.getJob`;
`AGW.SESSION_ENGINE()`; `engine.isPermissionEnabled(rulesIds[i], agw)` per rule. Before them, for an existing
wallet, `AGW.grantNonce()` is read.

### Views

| View | Returns | Notes |
|---|---|---|
| `getAgentCard(uint256 cardId)` | `AgentCardView{card, rules, jobSpecTemplate, version, verified, disabled}` | All zero for an unknown card. `rules` is `abi.encode(CardRule[])`. |
| `isAgentCardVerified(uint256 cardId)` | `bool` | Verified at the current version. |
| `isAgentCardDisabled(uint256 cardId)` | `bool` | |
| `agentCardVersion(uint256 cardId)` | `uint256` | 1 at registration, +1 per update, 0 if unknown. |
| `agentCardCount()` | `uint256` | The last card id. |
| `agentCardOf(address provider)` | `uint256` | The provider's card id; 0 for none. |
| `getAgentRating(address agent)` | `uint256` | 0 by default. |
| `maxRulesPerCard()` | `uint8` | The live cap on rules per card (new in 2.1.0). |
| `activeJobOf(address agw)` | `uint256` | The AGW's last job opened here while it is Funded, Submitted, or Open with `block.timestamp < expiredAt`; else 0 (§10). |
| `cardOfJob(uint256 jobId)` / `agwOfJob` / `cardVersionOfJob` | card id / AGW / card version | Recorded by `openJob`; zero for jobs not opened here. |
| `rulesOfJob(uint256 jobId)` | `bytes32[]` | The rules sets granted for the job, one per card rule, in rule order; empty for jobs not opened here. Changed in 2.1.0 (was one `bytes32`). |
| `ceaDeployment(bytes32 chainHash)` | `(address ceaFactory, address ceaProxyImpl)` | Zero if unconfigured or cleared. |
| `computeCEA(address agw, bytes32 chainHash)` | `address` | The AGW's CEA on that chain (§9). Reverts `ChainNotSupported(chainHash)` if unconfigured. |
| `buildCreateJobCalldata(uint256 cardId, address owner, uint96 index, JobInputs job, Session[] sessions)` | `(bytes32 mode, bytes executionCalldata)` | `(MODE_BATCH, abi.encode(Execution[]))`: exactly the batch `openJob` executes for wallet `index` of `owner`, `[grantRules(sessions[0]) … grantRules(sessions[n−1]), createJob(…)]`. Reverts `AgentCardInactive()` for an unknown card, and like the build step on a bad template or bad inputs. Does not check the session count. |
| `previewIntent(IntentRequest r, Session[] sessions)` | `OwnerIntent` | The intent to sign (§8). Nonces are read from the wallet, or 0 if not yet deployed. Reverts like `buildCreateJobCalldata`. |
| `AGW_FACTORY()`, `KERNEL()`, `RULES()` | addresses | Set once at `initialize`. |
| `PUSH_CHAIN_HASH()` | `bytes32` | `keccak256("eip155:" ‖ block.chainid)` at initialization. |
| `hook()`, `evaluator()` | addresses | Admin-settable. |
| `version()` | `string` | `"2.1.0"` (`pure`). |
| `hasRole`, `paused`, … | | OZ AccessControl and Pausable views. |

`previewIntent` output:

| Field | Value |
|---|---|
| `owner`, `index`, `deadline`, `signerChainId` | from the request |
| `wallet` | `AGW_FACTORY.predictWallet(owner, index)` |
| `executor` | the marketplace |
| `sessionHash` | `bytes32(0)`: the rules are granted inside the batch, not through the grant door |
| `mode` | `MODE_BATCH` |
| `execCalldataHash` | `keccak256` of the batch (`buildCreateJobCalldata`'s `executionCalldata`) |
| `nonceKey` | `OPENJOB_LANE` |
| `nonceSeq` | `AGW.getNonce(OPENJOB_LANE)` if deployed, else 0 |
| `grantNonce` | `AGW.grantNonce()` if deployed, else 0 (informational: the batch's grants consume `grantNonce … grantNonce + n − 1`) |

Removed in v2: `setUniversalPaused`, `isUniversalPaused`, `isAGWFree`, the public `lastJobOf`, `expectedCEAOf`,
`startJob`, `registerCard`, `modifyAgentCard`, `setCardActive`, `adminDisableCard`, `getCard`, `isCardVerified`,
`isCardAdminDisabled`, `cardVersion`, `cardCount`, `TERMS`, `pushChainHash`, `STARTJOB_LANE`.

### Constants

| Constant | Value | Use |
|---|---|---|
| `ADMIN_ROLE` | `keccak256("ADMIN_ROLE")` | every admin function |
| `OPENJOB_LANE` | `OWNER_LANE_FLAG` (`1 << 191`, imported from AGW v6) | the AGW nonce lane `openJob`'s execution uses (owner lane, key 0) |
| `MODE_BATCH` | `bytes32(bytes1(0x01))` | ERC-7579 batch, default exec type (AGW `ModeLib.encodeSimpleBatch()`): the mode `openJob` signs and executes. New in 2.1.0 |
| `MODE_SINGLE` | `bytes32(0)` | ERC-7579 single call; still public, no longer used by `openJob` (an intent in this mode fails `IntentExecMismatch`) |
| `MIN_DURATION` (internal) | `1 hours` | lower bound on a card's `minDuration` |
| `EVM_PREFIX` (internal) | `"eip155:"` | unused since the chain-namespace check moved to the rules helper, which has its own copy |
| `MAX_RULES` (file-level, `Types.sol`) | 4 | hard cap on `maxRulesPerCard` |

### Storage layout

A fresh layout for the 2.1.0 deployment (a new proxy, not an upgrade of 2.0.0): the reserved slot 14 of 2.0.0 is
dropped, and everything after it moved up one. Append-only from this layout. OZ upgradeable bases use ERC-7201
namespaced storage and occupy none of these slots, so slot 0 is the marketplace's. Pinned by
`test_MV09_storageLayout_bySlot`, which also asserts slots 23–50 are never written.

| Slot | Variable | Type |
|---|---|---|
| 0 | `AGW_FACTORY` | `IAGWFactory` |
| 1 | `KERNEL` | `IAgenticCommerce` |
| 2 | `hook` | `address` |
| 3 | `evaluator` | `address` |
| 4 | `PUSH_CHAIN_HASH` | `bytes32` |
| 5 | `RULES` | `IUniversalMarketplaceRules` |
| 6 | `agentCardCount` | `uint256` |
| 7 | `_cards` | `mapping(uint256 => AgentCard)` |
| 8 | `_agentCardRules` | `mapping(uint256 => bytes)` |
| 9 | `_jobSpecTemplates` | `mapping(uint256 => bytes)` |
| 10 | `agentCardVersion` | `mapping(uint256 => uint256)` |
| 11 | `isAgentCardVerified` | `mapping(uint256 => bool)` |
| 12 | `isAgentCardDisabled` | `mapping(uint256 => bool)` |
| 13 | `ceaDeployment` | `mapping(bytes32 => CEADeployment)` |
| 14 | `_lastJobOf` | `mapping(address => uint256)` |
| 15 | `cardOfJob` | `mapping(uint256 => uint256)` |
| 16 | `agwOfJob` | `mapping(uint256 => address)` |
| 17 | `_rulesOfJob` | `mapping(uint256 => bytes32[])` |
| 18 | `agentCardOf` | `mapping(address => uint256)` |
| 19 | `cardVersionOfJob` | `mapping(uint256 => uint256)` |
| 20 | `_agentRating` | `mapping(address => uint256)` |
| 21 | `maxRulesPerCard` | `uint8` |
| 22 | `_cardChainHashes` | `mapping(uint256 => bytes32[])`: each rule's `keccak256(chainNamespace)`, in rule order |
| 23–49 | `__gap` | `uint256[27]` |

---

## UniversalMarketplaceRules

[`src/agentic-commerce-8183/UniversalMarketplaceRules.sol`](../../src/agentic-commerce-8183/UniversalMarketplaceRules.sol),
implementing [`IUniversalMarketplaceRules`](../../src/agentic-commerce-8183/interfaces/IUniversalMarketplaceRules.sol).
Stateless and `pure`, with no admin and no upgrade. Split out of the marketplace for EIP-170. Reverts with
`UniversalMarketplaceErrors`, so its reverts bubble through the marketplace unchanged.

| Constant | Value |
|---|---|
| `MAX_ALLOWED_CALLS` | 32 (URP's allow-list bound; internal there, so mirrored) |
| `ERC20_TRANSFER` / `ERC20_APPROVE` / `ERC20_TRANSFER_FROM` | `IERC20.transfer/approve/transferFrom.selector` (`0xa9059cbb` / `0x095ea7b3` / `0x23b872dd`) |
| `ERC20_INCREASE_ALLOWANCE` | `bytes4(keccak256("increaseAllowance(address,uint256)"))` (`0x39509351`) |
| `EVM_PREFIX` | `"eip155:"` |
| `ARG0` / `ARG1` | 4 / 36: the calldata offsets of an ERC-20 call's first and second argument |
| `MAX_ASSETS`, `MAX_PINS`, `MAX_ALLOWED_CALL_PINS`, `ENVELOPE_VERSION` | 8, 8, 32, 1 (imported from AGW v6 `Types.sol`) |
| `MARKER_WALLET`, `MARKER_PRINCIPAL` | imported from the package's `Types.sol` ([Markers](#markers-and-limits)) |

#### `validateAgentCardRules(bytes calldata rules, uint256 maxRules) external pure returns (bytes32[] memory chainHashes, address[] memory tokens, bytes32[] memory tokenChains)`

Decodes `CardRule[]` with `abi.decode` (malformed bytes revert without data). Checks **in this order**; the first
failure reverts. The marketplace passes `maxRules = maxRulesPerCard`.

| # | Check | Error |
|---|---|---|
| U1 | `1 ≤ rules.length ≤ maxRules` | `RulesEmpty()` · `TooManyRules(n, maxRules)` |
| | **for each rule `i`, in order:** | |
| U2 | `chainNamespace` starts with `"eip155:"` and is longer than 7 bytes | `InvalidAgentCard("chain namespace")` |
| U3 | no earlier rule has the same `keccak256(chainNamespace)` | `DuplicateChain(i)` |
| U4 | `terms.validUntil == 0` and `terms.expectedCEA == address(0)` | `RuleHasAgent(i)` |
| R1 | `1 ≤ assets.length ≤ MAX_ASSETS` | `InvalidAgentCard("asset count")` |
| R3 | every asset's `token != address(0)` | `InvalidAgentCard("asset zero")` |
| R4 | no two assets of the rule share a token | `InvalidAgentCard("duplicate asset")` |
| R8 | `1 ≤ allowedCalls.length ≤ MAX_ALLOWED_CALLS` | `InvalidAgentCard("allow-list size")` |
| R9 | for each call `pins.length ≤ MAX_PINS`, and the sum over the rule's calls `≤ MAX_ALLOWED_CALL_PINS` | `InvalidAgentCard("too many pins")` |
| R10 | a pin with `value == MARKER_WALLET` has `op == PinOp.EQ` | `InvalidAgentCard("wallet marker op")` |
| R11 | no two calls byte-identical (`keccak256(abi.encode(call))`) | `InvalidAgentCard("duplicate call")` |
| R12 | two calls with the same `(target, selector)` both have `pins.length > 0` | `InvalidAgentCard("unpinned duplicate")` |
| R13 | no call with `selector == ERC20_INCREASE_ALLOWANCE` | `InvalidAgentCard("increaseAllowance")` |
| R14 | each `approve` has a pin `{offset 4, EQ, v}`, `v != 0` and `uint256(v) >> 160 == 0` (a clean address word, so never a marker) | `UnpinnedApprove(i, call)` |
| R15 | each `approve` has a pin `{offset 36, MAX, *}` (a literal or `MARKER_PRINCIPAL`) | `InvalidAgentCard("approve amount not capped")` |
| R16 | each `transfer` binds its recipient (offset 4) to the user's account: `hasBeneficiary && beneficiaryOffset == 4`, **or** a pin `{4, EQ, MARKER_WALLET}` | `UnpinnedTransfer(i, call)` |
| R17 | each `transferFrom` likewise at offset 36 | `UnpinnedTransfer(i, call)` |
| | **across all rules, one pass over every asset in rule order:** | |
| R6 | an asset with `maxTotal == uint256(MARKER_PRINCIPAL)` has `maxPerCall != 0` | `InvalidAgentCard("principal per-call zero")` |
| R7 | any other asset has `maxPerCall != uint256(MARKER_PRINCIPAL)` | `InvalidAgentCard("marker off principal asset")` |
| R5 | exactly one asset has `maxTotal == uint256(MARKER_PRINCIPAL)`: the principal | `NoPrincipal()` · `ManyPrincipals()` |

Returns `chainHashes[i] = keccak256(rules[i].chainNamespace)`, and every asset's `token` with the chain hash of the
rule it sits in (`tokens`, `tokenChains`, rule by rule). The marketplace then checks each chain hash is not Push and
has a CEA deployment, and each token's `SOURCE_CHAIN_NAMESPACE()` against its rule's chain (README §4.2).

Implementation notes: each per-rule check runs over every item of the rule before the next check starts. R11/R12
compare across the rule's entries (O(n²), n ≤ 32). The required pins of R14–R17 may sit anywhere in `pins[]`;
extra pins are allowed. R6 and R7 are checked inside the counting pass, so they can fire before R5's count error.
A second asset whose `maxTotal` is the marker is a second principal (`ManyPrincipals`). Changed in 2.1.0: R2 (a
`principalAsset` index) is gone; the chain-namespace check moved here from the marketplace; R14 and R16–R17 have
their own errors naming `(rule, call)`. Known limit: whether a `MARKER_PRINCIPAL` pin sits on the **principal**
token's `approve` is not checked (`IPRC20` has no source-token view); the verified tag covers it.

#### `checkRulesMatchCard(bytes calldata cardRules, Session[] calldata sessions, SessionContext calldata ctx) external pure`

`ctx` is `SessionContext{agent, principal, expiredAt, expectedCEAs}`, filled by the marketplace from the card, the
job and `computeCEA` (one CEA per card rule, in rule order). Checks **in this order**; the first failure reverts.

| # | Check | Error |
|---|---|---|
| C0 | `sessions.length == rules.length` | `SessionCountMismatch(rules.length, sessions.length)` |
| — | `ctx.expectedCEAs.length == rules.length` (built by the marketplace, so a mismatch is a bug) | `assert` (Panic 0x01) |
| | **for each pair `i` (card rule `i`, session `i`):** | |
| C1 | `keccak256(sessionValidatorInitData) == keccak256(abi.encode(ctx.agent))` | `AgentMismatch(i)` |
| C2 | `actions.length == 1` | `ActionCount(i)` |
| C3 | `actions[0].actionPolicies.length == 1` | `PolicyShape(i)` |
| C4 | let `d = actionPolicies[0].initData`: `uint256(bytes32(d[0:32])) == ENVELOPE_VERSION`, read **before any decode**; `actual = 0` if `d` is under 32 bytes | `EnvelopeVersionMismatch(i, actual)` |
| C5 | `(, string chain, bytes body) = abi.decode(d, (uint16, string, bytes))`; `keccak256(chain) == keccak256(rules[i].chainNamespace)` | `ChainMismatch(i)` |
| C6 | `t = abi.decode(body, (UniversalTerms))`; `t.assets.length == card.assets.length` | `AssetCountMismatch(i, expected, actual)` |
| C7 | for each asset `j`: same token | `AssetMismatch(i, j)` |
| C8 | for the principal asset (card `maxTotal == MARKER_PRINCIPAL`): `t.maxTotal == ctx.principal`, and `t.maxPerCall == ctx.principal` if the card's `maxPerCall` is the marker, else the card's number | `AssetMismatch(i, j)` |
| C9 | every other asset: `maxPerCall` and `maxTotal` equal the card's | `AssetMismatch(i, j)` |
| C10 | `t.maxGasPerCall == card.maxGasPerCall` | `GasCapMismatch(i)` |
| C11 | same call count; per call `target`, `selector`, `beneficiaryOffset`, `hasBeneficiary`, `maxValue`, `pins.length` equal; per pin `offset` and `op` equal | `ActionsMismatch(i)` |
| C12 | per pin: card `MARKER_WALLET` ⇒ session `bytes32(uint256(uint160(ctx.expectedCEAs[i])))`; card `MARKER_PRINCIPAL` ⇒ `bytes32(ctx.principal)`; otherwise equal | `PinMismatch(i, call, pin)` |
| C13 | `t.validUntil == ctx.expiredAt` | `ExpiryMismatch(i)` |
| C14 | `t.expectedCEA == ctx.expectedCEAs[i]` | `ExpectedCEAMismatch(i, expected, actual)` |

C11 and C12 share one loop: per call, the call fields; then per pin, offset and op, then value. Never compared: the
session's validator, policy address, action target and selector, userOp and ERC-7739 lists, paymaster flag and
salt — AGW v6 `_grantRules` pins all of them and overwrites the salt with its grant nonce (README §13.2).
Malformed bytes after a correct version word, an undecodable body or undecodable card rules revert in
`abi.decode` without data (`test_MT10_malformedInputs`). Changed in 2.1.0: every error names the rule first;
`PrincipalCapMismatch` became `AssetMismatch(rule, index)`.

---

## JobSpecBuilder

[`src/agentic-commerce-8183/libraries/JobSpecBuilder.sol`](../../src/agentic-commerce-8183/libraries/JobSpecBuilder.sol).
An external library: deployed once, linked into the marketplace, called by `DELEGATECALL`. Inlined, it would put
the marketplace over the size limit.

#### `build(bytes memory jobSpecTemplate, BuildContext memory ctx) public view returns (bytes memory)`
Returns `abi.encode(JobSpec)` for one job: the 8183 job's description. Algorithm and checks are in
[`criteria.md`](./criteria.md#building-a-jobspec). `logic`, every check's `left` / `right` and every read's `at`
are copied verbatim; `allowedMutability` is always `NONE`; there is no timing.

`BuildContext{agw, principal, params, origin}` comes from the job's inputs and
`origin = keccak256(abi.encode(marketplace, cardId, cardVersion, principal))`.

The library reads CEAs with `IUniversalMarketplace(address(this)).computeCEA(agw, chainHash)`, with
`chainHash = keccak256(abi.encodePacked(read.chainNamespace, ":", read.chainId))`. Under `DELEGATECALL`,
`address(this)` is the marketplace proxy, so this is an external call back into the marketplace. Called directly
(not through the marketplace), a template that needs a CEA reverts, because the library would ask itself. It has
no storage.

---

## RulesBindingHook (interim hook)

[`src/agentic-commerce-8183/hooks/RulesBindingHook.sol`](../../src/agentic-commerce-8183/hooks/RulesBindingHook.sol),
on [`BaseERC8183Hook`](../../src/agentic-commerce-8183/hooks/BaseERC8183Hook.sol). Not part of the marketplace. It
was the hook of the retired 2.0.0 deployment and is the hook of the unit and fork suites; the 2.1.0 deployment is
wired to the UniversalHook instead (README §12). Behind a `TransparentUpgradeableProxy`; storage continues the base
at slot 50. Like the UniversalHook, it binds **one** rules set per job at `fund`.

| Item | Behaviour |
|---|---|
| `initialize(address kernel, address agwFactory, address sessionEngine)` | All non-zero (`ERC8183HookErrors.ZeroAddress()`). Sets `KERNEL`, `AGW_FACTORY`, `SESSION_ENGINE`. |
| `beforeAction` / `afterAction` | Kernel only (`CallerIsNotKernel(caller)`). Acts only in `beforeAction(fund)`; every other action passes through. |
| `beforeAction(fund)` | In order: `fund.optParams` is exactly 32 bytes, `abi.encode(rulesId)` (`InvalidOptParams(length)`); the client is a factory AGW (`CallerIsNotAGW(caller)`); `SESSION_ENGINE.isPermissionEnabled(rulesId, client)` (`RulesNotLive(agw, rulesId)`); `activeJobOf(client) == 0` (`AGWHasLiveJob(agw, liveJobId)`). Then records the binding and the AGW's live job, and emits `RulesBound(jobId, agw, rulesId)`. |
| `rulesOfJob(uint256 jobId)` | The `rulesId` bound at `fund`, or zero. |
| `agwOfJob(uint256 jobId)` | The AGW bound at `fund`, or zero. |
| `activeJobOf(address agw)` | The AGW's last bound job while it is Funded or Submitted; else 0. Narrower than the marketplace's view (README §10). |

Storage: 50 `AGW_FACTORY`, 51 `SESSION_ENGINE`, 52 `_bindingOf` (`mapping(uint256 => Binding{agw, rulesId})`),
53 `_liveJobOf` (`mapping(address => uint256)`), 54–103 `__gap[50]`. Because the hook runs in `beforeAction`, any
revert leaves the job Open with no escrow moved. A wallet is freed by reading the kernel's job status, so an
unhooked `claimRefund` frees it too. `optParams` stays exactly `abi.encode(rulesId)`.

---

## Types

All in [`libraries/Types.sol`](../../src/agentic-commerce-8183/libraries/Types.sol), file-level. The built
criteria (`JobSpec`, `Read`, `Check`, `Logic` and the enums) are in
[`libraries/JobSpecTypes.sol`](../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol), an exact copy of the
evaluator's ([`criteria.md`](./criteria.md)). The AGW types (`OwnerIntent`, `AssetCap`, `AllowedCall`, `ArgPin`,
`PinOp`, `UniversalTerms`) are imported from `@push-agw/libraries/Types.sol`; `Execution` from
`@push-agw/libraries/ExecutionLib.sol`; the SmartSession `Session` and its parts are mirrored in
[`interfaces/external/IAGW.sol`](../../src/agentic-commerce-8183/interfaces/external/IAGW.sol).

| Type | Fields | Notes |
|---|---|---|
| `AgentCard` | `provider`, `jobType`, `metadataURI`, `metadataHash`, `providerFee`, `paymentToken`, `minDuration` (uint32), `maxDuration` (uint32), `active` | `provider` and `active` are contract-written. `providerFee` is in `paymentToken`, which must equal `KERNEL.paymentToken()`; durations in seconds. Changed in 2.1.0: no `chainNamespace`, `principalMin` / `principalMax`, `minExecuteWindow` or `settleWindow`. |
| `CardRule` | `chainNamespace` (string, full CAIP-2 `"eip155:<id>"`), `terms` (`UniversalTerms`) | One per destination chain. `terms.validUntil` and `terms.expectedCEA` are 0 in the card. A card's `rules` is `abi.encode(CardRule[])`. Replaces 2.0.0's `AgentCardRules`. |
| `CEADeployment` | `ceaFactory`, `ceaProxyImpl` | Per destination chain. |
| `AgentCardView` | `card`, `rules`, `jobSpecTemplate`, `version`, `verified`, `disabled` | `getAgentCard`'s return. |
| `JobInputs` | `principal` (> 0), `expiredAt` (uint48), `params` (int256[]) | Per-job inputs the owner signs. Changed in 2.1.0: no `executeBy`. |
| `OpenJobParams` | `cardId`, `cardVersion`, `job`, `sessions` (`Session[]`), `intent`, `sig`, `label` | `openJob`'s argument. Changed in 2.1.0: `sessions`, one per card rule (was one `session`). |
| `IntentRequest` | `cardId`, `owner`, `index`, `job`, `deadline`, `signerChainId` | `previewIntent`'s argument. |
| `InitParams` | `agwFactory`, `kernel`, `hook`, `evaluator`, `rules`, `admin` | `initialize`'s argument. |
| `SessionContext` | `agent`, `principal`, `expiredAt`, `expectedCEAs` (`address[]`) | The rules helper's per-job context; one CEA per card rule. Changed in 2.1.0: no `chainHash`; `expectedCEA` became `expectedCEAs`. |
| `FillSource`, `Fill`, `ReadTemplate`, `TargetSource`, `CheckTemplate`, `ParamBounds`, `JobSpecTemplate`, `BuildContext` | | The criteria template; see [`criteria.md`](./criteria.md). `ReadTemplate` ends with `ReadAt at`; `CheckTemplate` is `{left, right, evaluation, operation, source, value}`; `JobSpecTemplate` is `{reads, checks, logic, params}`; `BuildContext` is `{agw, principal, params, origin}`. |

Deleted in v2: `Approval`, `RulesCardTerms`, `CardView`, `StartJobParams`, `EvaluationTemplate`, and the local
copies of `OwnerIntent`, `OWNER_LANE_FLAG`, `AllowedCall`, `UniversalTerms`. Deleted in 2.1.0: `AgentCardRules`.

---

## Markers and limits

Published constants in [`libraries/Types.sol`](../../src/agentic-commerce-8183/libraries/Types.sol); the SDK uses
the same values. Pinned by `test_naming_markers`.

| Constant | Value | Meaning in a card |
|---|---|---|
| `MARKER_WALLET` | `0x38beb8621ef19c2ac125b45b1ac07225511365301161eb56ac7a21aa8641cf5a` = `keccak256("push.marketplace.marker.WALLET")` | "the user's account (CEA) on **this rule's** chain". EQ pins only (R10). |
| `MARKER_PRINCIPAL` | `0xc12ba2e9bfe16dd303c04d7f517245a6b49fd69f9d0e5c82d14be8c18ef34d52` = `keccak256("push.marketplace.marker.PRINCIPAL")` | "this job's principal". Pins (EQ or MAX) and the principal asset's caps, as `uint256`. The one asset across all rules whose `maxTotal` is this marker **is** the principal. |
| `MAX_RULES` | `4` | hard cap on rules per card; the live cap is `maxRulesPerCard` |

How each marker is filled is the table in README §6.1. Other constants: `ENVELOPE_VERSION` 1, `MAX_ASSETS` 8,
`MAX_PINS` 8, `MAX_ALLOWED_CALL_PINS` 32 (AGW `Types.sol`); `MAX_ALLOWED_CALLS` 32 (rules helper); `OPENJOB_LANE`
`OWNER_LANE_FLAG` (`1 << 191`); `MODE_BATCH` `bytes32(bytes1(0x01))`; `version()` `"2.1.0"`.

---

## Events

Emitted by the marketplace (declared in `IUniversalMarketplace`, banner UM_1):

| Event | Emitted by |
|---|---|
| `AgentCardRegistered(uint256 indexed cardId, address indexed provider, bytes32 indexed jobType, bytes32 rulesHash, bytes32 jobSpecHash, bytes32 metadataHash, uint256 providerFee)` | `registerAgentCard`. Changed in 2.1.0: no `chainNamespace` |
| `AgentCardUpdated(uint256 indexed cardId, uint256 version, bytes32 rulesHash, bytes32 jobSpecHash, bytes32 metadataHash, uint256 providerFee)` | `updateAgentCard` |
| `AgentCardStatusChanged(uint256 indexed cardId, bool active)` | `setAgentCardActive` |
| `AgentCardDisabled(uint256 indexed cardId)` | `disableAgentCard` |
| `AgentCardVerified(uint256 indexed cardId, uint256 version)` | `verifyAgentCard` |
| `AgentCardVerificationRevoked(uint256 indexed cardId)` | `revokeAgentCardVerification`, `updateAgentCard`, `disableAgentCard` (only when a tag is cleared) |
| `AgentRatingSet(address indexed agent, uint256 rating)` | `setAgentRating` |
| `HookUpdated(address hook)` | `initialize`, `setHook` |
| `EvaluatorUpdated(address evaluator)` | `initialize`, `setEvaluator` |
| `MaxRulesPerCardUpdated(uint8 n)` | `initialize` (with 1), `setMaxRulesPerCard`. New in 2.1.0 |
| `CEADeploymentSet(bytes32 indexed chainHash, address ceaFactory, address ceaProxyImpl)` | `setCEADeployment` (both zero when clearing) |
| `JobOpened(uint256 indexed cardId, address indexed owner, address indexed agw, uint256 jobId, bytes32[] rulesIds, uint256 principal, uint256 cardVersion)` | `openJob`. Changed in 2.1.0: `bytes32[] rulesIds` (was `bytes32 rulesId`) |

`rulesHash = keccak256(rules)` and `jobSpecHash = keccak256(jobSpecTemplate)`, so an indexer can check the blobs
returned by `getAgentCard`. Removed: `UniversalChainPaused`. The hook emits
`RulesBound(uint256 indexed jobId, address indexed agw, bytes32 indexed rulesId)`. OZ emits `RoleGranted`,
`Paused`, `Unpaused`, `Initialized`.

---

## Errors

All marketplace, rules-helper and builder errors are in the `UniversalMarketplaceErrors` library
([`libraries/Errors.sol`](../../src/agentic-commerce-8183/libraries/Errors.sol)). A library error has the same
selector wherever it is raised, so a helper or builder revert bubbles through `openJob` unchanged.

Each contract's ABI lists only the errors that contract itself raises. **Decode marketplace reverts with the
`UniversalMarketplaceErrors` artifact**, which lists all 48. The status column is relative to 2.0.0.

| Error | Raised by | Status |
|---|---|---|
| `ZeroAddress()` | initialize, setters, `setCEADeployment` (one zero) | unchanged |
| `HookNotWhitelisted()` | `setHook`, initialize | unchanged |
| `AgentCardInactive()` | `openJob` (inactive or unknown card), `_requireCard` (unknown card in disable, verify, revoke, `buildCreateJobCalldata`, `previewIntent`) | unchanged |
| `CallerIsNotProvider()` | update, setActive (also for an unknown card) | unchanged |
| `AgentCardDisabled(uint256 cardId)` | update, setActive(on), verify | unchanged |
| `ChainNotSupported(bytes32 chainHash)` | register/update (a rule names Push or a chain without a CEA deployment), `computeCEA` (so also `openJob` and the builder) | unchanged |
| `InvalidAgentCard(string reason)` | register/update, rules helper | unchanged; reasons below |
| `AgentCardVersionMismatch(uint256 provided, uint256 current)` | `openJob`, verify | unchanged |
| `AgentCardAlreadyRegistered(address provider)` | register | unchanged |
| `InvalidMaxRules(uint8 n)` | `setMaxRulesPerCard` | **new** |
| `RulesEmpty()`, `TooManyRules(uint256 n, uint256 max)` | rules helper U1 | **new** |
| `DuplicateChain(uint256 rule)` | rules helper U3 | **new** |
| `RuleHasAgent(uint256 rule)` | rules helper U4 | **new** |
| `NoPrincipal()`, `ManyPrincipals()` | rules helper R5 | **new** (replace `"principal asset"` / `"principal total not marker"`) |
| `UnpinnedApprove(uint256 rule, uint256 call)` | rules helper R14 | **new** (was `"approve spender not pinned"`) |
| `UnpinnedTransfer(uint256 rule, uint256 call)` | rules helper R16, R17 | **new** (was `"erc20 transfer recipient"` / `"erc20 transferFrom recipient"`) |
| `ZeroPrincipal()` | `openJob` | **new** |
| `ExpiryOutOfRange()`, `ProviderIsEvaluator()` | `openJob` | unchanged |
| `ParamCountMismatch(uint256 expected, uint256 actual)`, `ParamOutOfRange(uint256 index, int256 value)`, `TargetOverflow(uint256 check)`, `FillOutOfBounds(uint256 read, uint256 fill)` | builder | unchanged |
| `IntentWalletMismatch(address expected, address provided)`, `ExecutorMismatch(address expected, address actual)`, `AGWMismatch(address expected, address actual)`, `WalletOwnerMismatch(address expected, address actual)` | `openJob` | unchanged |
| `IntentSessionMismatch(bytes32 actual)` | `openJob`: the intent's `sessionHash` is not 0 | now always carries `bytes32(0)` |
| `IntentExecMismatch(bytes32 actualCalldataHash)` | `openJob`: the intent's mode is not `MODE_BATCH`, its `execCalldataHash` is not the batch's, or its `nonceKey` is not `OPENJOB_LANE` | unchanged |
| `WalletHasActiveJob(address agw, uint256 jobId)` | `openJob` step 6 | unchanged |
| `RulesNotGranted(uint256 rule)` | `openJob` step 12: rule `rule`'s computed id is not enabled on the engine | **new** |
| `SessionCountMismatch(uint256 expected, uint256 actual)` | rules helper C0 | **new** |
| `AgentMismatch(uint256 rule)`, `ActionCount(uint256 rule)`, `PolicyShape(uint256 rule)`, `ChainMismatch(uint256 rule)`, `GasCapMismatch(uint256 rule)`, `ActionsMismatch(uint256 rule)`, `ExpiryMismatch(uint256 rule)` | rules helper C1–C3, C5, C10, C11, C13 | **now carry the rule index** |
| `EnvelopeVersionMismatch(uint256 rule, uint256 actual)` | rules helper C4 | **rule index added** |
| `AssetCountMismatch(uint256 rule, uint256 expected, uint256 actual)` | rules helper C6 | **rule index added** |
| `AssetMismatch(uint256 rule, uint256 index)` | rules helper C7–C9 | **rule index added**; now also C8 |
| `PinMismatch(uint256 rule, uint256 call, uint256 pin)` | rules helper C12 | **rule index added** |
| `ExpectedCEAMismatch(uint256 rule, address expected, address actual)` | rules helper C14 | **rule index added** |
| `UnexpectedJobCount(uint256 before, uint256 afterCount)`, `JobMismatch()` | `openJob` step 11 | unchanged |
| ~~`PrincipalCapMismatch()`~~ | | **deleted** (now `AssetMismatch(rule, index)`) |
| ~~`PrincipalOutOfRange()`~~, ~~`ExecuteByOutOfRange()`~~ | | **deleted** (no principal bounds, no timing) |
| ~~`AgentCardIdentityImmutable()`~~ | | **deleted** (an update may change the chains) |

### `InvalidAgentCard` reasons

| Raised by | Reasons |
|---|---|
| marketplace | `"job type zero"`, `"metadata uri empty"`, `"metadata hash zero"`, `"payment token"`, `"provider is evaluator"`, `"duration range"`, `"asset"`, `"asset chain"` |
| rules helper | `"chain namespace"` (moved here from the marketplace), `"asset count"`, `"asset zero"`, `"duplicate asset"`, `"principal per-call zero"`, `"marker off principal asset"`, `"allow-list size"`, `"too many pins"`, `"wallet marker op"`, `"duplicate call"`, `"unpinned duplicate"`, `"increaseAllowance"`, `"approve amount not capped"` |
| deleted in 2.1.0 | `"principal range"`, `"settle window"`, `"execute window"`, `"principal asset"`, `"principal total not marker"`, `"approve spender not pinned"`, `"erc20 transfer recipient"`, `"erc20 transferFrom recipient"` |

### Hook errors

Unchanged.

| Library | Error |
|---|---|
| `RulesBindingHookErrors` | `InvalidOptParams(uint256 length)`, `CallerIsNotAGW(address caller)`, `RulesNotLive(address agw, bytes32 rulesId)`, `AGWHasLiveJob(address agw, uint256 liveJobId)` |
| `ERC8183HookErrors` | `CallerIsNotKernel(address caller)`, `ZeroAddress()` |
