// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {AllowedCall, OwnerIntent, Session} from "./external/IAGW.sol";

/// @title IUniversalMarketplaceErrors
/// @notice Every error the marketplace, its Terms helper and JobSpecBuilder raise. One declaration, shared, so
///         a helper's revert bubbles through the marketplace with the selector its callers expect.
interface IUniversalMarketplaceErrors {
    // ───────── config and cards ─────────

    error ZeroAddress();
    error HookNotWhitelisted();
    error CardInactive();
    error NotProvider();
    error CardAdminDisabled(uint256 cardId);
    error ChainNotSupported(bytes32 chainHash);
    error ChainPaused(bytes32 chainHash);
    /// @dev The single registration error; every `reason` is listed in PRD 09 Appendix A.
    error InvalidCard(string reason);
    /// @dev `provided` is not the card's `current` version (startJob, verifyAgentCard).
    error CardVersionMismatch(uint256 provided, uint256 current);
    /// @dev `modifyAgentCard` tried to change the card's execution chain.
    error CardIdentityImmutable();

    // ───────── startJob: the job ─────────

    error PrincipalOutOfRange();
    error ExpiryOutOfRange();
    error ExecuteByOutOfRange();
    /// @dev The configured evaluator is the card's provider (the evaluator changed after registration).
    error ProviderIsEvaluator();
    error ParamCountMismatch(uint256 expected, uint256 actual);
    error ParamOutOfRange(uint256 index, int256 value);
    /// @dev A PRINCIPAL_BPS target overflows: `principal × bps` does not fit uint256.
    error TargetOverflow(uint256 check);
    /// @dev The card's template writes fill `fill` of read `read` outside that read's args.
    error FillOutOfBounds(uint256 read, uint256 fill);

    // ───────── startJob: wallet and intent (same shapes as the AGW's errors of the same name) ─────────

    error IntentWalletMismatch(address expected, address provided);
    error ExecutorMismatch(address expected, address actual);
    error IntentSessionMismatch(bytes32 actual);
    error IntentExecMismatch(bytes32 actualCalldataHash);
    error AGWBusy(address agw, uint256 jobId);
    error AGWMismatch(address expected, address actual);
    error WalletOwnerMismatch(address expected, address actual);

    // ───────── startJob: rules ⊆ card ─────────

    error AgentMismatch();
    error ActionCount();
    error PolicyShape(uint256 i);
    error ChainMismatch(uint256 i);
    error AssetMismatch();
    error PCCapMismatch();
    error ActionsMismatch();
    error CapMismatch();
    error ExpiryMismatch();
    error ExpectedCEAMismatch(address expected, address actual);

    // ───────── startJob: the created job ─────────

    error UnexpectedJobCount(uint256 before, uint256 afterCount);
    error JobMismatch();
}

/// @title IUniversalMarketplace
/// @notice Agent cards, and `startJob`: one relayed call that deploys the user's AGW (if needed), grants it
///         the card's rules, and creates the ERC-8183 job with the AGW as client. Moves no funds.
interface IUniversalMarketplace is IUniversalMarketplaceErrors {
    // ─────────────────────────────── types ───────────────────────────────

    /// @notice One standing offer from one provider: one job type on one EVM execution chain.
    /// @dev - `provider` and `active` are contract-written; caller values are ignored.
    ///      - `chainNamespace` is immutable after registration.
    struct AgentCard {
        address provider; // msg.sender at registration · the rules agent · 8183 provider · fee recipient
        bytes32 jobType; // e.g. keccak256("LENDING_DEPOSIT")
        string metadataURI; // off-chain JSON: name, summary, ABIs, criteria in words, param units
        bytes32 metadataHash; // keccak256 of that JSON
        string chainNamespace; // CAIP-2 execution chain, "eip155:<id>", never Push
        uint256 fee; // reference price in the kernel's payment token; enforced at 8183 fund
        uint256 principalMin; // the job's size, in the rules asset's units
        uint256 principalMax;
        uint32 minDuration; // job expiry window, seconds from startJob
        uint32 maxDuration;
        uint32 minExecuteWindow; // executeBy ≥ startJob time + this
        uint32 settleWindow; // failFinalAt = executeBy + this; executeBy + this ≤ expiredAt
        bool active;
    }

    /// @notice A token allowance the agent needs on the execution chain.
    /// @dev Executed by the OWNER in the funding transaction the SDK builds; never agent authority.
    struct Approval {
        address token; // on the execution chain
        address spender;
        bool capIsPrincipal; // true: amount = principal (cap must be 0) · false: amount = cap (> 0)
        uint256 cap;
    }

    /// @notice What the agent needs. `expectedCEA`, `validUntil` and the amount caps are per job.
    struct RulesCardTerms {
        address asset; // PRC20 whose SOURCE_CHAIN_NAMESPACE() == card.chainNamespace
        uint256 maxPCPerCall;
        AllowedCall[] allowedCalls;
        Approval[] approvals;
    }

    /// @notice A destination chain's CEA factory and proxy implementation, for `expectedCEAOf`.
    struct CEADeployment {
        address ceaFactory;
        address ceaProxyImpl;
    }

    /// @notice The full card, for the SDK. One call.
    struct CardView {
        AgentCard card;
        bytes rulesTerms; // abi.encode(RulesCardTerms)
        bytes evaluation; // abi.encode(EvaluationTemplate)
        uint256 version;
        bool verified;
        bool adminDisabled;
    }

    /// @notice Per-job inputs the owner signs (inside the createJob calldata and the session).
    struct JobInputs {
        uint256 principal;
        uint48 expiredAt;
        uint48 executeBy;
        int256[] params; // one per template param, within its bounds
    }

    /// @notice Everything `startJob` needs.
    struct StartJobParams {
        uint256 cardId;
        uint256 cardVersion; // the version the owner signed against
        JobInputs job;
        Session session;
        OwnerIntent intent;
        bytes sig;
        string label; // wallet label, used only when deploying
    }

    /// @notice What `previewIntent` needs to build the OwnerIntent the owner signs.
    struct IntentRequest {
        uint256 cardId;
        address owner;
        uint96 index;
        JobInputs job;
        uint48 deadline;
        uint256 signerChainId;
    }

    /// @notice `initialize` arguments. Every field must be non-zero.
    struct InitParams {
        address agwFactory;
        address kernel;
        address hook; // must be whitelisted on the kernel
        address evaluator; // the marketplace-wide 8183 evaluator
        address terms; // UniversalMarketplaceTerms
        address admin; // receives DEFAULT_ADMIN_ROLE and ADMIN_ROLE
    }

    // ─────────────────────────────── events ───────────────────────────────

    /// @dev `rulesHash = keccak256(rulesTerms)`, `evaluationHash = keccak256(evaluation)`.
    event CardRegistered(
        uint256 indexed cardId,
        address indexed provider,
        bytes32 indexed jobType,
        string chainNamespace,
        bytes32 rulesHash,
        bytes32 evaluationHash,
        bytes32 metadataHash,
        uint256 fee
    );
    /// @notice The provider changed the card. `version` is the new version; the verified tag is cleared.
    event CardModified(
        uint256 indexed cardId,
        uint256 version,
        bytes32 rulesHash,
        bytes32 evaluationHash,
        bytes32 metadataHash,
        uint256 fee
    );
    event CardStatusChanged(uint256 indexed cardId, bool active);
    event CardDisabledByAdmin(uint256 indexed cardId);
    /// @notice The admin verified the card AT `version`. Any later modification clears the tag.
    event CardVerified(uint256 indexed cardId, uint256 version);
    /// @notice The verified tag was removed: by the admin, by a modification, or by `adminDisableCard`.
    event CardVerificationRevoked(uint256 indexed cardId);
    event HookUpdated(address hook);
    event EvaluatorUpdated(address evaluator);
    event CEADeploymentSet(bytes32 indexed chainHash, address ceaFactory, address ceaProxyImpl);
    event UniversalChainPaused(bytes32 indexed chainHash, bool paused);
    event JobStarted(
        uint256 indexed cardId,
        address indexed owner,
        address indexed agw,
        uint256 jobId,
        bytes32 rulesId,
        uint256 principal,
        uint256 cardVersion
    );

    // ─────────────────────────────── admin ───────────────────────────────

    /// @notice Sets the hook every new job is created with. Must be whitelisted on the kernel.
    function setHook(address hook) external;

    /// @notice Sets the evaluator every new job is created with.
    function setEvaluator(address evaluator) external;

    /// @notice Registers a destination chain's CEA deployment; a chain without one cannot carry cards.
    function setCEADeployment(bytes32 chainHash, address ceaFactory, address ceaProxyImpl) external;

    /// @notice Pauses `startJob` for cards on `chainHash` (e.g. during a destination CEA rotation).
    function setUniversalPaused(bytes32 chainHash, bool paused) external;

    /// @notice Pauses card registration, modification and `startJob`. Admin functions stay live.
    function pause() external;

    /// @notice Lifts `pause`.
    function unpause() external;

    /// @notice Permanently disables a card and clears its verified tag.
    function adminDisableCard(uint256 cardId) external;

    /// @notice Tags the card verified at `version`, which must be its current version.
    function verifyAgentCard(uint256 cardId, uint256 version) external;

    /// @notice Clears the verified tag. Idempotent.
    function revokeAgentCardVerification(uint256 cardId) external;

    // ─────────────────────────────── cards ───────────────────────────────

    /// @notice Registers a card with its content. The caller becomes its provider.
    /// @param c The card; `provider` and `active` are ignored.
    /// @param rulesTerms `abi.encode(RulesCardTerms)`.
    /// @param evaluation `abi.encode(EvaluationTemplate)`.
    function registerCard(AgentCard calldata c, bytes calldata rulesTerms, bytes calldata evaluation)
        external
        returns (uint256 cardId);

    /// @notice Replaces every mutable field and both content blobs; bumps the version, clears the verified tag.
    function modifyAgentCard(uint256 cardId, AgentCard calldata c, bytes calldata rulesTerms, bytes calldata evaluation)
        external;

    /// @notice The provider switches the card on or off. An admin-disabled card cannot be switched on.
    function setCardActive(uint256 cardId, bool active) external;

    /// @notice The card, its content, version and tags. The zero view for an unknown card.
    function getCard(uint256 cardId) external view returns (CardView memory);

    /// @notice Whether the admin has verified the card at its current version.
    function cardVerified(uint256 cardId) external view returns (bool);

    /// @notice 1 at registration, +1 per modification, 0 for an unknown card.
    function cardVersion(uint256 cardId) external view returns (uint256);

    // ─────────────────────────────── jobs ───────────────────────────────

    /// @notice Deploys the AGW if needed, grants the card's rules, and creates the job. Moves no funds.
    /// @return jobId The kernel job.
    /// @return agw The AGW, the job's client.
    /// @return rulesId The granted rules (the engine's permissionId).
    function startJob(StartJobParams calldata p) external returns (uint256 jobId, address agw, bytes32 rulesId);

    // ─────────────────────────────── views ───────────────────────────────

    /// @notice False while the AGW's last job started here is Funded, Submitted, or Open and unexpired.
    function isAGWFree(address agw) external view returns (bool);

    /// @notice The AGW's CEA on `chainHash`. Reverts `ChainNotSupported` for a chain without a CEA deployment.
    function expectedCEAOf(address agw, bytes32 chainHash) external view returns (address);

    /// @notice The ERC-7579 single execution `startJob` makes the AGW run: `createJob` on the kernel.
    function buildCreateJobCalldata(uint256 cardId, address owner, uint96 index, JobInputs calldata job)
        external
        view
        returns (bytes32 mode, bytes memory executionCalldata);

    /// @notice The OwnerIntent the owner signs for `startJob`.
    function previewIntent(IntentRequest calldata r, Session calldata s) external view returns (OwnerIntent memory);
}
