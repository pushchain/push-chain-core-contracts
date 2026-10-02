// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {OwnerIntent, Session} from "./external/IAGW.sol";
import {IAGWFactory} from "./external/IAGWFactory.sol";
import {IAgenticCommerce} from "./IAgenticCommerce.sol";
import {IUniversalMarketplaceTerms} from "./IUniversalMarketplaceTerms.sol";
import {AgentCard, CardView, JobInputs, StartJobParams, IntentRequest} from "../libraries/Types.sol";

/// @title IUniversalMarketplace
/// @notice Agent cards, and `startJob`: one relayed call that deploys the user's AGW (if needed), grants it
///         the card's rules, and creates the ERC-8183 job with the AGW as client. Moves no funds.
/// @dev Errors live in `UniversalMarketplaceErrors` (`libraries/Errors.sol`); types in `libraries/Types.sol`.
interface IUniversalMarketplace {
    // ═══ UM_1: EVENTS ═══

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

    // ═══ UM_2: ADMIN ═══

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

    // ═══ UM_3: CARDS ═══

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

    // ═══ UM_4: JOBS ═══

    /// @notice Deploys the AGW if needed, grants the card's rules, and creates the job. Moves no funds.
    /// @return jobId The kernel job.
    /// @return agw The AGW, the job's client.
    /// @return rulesId The granted rules (the engine's permissionId).
    function startJob(StartJobParams calldata p) external returns (uint256 jobId, address agw, bytes32 rulesId);

    // ═══ UM_5: VIEWS ═══

    /// @notice The card, its content, version and tags. The zero view for an unknown card.
    function getCard(uint256 cardId) external view returns (CardView memory);

    /// @notice Whether the admin has verified the card at its current version.
    function isCardVerified(uint256 cardId) external view returns (bool);

    /// @notice Whether the admin has disabled the card. Permanent.
    function isCardAdminDisabled(uint256 cardId) external view returns (bool);

    /// @notice Whether `startJob` is paused for cards on `chainHash`.
    function isUniversalPaused(bytes32 chainHash) external view returns (bool);

    /// @notice 1 at registration, +1 per modification, 0 for an unknown card.
    function cardVersion(uint256 cardId) external view returns (uint256);

    /// @notice The AGW factory. Set once, at initialization.
    function AGW_FACTORY() external view returns (IAGWFactory);

    /// @notice The ERC-8183 kernel. Set once, at initialization.
    function KERNEL() external view returns (IAgenticCommerce);

    /// @notice The rules-side helper (UniversalMarketplaceTerms). Set once, at initialization.
    function TERMS() external view returns (IUniversalMarketplaceTerms);

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
