// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DecimalConstants} from "./DecimalConstants.sol";
import {SafeTokenTransfers} from "./SafeTokenTransfers.sol";
import {ShareTokenUpgradeable} from "./ShareTokenUpgradeable.sol";
import {IERC7540, IERC7540Deposit, IERC7540Operator, IERC7540Redeem} from "./interfaces/IERC7540.sol";
import {IERC7575} from "./interfaces/IERC7575.sol";
import {IERC7575Errors} from "./interfaces/IERC7575Errors.sol";
import {IERC7887, IERC7887DepositCancelation, IERC7887RedeemCancelation} from "./interfaces/IERC7887.sol";

import {IVaultMetrics} from "./interfaces/IVaultMetrics.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

import {IERC1822Proxiable} from "@openzeppelin/contracts/interfaces/draft-IERC1822.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title ERC7575VaultUpgradeable
 * @dev FULLY COMPLIANT implementation of ERC7575 + ERC7540 + ERC7887 + ERC4626 standards
 *
 * STANDARDS COMPLIANCE VERIFICATION:
 *
 * - ERC7575: Multi-Asset ERC-4626 Vaults (https://eips.ethereum.org/EIPS/eip-7575)
 *    CORE SPECIFICATION REQUIREMENTS:
 *    "Multi-Asset Vaults share a single `share` token with multiple entry points
 *     denominated in different `asset` tokens."
 *    "Entry points SHOULD NOT be ERC-20" - COMPLIANT: Vaults implement ERC4626/7575, not ERC-20
 *    "Each entry point must implement share() method" - IMPLEMENTED
 *    "Share single share token across multiple entry points" - IMPLEMENTED: ShareTokenUpgradeable
 *
 * - ERC7540: Asynchronous Tokenized Vault Standard (https://eips.ethereum.org/EIPS/eip-7540)
 *    CORE SPECIFICATION REQUIREMENTS:
 *    "Transfers `assets` from `owner` into the Vault and submits a Request for asynchronous `deposit`" - IMPLEMENTED
 *    "Assumes control of `shares` from `owner` and submits a Request for asynchronous `redeem`" - IMPLEMENTED
 *    "Grants or revokes permissions for `operator` to manage Requests on behalf of the `msg.sender`" - IMPLEMENTED
 *    LIFECYCLE: Pending → Claimable → Claimed (no short-circuiting) - COMPLIANT
 *
 * - ERC7887: Asynchronous Tokenized Vault Cancelation (https://eips.ethereum.org/EIPS/eip-7887)
 *    CORE SPECIFICATION REQUIREMENTS:
 *    "Cancel pending deposit or redeem requests with asynchronous lifecycle" - IMPLEMENTED
 *    "Pending → Claimable → Claimed state transitions (no short-circuiting)" - COMPLIANT
 *    "Block new deposit/redeem requests while cancelation is pending" - IMPLEMENTED
 *    "Cancelations only work on Pending requests, not Claimable" - COMPLIANT
 *
 * - ERC4626: Complete tokenized vault functionality + ERC165 interface detection
 *
 * SECURITY FEATURES:
 * - Asynchronous flows prevent flash loan attacks
 * - Comprehensive reentrancy protection
 * - Multi-signature operator delegation system
 * - Investment vault integration for yield generation
 * - Request blocking prevents race conditions in cancelations
 * - Upgradeable with proper storage layout
 */
contract ERC7575VaultUpgradeable is Initializable, ReentrancyGuardTransient, Ownable2StepUpgradeable, IERC7540, IERC7887, IERC165, IVaultMetrics, IERC7575Errors, IERC20Errors {
    using Math for uint256;
    using SafeERC20 for IERC20Metadata;
    using EnumerableSet for EnumerableSet.AddressSet;

    // Note: Common errors are now inherited from IERC7575Errors interface

    // Events from IERC7540 are inherited from the interfaces
    // Additional custom events for ERC4626 compatibility
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    // Investment management events
    event AssetsInvested(uint256 indexed amount, uint256 indexed shares, address indexed investmentVault);
    event AssetsWithdrawnFromInvestment(uint256 indexed requested, uint256 indexed actual, address indexed investmentVault);

    uint256 internal constant REQUEST_ID = 0;

    // Storage slot for Vault-specific data (ERC-7201 namespaced storage).
    // = keccak256(abi.encode(uint256(keccak256("erc7575.vault.storage")) - 1)) & ~bytes32(uint256(0xff))
    // Precomputed literal (abi.encode is not a constant expression); the trailing 0x00 byte reserves a
    // 256-slot gap so the struct cannot collide with mapping/array data laid out from this base.
    bytes32 private constant VAULT_STORAGE_SLOT = 0xbb51f1ae7e7620402e5a07ea3027acf79ca69fc4b9ffaa8b9bd87595a07ccf00;
    address private immutable __self = address(this);

    error UUPSUnauthorizedCallContext();
    error UUPSUnsupportedProxiableUUID(bytes32 slot);

    struct VaultStorage {
        // Storage slot optimization: pack address + uint64 + bool in single 32-byte slot
        address asset; // 20 bytes
        uint64 scalingFactor; // 8 bytes
        bool isActive; // 1 byte (fits with asset + scalingFactor: total 29 bytes + 3 bytes padding)
        uint8 assetDecimals; // 1 byte
        uint16 minimumDepositAmount; // 2 bytes
        // Remaining addresses (each takes full 32-byte slot)
        address shareToken;
        address investmentManager;
        address investmentVault;
        // Large numbers (each takes full 32-byte slot)
        uint256 totalPendingDepositAssets;
        uint256 totalClaimableRedeemAssets; // Assets reserved for users who can claim them
        uint256 totalClaimableRedeemShares; // Shares held by vault that will be burned on redeem/withdraw
        // Aggregate obligation totals that back the migrateBackingOut quiescence gate directly (so it
        // does not rely on the activeDeposit/RedeemRequesters sets, whose membership can desync across
        // interleaved fulfill/claim/cancel sequences):
        uint256 totalClaimableDepositShares; // Shares minted-to-vault for fulfilled-but-unclaimed deposits
        uint256 totalPendingRedeemShares; // Shares escrowed in the vault for pending (unfulfilled) redeems
        // ERC7540 mappings with descriptive names
        mapping(address controller => uint256 assets) pendingDepositAssets;
        mapping(address controller => uint256 shares) claimableDepositShares;
        mapping(address controller => uint256 assets) claimableDepositAssets; // Store corresponding asset amounts
        mapping(address controller => uint256 shares) pendingRedeemShares;
        mapping(address controller => uint256 assets) claimableRedeemAssets;
        mapping(address controller => uint256 shares) claimableRedeemShares;
        // Off-chain helper sets for tracking active requests (using EnumerableSet for O(1) operations)
        EnumerableSet.AddressSet activeDepositRequesters;
        EnumerableSet.AddressSet activeRedeemRequesters;
        // ERC7887 Cancelation Request Storage (simplified - requestId is always 0)
        // Deposit cancelations: controller => assets (requestId always 0)
        mapping(address controller => uint256 assets) pendingCancelDepositAssets;
        mapping(address controller => uint256 assets) claimableCancelDepositAssets;
        // Redeem cancelations: controller => shares (requestId always 0)
        mapping(address controller => uint256 shares) pendingCancelRedeemShares;
        mapping(address controller => uint256 shares) claimableCancelRedeemShares;
        // Total pending and claimable cancelation deposit assets (for totalAssets() calculation)
        uint256 totalCancelDepositAssets;
        // Total pending + claimable cancelation redeem SHARES (escrowed in the vault, owed back to the
        // canceling redeemer). Not part of totalAssets() (shares, not the underlying asset); used to
        // block decommissioning while a redeem-cancelation is outstanding.
        uint256 totalCancelRedeemShares;
        // ERC7540 operator approvals — scoped to THIS vault (per-vault, per ERC-7540).
        // Each controller approves operators for their own requests on this vault only.
        mapping(address controller => mapping(address operator => bool approved)) operators;
    }

    /**
     * @dev Returns the Vault storage struct
     */
    /**
     * @dev Returns the Vault storage struct
     * @return $ The vault storage pointer
     */
    function _getVaultStorage() private pure returns (VaultStorage storage $) {
        bytes32 slot = VAULT_STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev ERC-1822 compatibility marker used to validate future upgrades.
     * Reverts when called through a proxy so a proxy cannot be accepted as a
     * future implementation and accidentally delegatecall into itself.
     */
    function proxiableUUID() external view returns (bytes32) {
        if (address(this) != __self) revert UUPSUnauthorizedCallContext();
        return ERC1967Utils.IMPLEMENTATION_SLOT;
    }

    /**
     * @dev Initializes the vault
     * @param asset_ The asset token for this vault
     * @param shareToken_ The share token address
     * @param owner Initial owner address
     */
    function initialize(IERC20Metadata asset_, address shareToken_, address owner) public initializer {
        if (shareToken_ == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (address(asset_) == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }

        // Validate asset compatibility and get decimals
        uint8 assetDecimals;
        try IERC20Metadata(address(asset_)).decimals() returns (uint8 decimals) {
            if (decimals < DecimalConstants.MIN_ASSET_DECIMALS || decimals > DecimalConstants.SHARE_TOKEN_DECIMALS) {
                revert UnsupportedAssetDecimals();
            }
            assetDecimals = decimals;
        } catch {
            revert AssetDecimalsFailed();
        }
        // Validate share token compatibility and enforce 18 decimals
        try IERC20Metadata(shareToken_).decimals() returns (uint8 decimals) {
            if (decimals != DecimalConstants.SHARE_TOKEN_DECIMALS) {
                revert WrongDecimals();
            }
        } catch {
            revert AssetDecimalsFailed();
        }
        __Ownable_init(owner);

        VaultStorage storage $ = _getVaultStorage();
        $.asset = address(asset_);
        $.assetDecimals = assetDecimals;
        $.shareToken = shareToken_;
        $.investmentManager = owner; // Initially owner is investment manager
        $.isActive = true; // Vault is active by default

        // Calculate scaling factor for decimal normalization: 10^(18 - assetDecimals)
        uint256 scalingFactor = 10 ** (DecimalConstants.SHARE_TOKEN_DECIMALS - assetDecimals);
        $.scalingFactor = uint64(scalingFactor);
        $.minimumDepositAmount = 1000;
    }

    /**
     * @dev Returns the asset token address
     * @return Asset token address
     */
    function asset() public view returns (address) {
        VaultStorage storage $ = _getVaultStorage();
        return $.asset;
    }

    /**
     * @dev Returns the scaling factor for asset normalization
     * @return Scaling factor (10^(18 - assetDecimals))
     */
    function getScalingFactor() public view returns (uint256) {
        VaultStorage storage $ = _getVaultStorage();
        return $.scalingFactor;
    }

    // ========== ERC7575 Implementation ==========

    /**
     * @dev Returns the share token address
     *
     * ERC7575 SPECIFICATION:
     * "The address of the underlying `share` received on deposit into the Vault.
     * MUST return an address of an ERC-20 share representation of the Vault."
     *
     * ERC7575 MULTI-ASSET ARCHITECTURE:
     * "Multi-Asset Vaults share a single `share` token with multiple entry points
     * denominated in different `asset` tokens."
     *
     * @return Share token address
     */
    function share() public view virtual returns (address) {
        VaultStorage storage $ = _getVaultStorage();
        return $.shareToken;
    }

    // ========== IERC7540 Operator Implementation ==========

    /**
     * @dev Sets or revokes operator approval for the caller (ERC7540 compliant)
     *
     * Allows the caller to approve or revoke an operator who can manage async requests
     * (deposits, redeems, cancelations) on their behalf. The operator system provides
     * a flexible alternative to direct ERC20 allowance for vault authorization.
     *
     * OPERATOR PERMISSIONS:
     * Approved operators can:
     * - Call requestDeposit() on behalf of owner
     * - Call requestRedeem() on behalf of owner (with share allowance if needed)
     * - Call cancelDepositRequest() on behalf of controller
     * - Call cancelRedeemRequest() on behalf of controller
     * - Call deposit()/mint()/redeem() to claim requests on behalf of controller
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7540: Asynchronous Tokenized Vault Standard
     * - Operator approvals are per-vault: scoped to this vault, which owns its Requests
     * - Operators bypass ERC20 allowance checks on this vault's operations
     * - Compatible with multi-asset vault architecture
     *
     * OPERATOR ARCHITECTURE:
     * Operator approval is stored on this vault (operators[controller][operator]), not on the share
     * token. Each vault sharing the same share token keeps its own operator table, as ERC-7540 requires
     * (the vault owns the Requests an operator acts on).
     *
     * @param operator Address to approve or revoke as an operator
     * @param approved True to grant operator permission, false to revoke
     *
     * @return Always returns true to indicate operation succeeded
     *
     * @custom:event OperatorSet(msg.sender, operator, approved)
     */
    function setOperator(address operator, bool approved) public virtual returns (bool) {
        VaultStorage storage $ = _getVaultStorage();
        // Per-vault operator approval (ERC-7540): approval is scoped to this vault only.
        // ERC-7540 mandates this MUST set status, emit, and return true for any operator — including
        // operator == msg.sender. Self-operator is a harmless no-op: every authorization path already
        // short-circuits on `controller == msg.sender` before consulting operators[controller][operator].
        $.operators[msg.sender][operator] = approved;
        emit OperatorSet(msg.sender, operator, approved);
        return true;
    }

    /**
     * @dev Checks if an operator is approved for a controller on THIS vault (ERC7540)
     *
     * ERC7540 SPECIFICATION:
     * "Returns `true` if the `operator` is approved as an operator for a `controller`."
     *
     * Operator approvals are per-vault (ERC-7540 scopes operators to the vault that owns
     * the Requests). To authorize an operator across multiple vaults sharing this share
     * token, call setOperator on each vault.
     *
     * @param controller Address of the controller
     * @param operator Address of the operator
     * @return True if operator is approved
     */
    function isOperator(address controller, address operator) external view returns (bool) {
        return _isOperator(controller, operator);
    }

    /**
     * @dev Internal per-vault operator lookup used by the request/claim authorization paths.
     */
    function _isOperator(address controller, address operator) internal view returns (bool) {
        return _getVaultStorage().operators[controller][operator];
    }

    // ========== IERC7540Deposit Implementation ==========

    /**
     * @dev Submits a request to deposit assets into the vault (ERC7540 compliant)
     *
     * Initiates an asynchronous deposit request by transferring assets from the owner
     * to the vault. Assets enter the Pending state and must be fulfilled by the investment
     * manager before being converted to shares that can be claimed.
     *
     * DEPOSIT LIFECYCLE:
     * 1. Pending: User calls requestDeposit() to submit request with assets
     * 2. Claimable: Investment manager calls fulfillDeposit() to convert assets to shares
     * 3. Claimed: User calls deposit() to claim the shares
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7540: Asynchronous Tokenized Vault Standard
     * - Assets transferred immediately via Pull-Then-Credit pattern
     * - Three-state lifecycle without short-circuiting
     * - Reentrancy-protected via nonReentrant
     * - Blocks new deposits while ERC7887 cancelation is pending
     *
     * AUTHORIZATION:
     * Owner (msg.sender == owner) can call directly, or
     * Operator must be approved via setOperator() on this vault
     *
     * SECURITY CONSIDERATIONS:
     * - Uses nonReentrant guard to prevent reentrancy attacks
     * - Uses Pull-Then-Credit pattern: transfers before state updates
     * - Validates owner balance before transfer for safety
     * - Blocks new requests during pending ERC7887 cancelations
     * - Vault must be active (not paused)
     * - Assets below minimum deposit amount are rejected
     *
     * @param assets The amount of assets to deposit
     * @param controller Address to receive shares when claim is made
     * @param owner Address that owns the assets being deposited
     *
     * @return requestId The requestId of this deposit request (always 0 in this implementation)
     *
     * @custom:throws VaultNotActive If vault has been paused/deactivated
     * @custom:throws InvalidOwner If caller is neither owner nor approved operator
     * @custom:throws ZeroAssets If assets parameter is 0
     * @custom:throws InsufficientDepositAmount If assets < minimum deposit (1000 * 10^decimals)
     * @custom:throws InsufficientBalance If owner has less assets than requested
     * @custom:throws DepositCancelationPending If this controller has pending cancelation
     *
     * @custom:event DepositRequest(controller, owner, requestId, msg.sender, assets)
     */
    function requestDeposit(uint256 assets, address controller, address owner) external nonReentrant returns (uint256 requestId) {
        VaultStorage storage $ = _getVaultStorage();
        if (!$.isActive) revert VaultNotActive();
        if (controller == address(0)) revert ZeroAddress(); // a zero controller would strand the pulled assets (unclaimable)
        if (!(owner == msg.sender || _isOperator(owner, msg.sender))) revert InvalidOwner();
        if (assets == 0) revert ZeroAssets();
        if (assets < $.minimumDepositAmount * (10 ** $.assetDecimals)) {
            revert InsufficientDepositAmount();
        }
        // ERC7887: block new deposit requests only while a cancelation is in the Pending state.
        // pendingCancelDepositAssets is cleared at fulfillment (→ Claimable), so the gate lifts then,
        // matching pendingCancelDepositRequest() and the spec's "while cancelation is pending" scope.
        if ($.pendingCancelDepositAssets[controller] > 0) {
            revert DepositCancelationPending();
        }

        // Pull-Then-Credit pattern: Transfer assets first before updating state
        // This ensures we only credit assets that have been successfully received
        // Protects against transfer fee tokens and validates the actual amount transferred
        SafeTokenTransfers.safeTransferFrom($.asset, owner, address(this), assets);

        // State changes after successful transfer
        $.pendingDepositAssets[controller] += assets;
        $.totalPendingDepositAssets += assets;
        $.activeDepositRequesters.add(controller);

        // Event emission
        emit DepositRequest(controller, owner, REQUEST_ID, msg.sender, assets);
        return REQUEST_ID;
    }

    /**
     * @dev Returns the pending deposit amount for a controller
     *
     * ERC7540 SPECIFICATION:
     * "The amount of requested `assets` in Pending state for the `controller` with the given `requestId`.
     * - MUST NOT include any `assets` in Claimable state for deposit or mint.
     * - MUST NOT show any variations depending on the caller.
     * - MUST NOT revert unless due to integer overflow caused by an unreasonably large input."
     *
     * @param controller Address of the controller
     * @return pendingAssets Amount of assets pending deposit
     */
    function pendingDepositRequest(uint256 requestId, address controller) external view returns (uint256 pendingAssets) {
        if (requestId != REQUEST_ID) return 0; // this vault only uses requestId 0; no such request otherwise
        VaultStorage storage $ = _getVaultStorage();
        return $.pendingDepositAssets[controller];
    }

    /**
     * @dev Fulfills a pending deposit request by converting assets to shares (ERC7540 compliant)
     *
     * Investment manager calls this to fulfill a pending deposit request. Converts the
     * deposited assets into shares and moves them to the Claimable state so the user
     * can claim the shares via deposit() or mint().
     *
     * DEPOSIT LIFECYCLE:
     * 1. Pending: User calls requestDeposit() with assets
     * 2. Claimable: Investment manager calls fulfillDeposit() to convert to shares (THIS FUNCTION)
     * 3. Claimed: User calls deposit() or mint() to receive the shares
     *
     * SHARES MINTING:
     * - Shares are minted to the vault contract immediately
     * - Shares are held by vault until user calls deposit()/mint()
     * - Users can claim using exact assets or exact shares parameters
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7540: Asynchronous Tokenized Vault Standard
     * - Converts pending assets to claimable shares
     * - Uses Floor rounding for conservative share calculation
     *
     * ACCESS CONTROL:
     * - Only callable by the investment manager
     * - Investment manager is set via setInvestmentManager()
     *
     * @param controller Address that made the original deposit request
     * @param assets Amount of assets to fulfill (must be <= pendingDepositAssets[controller])
     *
     * @return shares Amount of shares that will be claimable for this controller
     *
     * @custom:throws OnlyInvestmentManager If caller is not the investment manager
     * @custom:throws InsufficientBalance If assets > pendingDepositAssets[controller]
     * @custom:throws ZeroShares If share calculation results in 0 shares
     */
    function fulfillDeposit(address controller, uint256 assets) public nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        uint256 pendingAssets = $.pendingDepositAssets[controller];
        if (assets > pendingAssets) {
            revert ERC20InsufficientBalance(address(this), pendingAssets, assets);
        }

        shares = _convertToShares(assets, Math.Rounding.Floor);
        if (shares == 0) revert ZeroShares();

        $.pendingDepositAssets[controller] -= assets;
        $.totalPendingDepositAssets -= assets;
        $.claimableDepositShares[controller] += shares;
        $.totalClaimableDepositShares += shares;
        $.claimableDepositAssets[controller] += assets; // Store asset amount for precise claiming

        // Mint shares to this vault (will be transferred to user on claim)
        ShareTokenUpgradeable($.shareToken).mint(address(this), shares);

        return shares;
    }

    /**
     * @dev Fulfills multiple pending deposit requests in a batch (only investment manager)
     * @param controllers Array of addresses that made the deposit requests
     * @param assets Array of asset amounts to fulfill for each controller
     * @return shares Array of shares that will be claimable for each controller
     */
    function fulfillDeposits(address[] calldata controllers, uint256[] calldata assets) public nonReentrant returns (uint256[] memory shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if (controllers.length != assets.length) revert LengthMismatch();

        shares = new uint256[](controllers.length);
        uint256 assetAmounts = 0;
        uint256 shareAmounts = 0;
        for (uint256 i = 0; i < controllers.length; ++i) {
            address controller = controllers[i];
            uint256 assetAmount = assets[i];
            uint256 pendingAssets = $.pendingDepositAssets[controller];
            if (assetAmount > pendingAssets) {
                revert ERC20InsufficientBalance(address(this), pendingAssets, assetAmount);
            }

            uint256 shareAmount = _convertToShares(assetAmount, Math.Rounding.Floor);
            if (shareAmount == 0) revert ZeroShares();

            assetAmounts += assetAmount;
            shareAmounts += shareAmount;
            $.pendingDepositAssets[controller] -= assetAmount;
            $.claimableDepositShares[controller] += shareAmount;
            $.claimableDepositAssets[controller] += assetAmount; // Store asset amount for precise claiming

            shares[i] = shareAmount;
        }
        $.totalPendingDepositAssets -= assetAmounts;
        $.totalClaimableDepositShares += shareAmounts;
        // Mint shares to this vault (will be transferred to user on claim)
        ShareTokenUpgradeable($.shareToken).mint(address(this), shareAmounts);
        return shares;
    }

    /**
     * @dev Returns the claimable deposit amount for a controller
     *
     * ERC7540 SPECIFICATION:
     * "The amount of requested `assets` in Claimable state for the `controller` with the given `requestId`.
     * - MUST NOT include any `assets` in Pending state for deposit or mint.
     * - MUST NOT show any variations depending on the caller.
     * - MUST NOT revert unless due to integer overflow caused by an unreasonably large input."
     *
     * IMPLEMENTATION NOTES:
     * In our case, since we have minted shares for an amount of assets,
     * it is preferable to get the claimable shares instead of the claimable assets.
     * @param controller Address of the controller
     * @return claimableAssets Amount of assets ready to claim
     */
    function claimableDepositRequest(uint256 requestId, address controller) external view returns (uint256 claimableAssets) {
        if (requestId != REQUEST_ID) return 0;
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableDepositAssets[controller];
    }

    /**
     * @dev Returns the claimable deposit shares for a controller
     * @param controller Address of the controller
     * @return claimableShares Amount of shares ready to claim
     */
    function claimableShares(address controller) external view returns (uint256) {
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableDepositShares[controller];
    }

    /**
     * @dev Claims shares from a fulfilled deposit request by specifying assets (ERC7540 compliant)
     *
     * Final step in the deposit lifecycle: converts claimable assets to shares and transfers
     * them to the receiver. Controller (or their operator) calls this to complete the deposit.
     *
     * DEPOSIT LIFECYCLE:
     * 1. Pending: User calls requestDeposit() with assets
     * 2. Claimable: Investment manager calls fulfillDeposit() to convert assets to shares
     * 3. Claimed: User calls deposit() to receive shares (THIS FUNCTION)
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7540: Asynchronous Tokenized Vault Standard
     * - Converts assets to shares using the stored asset-share ratio
     * - Allows partial claims of claimable amounts
     * - Reentrancy-protected via nonReentrant
     *
     * AUTHORIZATION:
     * Controller (msg.sender == controller) can call directly, or
     * Operator must be approved via setOperator() on this vault
     *
     * SECURITY CONSIDERATIONS:
     * - Uses nonReentrant guard to prevent reentrancy attacks
     * - Share calculation uses Floor rounding (conservative for protocol)
     * - Only callable by controller or approved operator
     * - Removes controller from active set if all assets are claimed
     *
     * @param assets The amount of assets to claim (must be <= claimableDepositAssets[controller])
     * @param receiver Address that will receive the shares
     * @param controller Address that made the original deposit request
     *
     * @return shares The amount of shares received from the claim
     *
     * @custom:throws InvalidCaller If caller is neither controller nor approved operator
     * @custom:throws ZeroAssets If assets parameter is 0
     * @custom:throws InsufficientClaimableAssets If assets > claimableDepositAssets[controller]
     * @custom:throws ZeroSharesCalculated If share calculation results in 0 (request too small)
     * @custom:throws ShareTransferFailed If share transfer to receiver fails
     *
     * @custom:event Deposit(sender=controller, owner=receiver, assets, shares) (ERC-4626 event, ERC-7540 semantics)
     */
    function deposit(uint256 assets, address receiver, address controller) public nonReentrant returns (uint256 shares) {
        if (receiver == address(0)) revert ERC20InvalidReceiver(receiver);
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || _isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
        if (assets == 0) revert ZeroAssets();

        uint256 availableShares = $.claimableDepositShares[controller];
        uint256 availableAssets = $.claimableDepositAssets[controller];

        if (assets > availableAssets) revert InsufficientClaimableAssets();

        // Calculate shares proportionally from the stored asset-share ratio
        shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Floor);
        if (shares == 0) revert ZeroSharesCalculated();

        // Remove from active deposit requesters if no more claimable assets
        if (availableAssets == assets) {
            $.activeDepositRequesters.remove(controller);
            $.totalClaimableDepositShares -= availableShares;
            delete $.claimableDepositShares[controller];
            delete $.claimableDepositAssets[controller];
        } else {
            $.claimableDepositShares[controller] -= shares;
            $.totalClaimableDepositShares -= shares;
            $.claimableDepositAssets[controller] -= assets;
        }

        emit Deposit(controller, receiver, assets, shares);

        // Transfer shares from vault to receiver using ShareToken
        if (!IERC20Metadata($.shareToken).transfer(receiver, shares)) {
            revert ShareTransferFailed();
        }
    }

    /**
     * @dev Claims exactly specified shares from a fulfilled deposit request (ERC7540 compliant)
     *
     * Final step in the deposit lifecycle: mints exactly the specified shares and transfers them
     * to the receiver. Controller (or their operator) calls this to complete the deposit with exact
     * share amount guarantee.
     *
     * DEPOSIT LIFECYCLE:
     * 1. Pending: User calls requestDeposit() with assets
     * 2. Claimable: Investment manager calls fulfillDeposit() to convert assets to shares
     * 3. Claimed: User calls mint() to receive exact shares (THIS FUNCTION)
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7540: Asynchronous Tokenized Vault Standard
     * - Mints exactly the specified number of shares
     * - Allows partial claims of claimable amounts
     * - Reentrancy-protected via nonReentrant
     *
     * AUTHORIZATION:
     * Controller (msg.sender == controller) can call directly, or
     * Operator must be approved via setOperator() on this vault
     *
     * SECURITY CONSIDERATIONS:
     * - Uses nonReentrant guard to prevent reentrancy attacks
     * - Asset calculation uses Floor rounding (conservative for protocol)
     * - Only callable by controller or approved operator
     * - Removes controller from active set if all shares are claimed
     *
     * @param shares The exact amount of shares to claim
     * @param receiver Address that will receive the shares
     * @param controller Address that made the original deposit request
     *
     * @return assets The amount of assets consumed to generate the shares
     *
     * @custom:throws InvalidCaller If caller is neither controller nor approved operator
     * @custom:throws ZeroAssets If shares parameter is 0 (check fails on zero shares)
     * @custom:throws InsufficientClaimableAssets If assets needed for shares > claimableDepositAssets
     * @custom:throws ZeroSharesCalculated If asset calculation results in 0
     * @custom:throws ShareTransferFailed If share transfer to receiver fails
     *
     * @custom:event Deposit(sender=controller, owner=receiver, assets, shares) (ERC-4626 event, ERC-7540 semantics)
     */
    function mint(uint256 shares, address receiver, address controller) public nonReentrant returns (uint256 assets) {
        if (receiver == address(0)) revert ERC20InvalidReceiver(receiver);
        VaultStorage storage $ = _getVaultStorage();
        if (!(controller == msg.sender || _isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
        if (shares == 0) revert ZeroAssets();

        uint256 availableShares = $.claimableDepositShares[controller];
        uint256 availableAssets = $.claimableDepositAssets[controller];

        if (shares > availableShares) revert InsufficientClaimableShares();

        // Calculate assets proportionally from the stored asset-share ratio
        assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor);
        if (assets == 0) revert ZeroAssetsCalculated();

        // Remove from active deposit requesters if no more claimable shares
        if (availableShares == shares) {
            $.activeDepositRequesters.remove(controller);
            $.totalClaimableDepositShares -= availableShares;
            delete $.claimableDepositShares[controller];
            delete $.claimableDepositAssets[controller];
        } else {
            $.claimableDepositShares[controller] -= shares;
            $.totalClaimableDepositShares -= shares;
            $.claimableDepositAssets[controller] -= assets;
        }

        emit Deposit(controller, receiver, assets, shares);

        // Transfer shares from vault to receiver using ShareToken
        if (!IERC20Metadata($.shareToken).transfer(receiver, shares)) {
            revert ShareTransferFailed();
        }
    }

    // ========== IERC7540Redeem Implementation ==========

    /**
     * @dev Submits a request to redeem shares from the vault (ERC7540 compliant)
     *
     * Initiates an asynchronous redemption request by transferring shares from the owner
     * to the vault. Shares enter the Pending state and must be fulfilled by the investment
     * manager before being converted to assets that can be claimed.
     *
     * REDEEM LIFECYCLE:
     * 1. Pending: User calls requestRedeem() to submit request with shares
     * 2. Claimable: Investment manager calls fulfillRedeem() to convert shares to assets
     * 3. Claimed: User calls redeem() to claim the assets
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7540: Asynchronous Tokenized Vault Standard
     * - Shares transferred immediately via Pull-Then-Credit pattern
     * - Three-state lifecycle without short-circuiting
     * - Reentrancy-protected via nonReentrant
     * - Blocks new redeems while ERC7887 cancelation is pending
     *
     * AUTHORIZATION:
     * Owner (msg.sender == owner) can call directly, or
     * Operator must be approved via setOperator() on this vault, or
     * Spender must be approved via ERC20 approve() on the share token
     *
     * SECURITY CONSIDERATIONS:
     * - Uses nonReentrant guard to prevent reentrancy attacks
     * - Uses Pull-Then-Credit pattern: transfers before state updates
     * - Validates owner balance before transfer for safety
     * - Blocks new requests during pending ERC7887 cancelations
     * - Supports both operator and ERC20 allowance authorization
     * - Shares are held by vault and will be burned when assets are claimed
     *
     * @param shares The amount of shares to redeem
     * @param controller Address to receive assets when claim is made
     * @param owner Address that owns the shares being redeemed
     *
     * @return requestId The requestId of this redeem request (always 0 in this implementation)
     *
     * @custom:throws ERC20InsufficientAllowance If allowance is insufficient (via spendAllowance)
     * @custom:throws InsufficientBalance If owner has less shares than requested
     * @custom:throws ZeroShares If shares parameter is 0
     * @custom:throws RedeemCancelationPending If this controller has pending cancelation
     * @custom:throws ShareTransferFailed If share transfer to vault fails
     *
     * @custom:event RedeemRequest(controller, owner, requestId, msg.sender, shares)
     */
    function requestRedeem(uint256 shares, address controller, address owner) external nonReentrant returns (uint256 requestId) {
        if (shares == 0) revert ZeroShares();
        if (controller == address(0)) revert ZeroAddress(); // a zero controller would strand the pulled shares (unclaimable)
        VaultStorage storage $ = _getVaultStorage();

        // ERC7540 REQUIREMENT: Authorization check for redemption
        // Per spec: "Redeem Request approval of shares for a msg.sender NOT equal to owner may come
        // either from ERC-20 approval over the shares of owner or if the owner has approved the
        // msg.sender as an operator."
        bool isOwnerOrOperator = owner == msg.sender || _isOperator(owner, msg.sender);
        if (!isOwnerOrOperator) {
            ShareTokenUpgradeable($.shareToken).spendAllowance(owner, msg.sender, shares);
        }

        // ERC7887: block new redeem requests only while a cancelation is in the Pending state.
        // pendingCancelRedeemShares is cleared at fulfillment (→ Claimable), so the gate lifts then,
        // matching pendingCancelRedeemRequest() and the spec's "while cancelation is pending" scope.
        if ($.pendingCancelRedeemShares[controller] > 0) {
            revert RedeemCancelationPending();
        }

        // Pull-Then-Credit pattern: Transfer shares first before updating state
        // This ensures we only credit shares that have been successfully received
        if (!ShareTokenUpgradeable($.shareToken).vaultTransferFrom(owner, address(this), shares)) {
            revert ShareTransferFailed();
        }

        // State changes after successful transfer
        $.pendingRedeemShares[controller] += shares;
        $.totalPendingRedeemShares += shares;
        $.activeRedeemRequesters.add(controller);

        // Event emission
        emit RedeemRequest(controller, owner, REQUEST_ID, msg.sender, shares);
        return REQUEST_ID;
    }

    /**
     * @dev Returns the pending redemption amount for a controller
     *
     * ERC7540 SPECIFICATION:
     * "The amount of requested `shares` in Pending state for the `controller` with the given `requestId`.
     * - MUST NOT include any `shares` in Claimable state for redeem or withdraw.
     * - MUST NOT show any variations depending on the caller.
     * - MUST NOT revert unless due to integer overflow caused by an unreasonably large input."
     *
     * @param controller Address of the controller
     * @return pendingShares Amount of shares pending redemption
     */
    function pendingRedeemRequest(uint256 requestId, address controller) external view returns (uint256 pendingShares) {
        if (requestId != REQUEST_ID) return 0;
        VaultStorage storage $ = _getVaultStorage();
        return $.pendingRedeemShares[controller];
    }

    /**
     * @dev Returns the claimable redemption amount for a controller
     *
     * ERC7540 SPECIFICATION:
     * "The amount of requested `shares` in Claimable state for the `controller` with the given `requestId`.
     * - MUST NOT include any `shares` in Pending state for redeem or withdraw.
     * - MUST NOT show any variations depending on the caller.
     * - MUST NOT revert unless due to integer overflow caused by an unreasonably large input."
     *
     * @param controller Address of the controller
     * @return claimableRedeemShares Amount of shares ready to redeem
     */
    function claimableRedeemRequest(uint256 requestId, address controller) external view returns (uint256 claimableRedeemShares) {
        if (requestId != REQUEST_ID) return 0;
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableRedeemShares[controller];
    }

    /**
     * @dev Fulfills a pending redeem request by converting shares to assets (ERC7540 compliant)
     *
     * Investment manager calls this to fulfill a pending redeem request. Converts the
     * redeemed shares into assets and moves them to the Claimable state so the user
     * can claim the assets via redeem() or withdraw().
     *
     * REDEEM LIFECYCLE:
     * 1. Pending: User calls requestRedeem() with shares
     * 2. Claimable: Investment manager calls fulfillRedeem() to convert to assets (THIS FUNCTION)
     * 3. Claimed: User calls redeem() or withdraw() to receive the assets
     *
     * SHARES BURNING:
     * - Shares are NOT burned during fulfillment
     * - Shares are held by vault and burned when user claims them
     * - This prevents double-burning and enables partial claims
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7540: Asynchronous Tokenized Vault Standard
     * - Converts pending shares to claimable assets
     * - Uses Floor rounding for conservative asset calculation
     *
     * ACCESS CONTROL:
     * - Only callable by the investment manager
     * - Investment manager is set via setInvestmentManager()
     *
     * @param controller Address that made the original redeem request
     * @param shares Amount of shares to fulfill (must be <= pendingRedeemShares[controller])
     *
     * @return assets Amount of assets that will be claimable for this controller
     *
     * @custom:throws OnlyInvestmentManager If caller is not the investment manager
     * @custom:throws ZeroShares If shares parameter is 0
     * @custom:throws InsufficientBalance If shares > pendingRedeemShares[controller]
     */
    function fulfillRedeem(address controller, uint256 shares) public nonReentrant returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if (shares == 0) revert ZeroShares();
        uint256 pendingShares = $.pendingRedeemShares[controller];
        if (shares > pendingShares) {
            revert ERC20InsufficientBalance(address(this), pendingShares, shares);
        }

        assets = _convertToAssets(shares, Math.Rounding.Floor);
        // Reject fulfilling a redeem that Floor-rounds to zero assets (a sub-scalingFactor `shares`
        // amount for a low-decimal asset). Without this, the claim would burn the escrowed shares for
        // zero payout — a dust loss to the redeemer, socialized to remaining holders.
        if (assets == 0) revert ZeroAssets();
        if (assets > totalAssets()) {
            revert ERC20InsufficientBalance(address(this), totalAssets(), assets);
        }

        $.pendingRedeemShares[controller] -= shares;
        $.totalPendingRedeemShares -= shares;
        $.claimableRedeemAssets[controller] += assets;
        $.claimableRedeemShares[controller] += shares;
        $.totalClaimableRedeemAssets += assets;
        $.totalClaimableRedeemShares += shares; // Track shares that will be burned

        // Note: Shares are NOT burned here - they will be burned during redeem/withdraw claim
        return assets;
    }

    /**
     * @dev Claims assets from a fulfilled redemption request by specifying shares (ERC7540 compliant)
     *
     * Final step in the redeem lifecycle: converts claimable shares to assets, burns the shares,
     * and transfers assets to the receiver. Controller (or their operator) calls this to complete
     * the redemption.
     *
     * REDEEM LIFECYCLE:
     * 1. Pending: User calls requestRedeem() with shares
     * 2. Claimable: Investment manager calls fulfillRedeem() to convert shares to assets
     * 3. Claimed: User calls redeem() to receive assets (THIS FUNCTION)
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7540: Asynchronous Tokenized Vault Standard
     * - Converts shares to assets using the stored share-asset ratio
     * - Allows partial claims of claimable amounts
     * - Reentrancy-protected via nonReentrant
     *
     * AUTHORIZATION:
     * Controller (msg.sender == controller) can call directly, or
     * Operator must be approved via setOperator() on this vault
     *
     * SECURITY CONSIDERATIONS:
     * - Uses nonReentrant guard to prevent reentrancy attacks
     * - Asset calculation uses Floor rounding (conservative for protocol)
     * - Only callable by controller or approved operator
     * - Burns shares held by vault after asset calculation
     * - Removes controller from active set if all shares are claimed
     *
     * @param shares The amount of shares to redeem (must be <= claimableRedeemShares[controller])
     * @param receiver Address that will receive the assets
     * @param controller Address that made the original redeem request
     *
     * @return assets The amount of assets received from the redemption
     *
     * @custom:throws InvalidCaller If caller is neither controller nor approved operator
     * @custom:throws ZeroShares If shares parameter is 0
     * @custom:throws InsufficientClaimableShares If shares > claimableRedeemShares[controller]
     * @custom:throws AssetTransferFailed If asset transfer to receiver fails
     *
     * @custom:event Withdraw(sender=msg.sender, receiver, owner=controller, assets, shares) (ERC-4626 event, ERC-7540 semantics)
     */
    function redeem(uint256 shares, address receiver, address controller) public nonReentrant returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        if (receiver == address(0)) revert ERC20InvalidReceiver(receiver);
        if (!(controller == msg.sender || _isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
        if (shares == 0) revert ZeroShares();

        uint256 availableShares = $.claimableRedeemShares[controller];
        if (shares > availableShares) revert InsufficientClaimableShares();

        uint256 availableAssets = $.claimableRedeemAssets[controller];
        // Full claim is keyed on the INPUT shares (this is redeem(shares)), so redeeming the entire
        // claimable share balance always clears the position with no stranded dust — independent of the
        // conversion rounding. (shares == availableShares implies assets == availableAssets exactly, since
        // mulDiv(availableShares, availableAssets, availableShares) is exact, so the totals below — which
        // decrement by assets/shares — stay consistent with the deleted amounts.)
        if (shares == availableShares) {
            assets = availableAssets;
            $.activeRedeemRequesters.remove(controller);
            delete $.claimableRedeemAssets[controller];
            delete $.claimableRedeemShares[controller];
        } else {
            // Calculate proportional assets for the requested shares
            assets = shares.mulDiv(availableAssets, availableShares, Math.Rounding.Floor);
            // Reject a partial claim whose share amount Floor-rounds to zero assets — it would burn the
            // escrowed shares for no payout (dust loss to the redeemer, socialized to remaining holders).
            // The full branch always pays > 0: fulfillRedeem rejects assets==0, so availableAssets > 0
            // whenever a claimable exists, and there assets == availableAssets. Use withdraw() for an
            // asset-exact claim (it Ceil-rounds shares so a positive asset claim never burns zero shares).
            if (assets == 0) revert ZeroAssets();
            $.claimableRedeemAssets[controller] -= assets;
            $.claimableRedeemShares[controller] -= shares;
        }
        $.totalClaimableRedeemAssets -= assets;
        $.totalClaimableRedeemShares -= shares; // Decrement shares that are being burned

        // Burn the shares as per ERC7540 spec - shares are burned when request is claimed
        ShareTokenUpgradeable($.shareToken).burn(address(this), shares);

        emit Withdraw(msg.sender, receiver, controller, assets, shares);
        if (assets > 0) {
            SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
        }
    }

    /**
     * @dev Claims shares by specifying desired assets from fulfilled redemption
     * @param assets Amount of assets to withdraw
     * @param receiver Address to receive the assets
     * @param controller Address that made the original request
     * @return shares Amount of shares consumed
     */
    function withdraw(uint256 assets, address receiver, address controller) public nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (receiver == address(0)) revert ERC20InvalidReceiver(receiver);
        if (!(controller == msg.sender || _isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }
        if (assets == 0) revert ZeroAssets();

        uint256 availableAssets = $.claimableRedeemAssets[controller];
        if (assets > availableAssets) revert InsufficientClaimableAssets();

        uint256 availableShares = $.claimableRedeemShares[controller];
        if (availableShares == 0) revert InsufficientClaimableShares();

        if (assets == availableAssets) {
            shares = availableShares;
            // Remove from active redeem requesters if no more claimable assets and the potential dust
            $.activeRedeemRequesters.remove(controller);
            delete $.claimableRedeemAssets[controller];
            delete $.claimableRedeemShares[controller];
        } else {
            // Asset-exact withdrawals must round shares up so a positive asset
            // claim cannot be satisfied by burning zero shares.
            shares = assets.mulDiv(availableShares, availableAssets, Math.Rounding.Ceil);
            if (shares == 0) revert ZeroSharesCalculated();
            if (shares >= availableShares) revert InsufficientClaimableShares();

            $.claimableRedeemAssets[controller] -= assets;
            $.claimableRedeemShares[controller] -= shares;
        }

        $.totalClaimableRedeemAssets -= assets;
        $.totalClaimableRedeemShares -= shares; // Decrement shares that are being burned

        // Burn the shares as per ERC7540 spec - shares are burned when request is claimed
        if (shares > 0) {
            ShareTokenUpgradeable($.shareToken).burn(address(this), shares);
        }

        emit Withdraw(msg.sender, receiver, controller, assets, shares);

        SafeTokenTransfers.safeTransfer($.asset, receiver, assets);
    }

    // ========== ERC7887 Cancelation Fulfillment Functions ==========

    /**
     * @dev Fulfills a pending deposit cancelation request (ERC7887 compliant)
     *
     * Investment manager calls this to fulfill a pending deposit cancelation.
     * Transitions assets from pending cancelation to claimable state so the user
     * can claim the original assets back.
     *
     * CANCELATION LIFECYCLE:
     * 1. Pending: User calls cancelDepositRequest() to initiate cancelation
     * 2. Claimable: Investment manager calls fulfillCancelDepositRequest() to fulfill (THIS FUNCTION)
     * 3. Claimed: User calls claimCancelDepositRequest() to receive assets
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7887: Asynchronous Tokenized Vault Cancelation Extension
     * - Moves assets from pending to claimable state
     * - No state mutation until fulfillment
     *
     * ACCESS CONTROL:
     * - Only callable by the investment manager
     * - Investment manager is set via setInvestmentManager()
     *
     * @param controller Address that made the original deposit cancelation request
     *
     * @return assets Amount of assets now claimable for this controller
     *
     * @custom:throws OnlyInvestmentManager If caller is not the investment manager
     * @custom:throws NoPendingCancelDeposit If no pending cancelation exists for controller
     */
    function fulfillCancelDepositRequest(address controller) external returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();

        assets = $.pendingCancelDepositAssets[controller];
        if (assets == 0) revert NoPendingCancelDeposit();

        // Move from pending to claimable cancelation state
        delete $.pendingCancelDepositAssets[controller];
        $.claimableCancelDepositAssets[controller] += assets;

        return assets;
    }

    /**
     * @dev Fulfills multiple pending deposit cancelations in a batch (ERC7887 compliant)
     *
     * Investment manager calls this to efficiently fulfill multiple pending deposit
     * cancelation requests in a single transaction. Reduces gas costs for bulk operations.
     *
     * BATCH OPERATIONS:
     * - Processes all controllers regardless of whether they have pending cancelations
     * - Returns 0 for controllers with no pending cancelation
     * - Efficiently updates state for all controllers at once
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7887: Asynchronous Tokenized Vault Cancelation Extension
     * - Moves all pending assets to claimable state
     * - Optimized for batch processing
     *
     * ACCESS CONTROL:
     * - Only callable by the investment manager
     * - Investment manager is set via setInvestmentManager()
     *
     * @param controllers Array of addresses that made the original deposit cancelation requests
     *
     * @return assets Array of assets now claimable for each controller (0 if no pending)
     *
     * @custom:throws OnlyInvestmentManager If caller is not the investment manager
     */
    function fulfillCancelDepositRequests(address[] calldata controllers) external returns (uint256[] memory assets) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();

        assets = new uint256[](controllers.length);
        for (uint256 i = 0; i < controllers.length; ++i) {
            address controller = controllers[i];
            uint256 pendingAssets = $.pendingCancelDepositAssets[controller];

            if (pendingAssets > 0) {
                delete $.pendingCancelDepositAssets[controller];
                $.claimableCancelDepositAssets[controller] += pendingAssets;
                assets[i] = pendingAssets;
            }
        }

        return assets;
    }

    /**
     * @dev Fulfills a pending redeem cancelation request (ERC7887 compliant)
     *
     * Investment manager calls this to fulfill a pending redeem cancelation.
     * Transitions shares from pending cancelation to claimable state so the user
     * can claim the original shares back.
     *
     * CANCELATION LIFECYCLE:
     * 1. Pending: User calls cancelRedeemRequest() to initiate cancelation
     * 2. Claimable: Investment manager calls fulfillCancelRedeemRequest() to fulfill (THIS FUNCTION)
     * 3. Claimed: User calls claimCancelRedeemRequest() to receive shares
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7887: Asynchronous Tokenized Vault Cancelation Extension
     * - Moves shares from pending to claimable state
     * - No state mutation until fulfillment
     *
     * ACCESS CONTROL:
     * - Only callable by the investment manager
     * - Investment manager is set via setInvestmentManager()
     *
     * @param controller Address that made the original redeem cancelation request
     *
     * @return shares Amount of shares now claimable for this controller
     *
     * @custom:throws OnlyInvestmentManager If caller is not the investment manager
     * @custom:throws NoPendingCancelRedeem If no pending redeem cancelation exists for controller
     */
    function fulfillCancelRedeemRequest(address controller) external returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();

        shares = $.pendingCancelRedeemShares[controller];
        if (shares == 0) revert NoPendingCancelRedeem();

        // Move from pending to claimable cancelation state
        delete $.pendingCancelRedeemShares[controller];
        $.claimableCancelRedeemShares[controller] += shares;
    }

    /**
     * @dev Fulfills multiple pending redeem cancelations in a batch (ERC7887 compliant)
     *
     * Investment manager calls this to efficiently fulfill multiple pending redeem
     * cancelation requests in a single transaction. Reduces gas costs for bulk operations.
     *
     * BATCH OPERATIONS:
     * - Processes all controllers regardless of whether they have pending cancelations
     * - Returns 0 for controllers with no pending cancelation
     * - Efficiently updates state for all controllers at once
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7887: Asynchronous Tokenized Vault Cancelation Extension
     * - Moves all pending shares to claimable state
     * - Optimized for batch processing
     *
     * ACCESS CONTROL:
     * - Only callable by the investment manager
     * - Investment manager is set via setInvestmentManager()
     *
     * @param controllers Array of addresses that made the original redeem cancelation requests
     *
     * @return shares Array of shares now claimable for each controller (0 if no pending)
     *
     * @custom:throws OnlyInvestmentManager If caller is not the investment manager
     */
    function fulfillCancelRedeemRequests(address[] calldata controllers) external returns (uint256[] memory shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();

        shares = new uint256[](controllers.length);
        for (uint256 i = 0; i < controllers.length; ++i) {
            address controller = controllers[i];
            uint256 pendingShares = $.pendingCancelRedeemShares[controller];

            if (pendingShares > 0) {
                delete $.pendingCancelRedeemShares[controller];
                $.claimableCancelRedeemShares[controller] += pendingShares;
                shares[i] = pendingShares;
            }
        }
    }

    // ========== ERC4626-like functions ==========

    /**
     * @dev Returns total assets managed by the vault (EXCLUDES invested assets to avoid double counting)
     *
     * INVESTMENT ARCHITECTURE:
     * This function returns only assets physically held in this vault's token balance.
     * Assets are excluded in these states:
     * - Pending deposits (not yet fulfilled by investment manager)
     * - Claimable redemptions (reserved for user withdrawals)
     * - Invested in external investment vaults (tracked at ShareToken level)
     *
     * ASSET LIFECYCLE:
     * 1. User calls requestDeposit() → Assets transferred TO this vault (pending state)
     * 2. Manager calls fulfillDeposit() → Assets stay in vault, now available for investment
     * 3. Manager calls investAssets() → Assets transferred to investment vault
     * 4. Investment vault shares credited to ShareToken contract
     * 5. ShareToken's getInvestedAssets() includes these invested assets in global accounting
     *
     * This design prevents double-counting when aggregating across multiple vaults while
     * ensuring all assets are tracked somewhere in the system.
     *
     * ERC7575/ERC7540 DEVIATION FROM ERC4626:
     * This implementation differs from ERC4626 totalAssets() because of the async vault pattern:
     * - Only returns assets AVAILABLE in the vault (not allocated to pending operations)
     * - Excludes totalPendingDepositAssets (funds waiting for fulfillDeposit)
     * - Excludes totalClaimableRedeemAssets (funds reserved for user redemption claims)
     * - Excludes totalCancelDepositAssets (funds reserved for pending deposit cancelations)
     * - Excludes already invested assets (funds deployed to ERC7575 investment vaults)
     *   Once assets are invested, they may be withdrawn as different assets from the investment
     *   contract, so totalAssets() excludes them. Use ShareToken.getInvestedAssets() for invested
     *   asset accounting across all vaults.
     * - This prevents over-accounting when assets move between states (pending → claimable → claimed)
     * - Use for: conversion calculations, investment availability checks
     * - For complete asset accounting: sum this value + pending + claimable + cancelation + invested assets
     *
     * @return Total amount of assets available in the vault (not reserved for pending operations or invested)
     */
    function totalAssets() public view virtual returns (uint256) {
        VaultStorage storage $ = _getVaultStorage();
        uint256 balance = IERC20Metadata($.asset).balanceOf(address(this));
        // Exclude pending deposits, pending/claimable cancelation deposits, and claimable withdrawals from total assets
        uint256 reservedAssets = $.totalPendingDepositAssets + $.totalClaimableRedeemAssets + $.totalCancelDepositAssets;
        return balance > reservedAssets ? balance - reservedAssets : 0;
    }

    /**
     * @dev Internal function to convert assets to shares with specified rounding
     * @param assets Amount of assets to convert
     * @param rounding Rounding mode (Floor = favor vault, Ceil = favor user)
     * @return shares Amount of shares equivalent to assets
     */
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        // Normalize assets to 18 decimals. mulDiv(x, scaling, 1) == x * scaling exactly; the plain
        // multiply has the same overflow revert under checked arithmetic and is cheaper.
        uint256 normalizedAssets = assets * $.scalingFactor;

        // Use optimized ShareToken conversion method (single call instead of multiple)
        shares = ShareTokenUpgradeable($.shareToken).convertNormalizedAssetsToShares(normalizedAssets, rounding);
    }

    /**
     * @dev Internal function to convert shares to assets with specified rounding
     * @param shares Amount of shares to convert
     * @param rounding Rounding mode (Floor = favor vault, Ceil = favor user)
     * @return assets Amount of assets equivalent to shares
     */
    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view returns (uint256 assets) {
        VaultStorage storage $ = _getVaultStorage();
        uint256 scaling = $.scalingFactor;
        // Use optimized ShareToken conversion method (single call instead of multiple)
        uint256 normalizedAssets = ShareTokenUpgradeable($.shareToken).convertSharesToNormalizedAssets(shares, rounding);

        // Then denormalize back to original asset decimals
        if (scaling == 1) {
            return normalizedAssets;
        } else {
            return Math.mulDiv(normalizedAssets, 1, scaling, rounding);
        }
    }

    /**
     * @dev Converts assets to shares using current exchange rate
     * @param assets Amount of assets to convert
     * @return Amount of shares equivalent to assets
     */
    function convertToShares(uint256 assets) public view virtual returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }

    /**
     * @dev Converts shares to assets using current exchange rate
     * @param shares Amount of shares to convert
     * @return Amount of assets equivalent to shares
     */
    function convertToAssets(uint256 shares) public view virtual returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }

    /**
     * @dev Returns maximum assets that can be deposited for a controller
     * @param controller Address to check max deposit for
     * @return Maximum claimable assets for deposit
     *
     * Per ERC-7540 this is the controller's already-fulfilled (Claimable) deposit, i.e. what
     * deposit() would accept now. It is NOT gated on isActive: deactivation only freezes NEW requests
     * (requestDeposit), while claiming an already-fulfilled deposit stays enabled on a deactivated
     * vault — so gating here would understate an executable claim.
     */
    function maxDeposit(address controller) public view virtual returns (uint256) {
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableDepositAssets[controller];
    }

    /**
     * @dev Returns maximum shares that can be minted for a controller
     * @param controller Address to check max mint for
     * @return Maximum claimable shares for deposit
     *
     * As with {maxDeposit}, this reflects the Claimable deposit and is not gated on isActive (claiming
     * a fulfilled deposit remains executable on a deactivated vault).
     */
    function maxMint(address controller) public view virtual returns (uint256) {
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableDepositShares[controller];
    }

    /**
     * @dev Returns maximum assets that can be withdrawn for a controller
     * @param controller Address to check max withdraw for
     * @return Maximum claimable assets for redemption
     *
     * Per ERC-7540 this is the controller's claimable redeem assets, and that exact value is always
     * executable: withdraw(maxWithdraw) takes the `assets == availableAssets` equality branch, which
     * assigns shares = availableShares and clears the slot. The `shares >= availableShares` revert
     * only guards *partial* withdrawals, so the reported max never causes a revert.
     */
    function maxWithdraw(address controller) public view virtual returns (uint256) {
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableRedeemAssets[controller];
    }

    /**
     * @dev Returns maximum shares that can be redeemed for a controller
     * @param controller Address to check max redeem for
     * @return Maximum claimable shares for redemption
     */
    function maxRedeem(address controller) public view virtual returns (uint256) {
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableRedeemShares[controller];
    }

    /**
     * @dev Preview functions revert for async vaults (ERC7540)
     * @return Always reverts with AsyncFlow
     */
    function previewDeposit(uint256) public pure virtual returns (uint256) {
        revert AsyncFlow();
    }

    /**
     * @dev Preview functions revert for async vaults (ERC7540)
     * @return Always reverts with AsyncFlow
     */
    function previewMint(uint256) public pure virtual returns (uint256) {
        revert AsyncFlow();
    }

    /**
     * @dev Preview functions revert for async vaults (ERC7540)
     * @return Always reverts with AsyncFlow
     */
    function previewWithdraw(uint256) public pure virtual returns (uint256) {
        revert AsyncFlow();
    }

    /**
     * @dev Preview functions revert for async vaults (ERC7540)
     * @return Always reverts with AsyncFlow
     */
    function previewRedeem(uint256) public pure virtual returns (uint256) {
        revert AsyncFlow();
    }

    /**
     * @dev ERC-4626 deposit entrypoint. Per ERC-7540 the inherited 2-arg form claims the caller's own
     * fulfilled Request (controller == msg.sender) and delivers shares to `receiver`. Use the 3-arg
     * overload to claim a Request controlled by another account (via operator approval).
     * @param assets Amount of assets to claim
     * @param receiver Address to receive shares
     * @return shares Amount of shares received
     */
    function deposit(uint256 assets, address receiver) public virtual returns (uint256) {
        return deposit(assets, receiver, msg.sender);
    }

    /**
     * @dev ERC-4626 mint entrypoint. Per ERC-7540 the inherited 2-arg form claims the caller's own
     * fulfilled Request (controller == msg.sender) and delivers shares to `receiver`. Use the 3-arg
     * overload to claim a Request controlled by another account (via operator approval).
     * @param shares Amount of shares to mint
     * @param receiver Address to receive shares
     * @return assets Amount of assets consumed
     */
    function mint(uint256 shares, address receiver) public virtual returns (uint256) {
        return mint(shares, receiver, msg.sender);
    }

    // ========== ERC165 Support ==========

    /**
     * @dev Returns true if this contract implements the interface (ERC165)
     * @param interfaceId The interface identifier
     * @return True if interface is supported
     */
    function supportsInterface(bytes4 interfaceId) public pure virtual returns (bool) {
        // Only the canonical sub-interface IDs are advertised. The IERC7540/IERC7887 umbrella
        // interfaces declare no functions of their own, so type(...).interfaceId == 0x00000000 for
        // them; advertising those would make supportsInterface(0x00000000) return true (ERC-165
        // hygiene violation), so they are intentionally excluded.
        return interfaceId == type(IERC7575).interfaceId || interfaceId == type(IERC7540Deposit).interfaceId || interfaceId == type(IERC7540Redeem).interfaceId
            || interfaceId == type(IERC7540Operator).interfaceId || interfaceId == type(IERC7887DepositCancelation).interfaceId || interfaceId == type(IERC7887RedeemCancelation).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    // ========== Internal Security Functions ==========

    /**
     * @dev Validates token transfer behavior to detect non-standard tokens
     * @param $ Vault storage reference
     * @param from Token holder address
     * @param amount Amount to validate
     */

    // ========== Investment Management Functions ==========

    /**
     * @dev Sets the investment manager address (only owner or ShareToken)
     * @param newManager Address of the new investment manager
     */
    function setInvestmentManager(address newManager) external {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != owner() && msg.sender != $.shareToken) {
            revert Unauthorized();
        }
        if (newManager == address(0)) revert InvalidManager();
        $.investmentManager = newManager;
        emit InvestmentManagerSet(newManager);
    }

    /**
     * @dev Sets the investment vault for yield generation. Share-token-mediated ONLY: the sole caller is
     * ShareTokenUpgradeable, via setInvestmentShareToken / registerVault → _configureVaultInvestmentSettings.
     * @param investmentVault_ Address of the ERC7575 investment vault
     *
     * M-01: the direct owner path was removed. A direct owner call sets $.investmentVault but cannot grant
     * the operator allowance (allowance(shareToken, thisVault)) on the investment share token that
     * withdrawFromInvestment requires — that allowance is granted only by _configureVaultInvestmentSettings.
     * Such a route could therefore report a positive maxWithdraw yet revert at withdrawal, with no clean
     * recovery (setInvestmentShareToken is one-shot, the vault is already registered). Forcing the
     * share-token path means the allowance is always granted alongside the route.
     *
     * The investment vault MUST mint the share token's configured `investmentShareToken`: investAssets
     * deposits idle assets and receives `investmentVault.share()` tokens, while NAV only counts
     * `investmentShareToken`. A mismatch would silently drop invested assets from NAV. WERC-only
     * enforcement lives at ShareTokenUpgradeable.setInvestmentShareToken (the only entry to this path).
     */
    function setInvestmentVault(IERC7575 investmentVault_) external {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.shareToken) revert Unauthorized();
        if (address(investmentVault_) == address(0)) revert InvalidVault();
        if (address(investmentVault_.asset()) != $.asset) {
            revert AssetMismatch();
        }
        address configuredInvestmentShareToken = ShareTokenUpgradeable($.shareToken).getInvestmentShareToken();
        if (configuredInvestmentShareToken == address(0) || investmentVault_.share() != configuredInvestmentShareToken) {
            revert VaultShareMismatch();
        }
        $.investmentVault = address(investmentVault_);
        emit InvestmentVaultSet(address(investmentVault_));
    }

    /**
     * @dev Sets the vault active state (only owner)
     * @param _isActive True to activate, false to deactivate
     *
     * NOTE: isActive is purely a DEPOSIT FREEZE — it gates requestDeposit/maxDeposit/maxMint and is a
     * precondition for migrateBackingOut. It is NOT a solvency/NAV signal: a deactivated vault still
     * holds backing for the shares it already minted (which remain in circulating supply), so its
     * assets MUST keep counting toward global NAV. Excluding them here would socialize a phantom loss
     * across all holders. To actually remove a vault's backing from NAV without loss, use
     * ShareTokenUpgradeable.migrateAndUnregisterVault (which preserves normalized NAV at par).
     *
     * DEPEG RESPONSE (C-01, accepted residual — no on-chain oracle): cross-asset NAV assumes par
     * (all assets ~$1). There is NO automatic repricing if an asset depegs. Protection is the
     * operator gate, not an oracle: every value-moving path is permissioned — deposit/redeem
     * fulfillment is onlyInvestmentManager (async), and the WERC stack additionally requires
     * validator self-allowance + KYC. Deactivating here only stops the DEPOSIT leg of a depeg
     * arbitrage; it does NOT reprice, so redemptions against healthy vaults would still overpay at
     * par. Full operator runbook on a depeg: (1) setVaultActive(false) on the depegged vault;
     * (2) WITHHOLD redeem fulfillment across vaults until repriced; (3) migrateAndUnregisterVault to
     * swap the bad backing out (or deliberately socialize the loss). See docs/DESIGN_ASSUMPTIONS.md.
     */
    function setVaultActive(bool _isActive) external onlyOwner {
        VaultStorage storage $ = _getVaultStorage();
        $.isActive = _isActive;
        emit VaultActiveStateChanged(_isActive);
    }

    /**
     * @dev Self-validating decommission primitive: drains the vault's free assets to `recipient`.
     *
     * Restricted to the share token's migrateAndUnregisterVault flow. The vault validates its own
     * quiescence directly from storage (same invariants the share token enforces before unregister),
     * which avoids an external getVaultMetrics round-trip and cannot be spoofed:
     * - must already be deactivated;
     * - no pending deposits, claimable redemptions, deposit cancelations, or redeem cancelations
     *   (the latter escrow shares owed back to the canceling redeemer);
     * - no active deposit/redeem requesters.
     *
     * It then transfers totalAssets() out. Because the checks force reserved == 0, totalAssets()
     * equals the full asset balance (free backing + any stray dust), so the vault is left empty and
     * can be unregistered cleanly. The share token enforces, atomically, that an equal-or-greater
     * normalized amount of a good asset was injected into another vault, so total backing is
     * preserved (no holder loss); combined with the deactivated-only gate this is not a rug vector.
     *
     * @param recipient Address that receives the drained assets (the migration counterparty)
     * @return amount Amount of asset transferred out
     */
    function migrateBackingOut(address recipient) external nonReentrant returns (uint256 amount) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.shareToken) revert Unauthorized();
        if ($.isActive) revert CannotUnregisterActiveVault();
        // Authoritative obligation gate: aggregate totals cover every in-flight request state directly,
        // so quiescence does not depend on the activeDeposit/RedeemRequesters sets (whose membership can
        // desync across interleaved fulfill/claim/cancel). The set-length checks are kept as a redundant
        // belt-and-suspenders.
        if ($.totalPendingDepositAssets != 0) revert CannotUnregisterVaultPendingDeposits();
        if ($.totalClaimableDepositShares != 0) revert CannotUnregisterVaultClaimableDeposits();
        if ($.totalPendingRedeemShares != 0) revert CannotUnregisterVaultPendingRedeems();
        if ($.totalClaimableRedeemAssets != 0) revert CannotUnregisterVaultClaimableRedemptions();
        if ($.totalCancelDepositAssets != 0) revert CannotUnregisterVaultAssetBalance();
        if ($.totalCancelRedeemShares != 0) revert CannotUnregisterVaultRedeemCancelationsPending();
        if ($.activeDepositRequesters.length() != 0) revert CannotUnregisterVaultActiveDepositRequesters();
        if ($.activeRedeemRequesters.length() != 0) revert CannotUnregisterVaultActiveRedeemRequesters();

        amount = totalAssets();
        if (amount > 0) {
            SafeTokenTransfers.safeTransfer($.asset, recipient, amount);
        }
    }

    /**
     * @dev Returns whether the vault is active and accepting deposits
     * @return True if vault is active
     */
    function isVaultActive() external view returns (bool) {
        VaultStorage storage $ = _getVaultStorage();
        return $.isActive;
    }

    /**
     * @dev Sets the minimum deposit amount (only owner), expressed as a WHOLE-TOKEN count.
     * @param _minimumDepositAmount Minimum deposit in whole tokens; the gate uses
     *        `_minimumDepositAmount * 10^assetDecimals`, so granularity is one whole token and the cap
     *        is 65535 tokens (no sub-token minima).
     *
     * WHY VAULT-LEVEL: the minimum is denominated in THIS vault's asset units and uses its
     * assetDecimals, so it belongs with the asset (the share token is asset-agnostic and does not
     * process deposits). It also keeps the requestDeposit hot path free — minimumDepositAmount is
     * packed in the same warm storage slot as asset/isActive/assetDecimals, so the check needs no
     * extra SLOAD and no cross-contract call (a share-token-level minimum would add a STATICCALL per
     * deposit). Per-asset minima are intentional.
     *
     * SCOPE ASSUMPTION: the whole-token model assumes ~par-valued assets (this deployment is
     * stablecoins — USDT/USDC/HONEY — all ≈ $1, giving a uniform ~$N floor regardless of decimals).
     * It is NOT value-aware: a high-value or non-par asset (e.g. an 8-decimal WBTC) would make the
     * default (1000 whole tokens) an enormous floor and cannot express sub-token minima. Adding such
     * an asset requires switching this to a raw-atomic-unit (uint256) or oracle-denominated minimum.
     */
    function setMinimumDepositAmount(uint16 _minimumDepositAmount) external onlyOwner {
        VaultStorage storage $ = _getVaultStorage();
        $.minimumDepositAmount = _minimumDepositAmount;
    }

    /**
     * @dev Invests idle assets into the investment vault (only investment manager)
     * @param amount Amount of assets to invest
     * @return shares Number of shares received from investment vault
     */
    /**
     * @dev Invests idle assets into the investment vault (only investment manager)
     * @param amount Amount of assets to invest
     * @return shares Number of shares received from investment vault
     */
    function investAssets(uint256 amount) external nonReentrant returns (uint256 shares) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if ($.investmentVault == address(0)) revert NoInvestmentVault();
        if (amount == 0) revert ZeroAmount();

        uint256 availableBalance = totalAssets();
        if (amount > availableBalance) {
            revert ERC20InsufficientBalance(address(this), availableBalance, amount);
        }

        // Approve and deposit into investment vault with ShareToken as receiver
        IERC20Metadata($.asset).safeIncreaseAllowance($.investmentVault, amount);
        shares = IERC7575($.investmentVault).deposit(amount, $.shareToken);

        emit AssetsInvested(amount, shares, $.investmentVault);
        return shares;
    }

    /**
     * @dev Withdraws assets from the investment vault (only investment manager)
     * @param amount Amount of assets to withdraw; pass type(uint256).max to withdraw everything available
     * @return actualAmount Actual amount withdrawn
     *
     * Withdraws (not redeems) from the investment vault with the share token as owner, so the request is
     * asset-denominated and burns exactly amount*scalingFactor shares — a clean multiple of the target's
     * scaling — so no sub-unit NAV dust is ever socialized to holders. Investment targets are WERC-only
     * (rBalance lending model), enforced at ShareTokenUpgradeable.setInvestmentShareToken (the only entry
     * to the share-token-mediated setInvestmentVault path).
     *
     * The request is clamped to maxWithdraw(shareToken), which already folds in the three binding limits:
     * the share token's WERC balance (floored to whole asset units), the validator-issued SELF-allowance
     * (allowance(shareToken, shareToken) — the WERC redemption gate, see F-03), and the target's liquid
     * assets. The operator allowance (allowance(shareToken, thisVault)) is set to max at investment-route
     * configuration, so it is never the binding constraint. We deliberately do NOT pre-check any of these:
     * the clamp covers the partial cases, and when nothing is withdrawable (full freeze / pause / no KYC)
     * the clamp collapses to 0 and the target's withdraw() reverts with its own error.
     */
    function withdrawFromInvestment(uint256 amount) external nonReentrant returns (uint256 actualAmount) {
        VaultStorage storage $ = _getVaultStorage();
        if (msg.sender != $.investmentManager) revert OnlyInvestmentManager();
        if ($.investmentVault == address(0)) revert NoInvestmentVault();
        if (amount == 0) revert ZeroAmount();

        address shareToken_ = $.shareToken;
        uint256 cap = IERC7575($.investmentVault).maxWithdraw(shareToken_);
        uint256 assets = amount < cap ? amount : cap;

        uint256 balanceBefore = IERC20Metadata($.asset).balanceOf(address(this));
        // ShareToken is owner, this vault is receiver. The maxWithdraw clamp guarantees the burned
        // shares (assets*scalingFactor) fit within both the balance and the self-allowance, so the only
        // reverts left here come from withdraw() itself (e.g. ZeroAssets / pause), surfaced as its own error.
        IERC7575($.investmentVault).withdraw(assets, address(this), shareToken_);
        uint256 balanceAfter = IERC20Metadata($.asset).balanceOf(address(this));
        unchecked {
            actualAmount = balanceAfter - balanceBefore;
        }

        emit AssetsWithdrawnFromInvestment(amount, actualAmount, $.investmentVault);
        return actualAmount;
    }

    /**
     * @dev Gets the investment manager address
     * @return Address of current investment manager
     */
    /**
     * @dev Gets the current investment manager address
     * @return Address of the investment manager
     */
    function getInvestmentManager() external view returns (address) {
        VaultStorage storage $ = _getVaultStorage();
        return $.investmentManager;
    }

    /**
     * @dev The configured investment vault for this vault, or address(0) if none. A non-zero value means
     * this vault is a live withdrawal route for invested backing (withdrawFromInvestment can redeem the
     * share token's investment shares through it).
     * @return The investment vault address
     */
    function getInvestmentVault() external view returns (address) {
        VaultStorage storage $ = _getVaultStorage();
        return $.investmentVault;
    }

    /**
     * @dev Returns both claimable redemption shares and normalized assets in a single call
     * This is optimized for ShareToken's getCirculatingSupplyAndAssets() which needs both values
     * together for each vault in the loop
     * @return totalClaimableShares Total shares reserved for redemption claims
     * @return totalNormalizedAssets Total vault assets scaled to 18 decimals
     */
    function getClaimableSharesAndNormalizedAssets() external view returns (uint256 totalClaimableShares, uint256 totalNormalizedAssets) {
        VaultStorage storage $ = _getVaultStorage();
        totalClaimableShares = $.totalClaimableRedeemShares;

        uint256 vaultAssets = totalAssets();
        // mulDiv(x, scaling, 1) == x * scaling exactly; plain multiply has the same overflow revert.
        totalNormalizedAssets = vaultAssets * $.scalingFactor;
    }

    // ========== ERC7887 Cancelation Request Functions ==========

    /**
     * @dev Cancels a pending deposit request (ERC7887 compliant)
     *
     * Transitions assets from pending deposit to pending cancelation state.
     * Uses the Pending → Claimable → Claimed state lifecycle without short-circuiting.
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7887 Extension: Asynchronous Tokenized Vault Cancelation Extension
     * - Only works on Pending requests, not Claimable (already fulfilled)
     * - Blocks new deposit requests while cancelation is pending
     * - State transition: pendingDepositAssets → pendingCancelDepositAssets
     *
     * SECURITY CONSIDERATIONS:
     * - Only callable by the controller or their approved operator
     * - Uses nonReentrant to prevent reentrancy attacks
     * - Cannot cancel claimable (already fulfilled) deposits
     * - Blocks new requests to prevent race conditions
     * - Removes controller from active requesters set
     *
     * AUTHORIZATION:
     * Controller (msg.sender == controller) can call directly, or
     * Operator must be approved via setOperator() on this vault
     *
     * @param requestId The requestId from the original deposit request (must be 0 per implementation)
     * @param controller Address that made the original deposit request
     *
     * @custom:throws InvalidRequestId If requestId != REQUEST_ID (only requestId 0 is valid)
     * @custom:throws InvalidCaller If caller is neither controller nor approved operator
     * @custom:throws NoPendingCancelDeposit If no pending deposit exists for controller
     *
     * @custom:event CancelDepositRequest(controller, requestId, msg.sender)
     */
    function cancelDepositRequest(uint256 requestId, address controller) external nonReentrant {
        VaultStorage storage $ = _getVaultStorage();
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        if (!(controller == msg.sender || _isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 pendingAssets = $.pendingDepositAssets[controller];
        if (pendingAssets == 0) revert NoPendingCancelDeposit();

        // Move from pending to pending cancelation
        delete $.pendingDepositAssets[controller];
        $.totalPendingDepositAssets -= pendingAssets;
        $.pendingCancelDepositAssets[controller] = pendingAssets;
        $.totalCancelDepositAssets += pendingAssets;

        // New deposit requests are blocked while pendingCancelDepositAssets[controller] > 0 (set above).
        // Only drop the controller from the active set if it has no remaining CLAIMABLE deposit: that
        // state is tracked solely by this set (no aggregate total), so removing it while a fulfilled-
        // but-unclaimed deposit exists would let migrateBackingOut pass quiescence with a live claim.
        if ($.claimableDepositShares[controller] == 0) {
            $.activeDepositRequesters.remove(controller);
        }

        emit CancelDepositRequest(controller, REQUEST_ID, msg.sender);
    }

    /**
     * @dev Checks if a deposit cancelation request is pending (ERC7887 compliant)
     *
     * Returns true if the controller has a pending deposit cancelation in the Pending state.
     * Returns false for invalid requestIds or if no pending cancelation exists.
     *
     * STATE MACHINE:
     * - Pending: Assets have been moved from pendingDepositAssets to pendingCancelDepositAssets
     * - Claimable: Investment manager has fulfilled the cancelation, can be claimed
     * - Claimed: User has claimed the assets, cancelation complete
     *
     * SPECIFICATION COMPLIANCE:
     * - Only returns true for requestId == REQUEST_ID (0)
     * - Safe view function with no state changes
     * - Cannot short-circuit to claimed state
     *
     * @param requestId The requestId from the original deposit request (must be 0)
     * @param controller Address that made the original deposit request
     *
     * @return isPending True if a pending deposit cancelation exists, false otherwise
     */
    function pendingCancelDepositRequest(uint256 requestId, address controller) external view returns (bool isPending) {
        if (requestId != REQUEST_ID) return false;
        VaultStorage storage $ = _getVaultStorage();
        return $.pendingCancelDepositAssets[controller] > 0;
    }

    /**
     * @dev Returns the amount of assets available to claim from a fulfilled deposit cancelation (ERC7887)
     *
     * Returns the number of assets that the controller can claim after the investment manager
     * has fulfilled the deposit cancelation request. Returns 0 for invalid requestIds or if
     * no claimable cancelation exists.
     *
     * FLOW:
     * 1. Controller calls cancelDepositRequest() → moves to pendingCancelDepositAssets
     * 2. Investment manager calls fulfillCancelDepositRequest() → moves to claimableCancelDepositAssets
     * 3. Controller calls claimCancelDepositRequest() → receives assets
     *
     * SPECIFICATION COMPLIANCE:
     * - Only returns non-zero for requestId == REQUEST_ID (0)
     * - Safe view function with no state changes
     * - Amount represents assets that were pending deposit, now being canceled
     *
     * @param requestId The requestId from the original deposit request (must be 0)
     * @param controller Address that made the original deposit request
     *
     * @return assets Amount of assets available to claim from the canceled deposit
     */
    function claimableCancelDepositRequest(uint256 requestId, address controller) external view returns (uint256 assets) {
        if (requestId != REQUEST_ID) return 0;
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableCancelDepositAssets[controller];
    }

    /**
     * @dev Claims assets from a fulfilled deposit cancelation request (ERC7887 compliant)
     *
     * Final step in the cancelation lifecycle: transfers assets back to the receiver.
     * Can only claim assets that have been fulfilled by the investment manager and are
     * in the Claimable state. Follows CEI pattern with state changes before transfers.
     *
     * CANCELATION LIFECYCLE:
     * 1. Pending: User calls cancelDepositRequest() to initiate cancelation
     * 2. Claimable: Investment manager calls fulfillCancelDepositRequest() to fulfill
     * 3. Claimed: User calls claimCancelDepositRequest() to receive assets (THIS FUNCTION)
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7887: Asynchronous Cancelation Extension
     * - Three-state lifecycle without short-circuiting
     * - Uses CEI (Checks-Effects-Interactions) pattern
     * - Reentrancy-protected via nonReentrant
     *
     * SECURITY CONSIDERATIONS:
     * - Uses nonReentrant guard to prevent reentrancy attacks
     * - State changes occur before external transfers (CEI)
     * - Only callable by controller or approved operator
     * - Cannot claim assets if not in Claimable state
     *
     * AUTHORIZATION:
     * Controller (msg.sender == controller) can call directly, or
     * Operator must be approved via setOperator() on this vault
     *
     * @param requestId The requestId from the original deposit request (must be 0)
     * @param receiver Address that will receive the canceled asset amount
     * @param controller Address that made the original deposit request
     *
     * @custom:throws InvalidRequestId If requestId != REQUEST_ID (only requestId 0 is valid)
     * @custom:throws InvalidCaller If caller is neither controller nor approved operator
     * @custom:throws CancelationNotClaimable If no claimable deposit cancelation exists
     *
     * @custom:event CancelDepositClaim(controller, receiver, requestId, msg.sender, assets)
     */
    function claimCancelDepositRequest(uint256 requestId, address receiver, address controller) external nonReentrant {
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        VaultStorage storage $ = _getVaultStorage();
        if (receiver == address(0)) revert ERC20InvalidReceiver(receiver);
        if (!(controller == msg.sender || _isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 assets = $.claimableCancelDepositAssets[controller];
        if (assets == 0) revert CancelationNotClaimable();

        // CEI: State changes before external transfer
        delete $.claimableCancelDepositAssets[controller];
        $.totalCancelDepositAssets -= assets;

        // External interaction
        SafeTokenTransfers.safeTransfer($.asset, receiver, assets);

        // Event emission
        emit CancelDepositClaim(controller, receiver, REQUEST_ID, msg.sender, assets);
    }

    /**
     * @dev Cancels a pending redeem request (ERC7887 compliant)
     *
     * Transitions shares from pending redeem to pending cancelation state.
     * Uses the Pending → Claimable → Claimed state lifecycle without short-circuiting.
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7887 Extension: Asynchronous Tokenized Vault Cancelation Extension
     * - Only works on Pending requests, not Claimable (already fulfilled)
     * - Blocks new redeem requests while cancelation is pending
     * - State transition: pendingRedeemShares → pendingCancelRedeemShares
     *
     * SECURITY CONSIDERATIONS:
     * - Only callable by the controller or their approved operator
     * - Uses nonReentrant to prevent reentrancy attacks
     * - Cannot cancel claimable (already fulfilled) redeems
     * - Blocks new requests to prevent race conditions
     * - Removes controller from active requesters set
     *
     * AUTHORIZATION:
     * Controller (msg.sender == controller) can call directly, or
     * Operator must be approved via setOperator() on this vault
     *
     * @param requestId The requestId from the original redeem request (must be 0 per implementation)
     * @param controller Address that made the original redeem request
     *
     * @custom:throws InvalidRequestId If requestId != REQUEST_ID (only requestId 0 is valid)
     * @custom:throws InvalidCaller If caller is neither controller nor approved operator
     * @custom:throws NoPendingCancelRedeem If no pending redeem exists for controller
     *
     * @custom:event CancelRedeemRequest(controller, requestId, msg.sender)
     */
    function cancelRedeemRequest(uint256 requestId, address controller) external nonReentrant {
        VaultStorage storage $ = _getVaultStorage();
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        if (!(controller == msg.sender || _isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 pendingShares = $.pendingRedeemShares[controller];
        if (pendingShares == 0) revert NoPendingCancelRedeem();

        // Move from pending to pending cancelation
        delete $.pendingRedeemShares[controller];
        $.totalPendingRedeemShares -= pendingShares;
        $.pendingCancelRedeemShares[controller] = pendingShares;
        $.totalCancelRedeemShares += pendingShares; // tracks the escrowed-shares obligation through claim

        // New redeem requests are blocked while pendingCancelRedeemShares[controller] > 0 (set above).
        $.activeRedeemRequesters.remove(controller);

        emit CancelRedeemRequest(controller, REQUEST_ID, msg.sender);
    }

    /**
     * @dev Checks if a redeem cancelation request is pending (ERC7887 compliant)
     *
     * Returns true if the controller has a pending redeem cancelation in the Pending state.
     * Returns false for invalid requestIds or if no pending cancelation exists.
     *
     * STATE MACHINE:
     * - Pending: Shares have been moved from pendingRedeemShares to pendingCancelRedeemShares
     * - Claimable: Investment manager has fulfilled the cancelation, can be claimed
     * - Claimed: User has claimed the shares, cancelation complete
     *
     * SPECIFICATION COMPLIANCE:
     * - Only returns true for requestId == REQUEST_ID (0)
     * - Safe view function with no state changes
     * - Cannot short-circuit to claimed state
     *
     * @param requestId The requestId from the original redeem request (must be 0)
     * @param controller Address that made the original redeem request
     *
     * @return isPending True if a pending redeem cancelation exists, false otherwise
     */
    function pendingCancelRedeemRequest(uint256 requestId, address controller) external view returns (bool isPending) {
        if (requestId != REQUEST_ID) return false;
        VaultStorage storage $ = _getVaultStorage();
        return $.pendingCancelRedeemShares[controller] > 0;
    }

    /**
     * @dev Returns the amount of shares available to claim from a fulfilled redeem cancelation (ERC7887)
     *
     * Returns the number of shares that the controller can claim after the investment manager
     * has fulfilled the redeem cancelation request. Returns 0 for invalid requestIds or if
     * no claimable cancelation exists.
     *
     * FLOW:
     * 1. Controller calls cancelRedeemRequest() → moves to pendingCancelRedeemShares
     * 2. Investment manager calls fulfillCancelRedeemRequest() → moves to claimableCancelRedeemShares
     * 3. Controller calls claimCancelRedeemRequest() → receives shares
     *
     * SPECIFICATION COMPLIANCE:
     * - Only returns non-zero for requestId == REQUEST_ID (0)
     * - Safe view function with no state changes
     * - Amount represents shares that were pending redeem, now being canceled
     *
     * @param requestId The requestId from the original redeem request (must be 0)
     * @param controller Address that made the original redeem request
     *
     * @return shares Amount of shares available to claim from the canceled redeem
     */
    function claimableCancelRedeemRequest(uint256 requestId, address controller) external view returns (uint256 shares) {
        if (requestId != REQUEST_ID) return 0;
        VaultStorage storage $ = _getVaultStorage();
        return $.claimableCancelRedeemShares[controller];
    }

    /**
     * @dev Claims shares from a fulfilled redeem cancelation request (ERC7887 compliant)
     *
     * Final step in the redeem cancelation lifecycle: transfers shares back to the receiver.
     * Can only claim shares that have been fulfilled by the investment manager and are
     * in the Claimable state. Follows CEI pattern with state changes before transfers.
     *
     * CANCELATION LIFECYCLE:
     * 1. Pending: User calls cancelRedeemRequest() to initiate cancelation
     * 2. Claimable: Investment manager calls fulfillCancelRedeemRequest() to fulfill
     * 3. Claimed: User calls claimCancelRedeemRequest() to receive shares (THIS FUNCTION)
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7887: Asynchronous Cancelation Extension
     * - Three-state lifecycle without short-circuiting
     * - Uses CEI (Checks-Effects-Interactions) pattern
     * - Reentrancy-protected via nonReentrant
     *
     * SECURITY CONSIDERATIONS:
     * - Uses nonReentrant guard to prevent reentrancy attacks
     * - State changes occur before external transfers (CEI)
     * - Only callable by controller or approved operator
     * - Cannot claim shares if not in Claimable state
     *
     * AUTHORIZATION:
     * Controller (msg.sender == controller) can call directly, or
     * Operator must be approved via setOperator() on this vault
     *
     * NOTE: ERC-7887 is a draft and internally inconsistent for this method — its lifecycle/prose names
     * the third input `controller`, while one method table labels it `owner`. We use `controller`, which
     * matches the authorization semantics (and most of the ERC text). The ABI selector is identical
     * either way: claimCancelRedeemRequest(uint256,address,address).
     *
     * @param requestId The requestId from the original redeem request (must be 0)
     * @param receiver Address that will receive the canceled share amount
     * @param controller Address that made (controls) the original redeem request
     *
     * @custom:throws InvalidRequestId If requestId != REQUEST_ID (only requestId 0 is valid)
     * @custom:throws InvalidCaller If caller is neither controller nor approved operator
     * @custom:throws CancelationNotClaimable If no claimable redeem cancelation exists
     *
     * @custom:event CancelRedeemClaim(controller, receiver, requestId, msg.sender, shares)
     */
    function claimCancelRedeemRequest(uint256 requestId, address receiver, address controller) external nonReentrant {
        if (requestId != REQUEST_ID) revert InvalidRequestId();
        VaultStorage storage $ = _getVaultStorage();
        if (receiver == address(0)) revert ERC20InvalidReceiver(receiver);
        if (!(controller == msg.sender || _isOperator(controller, msg.sender))) {
            revert InvalidCaller();
        }

        uint256 shares = $.claimableCancelRedeemShares[controller];
        if (shares == 0) revert CancelationNotClaimable();

        // CEI: State changes before external transfer
        delete $.claimableCancelRedeemShares[controller];
        $.totalCancelRedeemShares -= shares;

        // External interaction
        SafeTokenTransfers.safeTransfer($.shareToken, receiver, shares);

        // Event emission
        emit CancelRedeemClaim(controller, receiver, REQUEST_ID, msg.sender, shares);
    }

    // ========== Off-Chain Helper Functions ==========

    /**
     * @dev Returns all addresses with active deposit requests (limited to 100 for RPC safety)
     *
     * Returns all controllers that have pending deposit requests in Pending state.
     * Limited to 100 entries to prevent RPC timeout. For production systems with many users,
     * use getDepositControllerStatusBatchPaginated() for scalable pagination.
     *
     * PERFORMANCE:
     * - O(n) operation where n = number of active deposit requesters
     * - Limited to 100 entries to prevent RPC overload
     * - Use pagination functions for production with >100 users
     *
     * USE CASES:
     * - Off-chain UI to show all users with pending deposits
     * - Investment manager to see all pending requests at a glance
     * - Monitoring and analytics dashboards
     *
     * @return Array of controller addresses with pending deposit requests
     *
     * @custom:throws TooManyRequesters If more than 100 active deposit requesters exist
     */
    function getActiveDepositRequesters() external view returns (address[] memory) {
        VaultStorage storage $ = _getVaultStorage();
        if ($.activeDepositRequesters.length() > 100) {
            revert TooManyRequesters();
        }
        return $.activeDepositRequesters.values();
    }

    /**
     * @dev Returns all addresses with active redeem requests (limited to 100 for RPC safety)
     *
     * Returns all controllers that have pending redeem requests in Pending state.
     * Limited to 100 entries to prevent RPC timeout. For production systems with many users,
     * use getRedeemControllerStatusBatchPaginated() for scalable pagination.
     *
     * PERFORMANCE:
     * - O(n) operation where n = number of active redeem requesters
     * - Limited to 100 entries to prevent RPC overload
     * - Use pagination functions for production with >100 users
     *
     * USE CASES:
     * - Off-chain UI to show all users with pending redemptions
     * - Investment manager to see all pending requests at a glance
     * - Monitoring and analytics dashboards
     *
     * @return Array of controller addresses with pending redeem requests
     *
     * @custom:throws TooManyRequesters If more than 100 active redeem requesters exist
     */
    function getActiveRedeemRequesters() external view returns (address[] memory) {
        VaultStorage storage $ = _getVaultStorage();
        if ($.activeRedeemRequesters.length() > 100) revert TooManyRequesters();
        return $.activeRedeemRequesters.values();
    }

    /**
     * @dev Returns complete request status for a single controller
     *
     * Returns all pending and claimable amounts for a given controller across
     * both deposit and redeem request flows.
     *
     * RETURNED DATA:
     * - controller: The controller address queried
     * - pendingDepositAssets: Assets in Pending deposit state
     * - claimableDepositShares: Shares in Claimable deposit state
     * - pendingRedeemShares: Shares in Pending redeem state
     * - claimableRedeemAssets: Assets in Claimable redeem state
     * - claimableRedeemShares: Shares being held for claimable redeems
     *
     * PERFORMANCE:
     * - O(1) operation: Single lookup per field
     * - Safe view function with no state changes
     *
     * @param controller Address to check
     *
     * @return status Complete controller status with all pending and claimable amounts
     */
    function getControllerStatus(address controller) external view returns (ControllerStatus memory status) {
        VaultStorage storage $ = _getVaultStorage();
        status = ControllerStatus({
            controller: controller,
            pendingDepositAssets: $.pendingDepositAssets[controller],
            claimableDepositShares: $.claimableDepositShares[controller],
            pendingRedeemShares: $.pendingRedeemShares[controller],
            claimableRedeemAssets: $.claimableRedeemAssets[controller],
            claimableRedeemShares: $.claimableRedeemShares[controller]
        });
    }

    /**
     * @dev Returns batch request status for multiple controllers
     *
     * Efficiently queries request status for multiple controllers in a single call.
     * Limited to MAX_BATCH_SIZE (1000) to prevent gas/RPC issues.
     *
     * BATCH OPERATIONS:
     * - Returns status for all provided controllers
     * - Limited to 1000 addresses per call
     * - More efficient than multiple getControllerStatus calls
     * - Returns empty status if controller has no requests
     *
     * PERFORMANCE:
     * - O(n) operation where n = number of controllers queried
     * - Each controller lookup is O(1)
     * - Total gas: linear in number of controllers
     *
     * @param controllers Array of controller addresses to check
     *
     * @return statuses Array of complete controller statuses (same length as input)
     *
     * @custom:throws BatchSizeTooLarge If controllers.length > MAX_BATCH_SIZE (1000)
     */
    function getControllerStatusBatch(address[] calldata controllers) external view returns (ControllerStatus[] memory statuses) {
        if (controllers.length > MAX_BATCH_SIZE) revert BatchSizeTooLarge();
        VaultStorage storage $ = _getVaultStorage();
        statuses = new ControllerStatus[](controllers.length);

        for (uint256 i = 0; i < controllers.length; i++) {
            address controller = controllers[i];
            statuses[i] = ControllerStatus({
                controller: controller,
                pendingDepositAssets: $.pendingDepositAssets[controller],
                claimableDepositShares: $.claimableDepositShares[controller],
                pendingRedeemShares: $.pendingRedeemShares[controller],
                claimableRedeemAssets: $.claimableRedeemAssets[controller],
                claimableRedeemShares: $.claimableRedeemShares[controller]
            });
        }
    }

    /**
     * @dev Returns comprehensive global vault metrics and configuration
     *
     * Provides a complete snapshot of vault state including pending requests,
     * claimable amounts, asset allocation, and configuration parameters.
     *
     * RETURNED METRICS:
     * - Pending/claimable requests: All asynchronous request amounts
     * - Asset allocation: Available for investment, in claims, etc.
     * - Configuration: Scaling factor, active status, manager addresses
     * - Request counts: Number of active requesters
     *
     * USES:
     * - Off-chain monitoring and analytics
     * - Dashboard calculations
     * - Health checks and reports
     * - Integration with portfolio tracking
     *
     * @return metrics Complete vault metrics including totals and configuration
     */
    function getVaultMetrics() external view returns (VaultMetrics memory metrics) {
        VaultStorage storage $ = _getVaultStorage();
        // Solvency visibility (L-04): expose gross balance, reserved obligations, and any shortfall so an
        // under-collateralization is not hidden by totalAssets()'s saturate-to-zero behavior.
        uint256 grossBalance = IERC20Metadata($.asset).balanceOf(address(this));
        uint256 reserved = $.totalPendingDepositAssets + $.totalClaimableRedeemAssets + $.totalCancelDepositAssets;
        metrics = VaultMetrics({
            totalPendingDepositAssets: $.totalPendingDepositAssets,
            totalClaimableDepositShares: $.totalClaimableDepositShares,
            totalClaimableRedeemAssets: $.totalClaimableRedeemAssets,
            totalPendingRedeemShares: $.totalPendingRedeemShares,
            totalCancelDepositAssets: $.totalCancelDepositAssets,
            totalCancelRedeemShares: $.totalCancelRedeemShares,
            scalingFactor: $.scalingFactor,
            totalAssets: totalAssets(),
            availableForInvestment: totalAssets(),
            activeDepositRequestersCount: $.activeDepositRequesters.length(),
            activeRedeemRequestersCount: $.activeRedeemRequesters.length(),
            isActive: $.isActive,
            asset: $.asset,
            shareToken: $.shareToken,
            investmentManager: $.investmentManager,
            investmentVault: $.investmentVault,
            grossAssetBalance: grossBalance,
            reservedAssets: reserved
        });
    }

    // ========== Scalable Off-Chain Helper Functions ==========

    // Maximum batch size to prevent RPC timeouts and gas issues
    uint256 public constant MAX_BATCH_SIZE = 1000;

    /**
     * @dev Internal helper for paginating ControllerStatus using built-in values() function
     * EnumerableSet.values() handles all bounds checking internally, so no manual validation needed
     * @param addressSet The EnumerableSet to paginate and get status for
     * @param offset Starting index (0-based)
     * @param limit Maximum number of statuses to return
     * @return statuses Paginated ControllerStatus array
     * @return total Total number of items in the set
     * @return hasMore True if there are more items beyond this batch
     */
    function _paginateControllerStatus(
        EnumerableSet.AddressSet storage addressSet,
        uint256 offset,
        uint256 limit
    )
        internal
        view
        returns (ControllerStatus[] memory statuses, uint256 total, bool hasMore)
    {
        if (limit > MAX_BATCH_SIZE) revert BatchSizeTooLarge();
        VaultStorage storage $ = _getVaultStorage();
        total = addressSet.length();

        // Get addresses using EnumerableSet's built-in range function (handles bounds automatically)
        address[] memory controllers = addressSet.values(offset, offset + limit);
        statuses = new ControllerStatus[](controllers.length);

        // Populate ControllerStatus array with complete data
        for (uint256 i = 0; i < controllers.length; i++) {
            address controller = controllers[i];
            statuses[i] = ControllerStatus({
                controller: controller,
                pendingDepositAssets: $.pendingDepositAssets[controller],
                claimableDepositShares: $.claimableDepositShares[controller],
                pendingRedeemShares: $.pendingRedeemShares[controller],
                claimableRedeemAssets: $.claimableRedeemAssets[controller],
                claimableRedeemShares: $.claimableRedeemShares[controller]
            });
        }

        hasMore = offset + controllers.length < total;
    }

    /**
     * @dev Returns count of active requesters without fetching arrays
     * Gas-efficient way to check queue sizes for monitoring
     * @return depositCount Number of active deposit requesters
     * @return redeemCount Number of active redeem requesters
     */
    function getActiveRequestersCount() external view returns (uint256 depositCount, uint256 redeemCount) {
        VaultStorage storage $ = _getVaultStorage();
        depositCount = $.activeDepositRequesters.length();
        redeemCount = $.activeRedeemRequesters.length();
    }

    /**
     * @dev Returns paginated ControllerStatus for active deposit requesters (comprehensive data)
     * Provides complete request status information for efficient off-chain processing
     *
     * @param offset Starting index in active deposit requesters array
     * @param limit Maximum number of statuses to return
     * @return statuses Array of ControllerStatus for deposit requesters (complete data)
     * @return total Total number of active deposit requesters
     * @return hasMore True if there are more results beyond this batch
     */
    function getDepositControllerStatusBatchPaginated(uint256 offset, uint256 limit) external view returns (ControllerStatus[] memory statuses, uint256 total, bool hasMore) {
        VaultStorage storage $ = _getVaultStorage();
        return _paginateControllerStatus($.activeDepositRequesters, offset, limit);
    }

    /**
     * @dev Returns paginated ControllerStatus for active redeem requesters (comprehensive data)
     * Provides complete request status information for efficient off-chain processing
     *
     * @param offset Starting index in active redeem requesters array
     * @param limit Maximum number of statuses to return
     * @return statuses Array of ControllerStatus for redeem requesters (complete data)
     * @return total Total number of active redeem requesters
     * @return hasMore True if there are more results beyond this batch
     */
    function getRedeemControllerStatusBatchPaginated(uint256 offset, uint256 limit) external view returns (ControllerStatus[] memory statuses, uint256 total, bool hasMore) {
        VaultStorage storage $ = _getVaultStorage();
        return _paginateControllerStatus($.activeRedeemRequesters, offset, limit);
    }

    /**
     * @dev Comprehensive controller status including all request states
     */
    struct ControllerStatus {
        address controller; // Address of the controller/requester
        uint256 pendingDepositAssets; // Assets in pending deposit state
        uint256 claimableDepositShares; // Shares ready to be claimed from deposits
        uint256 pendingRedeemShares; // Shares in pending redeem state
        uint256 claimableRedeemAssets; // Assets ready to be claimed from redemptions
        uint256 claimableRedeemShares; // Shares ready to be redeemed
    }
    // NOTE: per-controller cancelation state (deposit/redeem, pending/claimable) is intentionally NOT
    // duplicated here — it is already exposed by the ERC-7887 getters pendingCancelDepositRequest /
    // claimableCancelDepositRequest / pendingCancelRedeemRequest / claimableCancelRedeemRequest.
    // Adding it would add 4 SLOADs per controller to the batched/paginated status loops for no new data.

    // Investment events
    event InvestmentManagerSet(address indexed manager);
    event InvestmentVaultSet(address indexed vault);
    event VaultActiveStateChanged(bool indexed isActive);

    // ========== Upgrade Functions ==========

    /**
     * @dev Upgrade the implementation of the proxy (only owner)
     * @param newImplementation Address of the new implementation contract
     */
    function upgradeTo(address newImplementation) external onlyOwner {
        _upgradeToAndCallUUPS(newImplementation, "");
    }

    /**
     * @dev Upgrade the implementation and call a function (only owner)
     * @param newImplementation Address of the new implementation contract
     * @param data Calldata to execute on the new implementation
     */
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable onlyOwner {
        _upgradeToAndCallUUPS(newImplementation, data);
    }

    function _upgradeToAndCallUUPS(address newImplementation, bytes memory data) private {
        // onlyProxy: upgrades must run in proxy (delegatecall) context, never on the raw implementation.
        // Defense-in-depth — onlyOwner already blocks direct-impl calls (the impl is never initialized,
        // so its owner() is address(0)) — but this matches the OZ UUPS guard explicitly.
        if (address(this) == __self) revert UUPSUnauthorizedCallContext();

        try IERC1822Proxiable(newImplementation).proxiableUUID() returns (bytes32 slot) {
            if (slot != ERC1967Utils.IMPLEMENTATION_SLOT) {
                revert UUPSUnsupportedProxiableUUID(slot);
            }
        } catch {
            revert ERC1967Utils.ERC1967InvalidImplementation(newImplementation);
        }

        ERC1967Utils.upgradeToAndCall(newImplementation, data);
    }

    // ========== Internal Helper Functions for Safe Transfers ==========
}
