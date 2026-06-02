// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC7575, IERC7575ShareExtended} from "./interfaces/IERC7575.sol";

import {IERC7575Errors} from "./interfaces/IERC7575Errors.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {IERC1822Proxiable} from "@openzeppelin/contracts/interfaces/draft-IERC1822.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
// Interface for WERC7575 share tokens with restricted balance functionality

interface IWERC7575ShareToken {
    function rBalanceOf(address account) external view returns (uint256);
}

import {DecimalConstants} from "./DecimalConstants.sol";
import {ERC7575VaultUpgradeable} from "./ERC7575VaultUpgradeable.sol";
import {SafeTokenTransfers} from "./SafeTokenTransfers.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

// Forward declaration to avoid circular dependency
interface IERC7575Vault {
    function getClaimableSharesAndNormalizedAssets() external view returns (uint256 claimableShares, uint256 normalizedAssets);
}

/**
 * @title ShareTokenUpgradeable
 * @dev FULLY COMPLIANT ERC7575Share + ERC20 token for multi-asset vault systems
 *      (ERC-7540 operators are NOT here — they are per-vault; see the ERC7540 OPERATOR NOTE below)
 *
 * ERC7575 COMPLIANCE VERIFICATION:
 * IERC7575ShareExtended Interface (https://eips.ethereum.org/EIPS/eip-7575)
 *    - vault(address asset) → returns vault address for asset
 *    - getRegisteredAssets() → returns all registered assets
 *    - getCirculatingSupplyAndAssets() → aggregates supply and normalized assets across all vaults
 *    - VaultUpdate event emission on registration/unregistration
 *    - Multi-asset registry with asset→vault mapping
 *
 * ERC7540 OPERATOR NOTE:
 *    Operators are NOT managed here. Per ERC-7540, operator approvals are scoped to the
 *    vault that owns the Requests, so setOperator/isOperator live on each
 *    ERC7575VaultUpgradeable (per-vault). This share token holds no operator table.
 *
 * ARCHITECTURE FEATURES:
 * - Shared across multiple ERC7575VaultUpgradeable contracts (one per asset)
 * - Decimal normalization for cross-asset aggregation (18-decimal standard)
 * - Vault-only minting/burning with proper authorization controls
 * - Registry management for asset-to-vault relationships
 * - Per-vault operator management (operators live on each vault, per ERC-7540)
 * - CENTRALIZED investment manager control with automatic propagation to all vaults
 * - CENTRALIZED investment ShareToken configuration for unified investment strategy
 * - ERC165 interface detection support
 *
 * SECURITY:
 * - Only registered vaults can mint/burn tokens (onlyVaults modifier)
 * - Safe vault registration/unregistration with outstanding share checks
 * - Integer overflow protection with Math.mulDiv in aggregation
 * - Operator approvals are per-vault (ERC-7540); this share token holds no operator table
 * - Upgradeable with storage slots pattern for safe upgrades
 */
contract ShareTokenUpgradeable is Initializable, ERC20Upgradeable, Ownable2StepUpgradeable, IERC7575ShareExtended, IERC165, IERC7575Errors {
    using EnumerableMap for EnumerableMap.AddressToAddressMap;
    // Storage slot for ShareToken-specific data

    // Note: Common errors are now inherited from IERC7575Errors interface

    // ERC-7201 namespaced storage slot.
    // = keccak256(abi.encode(uint256(keccak256("erc7575.sharetoken.storage")) - 1)) & ~bytes32(uint256(0xff))
    // Precomputed literal (abi.encode is not a constant expression); the trailing 0x00 byte reserves a
    // 256-slot gap so the struct cannot collide with mapping/array data laid out from this base.
    bytes32 private constant SHARE_TOKEN_STORAGE_SLOT = 0x24a8ea2064e345bc9bcf866d4ea871e7f1c841a2346e04841a10d2a8ea155200;
    address private immutable __self = address(this);

    error UUPSUnauthorizedCallContext();
    error UUPSUnsupportedProxiableUUID(bytes32 slot);

    // Security constants
    uint256 private constant VIRTUAL_SHARES = 1e6; // Virtual shares for inflation protection
    uint256 private constant VIRTUAL_ASSETS = 1e6; // Virtual assets for inflation protection
    uint256 private constant MAX_VAULTS_PER_SHARE_TOKEN = 10; // DoS mitigation: prevents unbounded loop in aggregation

    struct ShareTokenStorage {
        // EnumerableMap from asset to vault address (replaces both vaults mapping and registeredAssets array)
        EnumerableMap.AddressToAddressMap assetToVault;
        // Reverse mapping from vault to asset for quick lookup
        mapping(address vault => address asset) vaultToAsset;
        // Investment configuration - centralized at ShareToken level
        address investmentShareToken; // The ShareToken used for investments
        address investmentManager; // Centralized investment manager for all vaults
    }

    /**
     * @dev Returns the ShareToken storage struct
     */
    function _getShareTokenStorage() private pure returns (ShareTokenStorage storage $) {
        bytes32 slot = SHARE_TOKEN_STORAGE_SLOT;
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
     * @dev Initializes the contract
     * @param name Token name
     * @param symbol Token symbol
     * @param owner Initial owner address
     */
    function initialize(string memory name, string memory symbol, address owner) public initializer {
        __ERC20_init(name, symbol);
        __Ownable_init(owner);

        // Enforce 18 decimals for consistency with ERC7575 standard
        if (decimals() != DecimalConstants.SHARE_TOKEN_DECIMALS) {
            revert WrongDecimals();
        }
    }

    // Modifier to restrict minting/burning to registered vaults
    modifier onlyVaults() {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        if ($.vaultToAsset[msg.sender] == address(0)) revert Unauthorized();
        _;
    }

    /**
     * @dev Returns the vault address for a specific asset
     *
     * ERC7575 SPECIFICATION (IERC7575ShareExtended interface):
     * "Returns the vault address for a specific asset.
     * Allows share tokens to point back to their vaults."
     *
     * @param asset The asset token address
     * @return vaultAddress The vault address that handles this asset
     */
    function vault(address asset) external view override returns (address vaultAddress) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        (, vaultAddress) = $.assetToVault.tryGet(asset);
    }

    /**
     * @dev Registers a new vault for an asset in the multi-asset system (ERC7575 compliant)
     *
     * Establishes a one-to-one relationship between an asset and a vault. All users
     * depositing/redeeming that asset will use this vault. Automatically configures
     * the new vault with existing investment settings for seamless integration.
     *
     * MULTI-ASSET ARCHITECTURE:
     * "Multi-Asset Vaults share a single `share` token with multiple entry points
     * denominated in different `asset` tokens." (ERC7575 specification)
     *
     * AUTOMATIC CONFIGURATION:
     * When a vault is registered, it automatically inherits:
     * - Investment ShareToken configuration (if already set)
     * - Investment manager (if already configured)
     * - Appropriate allowances for investment operations
     *
     * This ensures newly registered vaults work immediately without separate setup.
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7575: Multi-asset vault standard
     * - One-to-one asset-to-vault mapping enforced
     * - DoS mitigation: Maximum 10 vaults per share token
     * - VaultUpdate event emission
     *
     * ACCESS CONTROL:
     * - Only callable by share token owner
     * - Validates vault configuration before registration
     *
     * VALIDATION:
     * - Asset and vault addresses must not be zero
     * - Asset must not already be registered
     * - Vault's asset() must match the asset parameter
     * - Vault's share() must match this ShareToken address
     * - Total vaults must not exceed MAX_VAULTS_PER_SHARE_TOKEN (10)
     *
     * @param asset The asset token address to register
     * @param vaultAddress The vault contract address for this asset
     *
     * @custom:throws ZeroAddress If asset or vault address is zero
     * @custom:throws AssetMismatch If vault.asset() != provided asset
     * @custom:throws VaultShareMismatch If vault.share() != this ShareToken
     * @custom:throws AssetAlreadyRegistered If asset is already registered
     * @custom:throws MaxVaultsExceeded If maximum vault limit (10) is reached
     *
     * @custom:event VaultUpdate(asset, vaultAddress)
     */
    function registerVault(address asset, address vaultAddress) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        if (vaultAddress == address(0)) revert ZeroAddress();

        // Validate that vault's asset matches the provided asset parameter
        if (IERC7575(vaultAddress).asset() != asset) revert AssetMismatch();

        // Validate that vault's share token matches this ShareToken
        if (IERC7575(vaultAddress).share() != address(this)) {
            revert VaultShareMismatch();
        }

        ShareTokenStorage storage $ = _getShareTokenStorage();

        // DoS mitigation: Enforce maximum vaults per share token to prevent unbounded loop in getCirculatingSupplyAndAssets
        if ($.assetToVault.length() >= MAX_VAULTS_PER_SHARE_TOKEN) {
            revert MaxVaultsExceeded();
        }

        // Register new vault - set() returns true if newly added, false if already existed
        if (!$.assetToVault.set(asset, vaultAddress)) {
            revert AssetAlreadyRegistered();
        }
        $.vaultToAsset[vaultAddress] = asset;

        // If investment ShareToken is already configured, set up investment for the new vault
        // Only configure if the vault address is a deployed contract
        address investmentShareToken = $.investmentShareToken;
        if (investmentShareToken != address(0)) {
            _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken);
        }

        // If investment manager is already configured, set it for the new vault
        // Only configure if the vault address is a deployed contract
        address investmentManager = $.investmentManager;
        if (investmentManager != address(0)) {
            ERC7575VaultUpgradeable(vaultAddress).setInvestmentManager(investmentManager);
        }

        emit VaultUpdate(asset, vaultAddress);
    }

    /**
     * @dev Unregisters a vault and removes it from the multi-asset system (ERC7575 compliant)
     *
     * Removes a vault from the asset-to-vault registry. This is a permanent operation
     * that can only be performed when the vault has zero pending requests and no remaining
     * assets, ensuring no user funds are at risk.
     *
     * PREREQUISITES FOR UNREGISTRATION:
     * The vault must meet ALL of these conditions:
     * 1. Vault must be inactive (isActive = false)
     * 2. No pending deposit requests (totalPendingDepositAssets = 0)
     * 3. No claimable redemptions (totalClaimableRedeemAssets = 0)
     * 4. No ERC7887 pending/claimable cancelations (totalCancelDepositAssets = 0)
     * 5. No active deposit requesters (activeDepositRequestersCount = 0)
     * 6. No active redeem requesters (activeRedeemRequestersCount = 0)
     * 7. No asset tokens remaining in vault balance
     *
     * SAFETY GUARANTEES:
     * - Comprehensive multi-step validation prevents accidental unregistration
     * - Checks both request state and physical asset balance
     * - Catches investment vaults and edge cases
     * - Atomic operation: all validations or complete rollback
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7575: Multi-asset vault standard
     * - Safe unregistration without user fund loss
     * - VaultUpdate event emission with zero address
     *
     * ACCESS CONTROL:
     * - Only callable by share token owner
     * - Owner responsibility to pause vault before unregistration
     *
     * @param asset The asset token address to unregister
     *
     * @custom:throws ZeroAddress If asset address is zero
     * @custom:throws AssetNotRegistered If asset is not currently registered
     * @custom:throws CannotUnregisterActiveVault If vault is still active
     * @custom:throws CannotUnregisterVaultPendingDeposits If pending deposits exist
     * @custom:throws CannotUnregisterVaultClaimableRedemptions If claimable redemptions exist
     * @custom:throws CannotUnregisterVaultAssetBalance If ERC7887 cancelations or assets remain
     * @custom:throws CannotUnregisterVaultActiveDepositRequesters If active deposit requesters exist
     * @custom:throws CannotUnregisterVaultActiveRedeemRequesters If active redeem requesters exist
     *
     * @custom:event VaultUpdate(asset, address(0))
     */
    function unregisterVault(address asset) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        // Thin wrapper for removing an EMPTY vault: delegates to the shared core with a null toAsset.
        // The core only needs/uses a toAsset when the vault still holds backing (moved > 0); with a
        // null toAsset that case reverts (AssetNotRegistered) instead of orphaning the backing. So
        // this succeeds only for a quiescent, drained vault. To remove a vault that still holds
        // backing WITHOUT a loss, call migrateAndUnregisterVault with a real toAsset.
        //
        // NOTE: a quiescent vault is NOT necessarily empty — claiming a deposit moves only the shares
        // to the user, the assets stay as backing (totalAssets(), which also includes any dust). The
        // core drains that via migrateBackingOut, so backing can never be silently stranded here.
        _migrateAndUnregisterVault(asset, address(0));
    }

    /// @dev Emitted when a deactivated vault's backing is migrated into another vault and unregistered
    event VaultBackingMigrated(address indexed fromAsset, address fromVault, uint256 amountRemoved, address indexed toAsset, address toVault, uint256 amountInjected);

    /**
     * @dev Migrates a DEACTIVATED vault's entire backing into another registered vault, then
     * unregisters it — preserving total normalized backing so no holder takes a loss.
     *
     * Use case: removing a non-compliant or depegged asset without socializing a loss. The exact
     * amount of `toAsset` needed to preserve normalized backing at par is computed from the drained
     * amount and pulled from the owner; the deactivated `fromAsset` vault is drained to the owner
     * (who liquidates it off-chain and absorbs any real shortfall); `fromAsset` is then unregistered.
     * `totalSupply` is untouched and `totalNormalizedAssets` is preserved (rounding favors the pool),
     * so the share-price ratio is maintained.
     *
     * The `fromAsset` vault must already be deactivated and quiescent; `migrateBackingOut` enforces
     * those invariants (inactive, no pending/claimable/cancelation, no active requesters) directly
     * from the vault's own storage. Because reserved == 0 there, the vault is drained to zero and
     * unregisters cleanly with nothing stranded.
     *
     * @param fromAsset Asset of the deactivated vault being removed
     * @param toAsset   Asset of the vault that receives the compensating backing
     */
    function migrateAndUnregisterVault(address fromAsset, address toAsset) external onlyOwner {
        _migrateAndUnregisterVault(fromAsset, toAsset);
    }

    /**
     * @dev Shared core for vault decommissioning, used by both unregisterVault (toAsset == 0) and
     * migrateAndUnregisterVault. Drains the deactivated fromVault; if it still held backing
     * (moved > 0) an equal-or-greater normalized amount of toAsset is pulled from the caller into
     * toVault first (preserving NAV at par, rounding favors the pool); then fromVault is unregistered.
     * Kept internal so msg.sender stays the original owner for the safeTransferFrom pull.
     */
    function _migrateAndUnregisterVault(address fromAsset, address toAsset) internal {
        if (fromAsset == toAsset) revert SameAssetMigration();
        ShareTokenStorage storage $ = _getShareTokenStorage();
        (bool fromExists, address fromVault) = $.assetToVault.tryGet(fromAsset);
        if (!fromExists) revert AssetNotRegistered();

        // migrateBackingOut self-validates quiescence + inactive; moved == 0 ⇒ vault was empty.
        uint256 moved = ERC7575VaultUpgradeable(fromVault).migrateBackingOut(msg.sender);

        // toAsset (compensation) is only required when there is backing to migrate. The empty-vault
        // wrapper passes toAsset == 0; reaching here with backing and no toAsset means a backed vault
        // was passed to plain unregisterVault — reject it rather than orphan the backing.
        if (moved > 0) {
            if (toAsset == address(0)) revert CannotUnregisterVaultAssetBalance();
            (bool toExists, address toVault) = $.assetToVault.tryGet(toAsset);
            if (!toExists) revert AssetNotRegistered();

            uint256 fromScaling = ERC7575VaultUpgradeable(fromVault).getScalingFactor();
            uint256 toScaling = ERC7575VaultUpgradeable(toVault).getScalingFactor();
            // ceil so the pool is never under-compensated when scalingTo does not divide evenly.
            uint256 amountIn = Math.mulDiv(moved, fromScaling, toScaling, Math.Rounding.Ceil);

            // Snapshot the destination's withdrawable assets before compensation so we can verify the
            // transfer actually lands as NAV (M-01 hardening).
            uint256 toAssetsBefore = ERC7575VaultUpgradeable(toVault).totalAssets();

            // Raw transfer into toVault raises its totalAssets() with no new shares minted.
            if (amountIn > 0) {
                SafeTokenTransfers.safeTransferFrom(toAsset, msg.sender, toVault, amountIn);
            }

            // Destination-solvency postcondition: totalAssets() is net of reserves and saturates to zero,
            // so an under-reserved destination (after an external asset loss/depeg) would silently absorb
            // the compensation into its deficit rather than preserving NAV. Require the REAL normalized
            // increase in toVault.totalAssets() to cover the normalized backing removed from fromVault,
            // instead of trusting the raw transfer. Solvent migrations always pass (delta == amountIn and
            // amountIn*toScaling >= moved*fromScaling by the ceil above).
            uint256 normalizedDelta = (ERC7575VaultUpgradeable(toVault).totalAssets() - toAssetsBefore) * toScaling;
            if (normalizedDelta < moved * fromScaling) revert MigrationNavNotPreserved();

            emit VaultBackingMigrated(fromAsset, fromVault, moved, toAsset, toVault, amountIn);
        }

        $.assetToVault.remove(fromAsset);
        delete $.vaultToAsset[fromVault];
        if ($.investmentShareToken != address(0)) {
            IERC20($.investmentShareToken).approve(fromVault, 0);
        }

        // M-01: invested backing lives as investment shares held by THIS share token and is redeemed
        // back to a user-facing asset via withdrawFromInvestment on a registered vault whose investment
        // vault is configured. Removing the last such route while investment shares are still
        // outstanding would strand that backing (counted in NAV, but with no on-chain withdrawal path).
        // Require at least one remaining route in that case; the owner must withdraw the invested assets
        // first, then unregister.
        if (_calculateInvestmentAssets() > 0 && !_hasInvestmentWithdrawalRoute()) {
            revert CannotRemoveLastInvestmentWithdrawalRoute();
        }

        emit VaultUpdate(fromAsset, address(0));
    }

    /**
     * @dev True if at least one registered vault has a configured investment vault, i.e. a live route
     * for withdrawFromInvestment to redeem this share token's investment shares. Bounded by
     * MAX_VAULTS_PER_SHARE_TOKEN; reads each registered vault's configured investment vault.
     */
    function _hasInvestmentWithdrawalRoute() internal view returns (bool) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        uint256 length = $.assetToVault.length();
        for (uint256 i = 0; i < length; i++) {
            (, address vaultAddress) = $.assetToVault.at(i);
            if (ERC7575VaultUpgradeable(vaultAddress).getInvestmentVault() != address(0)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Returns whether an address is a registered vault.
     */
    /**
     * @dev Checks if an address is a registered vault
     * @param vaultAddress The address to check
     * @return True if the address is a registered vault
     */
    function isVault(address vaultAddress) external view returns (bool) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        return $.vaultToAsset[vaultAddress] != address(0);
    }

    /**
     * @dev Returns all registered assets in the multi-asset system
     *
     * ERC7575 SPECIFICATION (IERC7575ShareExtended interface):
     * "Returns all registered assets in the multi-asset system."
     *
     * MULTI-ASSET ARCHITECTURE:
     * "Multi-Asset Vaults share a single `share` token with multiple entry points
     * denominated in different `asset` tokens."
     *
     * @return Array of all asset addresses that have registered vaults
     */
    function getRegisteredAssets() external view returns (address[] memory) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        return $.assetToVault.keys();
    }

    /**
     * @dev Returns both circulating supply and normalized assets in a single call
     *
     * Circulating supply excludes shares held by vaults for redemption claims.
     * Total normalized assets excludes assets reserved for redemption claims.
     * Both values exclude the same economic scope for consistent conversion ratios.
     *
     * @return circulatingSupply Total supply minus shares held by vaults for redemption claims
     * @return totalNormalizedAssets Total normalized assets across all vaults (18 decimals)
     */
    function getCirculatingSupplyAndAssets() external view returns (uint256 circulatingSupply, uint256 totalNormalizedAssets) {
        return _getCirculatingSupplyAndAssets();
    }

    /// @dev Internal core of getCirculatingSupplyAndAssets. Called directly by the convert* functions
    /// to avoid an external STATICCALL to self (`this.getCirculatingSupplyAndAssets()`) on the hot path.
    function _getCirculatingSupplyAndAssets() internal view returns (uint256 circulatingSupply, uint256 totalNormalizedAssets) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        uint256 totalClaimableShares = 0;
        uint256 length = $.assetToVault.length();

        for (uint256 i = 0; i < length; i++) {
            (, address vaultAddress) = $.assetToVault.at(i);

            // Every REGISTERED vault is summed regardless of its isActive flag: deactivation only
            // freezes new deposits, it does not burn the shares a vault already minted nor remove its
            // backing. Skipping inactive vaults here would drop real backing for still-circulating
            // shares and socialize a phantom loss. Backing leaves NAV only via unregister/migration.
            (uint256 vaultClaimableShares, uint256 vaultNormalizedAssets) = IERC7575Vault(vaultAddress).getClaimableSharesAndNormalizedAssets();
            totalClaimableShares += vaultClaimableShares;
            totalNormalizedAssets += vaultNormalizedAssets;
        }

        // Add invested assets from the investment ShareToken (if configured)
        totalNormalizedAssets += _calculateInvestmentAssets();

        // Get total supply
        uint256 supply = totalSupply();
        // Calculate circulating supply: total supply minus vault-held shares for redemption claims
        circulatingSupply = totalClaimableShares > supply ? 0 : supply - totalClaimableShares;
    }

    /**
     * @dev Mint shares to an account. Only callable by authorized vaults.
     */
    /**
     * @dev Mints shares to an account (only registered vaults)
     * @param account The account to mint shares to
     * @param amount The amount of shares to mint
     */
    function mint(address account, uint256 amount) external onlyVaults {
        _mint(account, amount);
    }

    /**
     * @dev Burn shares from an account. Only callable by authorized vaults.
     */
    /**
     * @dev Burns shares from an account (only registered vaults)
     * @param account The account to burn shares from
     * @param amount The amount of shares to burn
     */
    function burn(address account, uint256 amount) external onlyVaults {
        _burn(account, amount);
    }

    /**
     * @dev Spends allowance for an owner (vault-only operation)
     * @param owner The owner address whose shares are being spent
     * @param spender The spender address spending the allowance
     * @param amount The amount of shares to spend from allowance
     */
    function spendAllowance(address owner, address spender, uint256 amount) external onlyVaults {
        _spendAllowance(owner, spender, amount);
    }

    // ========== Operators ==========
    // ERC-7540 operator approvals are managed per-vault on each ERC7575VaultUpgradeable
    // (operators are scoped to the Requests they manage, per the standard). The share token
    // intentionally holds NO centralized operator table — see
    // ERC7575VaultUpgradeable.setOperator / isOperator. This removes the cross-vault
    // authority a single registered vault would otherwise have over arbitrary controllers.

    // ========== Investment Configuration Management ==========

    /**
     * @dev Internal helper function to configure investment settings for a single vault
     * @param asset The asset address
     * @param vaultAddress The vault address to configure
     * @param investmentShareToken The investment ShareToken address
     */
    function _configureVaultInvestmentSettings(address asset, address vaultAddress, address investmentShareToken) internal {
        // Find the corresponding investment vault for this asset
        address investmentVaultAddress = IERC7575ShareExtended(investmentShareToken).vault(asset);

        // Configure investment vault if there's a matching one for this asset
        if (investmentVaultAddress != address(0)) {
            // The investment vault must mint the configured investmentShareToken; otherwise invested
            // assets would land in a token _calculateInvestmentAssets does not count (NAV loss).
            if (IERC7575(investmentVaultAddress).share() != investmentShareToken) revert VaultShareMismatch();

            ERC7575VaultUpgradeable(vaultAddress).setInvestmentVault(IERC7575(investmentVaultAddress));

            // Unlimited allowance so the vault can redeem the investment share token on this token's
            // behalf in withdrawFromInvestment. Not a least-privilege concern: a registered vault is
            // already fully trusted (it can mint/burn this share token), so the trust surface is the
            // set of registered vaults, governed by registration/upgrade control — not this allowance.
            IERC20(investmentShareToken).approve(vaultAddress, type(uint256).max);
        }
    }

    /**
     * @dev Sets the investment ShareToken address and configures all vault investment mappings (only owner)
     *
     * This function:
     * 1. Sets the investment ShareToken for the multi-asset system
     * 2. Iterates through all registered assets
     * 3. For each asset, finds the matching investment vault from the investment ShareToken
     * 4. Configures each vault with its corresponding investment vault
     *
     * ARCHITECTURE:
     * - All investments will be made in the name of this ShareToken
     * - Each vault will have its counterpart investment vault (same asset)
     * - Enables centralized investment management across the multi-asset system
     *
     * @param investmentShareToken_ The address of the investment ShareToken
     */
    function setInvestmentShareToken(address investmentShareToken_) external onlyOwner {
        if (investmentShareToken_ == address(0)) revert ZeroAddress();
        ShareTokenStorage storage $ = _getShareTokenStorage();
        if ($.investmentShareToken != address(0)) {
            revert InvestmentShareTokenAlreadySet();
        }

        // Enforce WERC-only investment targets: a WERC share token exposes rBalanceOf; a plain ERC-4626
        // target does not. Investment NAV is valued at par (balanceOf + rBalanceOf) and redemption
        // requires the validator self-allowance gate — both assume WERC. Probe rBalanceOf and reject a
        // non-WERC token; this guarantees _calculateInvestmentAssets can read rBalanceOf without a guard.
        if (!_isWercShareToken(investmentShareToken_)) revert InvestmentShareTokenNotWerc();

        // Store the investment ShareToken address
        $.investmentShareToken = investmentShareToken_;

        // Iterate through all registered assets and configure investment vaults
        uint256 length = $.assetToVault.length();
        for (uint256 i = 0; i < length; i++) {
            (address asset, address vaultAddress) = $.assetToVault.at(i);
            _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken_);
        }

        emit InvestmentShareTokenSet(investmentShareToken_);
    }

    /**
     * @dev Returns the current investment ShareToken address
     *
     * @return The address of the investment ShareToken, or zero address if not set
     */
    function getInvestmentShareToken() external view returns (address) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        return $.investmentShareToken;
    }

    /**
     * @dev True if `shareToken_` is a WERC-style share token, detected by probing rBalanceOf. Used once
     * at setInvestmentShareToken to reject non-WERC investment targets (try/catch is required here to
     * detect the absence; the hot-path read in _calculateInvestmentAssets needs no guard once accepted).
     */
    function _isWercShareToken(address shareToken_) internal view returns (bool) {
        try IWERC7575ShareToken(shareToken_).rBalanceOf(address(this)) returns (uint256) {
            return true;
        } catch {
            return false;
        }
    }

    /**
     * @dev Helper function to calculate total investment assets, normalized to 18 decimals.
     *
     * Investment targets are WERC-only (enforced at setInvestmentShareToken): the investment share token
     * is an 18-dec par wrapper (1 share == 1 normalized asset), so balanceOf is already normalized
     * assets, and rBalanceOf is the lent-out receivable. rBalanceOf is a guaranteed-present mapping read
     * for a WERC token, so it is called directly (no try/catch needed). balanceOf is likewise a core
     * read. A non-WERC token can never reach here because setInvestmentShareToken rejects it.
     *
     * @return totalInvestmentAssets Total invested assets, normalized to 18 decimals
     */
    function _calculateInvestmentAssets() internal view returns (uint256 totalInvestmentAssets) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        address investmentShareToken = $.investmentShareToken;

        if (investmentShareToken == address(0)) {
            return 0;
        }

        return IERC20(investmentShareToken).balanceOf(address(this)) + IWERC7575ShareToken(investmentShareToken).rBalanceOf(address(this));
    }

    /**
     * @dev Gets the total value of invested assets (normalized to 18 decimals)
     * @return Total value of assets invested through the investment ShareToken
     */
    function getInvestedAssets() external view returns (uint256) {
        return _calculateInvestmentAssets();
    }

    /**
     * @dev Sets the investment manager for all vaults (centralized management)
     *
     * Establishes centralized investment management by designating a single manager
     * responsible for fulfilling all deposit/redeem requests across all vaults in the
     * multi-asset system. The manager is automatically propagated to all registered vaults.
     *
     * CENTRALIZED INVESTMENT ARCHITECTURE:
     * - Single investment manager for ALL vaults
     * - Automatic propagation to existing vaults
     * - Automatic assignment to new vaults during registration
     * - Unified investment strategy across asset classes
     *
     * INVESTMENT MANAGER RESPONSIBILITIES:
     * - Call fulfillDeposit/fulfillDeposits to convert pending assets to shares
     * - Call fulfillRedeem to convert pending shares to assets
     * - Call fulfillCancelDepositRequest(s) for deposit cancelations
     * - Call fulfillCancelRedeemRequest(s) for redeem cancelations
     * - Manage investments through the investment vault
     * - Monitor vault metrics and manage liquidity
     *
     * ACCESS CONTROL:
     * - Only callable by share token owner
     * - Not restricted once set (can be changed by owner)
     *
     * @param newInvestmentManager The address of the new investment manager
     *
     * @custom:throws ZeroAddress If newInvestmentManager is zero address
     */
    function setInvestmentManager(address newInvestmentManager) external onlyOwner {
        if (newInvestmentManager == address(0)) revert ZeroAddress();
        ShareTokenStorage storage $ = _getShareTokenStorage();

        // Store the investment manager centrally
        $.investmentManager = newInvestmentManager;

        // Propagate to all registered vaults
        uint256 length = $.assetToVault.length();
        for (uint256 i = 0; i < length; i++) {
            (, address vaultAddress) = $.assetToVault.at(i);

            // Call setInvestmentManager on each vault
            ERC7575VaultUpgradeable(vaultAddress).setInvestmentManager(newInvestmentManager);
        }

        emit InvestmentManagerSet(newInvestmentManager);
    }

    /**
     * @dev Returns the current investment manager address
     * @return The address of the centralized investment manager
     */
    function getInvestmentManager() external view returns (address) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        return $.investmentManager;
    }

    /**
     *  OPTIMIZED CONVERSION: Normalized assets to shares with mathematical consistency
     *
     * - Assets: excludes reserved redemption assets
     * - Shares: excludes vault-held shares for redemption claims
     * Result: Both numerator and denominator represent the same economic scope
     *
     * VIRTUAL ASSETS/SHARES:
     * Added for inflation protection as per ERC4626 best practices
     *
     * @param normalizedAssets Amount of normalized assets (18 decimals)
     * @param rounding Rounding mode for the conversion
     * @return shares Amount of shares equivalent to the normalized assets
     */
    function convertNormalizedAssetsToShares(uint256 normalizedAssets, Math.Rounding rounding) external view returns (uint256 shares) {
        // Get both values in a single call
        (uint256 circulatingSupply, uint256 totalNormalizedAssets) = _getCirculatingSupplyAndAssets();

        // Add virtual amounts for inflation protection
        circulatingSupply += VIRTUAL_SHARES;
        totalNormalizedAssets += VIRTUAL_ASSETS;

        // shares = normalizedAssets * circulatingSupply / totalNormalizedAssets
        shares = Math.mulDiv(normalizedAssets, circulatingSupply, totalNormalizedAssets, rounding);
    }

    /**
     *  OPTIMIZED CONVERSION: Shares to normalized assets with mathematical consistency
     *
     * MATHEMATICAL CONSISTENCY:
     * This function uses the same circulating supply approach as convertNormalizedAssetsToShares
     * to ensure consistent conversion ratios in both directions during ERC7540 async operations.
     *
     * See convertNormalizedAssetsToShares documentation for detailed explanation of the
     * mathematical consistency fix.
     *
     * @param shares Amount of shares to convert
     * @param rounding Rounding mode for the conversion
     * @return normalizedAssets Amount of normalized assets (18 decimals) equivalent to the shares
     */
    function convertSharesToNormalizedAssets(uint256 shares, Math.Rounding rounding) external view returns (uint256 normalizedAssets) {
        // Get both values in a single call
        (uint256 circulatingSupply, uint256 totalNormalizedAssets) = _getCirculatingSupplyAndAssets();

        // Add virtual amounts for inflation protection
        circulatingSupply += VIRTUAL_SHARES;
        totalNormalizedAssets += VIRTUAL_ASSETS;

        // normalizedAssets = shares * totalNormalizedAssets / circulatingSupply
        normalizedAssets = Math.mulDiv(shares, totalNormalizedAssets, circulatingSupply, rounding);
    }

    /**
     * @dev Transfers shares from owner to vault without requiring allowance (vault-only operation)
     * This function is essential for ERC7540 operator functionality, allowing operators to
     * submit redemption requests on behalf of users without requiring pre-approval.
     *
     * @param from The owner address to transfer shares from
     * @param to The recipient address (typically the vault)
     * @param amount The amount of shares to transfer
     * @return success True if transfer successful
     */
    function vaultTransferFrom(address from, address to, uint256 amount) external onlyVaults returns (bool success) {
        if (from == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }
        // Shares may only be pulled INTO the calling vault (its redemption escrow), never to an
        // arbitrary address. This bounds the allowance-less transfer power granted to registered
        // vaults: a vault can escrow a holder's shares for a redeem request, not redirect them.
        if (to != msg.sender) {
            revert IERC20Errors.ERC20InvalidReceiver(to);
        }

        // Direct transfer without checking allowance since this is vault-only
        _transfer(from, to, amount);
        return true;
    }

    /**
     * @dev Event emitted when the investment ShareToken is updated
     */
    event InvestmentShareTokenSet(address indexed investmentShareToken);

    /**
     * @dev Event emitted when the investment manager is updated
     */
    event InvestmentManagerSet(address indexed investmentManager);

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

    // ========== ERC165 Support ==========

    /**
     * @dev Returns true if this contract implements the interface (ERC165)
     * @param interfaceId The interface identifier
     * @return True if interface is supported
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC7575ShareExtended).interfaceId || interfaceId == type(IERC165).interfaceId || interfaceId == 0xf815c03d;
    }
}
