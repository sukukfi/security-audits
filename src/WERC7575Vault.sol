// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DecimalConstants} from "./DecimalConstants.sol";
import {SafeTokenTransfers} from "./SafeTokenTransfers.sol";
import {WERC7575ShareToken} from "./WERC7575ShareToken.sol";
import {IERC7575} from "./interfaces/IERC7575.sol";
import {IERC7575Errors} from "./interfaces/IERC7575Errors.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title WERC7575Vault
 * @notice Synchronous ERC-7575 entry point for a single asset, paired with the restricted
 *         WERC7575ShareToken. Deposits/redeems convert at a fixed decimal-scaled par rate
 *         (1 asset ⇄ 1 normalized share); this is a wrapped receipt, not a yield-bearing ERC-4626.
 *
 * @dev NOT a standard ERC-4626 vault for integrators. Because the share token enforces restricted
 *      transfers, redemption deviates from ERC-4626:
 *      - withdraw()/redeem() require the `owner` to hold a validator-issued SELF-allowance on the
 *        share token (spendSelfAllowance) — even when msg.sender == owner. A plain owner redemption
 *        WILL revert without that permit.
 *      - when msg.sender != owner, BOTH the owner's self-allowance AND the caller's allowance are
 *        required (dual-gate).
 *      - all share recipients must be KYC-verified.
 *      Standard ERC-4626/ERC-20 integrations (DEXs, lenders, generic wallets) will fail. See the
 *      WERC7575ShareToken header and README for the full restricted-token integration notes.
 */
contract WERC7575Vault is IERC7575, ERC165, ReentrancyGuardTransient, Ownable2Step, Pausable, IERC7575Errors {
    using SafeERC20 for IERC20Metadata;

    /**
     * @dev Emitted when assets are deposited into the vault
     * @param sender The address that initiated the deposit
     * @param owner The address that received the shares
     * @param assets The amount of assets deposited
     * @param shares The amount of shares minted
     */
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);

    /**
     * @dev Emitted when assets are withdrawn from the vault
     * @param sender The address that initiated the withdrawal
     * @param receiver The address that received the assets
     * @param owner The address that owned the shares
     * @param assets The amount of assets withdrawn
     * @param shares The amount of shares burned
     */
    event Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    event VaultActiveStateChanged(bool indexed isActive);

    // Set once in the constructor, never mutated, and read on the hot conversion/transfer paths — so
    // they are immutable (bytecode reads, no SLOAD). This contract is non-upgradeable, so immutable is
    // safe (unlike the proxy-backed upgradeable vault, whose per-instance state must stay in storage).
    address private immutable _asset;
    uint64 private immutable _scalingFactor;
    WERC7575ShareToken private immutable _shareToken;
    bool private _isActive; // storage — mutated by setVaultActive()

    /**
     * @dev Initializes a synchronous ERC4626 vault for the multi-asset system (ERC7575 compliant)
     *
     * Creates a simple, synchronous vault that enables immediate deposit/redeem operations
     * for a single asset. Integrates with the shared ShareToken to participate in the
     * multi-asset vault ecosystem.
     *
     * VAULT ARCHITECTURE:
     * - Synchronous operations: deposits and redeems are immediate
     * - Single asset per vault (paired asset-vault relationship)
     * - Shares minted/burned directly (no async requests)
     * - Integrates with multi-asset ShareToken
     * - Can be paused by owner for emergency situations
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7575: Multi-asset vault standard
     * - ERC4626: Complete tokenized vault functionality
     * - Decimal normalization: 6-18 decimals for assets, 18 for shares
     *
     * INITIALIZATION:
     * After deployment, the owner must:
     * 1. Call shareToken.registerVault(asset, vault_address)
     * 2. Set vault as active if needed (defaults to active)
     *
     * VALIDATION:
     * - Asset must be valid ERC20 with 6-18 decimals
     * - ShareToken must be valid ERC20 with 18 decimals
     * - ShareToken address must not be zero
     * - Scaling factor must fit in uint64
     *
     * @param asset_ The underlying ERC20 asset token (e.g., USDC, USDT)
     * @param shareToken_ The ERC7575 share token for multi-asset vault system
     *
     * @custom:throws ZeroAddress If shareToken_ is zero address
     * @custom:throws UnsupportedAssetDecimals If asset decimals are not 6-18
     * @custom:throws WrongDecimals If shareToken decimals are not 18
     * @custom:throws AssetDecimalsFailed If asset.decimals() call fails
     * @custom:throws ScalingFactorTooLarge If scaling factor exceeds uint64 max
     */
    constructor(address asset_, WERC7575ShareToken shareToken_) Ownable(msg.sender) {
        // Validate asset compatibility
        uint8 assetDecimals;
        try IERC20Metadata(asset_).decimals() returns (uint8 decimals) {
            if (decimals < DecimalConstants.MIN_ASSET_DECIMALS || decimals > DecimalConstants.SHARE_TOKEN_DECIMALS) {
                revert UnsupportedAssetDecimals();
            }
            assetDecimals = decimals;
        } catch {
            revert AssetDecimalsFailed();
        }
        // Validate share token compatibility and enforce 18 decimals
        if (address(shareToken_) == address(0)) revert ZeroAddress();
        if (shareToken_.decimals() != DecimalConstants.SHARE_TOKEN_DECIMALS) {
            revert WrongDecimals();
        }

        // Precompute scaling factor: 10^(18 - assetDecimals)
        // Max scaling factor is 10^12 (for 6 decimals) which fits in uint64
        uint256 scalingFactor = 10 ** (DecimalConstants.SHARE_TOKEN_DECIMALS - assetDecimals);
        if (scalingFactor > type(uint64).max) revert ScalingFactorTooLarge();

        _asset = asset_;
        _scalingFactor = uint64(scalingFactor);
        _isActive = true; // Vault is active by default
        _shareToken = shareToken_;

        // Note: Owner must separately call shareToken.registerVault(asset, vault) after deployment
    }

    /**
     * @dev Pause all vault operations. Only callable by owner.
     * Used for emergency situations to halt deposits, withdrawals, mints, and redeems.
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Unpause all vault operations. Only callable by owner.
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @dev Sets the vault active state (only owner)
     * @param _active True to activate, false to deactivate
     */
    function setVaultActive(bool _active) external onlyOwner {
        _isActive = _active;
        emit VaultActiveStateChanged(_active);
    }

    /**
     * @dev Returns whether the vault is active and accepting deposits
     * @return True if vault is active
     */
    function isVaultActive() external view returns (bool) {
        return _isActive;
    }

    /**
     * @dev Returns the decimal scaling factor (10^(18 - assetDecimals)) used to normalize this
     * vault's asset to 18-decimal shares. Read by the share token's migrateAndUnregisterVault flow
     * to size the compensating backing at par across vaults of differing decimals.
     */
    function getScalingFactor() external view returns (uint64) {
        return _scalingFactor;
    }

    /**
     * @dev Self-validating decommission primitive: drains the vault's entire asset balance to
     * `recipient`. Restricted to the share token's migrateAndUnregisterVault flow.
     *
     * The vault must already be deactivated. There is no async/pending state on this wrapper, so the
     * sole invariant is `!_isActive`; transferring totalAssets() (== full balance, including any dust
     * a griefer sent directly) leaves the vault empty so it can be unregistered cleanly. The dust
     * goes out with the legitimate backing, which is why this closes the unregister dust-DoS.
     *
     * The share token enforces, atomically, that an equal-or-greater normalized amount of a good
     * asset is injected into another vault, so total backing is preserved (no holder loss); combined
     * with the deactivated-only gate this is not a rug vector.
     *
     * @param recipient Address that receives the drained assets (the migration counterparty)
     * @return amount Amount of asset transferred out
     */
    function migrateBackingOut(address recipient) external nonReentrant returns (uint256 amount) {
        if (msg.sender != address(_shareToken)) revert Unauthorized();
        if (_isActive) revert CannotUnregisterActiveVault();

        amount = totalAssets();
        if (amount > 0) {
            SafeTokenTransfers.safeTransfer(_asset, recipient, amount);
        }
    }

    /**
     * @dev Returns true if this contract implements the interface defined by interfaceId
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return bool True if the contract implements interfaceId
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165) returns (bool) {
        return interfaceId == type(IERC7575).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns the address of the share token contract
     * @return address The ERC7575 share token address
     */
    function share() external view returns (address) {
        return address(_shareToken);
    }

    /**
     * @dev Returns the address of the underlying asset token
     * @return address The ERC20 asset token address
     */
    function asset() external view returns (address) {
        return _asset;
    }

    /**
     * @dev Returns the total amount of underlying assets held by the vault
     * @return uint256 Total assets held in the vault
     */
    function totalAssets() public view returns (uint256) {
        return IERC20Metadata(_asset).balanceOf(address(this));
    }

    /**
     * @dev Converts asset amount to equivalent share amount
     * @param assets Amount of assets to convert
     * @return uint256 Equivalent amount of shares
     */
    function convertToShares(uint256 assets) public view returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }

    /**
     * @dev Converts share amount to equivalent asset amount
     * @param shares Amount of shares to convert
     * @return uint256 Equivalent amount of assets
     */
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }

    /**
     * @dev Converts assets to shares using decimal normalization for stablecoins
     * @param assets Amount of assets to convert
     * @return shares Amount of shares equivalent to assets
     *
     * Formula: shares = assets * 10^(18 - assetDecimals)
     *
     * For stablecoins with no yield:
     * - Share decimals: enforced to be 18 in ShareToken constructor
     * - Asset decimals: varies (6 for USDC, 18 for DAI, etc.)
     * - This provides 1:1 value conversion with decimal normalization
     * - No first depositor attack possible since conversion is deterministic
     * - No manipulation possible since no dependency on totalSupply or totalAssets
     */
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256) {
        // ShareToken always has 18 decimals, assetDecimals ∈ [6, 18]
        // shares = assets * _scalingFactor where _scalingFactor = 10^(18 - assetDecimals)
        // Use Math.mulDiv to prevent overflow on large amounts
        return Math.mulDiv(assets, uint256(_scalingFactor), 1, rounding);
    }

    /**
     * @dev Converts shares to assets using decimal normalization for stablecoins
     * @param shares Amount of shares to convert
     * @param rounding Rounding direction (Floor = favor vault, Ceil = favor user)
     * @return assets Amount of assets equivalent to shares
     *
     * Formula: assets = shares * 10^(assetDecimals) / 10^(shareDecimals)
     *
     * For stablecoins with no yield:
     * - Share decimals: queried from share token (typically 18)
     * - Asset decimals: varies (6 for USDC, 18 for DAI, etc.)
     * - This provides 1:1 value conversion with decimal normalization
     * - No first depositor attack possible since conversion is deterministic
     * - No manipulation possible since no dependency on totalSupply or totalAssets
     */
    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view returns (uint256) {
        // ShareToken always has 18 decimals, assetDecimals ∈ [6, 18]
        // When _scalingFactor == 1 (assetDecimals == 18): assets = shares
        // When _scalingFactor > 1 (assetDecimals < 18): assets = shares / _scalingFactor
        if (_scalingFactor == 1) {
            return shares;
        } else {
            return Math.mulDiv(shares, 1, uint256(_scalingFactor), rounding);
        }
    }

    /**
     * @dev Preview shares received for depositing assets
     * Uses Floor rounding to give slightly fewer shares to user (favors vault)
     */
    function previewDeposit(uint256 assets) public view returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }

    /**
     * @dev Preview assets needed to mint shares
     * Uses Ceil rounding to require slightly more assets from user (favors vault)
     */
    function previewMint(uint256 shares) public view returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Ceil);
    }

    /**
     * @dev Preview shares needed to withdraw assets
     * Uses Ceil rounding to require slightly more shares from user (favors vault)
     */
    function previewWithdraw(uint256 assets) public view returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Ceil);
    }

    /**
     * @dev Preview assets received for redeeming shares
     * Uses Floor rounding to give slightly fewer assets to user (favors vault)
     */
    function previewRedeem(uint256 shares) public view returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }

    /**
     * @dev Returns the maximum amount of assets that can be deposited for `receiver`.
     *
     * ERC-4626 requires this to never exceed what `deposit` would accept without reverting and to
     * fold in user-specific limits. `deposit` mints shares to `receiver` via the share token, which
     * gates minting on KYC AND on the share token's own pause (mint is whenNotPaused). So an unlimited
     * cap is only valid for a KYC-verified receiver while the vault is active and BOTH the vault and
     * the share token are unpaused; otherwise the executable maximum is 0.
     */
    function maxDeposit(address receiver) public view returns (uint256) {
        return (_isActive && !paused() && !_shareToken.paused() && _shareToken.isKycVerified(receiver)) ? type(uint256).max : 0;
    }

    /**
     * @dev Returns the maximum amount of shares that can be minted for `receiver`.
     * Same constraints as {maxDeposit}: KYC-gated receiver, and blocked when the vault is inactive or
     * either the vault or the share token is paused.
     */
    function maxMint(address receiver) public view returns (uint256) {
        return (_isActive && !paused() && !_shareToken.paused() && _shareToken.isKycVerified(receiver)) ? type(uint256).max : 0;
    }

    /**
     * @dev Returns the maximum amount of assets that can be withdrawn by `owner`.
     *
     * Capped by this vault's actual asset liquidity: WERC shares are fungible across every vault on
     * the shared share token, so an owner's balance can exceed what any single vault can pay out, and
     * `withdraw` would revert on the asset transfer. ERC-4626 requires underestimating, so we return
     * min(owner's share value, totalAssets()). Redemption burns the owner's shares on the share token,
     * and burn() requires the owner to be KYC-verified, runs whenNotPaused, and spends the owner's
     * validator-issued SELF-allowance (allowance(owner,owner)). So it returns 0 unless the owner is
     * KYC-verified and neither the vault nor the share token is paused, and is additionally capped by
     * that self-allowance. (Not gated on _isActive: withdraw/redeem remain enabled on a deactivated
     * vault so holders can exit.)
     */
    function maxWithdraw(address owner) public view returns (uint256) {
        if (paused() || _shareToken.paused() || !_shareToken.isKycVerified(owner)) return 0;
        uint256 byShares = _convertToAssets(_shareToken.balanceOf(owner), Math.Rounding.Floor);
        uint256 byAllowance = _convertToAssets(_shareToken.allowance(owner, owner), Math.Rounding.Floor);
        return Math.min(Math.min(byShares, byAllowance), totalAssets());
    }

    /**
     * @dev Returns the maximum amount of shares that can be redeemed by `owner`.
     * Mirror of {maxWithdraw} in share terms: 0 unless the owner is KYC-verified and nothing is paused;
     * otherwise capped by the owner's self-allowance and by the shares this vault's liquidity can cover
     * (convertToShares(totalAssets())).
     */
    function maxRedeem(address owner) public view returns (uint256) {
        if (paused() || _shareToken.paused() || !_shareToken.isKycVerified(owner)) return 0;
        uint256 byBalance = Math.min(_shareToken.balanceOf(owner), _shareToken.allowance(owner, owner));
        uint256 shares = Math.min(byBalance, _convertToShares(totalAssets(), Math.Rounding.Floor));
        // For <18-decimal assets, a sub-scalingFactor share amount converts to 0 assets, and redeem()
        // would revert ZeroAssets. ERC-4626 forbids max* returning a revert-causing value, so report 0.
        if (_convertToAssets(shares, Math.Rounding.Floor) == 0) return 0;
        return shares;
    }

    /**
     * @dev Internal function to handle deposit/mint logic
     * @param assets Amount of assets to transfer
     * @param shares Amount of shares to mint
     * @param receiver Address to receive shares
     */
    function _deposit(uint256 assets, uint256 shares, address receiver) internal {
        if (!_isActive) revert VaultNotActive();
        if (receiver == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (assets == 0) revert ZeroAssets();
        if (shares == 0) revert ZeroShares();

        SafeTokenTransfers.safeTransferFrom(_asset, msg.sender, address(this), assets);

        _shareToken.mint(receiver, shares);
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    /**
     * @dev Deposits exact amount of assets and receives corresponding shares (ERC4626 compliant)
     *
     * Synchronous deposit operation: immediately mints shares and transfers assets.
     * Simple one-step process without async state management.
     *
     * OPERATION:
     * - Previews share amount for the deposit
     * - Transfers assets from caller to vault
     * - Mints shares to receiver
     *
     * SECURITY:
     * - Reentrancy protected
     * - Paused state check
     * - Vault must be active
     * - Zero address validation
     *
     * @param assets Amount of assets to deposit
     * @param receiver Address to receive the minted shares
     *
     * @return shares Amount of shares minted
     */
    function deposit(uint256 assets, address receiver) public nonReentrant whenNotPaused returns (uint256 shares) {
        shares = previewDeposit(assets);
        _deposit(assets, shares, receiver);
    }

    /**
     * @dev Mints exact amount of shares by depositing necessary assets (ERC4626 compliant)
     *
     * Synchronous mint operation: caller specifies desired shares, assets calculated.
     * Transfers required assets and immediately mints specified shares.
     *
     * OPERATION:
     * - Previews asset amount needed for shares
     * - Transfers required assets from caller
     * - Mints exact shares to receiver
     *
     * USE CASE:
     * - When you want exactly X shares (not Y assets)
     * - May require more assets due to rounding
     *
     * @param shares Amount of shares to mint (exact)
     * @param receiver Address to receive the minted shares
     *
     * @return assets Amount of assets required for the mint
     */
    function mint(uint256 shares, address receiver) public nonReentrant whenNotPaused returns (uint256 assets) {
        assets = previewMint(shares);
        _deposit(assets, shares, receiver);
    }

    /**
     * @dev Internal function to handle withdraw/redeem logic
     * @param assets Amount of assets to transfer
     * @param shares Amount of shares to burn
     * @param receiver Address to receive assets
     * @param owner Address that owns the shares
     */
    function _withdraw(uint256 assets, uint256 shares, address receiver, address owner) internal {
        if (receiver == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (owner == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }
        if (assets == 0) revert ZeroAssets();
        if (shares == 0) revert ZeroShares();

        _shareToken.spendSelfAllowance(owner, shares);
        _shareToken.burn(owner, shares);
        SafeTokenTransfers.safeTransfer(_asset, receiver, assets);
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    /**
     * @dev Withdraws exact amount of assets from vault by burning shares (ERC4626 compliant)
     *
     * Synchronous withdrawal operation: caller specifies assets, shares calculated.
     * Burns required shares and immediately transfers assets to receiver.
     *
     * OPERATION:
     * - Previews share amount needed for assets
     * - Burns required shares from owner
     * - Transfers exact assets to receiver
     *
     * AUTHORIZATION:
     * - msg.sender must be owner OR have allowance for the shares
     * - Allows delegation to withdrawal operators
     *
     * @param assets Amount of assets to withdraw (exact)
     * @param receiver Address to receive the assets
     * @param owner Address that owns the shares to be burned
     *
     * @return shares Amount of shares burned
     */
    function withdraw(uint256 assets, address receiver, address owner) public nonReentrant whenNotPaused returns (uint256 shares) {
        // Validate addresses early
        if (receiver == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (owner == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }

        shares = previewWithdraw(assets);
        if (msg.sender != owner) {
            _shareToken.spendAllowance(owner, msg.sender, shares);
        }
        _withdraw(assets, shares, receiver, owner);
    }

    /**
     * @dev Redeems exact amount of shares for assets (ERC4626 compliant)
     *
     * Synchronous redemption operation: caller specifies shares, assets calculated.
     * Burns exact shares and transfers corresponding assets to receiver.
     *
     * OPERATION:
     * - Previews asset amount for shares
     * - Burns exact shares from owner
     * - Transfers corresponding assets to receiver
     *
     * AUTHORIZATION:
     * - msg.sender must be owner OR have allowance for the shares
     * - Allows delegation to redemption operators
     *
     * USE CASE:
     * - When you want to burn exactly X shares (not Y assets)
     * - Receives at least minimum due to rounding down
     *
     * @param shares Amount of shares to redeem (exact)
     * @param receiver Address to receive the assets
     * @param owner Address that owns the shares to be burned
     *
     * @return assets Amount of assets withdrawn
     */
    function redeem(uint256 shares, address receiver, address owner) public nonReentrant whenNotPaused returns (uint256 assets) {
        // Validate addresses early
        if (receiver == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (owner == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }

        if (msg.sender != owner) {
            _shareToken.spendAllowance(owner, msg.sender, shares);
        }
        assets = previewRedeem(shares);
        _withdraw(assets, shares, receiver, owner);
    }
}
