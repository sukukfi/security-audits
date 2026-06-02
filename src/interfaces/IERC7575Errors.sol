// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title IERC7575Errors
 * @dev Common error definitions for ERC7575 vault implementations
 *
 * This interface defines standard errors that are shared across multiple
 * ERC7575 vault implementations to ensure consistency and reusability.
 */
interface IERC7575Errors {
    // ============ Common Vault Errors ============

    /// @dev The vault is not currently active
    error VaultNotActive();

    /// @dev Operation involves zero assets
    error ZeroAssets();

    /// @dev Operation involves zero shares
    error ZeroShares();

    /// @dev Operation involves zero amount
    error ZeroAmount();

    /// @dev Zero address provided where valid address required
    error ZeroAddress();

    // ============ Access Control Errors ============

    /// @dev Invalid owner for the operation
    error InvalidOwner();

    /// @dev Invalid caller for the operation
    error InvalidCaller();

    /// @dev Unauthorized access
    error Unauthorized();

    /// @dev Only owner can perform this operation
    error OnlyOwner();

    // ============ Balance and Allowance Errors ============

    /// @dev Insufficient balance for the operation
    error InsufficientBalance();

    /// @dev Insufficient claimable assets
    error InsufficientClaimableAssets();

    /// @dev Insufficient claimable shares
    error InsufficientClaimableShares();

    /// @dev Deposit amount below minimum required
    error InsufficientDepositAmount();

    // ============ Calculation Errors ============

    /// @dev Zero assets calculated from shares
    error ZeroAssetsCalculated();

    /// @dev Zero shares calculated from assets
    error ZeroSharesCalculated();

    // ============ Array and Batch Operation Errors ============

    /// @dev Array length mismatch in batch operations
    error LengthMismatch();

    /// @dev Batch size too large
    error BatchSizeTooLarge();

    /// @dev Too many requesters for non-paginated operation
    error TooManyRequesters();

    /// @dev Maximum number of vaults per share token exceeded
    error MaxVaultsExceeded();

    // ============ State Errors ============

    /// @dev No pending deposit found
    error NoPendingDeposit();

    /// @dev No pending redemption found
    error NoPendingRedeem();

    // ============ Async Flow Errors ============

    /// @dev Generic async flow error
    error AsyncFlow();

    /// @dev Request is not yet claimable
    error NotClaimable();

    /// @dev Request already claimed
    error AlreadyClaimed();

    /// @dev Request is not in pending state
    error NotPending();

    // ============ Investment Errors ============

    /// @dev No investment vault configured
    error NoInvestmentVault();

    /// @dev Investment manager required but not set
    error OnlyInvestmentManager();

    /// @dev Invalid manager address
    error InvalidManager();

    /// @dev Invalid vault address
    error InvalidVault();

    /// @dev Asset mismatch between vaults
    error AssetMismatch();

    // ============ Transfer Errors ============

    /// @dev Share transfer failed
    error ShareTransferFailed();

    // ============ Configuration Errors ============

    /// @dev Wrong decimals for ShareToken
    error WrongDecimals();

    /// @dev Asset decimals retrieval failed
    error AssetDecimalsFailed();

    /// @dev Unsupported asset decimals
    error UnsupportedAssetDecimals();

    /// @dev Scaling factor exceeds uint64 maximum
    error ScalingFactorTooLarge();

    // ============ Registration and Lifecycle Errors ============

    /// @dev Asset not registered in the system
    error AssetNotRegistered();

    /// @dev Asset already registered (duplicate registration attempt)
    error AssetAlreadyRegistered();

    /// @dev Vault's share token does not match expected ShareToken
    error VaultShareMismatch();

    /// @dev Cannot unregister vault that is still active
    error CannotUnregisterActiveVault();

    /// @dev Cannot unregister vault with pending deposits
    error CannotUnregisterVaultPendingDeposits();

    /// @dev Cannot unregister vault with fulfilled-but-unclaimed (claimable) deposits
    error CannotUnregisterVaultClaimableDeposits();

    /// @dev Cannot unregister vault with pending (unfulfilled) redeem requests (shares escrowed)
    error CannotUnregisterVaultPendingRedeems();

    /// @dev Cannot unregister vault with claimable redemptions
    error CannotUnregisterVaultClaimableRedemptions();

    /// @dev Cannot unregister vault with active deposit requesters
    error CannotUnregisterVaultActiveDepositRequesters();

    /// @dev Cannot unregister vault with active redeem requesters
    error CannotUnregisterVaultActiveRedeemRequesters();

    /// @dev Cannot unregister vault with outstanding asset balance
    error CannotUnregisterVaultAssetBalance();

    /// @dev Cannot remove the last vault with a configured investment route while the share token still
    /// holds investment shares — doing so would strand that backing (counted in NAV) with no on-chain
    /// withdrawal path. Withdraw the invested assets first, then unregister.
    error CannotRemoveLastInvestmentWithdrawalRoute();

    /// @dev Cannot unregister vault with outstanding (pending or claimable) redeem cancelations — the
    /// vault still escrows shares owed back to the canceling redeemer.
    error CannotUnregisterVaultRedeemCancelationsPending();

    /// @dev Vault backing migration requires two distinct assets/vaults
    error SameAssetMigration();

    /// @dev Migration compensation did not raise the destination vault's normalized withdrawable
    /// assets by at least the normalized backing removed from the source (e.g. under-reserved destination)
    error MigrationNavNotPreserved();

    /// @dev Investment ShareToken already configured
    error InvestmentShareTokenAlreadySet();

    /// @dev The configured investment share token is not WERC-style (no rBalanceOf). Investment targets
    /// must be WERC: NAV values them at par (balanceOf + rBalanceOf) and redemption requires the
    /// validator self-allowance gate, both of which assume a WERC par wrapper.
    error InvestmentShareTokenNotWerc();

    // ============ Request ID Errors ============

    /// @dev Invalid requestId provided (only requestId 0 is supported)
    error InvalidRequestId();

    // ============ ERC7887 Cancelation Errors ============

    /// @dev Deposit cancelation request is pending for this controller (blocks new deposits)
    error DepositCancelationPending();

    /// @dev Redeem cancelation request is pending for this controller (blocks new redeems)
    error RedeemCancelationPending();

    /// @dev No pending cancelation deposit found
    error NoPendingCancelDeposit();

    /// @dev No pending cancelation redeem found
    error NoPendingCancelRedeem();

    /// @dev Cancelation request is not yet claimable
    error CancelationNotClaimable();

    /// @dev Cannot cancel a claimable or already claimed request
    error CannotCancelClaimable();
}
