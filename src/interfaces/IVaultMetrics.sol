// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

// Interface for vault metrics to check pending requests and active users
interface IVaultMetrics {
    struct VaultMetrics {
        uint256 totalPendingDepositAssets;
        uint256 totalClaimableDepositShares; // fulfilled-but-unclaimed deposit shares (minted to vault)
        uint256 totalClaimableRedeemAssets;
        uint256 totalPendingRedeemShares; // pending (unfulfilled) redeem shares escrowed in the vault
        uint256 totalCancelDepositAssets; // ERC7887 deposit-cancelation assets (pending + claimable)
        uint256 totalCancelRedeemShares; // ERC7887 redeem-cancelation SHARES escrowed (pending + claimable)
        uint64 scalingFactor;
        uint256 totalAssets;
        uint256 availableForInvestment;
        uint256 activeDepositRequestersCount;
        uint256 activeRedeemRequestersCount;
        bool isActive;
        address asset;
        address shareToken;
        address investmentManager;
        address investmentVault;
        // Solvency visibility (L-04): totalAssets() above saturates to 0 below reserves, hiding a
        // shortfall. These expose the raw picture so an under-collateralization is visible from the
        // getter. A shortfall is derivable: reservedAssets > grossAssetBalance ? (difference) : 0.
        uint256 grossAssetBalance; // raw asset.balanceOf(vault), before reserves
        uint256 reservedAssets; // pending deposits + claimable redeem + cancel-deposit reserves
    }

    function getVaultMetrics() external view returns (VaultMetrics memory);
}
