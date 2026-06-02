// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title IERC7575MultiAsset
 * @dev Interface for ERC-7575 Multi-Asset functionality
 *
 * This interface defines the multi-asset management capabilities
 * for ERC-7575 share tokens, allowing them to track and manage
 * multiple vaults each handling different underlying assets.
 */
interface IERC7575MultiAsset {
    /**
     * @dev Returns the vault address for a given asset
     * @param asset The underlying asset token address
     * @return vaultAddress The vault contract address managing this asset
     */
    function vault(address asset) external view returns (address vaultAddress);

    /**
     * @dev Emitted when a vault is added or removed for an asset
     * @param asset The asset token address
     * @param vault The vault address (zero address for removal)
     */
    event VaultUpdate(address indexed asset, address vault);
}
