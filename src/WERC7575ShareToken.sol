// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
// import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {DecimalConstants} from "./DecimalConstants.sol";
import {SafeTokenTransfers} from "./SafeTokenTransfers.sol";

import {IERC7575, IERC7575Share} from "./interfaces/IERC7575.sol";
import {IERC7575Errors} from "./interfaces/IERC7575Errors.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

// Interface for vault validation - minimal interface to avoid circular dependencies
interface IERC7575Vault {
    function totalAssets() external view returns (uint256);
    function getScalingFactor() external view returns (uint64);
    function migrateBackingOut(address recipient) external returns (uint256 amount);
}

/**
 * @title WERC7575ShareToken (Wrapped ERC20 Share Token)
 * @notice NON-STANDARD ERC-20 IMPLEMENTATION WITH RESTRICTED TRANSFERS
 *
 * WERC = Wrapped ERC20 - Represents underlying assets as normalized 18-decimal shares
 *
 * ARCHITECTURE OVERVIEW:
 * This token provides a 1:1 wrapped representation of underlying ERC20 assets (USDT, USDC, etc.)
 * with decimal normalization to 18 decimals. For example:
 * - 1 USDC (6 decimals) = 1e12 scaling → 1e18 WERC shares
 * - 1 DAI (18 decimals) = 1e0 scaling → 1e18 WERC shares
 *
 * The 1:1 ratio is maintained through deterministic decimal scaling, NOT through
 * totalSupply/totalAssets ratios, making this architecture immune to donation/inflation attacks.
 *
 * USE CASES:
 * - Regulatory-compliant tokenized assets requiring KYC/AML
 * - Institutional vaults with controlled transfer permissions
 * - Multi-asset vault systems with unified 18-decimal share representation
 *
 * @dev This token implements centralized transfer controls that deviate from standard ERC-20:
 *
 * CRITICAL INTEGRATION WARNINGS:
 * - transfer() requires pre-existing self-allowance via permit()
 * - transferFrom() requires both owner's self-allowance AND caller's allowance
 * - approve() blocks self-approval (only validator can authorize via permit)
 * - All recipients must be KYC-verified by the KYC admin
 * - Validator controls batch transfers and permit operations
 * - Revenue admin controls rBalance adjustments
 *
 * INCOMPATIBLE WITH STANDARD ERC-20 INTEGRATIONS:
 * - DEXs (Uniswap, SushiSwap) will fail without modifications
 * - Lending protocols (Compound, Aave) will fail
 * - Standard wallet transfer functions will fail
 * - Multi-sig operations may fail
 * - Token streaming/vesting protocols will fail
 *
 * CENTRALIZATION RISKS:
 * - Single point of failure: KYC admin key compromise can lock all users from transfers
 * - Single point of failure: Validator key compromise can halt batch transfers
 * - Single point of failure: Revenue admin key compromise can manipulate rBalance
 * - User lock-in: KYC admin + validator signatures required for all token movements
 * - Censorship capability: KYC admin can prevent any user from transferring via KYC denial
 *
 * FOR INTEGRATORS:
 * Before integration, ensure your protocol handles:
 * - Permit-based authorization flows instead of standard approvals
 * - KYC verification requirements for all recipients
 * - Validator signature dependencies for user operations
 * - Non-standard transfer mechanics and failure modes
 *
 * See documentation for detailed integration guidelines and risk assessment.
 */
contract WERC7575ShareToken is ERC20, IERC20Permit, EIP712, Nonces, ReentrancyGuardTransient, Ownable2Step, ERC165, Pausable, IERC7575Errors {
    using EnumerableMap for EnumerableMap.AddressToAddressMap;

    // Note: Common errors now inherited from IERC7575Errors interface
    // OnlyOwner is inherited from IERC7575Errors

    // WERC7575-specific errors. (Generic ones — batch-size, array-length, balance, zero-address — are
    // reused from the inherited IERC7575Errors: BatchSizeTooLarge, LengthMismatch, InsufficientBalance,
    // ZeroAddress — rather than redeclared here.)
    error KycRequired();
    error RBalanceAdjustmentAlreadyApplied();
    error FutureTimestampNotAllowed();
    error MaxReturnMultiplierExceeded();
    error NoRBalanceAdjustmentFound();
    error OnlyValidator();
    error AmountTooLarge();
    error RBalanceAdjustmentTooLarge();
    error InconsistentRAccounts(address account, bool firstDiscoveryFlag, bool currentTransferFlag);

    bytes32 private constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    // Batch transfer constants
    // Maximum batch size to prevent exceeding block gas limits
    // Calculated as: 30M gas limit / 25k per transfer ≈ 1000, conservatively set to 100
    // to leave headroom for complex transfers and other operations
    uint256 private constant MAX_BATCH_SIZE = 100;

    // Maximum allowed return multiplier (100% profit cap)
    // Protects against validator input errors and unrealistic returns
    // Value chosen to allow reasonable investment gains while preventing mistakes
    uint256 private constant MAX_RETURN_MULTIPLIER = 2;

    // Batch array size multiplier for worst-case scenario
    // Allocates 2x space: 1 entry per debtor + 1 entry per creditor
    // Handles case where no addresses overlap between debtors and creditors
    uint256 private constant BATCH_ARRAY_MULTIPLIER = 2;

    // Maximum number of vaults per share token - DoS mitigation
    // Prevents unbounded iteration in vault aggregation functions
    uint256 private constant MAX_VAULTS_PER_SHARE_TOKEN = 10;

    mapping(address => uint256) private _balances;
    mapping(address => uint256) private _rBalances;
    mapping(address => mapping(uint256 => uint256[2])) private _rBalanceAdjustments;
    uint256 private _totalSupply;

    mapping(address => bool) public isKycVerified;

    // Multi-vault support as per ERC7575 with EnumerableMap for better management
    EnumerableMap.AddressToAddressMap private _assetToVault; // asset => vault mapping with enumeration
    mapping(address => address) private _vaultToAsset; // vault => asset (for quick reverse lookup and authorization)

    address private _validator; // Controls batchTransfers and permit operations
    address private _kycAdmin; // Controls KYC verification
    address private _revenueAdmin; // Controls rBalance adjustments

    error ERC2612ExpiredSignature(uint256 deadline);
    error ERC2612InvalidSigner(address signer, address owner);
    error OnlyKycAdmin();
    error OnlyRevenueAdmin();

    event RBalanceAdjusted(address indexed account, uint256 amountInvested, uint256 amountReceived);
    event RBalanceAdjustmentCancelled(address indexed account, uint256 ts);
    event VaultUpdate(address indexed asset, address vault);
    event KYCStatusChanged(address indexed user, address indexed kycAdmin, bool indexed isVerified, uint256 timestamp);
    event ValidatorChanged(address indexed previousValidator, address indexed newValidator);
    event KycAdminChanged(address indexed previousKycAdmin, address indexed newKycAdmin);
    event RevenueAdminChanged(address indexed previousRevenueAdmin, address indexed newRevenueAdmin);

    /**
     * @dev Initializes the ERC7575 share token with multi-asset vault support
     * @param name_ The name of the share token (e.g., "Wrapped USDT")
     * @param symbol_ The symbol of the share token (e.g., "wUSDT")
     *
     * Requirements:
     * - Token decimals must be exactly 18
     * - Sets deployer as owner, validator, kycAdmin, and revenueAdmin
     */
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) EIP712(name_, "1") Ownable(msg.sender) {
        if (decimals() != DecimalConstants.SHARE_TOKEN_DECIMALS) {
            revert WrongDecimals();
        }
        _validator = msg.sender;
        _kycAdmin = msg.sender;
        _revenueAdmin = msg.sender;
    }

    /**
     * @dev Modifier to restrict functions to validator only
     */
    modifier onlyValidator() {
        if (_validator != msg.sender) revert OnlyValidator();
        _;
    }

    /**
     * @dev Modifier to restrict functions to KYC admin only
     */
    modifier onlyKycAdmin() {
        if (_kycAdmin != msg.sender) revert OnlyKycAdmin();
        _;
    }

    /**
     * @dev Modifier to restrict functions to revenue admin only
     */
    modifier onlyRevenueAdmin() {
        if (_revenueAdmin != msg.sender) revert OnlyRevenueAdmin();
        _;
    }

    /**
     * @dev Modifier to restrict functions to authorized vaults only
     */
    modifier onlyVaults() {
        if (_vaultToAsset[msg.sender] == address(0)) revert Unauthorized();
        _;
    }

    /**
     * @dev Adds a new vault for a specific asset (ERC7575 multi-asset support)
     * @param asset The asset token address that the vault will manage
     * @param vaultAddress The vault contract address to authorize
     *
     * Requirements:
     * - Asset must not be zero address
     * - Vault must not be zero address
     * - Asset must not already be registered
     * - Vault's asset() must match the provided asset parameter
     * - Vault's share() must match this ShareToken address
     * - Only callable by owner
     */
    function registerVault(address asset, address vaultAddress) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        if (vaultAddress == address(0)) revert ZeroAddress();
        if (_assetToVault.contains(asset)) revert AssetAlreadyRegistered();

        // Validate that vault's asset matches the provided asset parameter
        if (IERC7575(vaultAddress).asset() != asset) revert AssetMismatch();

        // Validate that vault's share token matches this ShareToken
        if (IERC7575(vaultAddress).share() != address(this)) {
            revert VaultShareMismatch();
        }

        // DoS mitigation: Enforce maximum vaults per share token to prevent unbounded loops
        if (_assetToVault.length() >= MAX_VAULTS_PER_SHARE_TOKEN) {
            revert MaxVaultsExceeded();
        }

        // Register new vault (automatically adds to enumerable collection)
        _assetToVault.set(asset, vaultAddress);
        _vaultToAsset[vaultAddress] = asset;

        emit VaultUpdate(asset, vaultAddress);
    }

    /// @dev Emitted when a deactivated vault's backing is migrated into another vault and unregistered
    event VaultBackingMigrated(address indexed fromAsset, address fromVault, uint256 amountRemoved, address indexed toAsset, address toVault, uint256 amountInjected);

    /**
     * @dev Unregisters a vault for a specific asset.
     *
     * Thin wrapper for removing an EMPTY, deactivated vault: delegates to the shared core with a null
     * toAsset. The core only needs a toAsset when the vault still holds backing (moved > 0); with a
     * null toAsset that case reverts (CannotUnregisterVaultAssetBalance) rather than orphaning the
     * backing. So this succeeds only for a deactivated, fully-drained vault. To remove a vault that
     * still holds backing WITHOUT a loss, call migrateAndUnregisterVault with a real toAsset — which
     * also sweeps any dust, so a griefer cannot block decommissioning by donating to the vault.
     *
     * Requirements:
     * - Vault must exist and be registered
     * - Vault must be deactivated and hold zero assets (no user funds at risk)
     * - Only callable by owner
     */
    function unregisterVault(address asset) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        _migrateAndUnregisterVault(asset, address(0));
    }

    /**
     * @dev Migrates a DEACTIVATED vault's entire backing into another registered vault, then
     * unregisters it — preserving total normalized backing so no holder takes a loss.
     *
     * Use case: removing a non-compliant or depegged asset without socializing a loss. The exact
     * amount of `toAsset` needed to preserve normalized backing at par is computed from the drained
     * amount and pulled from the owner; the deactivated `fromAsset` vault is drained to the owner
     * (who liquidates it off-chain and absorbs any real shortfall); `fromAsset` is then unregistered.
     * `totalSupply` is untouched, so the wrapped 1:1 ratio is maintained.
     *
     * The `fromAsset` vault must already be deactivated; migrateBackingOut enforces that and drains
     * the full balance (legitimate backing + any donated dust), so the vault is left empty and
     * unregisters cleanly with nothing stranded.
     *
     * @param fromAsset Asset of the deactivated vault being removed
     * @param toAsset   Asset of the vault that receives the compensating backing
     */
    function migrateAndUnregisterVault(address fromAsset, address toAsset) external onlyOwner {
        _migrateAndUnregisterVault(fromAsset, toAsset);
    }

    /**
     * @dev Shared core used by both unregisterVault (toAsset == 0) and migrateAndUnregisterVault.
     * Drains the deactivated fromVault; if it still held backing (moved > 0) an equal-or-greater
     * normalized amount of toAsset is pulled from the caller into toVault first (preserving the 1:1
     * ratio at par, rounding favors the pool); then fromVault is unregistered. Kept internal so
     * msg.sender stays the original owner for the safeTransferFrom pull.
     */
    function _migrateAndUnregisterVault(address fromAsset, address toAsset) internal {
        if (fromAsset == toAsset) revert SameAssetMigration();
        (bool fromExists, address fromVault) = _assetToVault.tryGet(fromAsset);
        if (!fromExists) revert AssetNotRegistered();

        // migrateBackingOut self-validates deactivation; moved == 0 ⇒ vault was empty.
        uint256 moved = IERC7575Vault(fromVault).migrateBackingOut(msg.sender);

        // toAsset (compensation) is only required when there is backing to migrate. The empty-vault
        // wrapper passes toAsset == 0; reaching here with backing and no toAsset means a backed vault
        // was passed to plain unregisterVault — reject it rather than orphan the backing.
        if (moved > 0) {
            if (toAsset == address(0)) {
                revert CannotUnregisterVaultAssetBalance();
            }
            (bool toExists, address toVault) = _assetToVault.tryGet(toAsset);
            if (!toExists) revert AssetNotRegistered();

            // ceil so the pool is never under-compensated when scalingTo does not divide evenly.
            uint256 amountIn = Math.mulDiv(moved, IERC7575Vault(fromVault).getScalingFactor(), IERC7575Vault(toVault).getScalingFactor(), Math.Rounding.Ceil);

            // Raw transfer into toVault raises its totalAssets() with no new shares minted.
            if (amountIn > 0) {
                SafeTokenTransfers.safeTransferFrom(toAsset, msg.sender, toVault, amountIn);
            }
            emit VaultBackingMigrated(fromAsset, fromVault, moved, toAsset, toVault, amountIn);
        }

        // Remove vault registration and authorization (automatically removes from enumerable collection)
        _assetToVault.remove(fromAsset);
        delete _vaultToAsset[fromVault]; // Also clear reverse mapping for authorization

        emit VaultUpdate(fromAsset, address(0));
    }

    /**
     * @dev Sets KYC status for an address
     * @param controller The address to set KYC status for
     * @param isVerified True to mark as KYC verified, false otherwise
     *
     * Emits KYCStatusChanged event only when status actually changes to save gas
     */
    function setKycVerified(address controller, bool isVerified) public onlyKycAdmin {
        bool previousStatus = isKycVerified[controller];

        // Only update and emit if status actually changes
        if (previousStatus != isVerified) {
            isKycVerified[controller] = isVerified;
            emit KYCStatusChanged(controller, msg.sender, isVerified, block.timestamp);
        }
    }

    /**
     * @dev Sets the validator address for permit operations and batch transfers
     * @param validator The new validator address
     *
     * Emits a ValidatorChanged event for off-chain monitoring
     */
    function setValidator(address validator) public onlyOwner {
        if (validator == address(0)) revert ZeroAddress();
        address previousValidator = _validator;
        if (previousValidator != validator) {
            _validator = validator;
            emit ValidatorChanged(previousValidator, validator);
        }
    }

    /**
     * @dev Sets the KYC admin address for managing KYC verification
     * @param kycAdmin The new KYC admin address
     *
     * Emits a KycAdminChanged event for off-chain monitoring
     */
    function setKycAdmin(address kycAdmin) public onlyOwner {
        if (kycAdmin == address(0)) revert ZeroAddress();
        address previousKycAdmin = _kycAdmin;

        if (previousKycAdmin != kycAdmin) {
            _kycAdmin = kycAdmin;
            emit KycAdminChanged(previousKycAdmin, kycAdmin);
        }
    }

    /**
     * @dev Sets the revenue admin address for managing rBalance adjustments
     * @param revenueAdmin The new revenue admin address
     *
     * Emits a RevenueAdminChanged event for off-chain monitoring
     */
    function setRevenueAdmin(address revenueAdmin) public onlyOwner {
        if (revenueAdmin == address(0)) revert ZeroAddress();
        address previousRevenueAdmin = _revenueAdmin;

        if (previousRevenueAdmin != revenueAdmin) {
            _revenueAdmin = revenueAdmin;
            emit RevenueAdminChanged(previousRevenueAdmin, revenueAdmin);
        }
    }

    /**
     * @dev Pause user-facing ShareToken operations. Only callable by owner, for emergencies.
     * Gates transfer/transferFrom and vault-driven mint/burn (i.e. deposit/redeem claims).
     *
     * Pause is NOT a full accounting freeze: validator batch settlement (batchTransfers /
     * rBatchTransfers) and revenue-admin rBalance adjustment (adjustrBalance) are intentionally
     * left ungated and continue while paused — see the notes on those paths.
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Unpause ShareToken operations. Only callable by owner.
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @dev Mints new share tokens to an address (vault-only operation)
     * @param to The address to mint tokens to
     * @param amount The amount of tokens to mint
     */
    function mint(address to, uint256 amount) external onlyVaults whenNotPaused {
        if (to == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }
        if (!isKycVerified[to]) revert KycRequired();
        _mint(to, amount);
    }

    /**
     * @dev Burns share tokens from an address (vault-only operation)
     * @param from The address to burn tokens from
     * @param amount The amount of tokens to burn
     */
    function burn(address from, uint256 amount) external onlyVaults whenNotPaused {
        if (from == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }
        if (!isKycVerified[from]) revert KycRequired();
        _burn(from, amount);
    }

    /**
     * @dev EIP-2612 permit (split ECDSA signature). Thin wrapper over the bytes-signature overload so
     * standard wallets/tooling that produce (v, r, s) keep working unchanged.
     * @param owner The owner of the tokens
     * @param spender The address to approve spending
     * @param value The amount to approve
     * @param deadline The signature expiration timestamp
     * @param v The recovery byte of the signature
     * @param r Half of the ECDSA signature pair
     * @param s Half of the ECDSA signature pair
     *
     * Special case: When owner == spender, validator signature is required.
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public virtual {
        permit(owner, spender, value, deadline, abi.encodePacked(r, s, v));
    }

    /**
     * @dev Permit with an opaque `signature` blob, verified via OZ SignatureChecker — accepts both
     * ECDSA signatures (EOAs, and EIP-7702 accounts signing with their underlying key) AND ERC-1271
     * signatures from contract signers (Safe/Argent, ERC-4337 accounts, multisigs). This is what lets
     * a smart-contract VALIDATOR (e.g. a multisig) authorize the self-allowance path that WERC
     * redemptions depend on — a raw ecrecover cannot validate a contract signer.
     *
     * Special case: When owner == spender (self-allowance), the required signer is the validator;
     * otherwise it is the owner.
     *
     * @param signature ECDSA (65-byte r‖s‖v) or ERC-1271 signature over the EIP-712 Permit digest
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes memory signature) public virtual {
        if (block.timestamp > deadline) {
            revert ERC2612ExpiredSignature(deadline);
        }

        uint256 nonce = _useNonce(owner);
        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline)));

        // Self-allowance must be authorized by the validator; all other approvals by the owner.
        address expectedSigner = owner == spender ? _validator : owner;
        if (!SignatureChecker.isValidSignatureNow(expectedSigner, hash, signature)) {
            revert ERC2612InvalidSigner(expectedSigner, owner);
        }
        _approve(owner, spender, value);
    }

    /**
     * @dev Approve function with self-approval protection
     * @param spender The address to approve spending
     * @param value The amount to approve
     * @return bool True if approval successful
     *
     * Note: Self-approval is blocked, use permit instead for self-spending
     */
    function approve(address spender, uint256 value) public virtual override returns (bool) {
        if (msg.sender != spender) {
            return super.approve(spender, value);
        }
        revert ERC20InvalidSpender(msg.sender);
    }

    /**
     * @dev Returns the current nonce for an owner address
     * @param owner The address to get nonce for
     * @return uint256 The current nonce value
     */
    function nonces(address owner) public view virtual override(IERC20Permit, Nonces) returns (uint256) {
        return super.nonces(owner);
    }

    /**
     * @dev Returns the domain separator for EIP-712 signatures
     * @return bytes32 The domain separator hash
     */
    // EIP-712 standard requires mixed-case DOMAIN_SEPARATOR
    function DOMAIN_SEPARATOR() external view virtual returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev Transfer function with self-allowance spending requirement
     * @param to The address to transfer tokens to
     * @param value The amount of tokens to transfer
     * @return bool True if transfer successful
     *
     * Note: Requires self-allowance via permit for transfers, rBalance should not be affected by transfer.
     */
    function transfer(address to, uint256 value) public override whenNotPaused returns (bool) {
        address from = msg.sender;
        if (!isKycVerified[to]) revert KycRequired();
        _spendAllowance(from, from, value);
        return super.transfer(to, value);
    }

    /**
     * @dev Restricted transferFrom — intended for DELEGATED transfers only.
     * @param from The address to transfer tokens from
     * @param to The address to transfer tokens to
     * @param value The amount of tokens to transfer
     * @return bool True if transfer successful
     *
     * Authorization model (intentional, non-standard ERC-20):
     * - `from` MUST hold a validator-issued self-allowance (allowance[from][from]) — the
     *   on-chain proof that `from` is permitted to move funds at all under the restricted model.
     * - When msg.sender != from, msg.sender must ADDITIONALLY hold a normal caller-allowance
     *   (allowance[from][msg.sender]). The two slots differ, so this is the intended dual-gate.
     * - When msg.sender == from (self-movement), the delegated caller-allowance slot IS the
     *   self-allowance slot, so the self-allowance is spent EXACTLY ONCE (not twice) — this path is
     *   equivalent to transfer(). (L-03: previously the self-call double-charged the owner's permit.)
     *
     * Note: rBalance is not affected by transferFrom.
     */
    function transferFrom(address from, address to, uint256 value) public override whenNotPaused returns (bool) {
        if (!isKycVerified[to]) revert KycRequired();
        _spendAllowance(from, from, value); // self-allowance gate (validator-issued restricted-token proof)
        if (msg.sender == from) {
            // Self-movement: do NOT consume the self-allowance a second time via the delegated path
            // (allowance[from][msg.sender] == allowance[from][from] here). Move balance directly,
            // exactly like transfer(). _transfer routes through the overridden _update (custom storage).
            _transfer(from, to, value);
            return true;
        }
        return super.transferFrom(from, to, value); // additionally spends the delegated allowance[from][msg.sender]
    }

    /**
     * @dev See {IERC20-totalSupply}.
     */
    function totalSupply() public view virtual override(ERC20) returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev Returns the token balance of an account
     * @param account The address to check balance for
     * @return uint256 The token balance
     */
    function balanceOf(address account) public view virtual override(ERC20) returns (uint256) {
        return _balances[account];
    }

    /**
     * @dev Internal update function that maintains custom balance tracking
     * @param from The address tokens are transferred from (zero for minting)
     * @param to The address tokens are transferred to (zero for burning)
     * @param value The amount of tokens being transferred
     *
     * This override maintains our custom _balances mapping to avoid double
     * Transfer event emission in batchTransfers function
     */
    function _update(address from, address to, uint256 value) internal virtual override {
        if (from == address(0)) {
            // Overflow check required: The rest of the code assumes that totalSupply never overflows
            _totalSupply += value;
        } else {
            uint256 fromBalance = _balances[from];
            if (fromBalance < value) {
                revert ERC20InsufficientBalance(from, fromBalance, value);
            }
            unchecked {
                // Overflow not possible: value <= fromBalance <= totalSupply.
                _balances[from] = fromBalance - value;
            }
        }

        if (to == address(0)) {
            unchecked {
                // Overflow not possible: value <= totalSupply or value <= fromBalance <= totalSupply.
                _totalSupply -= value;
            }
        } else {
            unchecked {
                // Overflow not possible: balance + value is at most totalSupply, which we know fits into a uint256.
                _balances[to] += value;
            }
        }

        emit Transfer(from, to, value);
    }

    /**
     * @dev Returns the reserved balance (rBalance) of an account
     * @param account The address to check rBalance for
     * @return uint256 The reserved balance amount
     */
    function rBalanceOf(address account) public view returns (uint256) {
        return _rBalances[account];
    }

    /**
     * @dev Returns the vault address for a given asset
     * @param asset The asset token address
     * @return v The vault address managing this asset (zero address if not registered)
     */
    function vault(address asset) external view returns (address v) {
        (, v) = _assetToVault.tryGet(asset);
    }

    /**
     * @dev Returns whether an address is a registered vault
     * @param vaultAddress The vault address to check
     * @return bool True if the address is a registered vault
     */
    function isVault(address vaultAddress) external view returns (bool) {
        return _vaultToAsset[vaultAddress] != address(0);
    }

    /**
     * @dev Returns all registered assets in the multi-asset system
     * @return address[] Array of all asset addresses that have registered vaults
     */
    function getRegisteredAssets() external view returns (address[] memory) {
        return _assetToVault.keys();
    }

    /**
     * @dev Returns all registered vaults in the multi-asset system
     * @return address[] Array of all vault addresses that are registered
     */
    function getRegisteredVaults() external view returns (address[] memory) {
        address[] memory assets = _assetToVault.keys();
        address[] memory vaults = new address[](assets.length);

        for (uint256 i = 0; i < assets.length; i++) {
            vaults[i] = _assetToVault.get(assets[i]);
        }

        return vaults;
    }

    /**
     * @dev Returns the total number of registered asset-vault pairs
     * @return uint256 The number of registered vaults
     */
    function getVaultCount() external view returns (uint256) {
        return _assetToVault.length();
    }

    /**
     * @dev Returns asset and vault at the given index (for iteration)
     * @param index The index to query
     * @return asset The asset address at this index
     * @return vaultAddress The vault address at this index
     */
    function getVaultAtIndex(uint256 index) external view returns (address asset, address vaultAddress) {
        return _assetToVault.at(index);
    }

    /**
     * @dev Returns the current validator address
     * @return address The validator address
     */
    function getValidator() external view returns (address) {
        return _validator;
    }

    /**
     * @dev Returns the current KYC admin address
     * @return address The KYC admin address
     */
    function getKycAdmin() external view returns (address) {
        return _kycAdmin;
    }

    /**
     * @dev Returns the current revenue admin address
     * @return address The revenue admin address
     */
    function getRevenueAdmin() external view returns (address) {
        return _revenueAdmin;
    }

    /**
     * @dev Returns true if this contract implements the interface defined by interfaceId
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return bool True if the contract implements interfaceId
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165) returns (bool) {
        // type(IERC7575Share).interfaceId is the canonical 0xf815c03d (vault(address) only).
        return interfaceId == type(IERC7575Share).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Spends self allowance for an owner (vault-only operation)
     * @param owner The owner address to spend allowance for
     * @param shares The amount of shares to spend from allowance
     */
    function spendSelfAllowance(address owner, uint256 shares) external onlyVaults {
        _spendAllowance(owner, owner, shares);
    }

    /**
     * @dev Spends allowance for an owner (vault-only operation)
     * @param owner The owner address to spend allowance for
     * @param spender The spender address to spend allowance for
     * @param shares The amount of shares to spend from allowance
     */
    function spendAllowance(address owner, address spender, uint256 shares) external onlyVaults {
        _spendAllowance(owner, spender, shares);
    }

    /**
     * @dev Structure to track debits and credits for batch transfer optimization
     * @param owner The account address
     * @param debit Total amount being debited from the account
     * @param credit Total amount being credited to the account
     */
    struct DebitAndCredit {
        address owner;
        uint256 debit;
        uint256 credit;
    }

    /**
     * @dev Performs batch transfers for settlement operations
     * @param debtors Array of addresses to debit tokens from
     * @param creditors Array of addresses to credit tokens to
     * @param amounts Array of amounts for each transfer
     * @return bool True if all transfers successful
     *
     * This function nets debits/credits on the regular balance (_balances) ONLY — it does not touch
     * reserved balance (rBalance). rBalance movement lives in rBatchTransfers and the revenue-admin
     * adjustment paths. Netting minimizes gas and avoids double Transfer event emission.
     *
     * REENTRANCY PROTECTION:
     * This function does NOT use nonReentrant guard because:
     * - Only manipulates internal state (_balances)
     * - Makes no external calls to other contracts
     * - Follows Checks-Effects-Interactions (CEI) pattern
     * - No way for an attacker to re-enter before state is finalized
     *
     * Requirements:
     * - All arrays must have the same length
     * - Maximum 100 transfers per batch
     * - Sufficient balance in debtor accounts
     *
     * NOTE: validator settlement is NOT gated by pause(). Pause only freezes user-facing flows
     * (transfer/transferFrom/mint/burn); privileged settlement and rBalance accounting continue while
     * paused, by design (see docs/DESIGN_ASSUMPTIONS.md "Pause Does Not Block Validator or
     * Revenue-Admin Balance Mutation"). For an emergency accounting freeze, rotate/disable the role.
     */
    function batchTransfers(address[] calldata debtors, address[] calldata creditors, uint256[] calldata amounts) external onlyValidator returns (bool) {
        (DebitAndCredit[] memory accounts, uint256 accountsLength) = consolidateTransfers(debtors, creditors, amounts);

        // CEI: Update balances only (do NOT modify rBalances - that is rBatchTransfers' job).
        // The whole loop is unchecked: both subtractions are branch-guarded (no underflow), the credit
        // (+=) cannot overflow because balances are conserved in netting and bounded by the checked
        // _totalSupply (_update mint), and ++i is loop-bounded. `unchecked` does NOT affect the
        // InsufficientBalance revert below nor the accounts[i] bounds check — both stay active.
        unchecked {
            for (uint256 i = 0; i < accountsLength; ++i) {
                DebitAndCredit memory account = accounts[i];
                if (account.debit > account.credit) {
                    uint256 amount = account.debit - account.credit;
                    if (_balances[account.owner] < amount) {
                        revert InsufficientBalance();
                    }
                    _balances[account.owner] -= amount;
                } else if (account.debit < account.credit) {
                    _balances[account.owner] += account.credit - account.debit;
                }
            }
        }

        // CEI: Emit Transfer events after all state changes are complete
        for (uint256 i = 0; i < debtors.length;) {
            emit Transfer(debtors[i], creditors[i], amounts[i]);
            unchecked {
                ++i;
            } // Unchecked pre-increment for gas optimization
        }

        return true;
    }

    /**
     * @dev Computes the rBalance flags bitmap for batch transfers
     * @param debtors Array of debtor addresses
     * @param creditors Array of creditor addresses
     * @param debtorsRBalanceFlags Boolean array: debtorsRBalanceFlags[i] = true if debtors[i] needs rBalance update
     * @param creditorsRBalanceFlags Boolean array: creditorsRBalanceFlags[i] = true if creditors[i] needs rBalance update
     * @return rBalanceFlags Computed bitmap for accounts array indices that need rBalance updates
     *
     * VALIDATION APPROACH:
     * This helper function separates validation from execution for integrity verification:
     *
     * PHASE 1 (PRE-COMPUTATION):
     * - Maps the boolean arrays (indexed by transfer number) to rBalanceFlags bitmap (indexed by aggregated account position)
     * - Replicates EXACT account aggregation logic from consolidateTransfers() for semantic equivalence
     * - Called OFF-CHAIN before transaction submission for verification
     * - Pure function: deterministic, no side effects, independently verifiable
     *
     * PHASE 2 (EXECUTION):
     * - Result passed to rBatchTransfers() as parameter
     * - Uses O(1) bitwise lookup: ((rBalanceFlags >> i) & 1) instead of O(N) search
     * - Ensures only pre-approved accounts have rBalance updated
     *
     * INPUT FORMAT (boolean arrays):
     * - debtorsRBalanceFlags[i]:     true if debtors[i] needs rBalance update
     * - creditorsRBalanceFlags[i]:   true if creditors[i] needs rBalance update
     *
     * OUTPUT FORMAT (rBalanceFlags bitmap):
     * - Bits 0..M-1:   Set if accounts[i] (in aggregated order) needs rBalance update
     *                  where M <= 2N (typically M much less due to deduplication)
     *
     * MAPPING EXAMPLE:
     * Transfer 0: alice → bob    [debtorsRBalanceFlags[0]=true, creditorsRBalanceFlags[0]=false]
     * Transfer 1: bob → charlie  [debtorsRBalanceFlags[1]=false, creditorsRBalanceFlags[1]=true]
     *
     * Account aggregation:
     * 1. Transfer 0: alice (new) → bob (new)
     *    - alice new at position 0, flag=true → set rBalanceFlags bit 0
     *    - bob new at position 1, flag=false → clear rBalanceFlags bit 1
     * 2. Transfer 1: bob (found) → charlie (new)
     *    - bob found at position 1 (no-op)
     *    - charlie new at position 2, flag=true → set rBalanceFlags bit 2
     * Result: rBalanceFlags = 0b101 (alice and charlie marked for update)
     *
     * FIRST-DISCOVERY FLAG DETERMINATION:
     * - Account rBalance flag is set based on FIRST occurrence (earliest transfer) of that account
     * - If alice appears as debtor in transfer 0 (marked for rBalance), alice's flag is set
     * - If alice appears again in transfer 5 (NOT marked for rBalance), flag ALREADY SET, not re-evaluated
     * - This ensures deterministic, order-dependent (but not arbitrary) flag assignment
     * - CONSISTENCY REQUIREMENT: If an account is marked in one role (debtor/creditor), it MUST be
     *   marked consistently in all subsequent transfers involving that account in any role
     *
     * SEMANTIC EQUIVALENCE:
     * The account aggregation logic in computeRBalanceFlags() MUST match
     * consolidateTransfers() exactly. Both:
     * - Skip self-transfers (debtor == creditor)
     * - Use identical bit flag patterns for account discovery
     * - Process accounts in identical discovery order
     * This ensures flags computed here will be applied to correct accounts in rBatchTransfers()
     *
     * INTEGRITY PROPERTIES:
     * 1. Deterministic: Same inputs always produce same output (pure function)
     * 2. Off-chain verifiable: Can compute and validate before submitting transaction
     * 3. First-discovery semantics: Flag set on first encounter, verified on subsequent encounters
     * 4. Clarity: Boolean arrays are more readable than packed bitmaps
     * 5. Type-safe: No bit manipulation errors from incorrect offsets
     */
    function computeRBalanceFlags(
        address[] calldata debtors,
        address[] calldata creditors,
        bool[] calldata debtorsRBalanceFlags,
        bool[] calldata creditorsRBalanceFlags
    )
        external
        pure
        returns (uint256 rBalanceFlags)
    {
        return _computeRBalanceFlagsInternal(debtors, creditors, debtorsRBalanceFlags, creditorsRBalanceFlags);
    }

    function _computeRBalanceFlagsInternal(
        address[] calldata debtorsData,
        address[] calldata creditorsData,
        bool[] calldata debtorsFlagsData,
        bool[] calldata creditorsFlagsData
    )
        internal
        pure
        returns (uint256 rBalanceFlags)
    {
        // Copy calldata to memory to reduce stack depth issues
        address[] memory debtors = debtorsData;
        address[] memory creditors = creditorsData;
        bool[] memory debtorsRBalanceFlags = debtorsFlagsData;
        bool[] memory creditorsRBalanceFlags = creditorsFlagsData;
        uint256 debtorsLength = debtors.length;
        if (debtorsLength > MAX_BATCH_SIZE) revert BatchSizeTooLarge();
        if (debtorsLength != creditors.length) revert LengthMismatch();
        if (debtorsLength != debtorsRBalanceFlags.length) {
            revert LengthMismatch();
        }
        if (debtorsLength != creditorsRBalanceFlags.length) {
            revert LengthMismatch();
        }

        // Allocate accounts array with same size as consolidateTransfers (2*N max)
        // This maintains semantic equivalence: same aggregation process = same account positions
        address[] memory accounts = new address[](debtorsLength * BATCH_ARRAY_MULTIPLIER);
        uint256 accountsLength = 0;

        // PHASE 1: Replicate account aggregation logic from consolidateTransfers()
        // This double-loop mirrors the exact pattern used in consolidateTransfers():
        // 1. For each transfer, check if debtor/creditor already exist in accounts array
        // 2. Mark with flags which new accounts need to be created
        // 3. When creating new account, check rAccounts input to determine if rBalance update needed
        // 4. Set corresponding bit in rBalanceFlags output bitmap
        // 5. VERIFY: When account is found again, ensure flag consistency with first discovery
        //
        // CRITICAL: This logic MUST remain synchronized with consolidateTransfers().
        // Any divergence will cause flags to be applied to wrong accounts in rBatchTransfers().
        for (uint256 i = 0; i < debtorsLength;) {
            address debtor = debtors[i];
            address creditor = creditors[i];

            // Skip self-transfers (debtor == creditor) - same as consolidateTransfers() line 828
            if (debtor != creditor) {
                // Bit flag tracking (identical pattern to consolidateTransfers lines 830-842):
                // Bit 0 (0x1): Set if debtor needs to be added to accounts array
                // Bit 1 (0x2): Set if creditor needs to be added to accounts array
                // Start with both bits set, clear as we find existing accounts
                uint8 addFlags = 0x3; // 0b11 = both addDebtor and addCreditor initially true

                // Check if debtor or creditor already exist in accounts array
                // IMPORTANT: Once an account is discovered and added, its rBalance flag is SET based on that
                // discovery transfer's rAccounts bit. Subsequent transfers involving same account DON'T
                // re-check or re-set the flag - it was determined by first appearance.
                // VERIFICATION: When account is found again, validate that the expected flag from
                // current transfer's rAccounts matches the flag already set (from first discovery).
                // Loop only while addFlags != 0 (break early if both found)
                for (uint256 j = 0; (j < accountsLength) && addFlags != 0; ++j) {
                    if (accounts[j] == debtor) {
                        // Debtor found in existing accounts (was added in earlier transfer)
                        // VERIFY: Check that this debtor's rBalance flag from current transfer
                        // matches the flag already set in rBalanceFlags at position j
                        // If first discovery marked debtor with flag, current transfer should also mark it
                        // If first discovery didn't mark debtor, current transfer shouldn't either
                        bool currentTransferMarksDebtor = debtorsRBalanceFlags[i];
                        bool debtorAlreadyMarked = ((rBalanceFlags >> j) & 1) == 1;

                        // VERIFICATION LOGIC:
                        // currentTransferMarksDebtor: Whether THIS transfer marks debtor for rBalance
                        // debtorAlreadyMarked: Whether debtor was already marked from FIRST discovery
                        //
                        // CRITICAL INVARIANT: If debtor was marked on first discovery, it MUST be marked
                        // on all subsequent transfers (same role). If not marked on first discovery,
                        // it must NOT be marked in any subsequent transfer (same role).
                        // This ensures consistent rBalance semantics - account flag doesn't change based on
                        // which transfer involves it.
                        //
                        // Enforcement: If boolean flags are inconsistent, revert with detailed error
                        // Custom error includes: account address, flag from first discovery, flag from current transfer
                        if (currentTransferMarksDebtor != debtorAlreadyMarked) {
                            revert InconsistentRAccounts(debtor, debtorAlreadyMarked, currentTransferMarksDebtor);
                        }

                        addFlags &= ~uint8(1); // Clear bit 0 (addDebtor = false)
                    } else if (accounts[j] == creditor) {
                        // Creditor found in existing accounts (was added in earlier transfer)
                        // VERIFY: Check that this creditor's rBalance flag from current transfer
                        // matches the flag already set in rBalanceFlags at position j
                        bool currentTransferMarksCreditor = creditorsRBalanceFlags[i];
                        bool creditorAlreadyMarked = ((rBalanceFlags >> j) & 1) == 1;

                        // VERIFICATION LOGIC: Same as debtor case
                        // currentTransferMarksCreditor: Whether THIS transfer marks creditor for rBalance
                        // creditorAlreadyMarked: Whether creditor was marked from FIRST discovery
                        //
                        // CRITICAL INVARIANT: If creditor was marked on first discovery, it MUST be marked
                        // on all subsequent transfers (same role). If not marked on first discovery,
                        // it must NOT be marked in any subsequent transfer (same role).
                        // This ensures consistent rBalance semantics - account flag doesn't change based on
                        // which transfer involves it.
                        //
                        // Enforcement: If boolean flags are inconsistent, revert with detailed error
                        // Custom error includes: account address, flag from first discovery, flag from current transfer
                        if (currentTransferMarksCreditor != creditorAlreadyMarked) {
                            revert InconsistentRAccounts(creditor, creditorAlreadyMarked, currentTransferMarksCreditor);
                        }

                        addFlags &= ~uint8(2); // Clear bit 1 (addCreditor = false)
                    }
                }

                // Create new account entries only if not found in existing accounts
                if ((addFlags & 1) != 0) {
                    // DEBTOR IS NEW - add to accounts array at current position (accountsLength)
                    // This position will be used as index when processing this account in rBatchTransfers()
                    accounts[accountsLength] = debtor;

                    // Check if this debtor transfer has rBalance update flag set
                    // Use the debtorsRBalanceFlags[i] boolean to determine if flag should be set
                    if (debtorsRBalanceFlags[i]) {
                        // Set corresponding bit in rBalanceFlags output
                        // This marks accounts[accountsLength] for rBalance update in rBatchTransfers()
                        rBalanceFlags |= (uint256(1) << accountsLength);
                    }
                    accountsLength++;
                }

                if ((addFlags & 2) != 0) {
                    // CREDITOR IS NEW - add to accounts array at current position
                    accounts[accountsLength] = creditor;

                    // Check if this creditor transfer has rBalance update flag set
                    // Use the creditorsRBalanceFlags[i] boolean to determine if flag should be set
                    if (creditorsRBalanceFlags[i]) {
                        // Set corresponding bit in rBalanceFlags output
                        // This marks accounts[accountsLength] for rBalance update in rBatchTransfers()
                        rBalanceFlags |= (uint256(1) << accountsLength);
                    }
                    accountsLength++;
                }
            }

            unchecked {
                ++i;
            }
        }

        // Return bitmap where bit i indicates if accounts[i] (in aggregated order) needs rBalance update
        // This bitmap will be used in rBatchTransfers() as: ((rBalanceFlags >> i) & 1) == 1
        return rBalanceFlags;
    }

    /**
     * @dev Consolidates multiple transfers into unique account debit/credit pairs
     * Inlines the account tracking logic for optimal gas efficiency
     * @param debtors Array of debtor addresses
     * @param creditors Array of creditor addresses
     * @param amounts Array of transfer amounts
     * @return accounts Array of consolidated DebitAndCredit structs
     * @return accountsLength Number of unique accounts in array
     *
     * CONSOLIDATION ALGORITHM:
     * Converts N transfers into M unique accounts where M <= 2N (typically M << 2N due to deduplication)
     *
     * Example: 5 transfers between 3 people
     * Input:
     *   Transfer 0: alice → bob (100)
     *   Transfer 1: bob → charlie (50)
     *   Transfer 2: charlie → alice (75)
     *   Transfer 3: alice → bob (25)
     *   Transfer 4: bob → alice (10)
     *
     * Consolidation Result (3 unique accounts):
     *   Account 0 (alice):   debit=100+25=125, credit=75+10=85, net_debit=40
     *   Account 1 (bob):     debit=50+10=60, credit=100+25=125, net_credit=65
     *   Account 2 (charlie): debit=75, credit=50, net_debit=25
     *
     * RELATIONSHIP TO computeRBalanceFlags():
     * - Both functions use identical account discovery logic (lines 819-831 vs 817-830)
     * - Both skip self-transfers (debtor == creditor)
     * - Both track accounts with bit flags (addFlags pattern)
     * - Both process accounts in identical order: order of first appearance in transfer list
     *
     * This means account positions computed in computeRBalanceFlags() correspond EXACTLY
     * to account positions in consolidateTransfers() output. This semantic equivalence is
     * critical for rBalanceFlags bitmap to work correctly.
     *
     * SECURITY NOTE:
     * The account order is deterministic and depends on:
     * 1. Transfer order (which account appears first: debtor or creditor)
     * 2. Transfer history (whether account was seen before)
     * This order cannot be manipulated by changing account balances or other state.
     */
    function consolidateTransfers(
        address[] calldata debtors,
        address[] calldata creditors,
        uint256[] calldata amounts
    )
        internal
        pure
        returns (DebitAndCredit[] memory accounts, uint256 accountsLength)
    {
        uint256 debtorsLength = debtors.length;
        if (debtorsLength > MAX_BATCH_SIZE) revert BatchSizeTooLarge();
        if (!(debtorsLength == creditors.length && debtorsLength == amounts.length)) revert LengthMismatch();

        accounts = new DebitAndCredit[](debtorsLength * BATCH_ARRAY_MULTIPLIER);
        accountsLength = 0;

        // Outer loop: process each transfer
        for (uint256 i = 0; i < debtorsLength;) {
            address debtor = debtors[i];
            address creditor = creditors[i];
            uint256 amount = amounts[i];

            // Reject zero-address settlement entries: a creditor of address(0) would shuffle real
            // balance to the zero address with no totalSupply change (silent value loss + Σbalances
            // drift). The standard transfer/transferFrom paths reject address(0); the batch paths must too.
            if (debtor == address(0) || creditor == address(0)) {
                revert ZeroAddress();
            }

            // Skip self-transfers (debtor == creditor)
            if (debtor != creditor) {
                // Inline addAccount logic with bit flags for account creation
                uint8 addFlags = 0x3; // 0b11 = both addDebtor and addCreditor initially true

                // Inner loop: check if debtor and creditor already exist in accounts array
                for (uint256 j = 0; (j < accountsLength) && addFlags != 0; ++j) {
                    if (accounts[j].owner == debtor) {
                        accounts[j].debit += amount;
                        addFlags &= ~uint8(1); // Clear bit 0 (addDebtor = false)
                    } else if (accounts[j].owner == creditor) {
                        // else if is safe here since debtor != creditor (self-transfers already skipped)
                        accounts[j].credit += amount;
                        addFlags &= ~uint8(2); // Clear bit 1 (addCreditor = false)
                    }
                }

                // Create new account entries only if not found in existing accounts
                if ((addFlags & 1) != 0) {
                    // Check bit 0 (addDebtor)
                    accounts[accountsLength] = DebitAndCredit(debtor, amount, 0);
                    accountsLength++;
                }
                if ((addFlags & 2) != 0) {
                    // Check bit 1 (addCreditor)
                    accounts[accountsLength] = DebitAndCredit(creditor, 0, amount);
                    accountsLength++;
                }
            }

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Performs batch transfers with selective reserved balance (rBalance) updates
     * @param debtors Array of addresses to debit tokens from
     * @param creditors Array of addresses to credit tokens to
     * @param amounts Array of amounts for each transfer
     * @param rBalanceFlags Bitmap indicating which accounts (by index in aggregated array) need rBalance updates
     *                      Pre-computed by computeRBalanceFlags() for integrity validation
     * @return bool True if all transfers successful
     *
     * PHASE 2 EXECUTION: Uses pre-computed rBalanceFlags for selective rBalance updates
     *
     * FLOW:
     * 1. Call consolidateTransfers() to aggregate N transfers into M unique accounts
     *    - Same aggregation algorithm as computeRBalanceFlags()
     *    - Account positions match rBalanceFlags bitmap indices
     * 2. For each aggregated account, calculate net debit/credit
     * 3. Update _balances directly (CEI pattern, before events)
     * 4. Selectively update _rBalances using rBalanceFlags bitmap
     *    - If ((rBalanceFlags >> accountIndex) & 1) == 1, update _rBalances
     *    - Otherwise, leave _rBalances unchanged
     * 5. Emit Transfer events for original transfers (not consolidated)
     *
     * RBALANCE UPDATES:
     * When account is debtor (debit > credit):
     *   - Loses tokens: _balances[account] -= net_debit
     *   - If flagged: _rBalances[account] += net_debit (restricted balance increases)
     *
     * When account is creditor (credit > debit):
     *   - Gains tokens: _balances[account] += net_credit
     *   - If flagged: _rBalances[account] -= net_credit (restricted balance decreases)
     *                  Capped at 0: if rBalance < net_credit, set to 0
     *
     * INTEGRITY PROPERTIES:
     * - Atomicity: All transfers succeed or all revert (no partial state)
     * - Determinism: Same inputs always produce same state changes
     * - Verification: rBalanceFlags can be pre-verified with computeRBalanceFlags()
     * - Access Control: Only VALIDATOR role can execute
     *
     * REENTRANCY PROTECTION:
     * This function does NOT use nonReentrant guard because:
     * - Only manipulates internal state (_balances and _rBalances)
     * - Makes no external calls to other contracts
     * - Follows Checks-Effects-Interactions (CEI) pattern
     * - No way for an attacker to re-enter before state is finalized
     *
     * This function optimizes batch transfers for investor pools that need selective rBalance updates.
     * Regular settlement operations should use batchTransfers() instead for better gas efficiency.
     *
     * Requirements:
     * - All arrays must have the same length
     * - Maximum 100 transfers per batch
     * - Sufficient balance in debtor accounts
     * - rBalanceFlags must be pre-computed using computeRBalanceFlags()
     *
     * NOTE: like batchTransfers, this is NOT gated by pause(). Pause freezes only user-facing flows;
     * validator settlement and rBalance accounting continue while paused, by design (see
     * docs/DESIGN_ASSUMPTIONS.md). An emergency accounting freeze requires rotating/disabling the role.
     *
     * BY DESIGN (audit M-03): rBalanceFlags is TRUSTED, not re-validated on-chain. The contract cannot
     * know which accounts are lenders without the off-chain loan-book, and recomputing on-chain would
     * defeat the bitmap's gas purpose. This adds no new trust surface — the validator is already
     * authorized (onlyValidator) to move arbitrary balances. computeRBalanceFlags() is the off-chain
     * verification tool (see the RBALANCEFLAGS VALIDATION SYSTEM docs below); correctness of the flags
     * is the validator's (trusted settlement engine's) responsibility, consistent with RBALANCE_MODEL R-2.
     */
    function rBatchTransfers(address[] calldata debtors, address[] calldata creditors, uint256[] calldata amounts, uint256 rBalanceFlags) external onlyValidator returns (bool) {
        // PHASE 2A: Consolidate transfers into aggregated accounts
        // Same aggregation as computeRBalanceFlags: N transfers → M unique accounts (M <= 2N)
        // Account order matches rBalanceFlags bitmap indices
        (DebitAndCredit[] memory accounts, uint256 accountsLength) = consolidateTransfers(debtors, creditors, amounts);

        // PHASE 2B: Update balances with Checks-Effects-Interactions pattern
        // Check: Verify sufficient balance BEFORE state change
        // Effects: Update _balances and _rBalances
        // Interactions: Emit events AFTER state is finalized
        for (uint256 i = 0; i < accountsLength;) {
            DebitAndCredit memory account = accounts[i];

            if (account.debit > account.credit) {
                // CASE 1: net DEBTOR (losing tokens). Subtraction is branch-safe and the balance decrement
                // is guarded by the InsufficientBalance revert — both unchecked (the revert is unaffected
                // by `unchecked`). amount is declared outside so the checked rBalance step below can use it.
                uint256 amount;
                unchecked {
                    amount = account.debit - account.credit; // safe: account.debit > account.credit
                    if (_balances[account.owner] < amount) {
                        revert InsufficientBalance();
                    }
                    _balances[account.owner] -= amount;
                }

                // CRITICAL: Selective rBalance update based on rBalanceFlags bitmap.
                // Bit position i in rBalanceFlags corresponds to accounts[i]; if set (1) this account's
                // rBalance increases. CHECKED arithmetic (NOT unchecked) so an rBalance increment can
                // never silently wrap (H-01 hardening) — _rBalances is not bounded by _totalSupply
                // (adjustrBalance can grow it), so a cumulative overflow must revert, not wrap.
                if (((rBalanceFlags >> i) & 1) == 1) {
                    // When losing tokens, restricted balance increases (restricted amount grows)
                    _rBalances[account.owner] += amount;
                }
            } else if (account.debit < account.credit) {
                // CASE 2: net CREDITOR (gaining tokens). Every op here is safe to be unchecked: the
                // subtraction is branch-safe, the balance credit is bounded by the checked _totalSupply,
                // and the rBalance decrement is guarded (floored at 0). No rBalance INCREMENT occurs here.
                unchecked {
                    uint256 amount = account.credit - account.debit; // safe: account.credit > account.debit
                    _balances[account.owner] += amount;

                    // Selective rBalance update (same bitmap lookup): a creditor's restricted balance
                    // decreases as it is used, floored at 0.
                    if (((rBalanceFlags >> i) & 1) == 1) {
                        uint256 rbalance = _rBalances[account.owner];
                        if (rbalance < amount) {
                            _rBalances[account.owner] = 0;
                        } else {
                            _rBalances[account.owner] -= amount;
                        }
                    }
                }
            }
            // Note: If debit == credit, account nets to zero (no balance changes)

            unchecked {
                ++i;
            } // Unchecked pre-increment for gas optimization
        }

        // PHASE 2C: Emit Transfer events after all state changes are complete (CEI pattern)
        // IMPORTANT: Emit ORIGINAL transfers (not consolidated), to match transfer semantics
        // Each debtors[i] → creditors[i] transfer gets one event, even if consolidated
        // This maintains compatibility with standard ERC20 event expectations
        for (uint256 i = 0; i < debtors.length;) {
            emit Transfer(debtors[i], creditors[i], amounts[i]);
            unchecked {
                ++i;
            } // Unchecked pre-increment for gas optimization
        }

        // SUCCESS: All state changes applied, all events emitted, transaction complete
        return true;
    }

    /**
     * RBALANCEFLAGS VALIDATION SYSTEM - COMPREHENSIVE ARCHITECTURAL DOCUMENTATION
     *
     * The rBalanceFlags validation approach is a two-phase system that separates pre-computation
     * (verification) from execution (application) for selective rBalance updates in batch transfers.
     *
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     * PHASE 1: VALIDATION (computeRBalanceFlags)
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     *
     * INPUT:  debtors[], creditors[], rAccounts
     *         - rAccounts: bitmap indexed by transfer number
     *           Bits 0..N-1:     Set if debtors[i] needs rBalance update
     *           Bits N..2N-1:    Set if creditors[i] needs rBalance update
     *
     * OUTPUT: rBalanceFlags bitmap indexed by account position
     *         - Bits 0..M-1:     Set if accounts[i] (in aggregated order) needs rBalance update
     *         - M <= 2N (typically M << 2N due to deduplication)
     *
     * MECHANISM:
     * 1. Iterate through N transfers in order
     * 2. For each transfer, check if debtor/creditor already exist in accounts array
     * 3. Use bit flags (addFlags) to track which accounts need to be added
     * 4. When creating new account at position j:
     *    - Check corresponding bit in rAccounts (bit i for debtor, bit i+N for creditor)
     *    - If set: mark bit j in rBalanceFlags output
     * 5. Result: rBalanceFlags bitmap where bit positions correspond to account positions
     *
     * PROPERTY: Pure function
     * - No side effects, no state changes
     * - Can be called off-chain to verify before submitting transaction
     * - Same inputs always produce identical output (deterministic)
     *
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     * PHASE 2: EXECUTION (rBatchTransfers)
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     *
     * INPUT:  debtors[], creditors[], amounts[], rBalanceFlags (pre-computed)
     *
     * OUTPUT: Updated _balances and _rBalances
     *
     * MECHANISM:
     * 1. Call consolidateTransfers() with same debtors/creditors/amounts
     *    - Produces M aggregated accounts (same order as Phase 1)
     * 2. For each account at position i:
     *    - Calculate net debit/credit
     *    - Update _balances accordingly
     *    - Check rBalanceFlags: if ((rBalanceFlags >> i) & 1) == 1:
     *      * Update _rBalances
     * 3. Emit Transfer events for original transfers
     * 4. Return success
     *
     * PROPERTY: State-changing transaction
     * - Only VALIDATOR role can execute
     * - No nonReentrant guard: makes no external calls (CEI), so there is no reentry vector
     * - Atomic: all updates succeed or all revert (no partial state)
     *
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     * CRITICAL INVARIANT: SEMANTIC EQUIVALENCE
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     *
     * INVARIANT: The account aggregation logic in computeRBalanceFlags() MUST be identical to
     *            consolidateTransfers() to ensure rBalanceFlags bitmap applies to correct accounts.
     *
     * Both functions:
     * ✓ Skip self-transfers: if (debtor != creditor)
     * ✓ Use identical bit flag patterns: 0x3 initial, &= ~1, &= ~2 for tracking
     * ✓ Check accounts in identical order: iterate j < accountsLength
     * ✓ Create accounts in identical order: accounts[accountsLength] = new account
     * ✓ Process transfers in identical order: for i = 0 to N
     *
     * CONSEQUENCE: If invariant is maintained, then:
     * account position i in Phase 1 computation
     *         =
     * account position i in Phase 2 execution
     *
     * If invariant is violated (code divergence):
     * - rBalanceFlags bits may be applied to wrong accounts
     * - Unintended accounts get rBalance updates
     * - Intended accounts miss rBalance updates
     * - Security risk and functional corruption
     *
     * MAINTENANCE: When modifying account aggregation logic, ALWAYS update BOTH functions
     * in lockstep. Add regression test to verify account order matches.
     *
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     * SECURITY PROPERTIES
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     *
     * 1. DETERMINISM
     *    - computeRBalanceFlags() is pure: same inputs → same output always
     *    - Off-chain verification possible and guaranteed accurate
     *    - No randomness or entropy involved
     *
     * 2. ACCESS CONTROL
     *    - Only VALIDATOR role can execute rBatchTransfers()
     *    - Only trusted validators can modify rBalances
     *    - Prevents unauthorized account manipulation
     *
     * 3. FIRST-DISCOVERY FLAG DETERMINATION
     *    - Account rBalance flag is set based on FIRST occurrence (earliest transfer) of that account
     *    - If alice appears as debtor in transfer 0 (marked for rBalance), alice's flag is set
     *    - If alice appears again in transfer 5 (NOT marked for rBalance), flag ALREADY SET, not re-evaluated
     *    - This ensures deterministic, order-dependent (but not arbitrary) flag assignment
     *
     * 4. REENTRANCY PROTECTION
     *    - No nonReentrant modifier: the function makes no external calls, so reentrancy is impossible
     *    - All state changes precede the Transfer events (CEI pattern); no callbacks to untrusted code
     *    - (Add nonReentrant if a future change introduces an external call)
     *
     * 5. INTEGRITY VERIFICATION
     *    - Caller can independently verify rBalanceFlags before submission
     *    - Off-chain computation can detect mismatch early
     *    - Prevents accidental wrong-flag submission
     *
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     * THREAT ANALYSIS
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     *
     * THREAT 1: Incorrect rBalanceFlags Provided
     * Attack:   Attacker provides flags that mark wrong accounts for rBalance update
     * Example:  rBalanceFlags = 0xFF (all bits set) instead of computed value
     * Impact:   Unintended rBalance updates, incorrect investor pool state
     * Defenses:
     *   - Off-chain verification: computeRBalanceFlags() can be called to check
     *   - Access control: Only VALIDATOR role allowed, must be trusted
     *   - Event monitoring: Observers can check Transfer events match expected flags
     * Risk:     Medium (mitigated by access control, but depends on validator trustworthiness)
     *
     * THREAT 2: Logic Divergence
     * Attack:   Code maintainer accidentally changes one function without other
     * Example:  consolidateTransfers() changes self-transfer handling, computeRBalanceFlags() doesn't
     * Impact:   Account position mismatch, flags applied to wrong accounts
     * Defenses:
     *   - Code review: Both functions side-by-side during modifications
     *   - Testing: Regression test verifies account order matches
     *   - Documentation: Comments link both functions and explain invariant
     * Risk:     Low (caught by testing and code review)
     *
     * THREAT 3: Reentrancy During Execution
     * Attack:   During _balances update, attacker attempts to call back into rBatchTransfers()
     * Impact:   Double spending, corrupted state, fund loss
     * Defenses:
     *   - No external calls: rBatchTransfers only touches internal _balances/_rBalances, so there is
     *     no callback into untrusted code and therefore no reentry vector (no nonReentrant needed)
     *   - CEI pattern: all state changes precede the Transfer events
     *   - Direct storage access: no fallback to external contract functions
     * Risk:     Low (no external calls + CEI pattern)
     *
     * THREAT 4: Insufficient Balance Not Caught
     * Attack:   Provide transfers that exceed available balances
     * Impact:   Partial state corruption, incorrect balances
     * Defenses:
     *   - Explicit check: if (debtorBalance < amount) revert InsufficientBalance()
     *   - Before state: Check happens BEFORE _balances update
     *   - Atomic: All transfers or none (no partial)
     * Risk:     Low (explicit check before state change)
     *
     * THREAT 5: rBalance Over-increment/Under-decrement
     * Attack:   rBalanceFlags cause rBalance to be updated incorrectly
     * Example:  rBalance += debit, but account was actually creditor (credit > debit)
     * Impact:   Restricted balance tracking corruption
     * Defenses:
     *   - Bit check is correct: if ((rBalanceFlags >> i) & 1) == 1
     *   - Offset is correct: debtor bit vs creditor bit i+N
     *   - Capping: rBalance -= amount capped at 0 (no negative)
     * Risk:     Very Low (conditional logic is straightforward)
     *
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     * PERFORMANCE ANALYSIS
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     *
     * computeRBalanceFlags():
     *   - Time Complexity: O(N²) in worst case
     *     Outer loop: N transfers
     *     Inner loop: up to 2N accounts checked per transfer
     *   - Space Complexity: O(N) for accounts array
     *   - Gas Cost: ~500k-600k for 100 transfers (depends on uniqueness ratio)
     *   - Cost Model: Paid by caller, off-chain execution possible
     *   - Optimization: Loop breaks early if both debtor/creditor found (addFlags != 0)
     *
     * rBatchTransfers():
     *   - Time Complexity: O(N²) for consolidation + O(M) for balance updates
     *     M <= 2N unique accounts
     *   - Space Complexity: O(M) for accounts array
     *   - Gas Cost: ~700k-900k for 100 transfers (on-chain)
     *   - Cost Model: Paid by validator in transaction gas
     *   - Benefit: O(1) per-account rBalance lookup via bitmap (vs O(N) search)
     *
     * Trade-off: Pay computation cost once (Phase 1) to get O(1) lookups during execution (Phase 2)
     *
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     * VALIDATION CHECKLIST
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     *
     * Before calling rBatchTransfers(), verify:
     *   ✓ Arrays (debtors, creditors, amounts) have equal length
     *   ✓ Length <= 100 (MAX_BATCH_SIZE)
     *   ✓ No duplicate (address, address) pairs in (debtors[i], creditors[i])
     *   ✓ All amounts > 0 (no zero transfers)
     *   ✓ rBalanceFlags = computeRBalanceFlags(debtors, creditors, rAccounts)
     *   ✓ All debtors have sufficient balances
     *   ✓ Caller is VALIDATOR role
     *   ✓ No reentrancy protection active
     *
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     * END OF RBALANCEFLAGS VALIDATION SYSTEM DOCUMENTATION
     * ═══════════════════════════════════════════════════════════════════════════════════════════
     */

    /**
     * @dev Adjusts the reserved balance (rBalance) for an account
     * @param account The account address to adjust rBalance for
     * @param ts Timestamp identifier for this adjustment (must be unique per account)
     * @param amounti The invested amount (original investment)
     * @param amountr The received amount (after investment returns/losses)
     *
     * This function allows revenue admin to adjust rBalance based on investment performance.
     * If amountr > amounti, rBalance increases (profit).
     * If amountr < amounti, rBalance decreases (loss).
     *
     * Requirements:
     * - No existing adjustment for the same account and timestamp
     * - Only callable by revenue admin
     * - Should be called as soon as invoice is generated for the invoicing cycle
     * - Reserved balance need to be adjusted before the invoice is paid otherwise we are at risk of creating non existing yield.
     *
     * Known issue:
     * - if the invoice is paid before the adjustment is applied, the adjustment will be wrong.
     * - If the invoice is already paid, no adjustement is required unless pending reserved balance exists.
     */
    function adjustrBalance(address account, uint256 ts, uint256 amounti, uint256 amountr) external onlyRevenueAdmin {
        if (account == address(0)) revert ZeroAddress();
        if (_rBalanceAdjustments[account][ts][0] != 0) {
            revert RBalanceAdjustmentAlreadyApplied();
        }
        if (amounti == 0) revert ZeroAmount();
        if (ts > block.timestamp) revert FutureTimestampNotAllowed();
        // Prevent overflow in return multiplier calculation
        if (amounti > type(uint256).max / MAX_RETURN_MULTIPLIER) {
            revert AmountTooLarge();
        }
        if (amountr > amounti * MAX_RETURN_MULTIPLIER) {
            revert MaxReturnMultiplierExceeded();
        }
        _rBalanceAdjustments[account][ts] = [amounti, amountr];

        uint256 difference;
        if (amountr > amounti) {
            unchecked {
                difference = amountr - amounti; // safe: amountr > amounti in this branch
            }
            // Increment stays CHECKED (H-01): an rBalance increment must revert on overflow, never wrap.
            _rBalances[account] += difference;
        } else if (amountr < amounti) {
            // Loss adjustment: rBalance DECREASES. No increment here, so the whole branch is unchecked —
            // the subtraction is branch-safe (amounti > amountr) and the rBalance -= is guarded by the
            // RBalanceAdjustmentTooLarge check (the revert is unaffected by `unchecked`).
            unchecked {
                difference = amounti - amountr;
                uint256 currentRBalance = _rBalances[account];
                if (currentRBalance < difference) {
                    // Should not happen otherwise we can't cancel with cancelrBalanceAdjustment.
                    // It would mean the investment vault received more assets than the original investment
                    // — a profit not backed by assets, which should not be possible.
                    revert RBalanceAdjustmentTooLarge();
                }
                _rBalances[account] -= difference; // safe: currentRBalance >= difference
            }
        }
        emit RBalanceAdjusted(account, amounti, amountr);
    }

    /**
     * @dev Cancels a previously applied rBalance adjustment
     * @param account The account address to cancel adjustment for
     * @param ts The timestamp identifier of the adjustment to cancel
     *
     * This function reverses the effects of a previous adjustrBalance call
     * by applying the opposite adjustment to restore the original rBalance.
     *
     * Requirements:
     * - An adjustment must exist for the given account and timestamp
     * - Only callable by revenue admin
     */
    function cancelrBalanceAdjustment(address account, uint256 ts) external onlyRevenueAdmin {
        if (account == address(0)) revert ZeroAddress();
        if (_rBalanceAdjustments[account][ts][0] == 0) {
            revert NoRBalanceAdjustmentFound();
        }

        uint256[2] memory adjustment = _rBalanceAdjustments[account][ts];
        uint256 amounti = adjustment[0];
        uint256 amountr = adjustment[1];

        if (amountr > amounti) {
            // Reversing a profit adjustment: rBalance DECREASES. No increment here, so the whole branch is
            // unchecked — the subtraction is branch-safe (amountr > amounti) and the rBalance -= is guarded
            // by the RBalanceAdjustmentTooLarge check (the revert is unaffected by `unchecked`).
            unchecked {
                uint256 difference = amountr - amounti;
                uint256 currentRBalance = _rBalances[account];
                if (currentRBalance < difference) {
                    // Should not happen otherwise we can't cancel with the adjustment.
                    revert RBalanceAdjustmentTooLarge();
                }
                _rBalances[account] -= difference; // safe: currentRBalance >= difference
            }
        } else if (amountr < amounti) {
            uint256 difference;
            unchecked {
                difference = amounti - amountr; // safe: amounti > amountr in this branch
            }
            // Increment stays CHECKED (H-01): an rBalance increment must revert on overflow, never wrap.
            _rBalances[account] += difference;
        }

        delete _rBalanceAdjustments[account][ts];
        emit RBalanceAdjustmentCancelled(account, ts);
    }
}
