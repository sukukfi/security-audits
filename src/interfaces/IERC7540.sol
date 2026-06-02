pragma solidity ^0.8.30;

interface IERC7540Operator {
    /**
     * @dev The `controller` has set the `approved` status to an `operator`.
     *
     * - MUST be logged when the operator status is set.
     * - MAY be logged when the operator status is set to the same status it was before the current call.
     */
    event OperatorSet(address indexed controller, address indexed operator, bool approved);

    /**
     * @dev Grants or revokes permissions for `operator` to manage Requests on behalf of the `msg.sender`.
     *
     * - MUST set the operator status to the `approved` value.
     * - MUST log the `OperatorSet` event.
     * - MUST return True.
     */
    function setOperator(address operator, bool approved) external returns (bool);

    /**
     * @dev Returns `true` if the `operator` is approved as an operator for an `controller`.
     */
    function isOperator(address controller, address operator) external view returns (bool status);
}

interface IERC7540Deposit {
    /**
     * @dev `owner` has locked `assets` in the Vault to Request a deposit with request ID `requestId`. `controller` controls this Request. `sender` is the caller of the `requestDeposit` which may not be equal to the `owner`.
     *
     * - MUST be emitted when a deposit Request is submitted using the requestDeposit method.
     */
    event DepositRequest(address indexed controller, address indexed owner, uint256 indexed requestId, address sender, uint256 assets);

    /**
     * @dev Transfers `assets` from `owner` into the Vault and submits a Request for asynchronous `deposit`.
     *
     * - MUST support ERC-20 `approve` / `transferFrom` on `asset` as a deposit Request flow.
     * - `owner` MUST equal `msg.sender` unless the `owner` has approved the `msg.sender` as an operator.
     * - MUST revert if all of `assets` cannot be requested for `deposit`/`mint`
     * - NOTE: most implementations will require pre-approval of the Vault with the Vault’s underlying `asset` token.
     * - MUST emit the `DepositRequest` event.
     */
    function requestDeposit(uint256 assets, address controller, address owner) external returns (uint256 requestId);

    /**
     * @dev The amount of requested `assets` in Pending state for the `controller` with the given `requestId` to `deposit` or `mint`.
     *
     * - MUST NOT include any `assets` in Claimable state for deposit or mint.
     * - MUST NOT show any variations depending on the caller.
     * - MUST NOT revert unless due to integer overflow caused by an unreasonably large input.
     */
    function pendingDepositRequest(uint256 requestId, address controller) external view returns (uint256 pendingAssets);

    /**
     * @dev The amount of requested `assets` in Claimable state for the `controller` with the given `requestId` to `deposit` or `mint`.
     *
     * - MUST NOT include any `assets` in Pending state for `deposit` or `mint`.
     * - MUST NOT show any variations depending on the caller.
     * - MUST NOT revert unless due to integer overflow caused by an unreasonably large input.
     */
    function claimableDepositRequest(uint256 requestId, address controller) external view returns (uint256 claimableAssets);

    /**
     * @dev Mints shares Vault shares to `receiver` by claiming the Request of the `controller`.
     *
     * - MUST revert unless `msg.sender` is either equal to `controller` or an operator approved by `controller`.
     * - MUST emit the `Deposit` event.
     * - MUST revert if all of assets cannot be deposited (due to deposit limit being reached, slippage, the user not
     *   approving enough underlying tokens to the Vault contract, etc).
     */
    function deposit(uint256 assets, address receiver, address controller) external returns (uint256 shares);

    /**
     * @dev Mints exactly shares Vault shares to `receiver` by claiming the Request of the `controller`.
     *
     * - MUST revert unless `msg.sender` is either equal to `controller` or an operator approved by `controller`.
     * - MUST emit the Deposit event.
     * - MUST revert if all of shares cannot be minted (due to deposit limit being reached, slippage, the user not
     *   approving enough underlying tokens to the Vault contract, etc).
     */
    function mint(uint256 shares, address receiver, address controller) external returns (uint256 assets);
}

interface IERC7540Redeem is IERC7540Operator {
    /**
     * @dev `sender` has locked `shares`, owned by `owner`, in the Vault to Request a redemption. `controller` controls this Request, but is not necessarily the `owner`.
     *
     * - MUST be emitted when a redemption Request is submitted using the `requestRedeem` method.
     */
    event RedeemRequest(address indexed controller, address indexed owner, uint256 indexed requestId, address sender, uint256 shares);

    /**
     * @dev Assumes control of `shares` from `owner` and submits a Request for asynchronous `redeem`.
     *
     * - MUST remove `shares` from the custody of `owner` upon `requestRedeem` and burned by the time the request is Claimed.
     *   where msg.sender has ERC-20 approval over the shares of owner.
     * - MUST revert if all of shares cannot be requested for `redeem` / `withdraw`
     * - MUST emit the `RedeemRequest` event.
     *
     */
    function requestRedeem(uint256 shares, address controller, address owner) external returns (uint256 requestId);

    /**
     * @dev The amount of requested `shares` in Pending state for the `controller` with the given `requestId` to `redeem` or `withdraw`.
     *
     * - MUST NOT include any `shares` in Claimable state for `redeem` or `withdraw`.
     * - MUST NOT show any variations depending on the caller.
     * - MUST NOT revert unless due to integer overflow caused by an unreasonably large input.
     */
    function pendingRedeemRequest(uint256 requestId, address controller) external view returns (uint256 pendingShares);

    /**
     * @dev The amount of requested `shares` in Claimable state for the `controller` with the given `requestId` to `redeem` or `withdraw`.
     *
     * - MUST NOT include any `shares` in Pending state for `redeem` or `withdraw`.
     * - MUST NOT show any variations depending on the caller.
     * - MUST NOT revert unless due to integer overflow caused by an unreasonably large input.
     */
    function claimableRedeemRequest(uint256 requestId, address controller) external view returns (uint256 claimableShares);
}

/**
 * @title  IERC7540
 * @dev    Interface of the ERC7540 "Asynchronous Tokenized Vault Standard", as defined in
 *         https://eips.ethereum.org/EIPS/eip-7540
 */
interface IERC7540 is IERC7540Operator, IERC7540Deposit, IERC7540Redeem {}
