// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title IERC7887
 * @dev Interface for ERC7887 "Asynchronous Tokenized Vault Cancelation Extension"
 *      Extends ERC7540 with asynchronous cancelation capabilities
 *      https://eips.ethereum.org/EIPS/eip-7887
 */
interface IERC7887DepositCancelation {
    /**
     * @dev Emitted when a deposit cancelation request is submitted
     * controller - address that controls the cancelation request
     * requestId - unique identifier for the cancelation request
     * sender - address that called cancelDepositRequest
     */
    event CancelDepositRequest(address indexed controller, uint256 indexed requestId, address sender);

    /**
     * @dev Emitted when a deposit cancelation is claimed
     * controller - address that controlled the cancelation request
     * receiver - address that received the assets
     * requestId - unique identifier for the cancelation request
     * sender - address that called claimCancelDepositRequest
     * assets - amount of assets claimed
     */
    event CancelDepositClaim(address indexed controller, address indexed receiver, uint256 indexed requestId, address sender, uint256 assets);

    /**
     * @dev Submits a request to cancel a pending deposit request
     * Transitions the deposit request assets from pending state into pending cancelation state
     *
     * - MUST revert unless `msg.sender` is either equal to `controller` or an operator approved by `controller`
     * - MUST block new deposit requests for this controller while cancelation is pending
     * - MUST emit `CancelDepositRequest` event
     * - Can only cancel deposits in Pending state, not Claimable state
     *
     * @param requestId The requestId from the original deposit request (identifies which deposit to cancel)
     * @param controller Address that made the original deposit request
     */
    function cancelDepositRequest(uint256 requestId, address controller) external;

    /**
     * @dev Whether the given requestId and controller have a pending deposit cancelation request
     *
     * - Returns true if a deposit cancelation is in Pending state for this controller
     * - MUST NOT show any variations depending on the caller
     * - MUST NOT revert unless due to integer overflow
     *
     * @param requestId Cancelation request identifier
     * @param controller Address that made the original deposit request
     * @return isPending Whether a pending deposit cancelation exists for this controller
     */
    function pendingCancelDepositRequest(uint256 requestId, address controller) external view returns (bool isPending);

    /**
     * @dev Returns the amount of assets in claimable cancelation state
     *
     * - MUST NOT include any assets in Pending state
     * - MUST NOT show any variations depending on the caller
     * - MUST NOT revert unless due to integer overflow
     *
     * @param requestId Cancelation request identifier
     * @param controller Address that made the original deposit request
     * @return assets Amount of assets ready to claim
     */
    function claimableCancelDepositRequest(uint256 requestId, address controller) external view returns (uint256 assets);

    /**
     * @dev Claims assets from a claimable deposit cancelation request
     *
     * - MUST revert unless `msg.sender` is either equal to `controller` or an operator approved by `controller`
     * - MUST transition request from Claimable to Claimed state
     * - MUST transfer assets to `receiver`
     * - MUST emit `CancelDepositClaim` event
     * - Cannot be called unless request is in Claimable state
     *
     * @param requestId Cancelation request identifier
     * @param receiver Address to receive the claimed assets
     * @param controller Address that made the original deposit request
     */
    function claimCancelDepositRequest(uint256 requestId, address receiver, address controller) external;
}

interface IERC7887RedeemCancelation {
    /**
     * @dev Emitted when a redeem cancelation request is submitted
     * controller - address that controls the cancelation request
     * requestId - unique identifier for the cancelation request
     * sender - address that called cancelRedeemRequest
     */
    event CancelRedeemRequest(address indexed controller, uint256 indexed requestId, address sender);

    /**
     * @dev Emitted when a redeem cancelation is claimed
     * controller - address that controlled the cancelation request
     * receiver - address that received the shares
     * requestId - unique identifier for the cancelation request
     * sender - address that called claimCancelRedeemRequest
     * shares - amount of shares claimed
     */
    event CancelRedeemClaim(address indexed controller, address indexed receiver, uint256 indexed requestId, address sender, uint256 shares);

    /**
     * @dev Submits a request to cancel a pending redeem request
     * Transitions the redeem request shares from pending state into pending cancelation state
     *
     * - MUST revert unless `msg.sender` is either equal to `controller` or an operator approved by `controller`
     * - MUST block new redeem requests for this controller while cancelation is pending
     * - MUST emit `CancelRedeemRequest` event
     * - Can only cancel redeems in Pending state, not Claimable state
     *
     * @param requestId The requestId from the original redeem request (identifies which redeem to cancel)
     * @param controller Address that made the original redeem request
     */
    function cancelRedeemRequest(uint256 requestId, address controller) external;

    /**
     * @dev Whether the given requestId and controller have a pending redeem cancelation request
     *
     * - Returns true if a redeem cancelation is in Pending state for this controller
     * - MUST NOT show any variations depending on the caller
     * - MUST NOT revert unless due to integer overflow
     *
     * @param requestId Cancelation request identifier
     * @param controller Address that made the original redeem request
     * @return isPending Whether a pending redeem cancelation exists for this controller
     */
    function pendingCancelRedeemRequest(uint256 requestId, address controller) external view returns (bool isPending);

    /**
     * @dev Returns the amount of shares in claimable cancelation state
     *
     * - MUST NOT include any shares in Pending state
     * - MUST NOT show any variations depending on the caller
     * - MUST NOT revert unless due to integer overflow
     *
     * @param requestId Cancelation request identifier
     * @param controller Address that made the original redeem request
     * @return shares Amount of shares ready to claim
     */
    function claimableCancelRedeemRequest(uint256 requestId, address controller) external view returns (uint256 shares);

    /**
     * @dev Claims shares from a claimable redeem cancelation request
     *
     * - MUST revert unless `msg.sender` is either equal to `controller` or an operator approved by `controller`
     * - MUST transition request from Claimable to Claimed state
     * - MUST transfer shares to `receiver`
     * - MUST emit `CancelRedeemClaim` event
     * - Cannot be called unless request is in Claimable state
     *
     * @param requestId Cancelation request identifier
     * @param receiver Address to receive the claimed shares
     * @param controller Address that made (controls) the original redeem request
     */
    function claimCancelRedeemRequest(uint256 requestId, address receiver, address controller) external;
}

/**
 * @title IERC7887
 * @dev Full ERC7887 interface combining deposit and redeem cancelation
 */
interface IERC7887 is IERC7887DepositCancelation, IERC7887RedeemCancelation {}
