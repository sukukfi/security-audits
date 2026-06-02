// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/**
 * @title ERC20Faucet
 * @dev A test token faucet that allows users to request tokens with a cooldown period
 * Used for testing and development purposes. Includes permit functionality for gasless approvals.
 */
contract ERC20Faucet is ERC20, ERC20Permit {
    uint256 public constant FAUCET_AMOUNT = 10000 * 10 ** 18; // Amount of tokens dispensed by the faucet
    uint256 public constant MAX_FAUCET_AMOUNT = 100000 * 10 ** 18; // Maximum amount of tokens dispensed by the faucet
    mapping(address => uint256) public lastRequestTime;
    uint256 public constant COOLDOWN_TIME = 1 hours; // Cooldown period

    /**
     * @dev Constructor that initializes the token with custom name and symbol
     * @param name_ The name of the token (e.g., "USD Tether")
     * @param symbol_ The symbol of the token (e.g., "USDT")
     * @param initialSupply The initial token supply to mint to deployer
     *
     * Mints initial supply to the deployer and enables permit functionality for gasless approvals.
     */
    constructor(string memory name_, string memory symbol_, uint256 initialSupply) ERC20(name_, symbol_) ERC20Permit(name_) {
        _mint(msg.sender, initialSupply);
    }

    /**
     * @dev Request standard faucet amount for the caller
     */
    function faucet() public {
        _faucetFor(msg.sender, FAUCET_AMOUNT);
    }

    /**
     * @dev Request specific amount of tokens for the caller
     * @param amount Amount of tokens to request
     */
    function faucetAmount(uint256 amount) public {
        _faucetFor(msg.sender, amount);
    }

    /**
     * @dev Request standard faucet amount for a specific receiver
     * @param receiver Address to receive the tokens
     */
    function faucetFor(address receiver) public {
        _faucetFor(receiver, FAUCET_AMOUNT);
    }

    /**
     * @dev Request specific amount of tokens for a specific receiver
     * @param receiver Address to receive the tokens
     * @param amount Amount of tokens to request
     */
    function faucetAmountFor(address receiver, uint256 amount) public {
        _faucetFor(receiver, amount);
    }

    /**
     * @dev Internal function to handle faucet requests with cooldown and limit checks
     * @param receiver Address to receive the tokens
     * @param amount Amount of tokens to mint
     */
    function _faucetFor(address receiver, uint256 amount) internal {
        require(block.timestamp > lastRequestTime[receiver] + COOLDOWN_TIME, "You must wait for the cooldown period to end.");
        require(amount <= MAX_FAUCET_AMOUNT, "Amount exceeds maximum faucet amount.");
        _mint(receiver, amount);
        lastRequestTime[receiver] = block.timestamp;
    }
}
