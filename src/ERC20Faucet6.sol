// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/**
 * @title ERC20Faucet6
 * @dev Test token faucet with 6 decimals (USDC/USDT-like) and permit support.
 */
contract ERC20Faucet6 is ERC20, ERC20Permit {
    uint8 private constant DECIMALS = 6;
    uint256 public constant FAUCET_AMOUNT = 10_000 * 10 ** DECIMALS;
    uint256 public constant MAX_FAUCET_AMOUNT = 100_000 * 10 ** DECIMALS;
    uint256 public constant COOLDOWN_TIME = 1 hours;

    mapping(address => uint256) public lastRequestTime;

    /**
     * @param name_ Token name (e.g., "USD Coin")
     * @param symbol_ Token symbol (e.g., "USDC")
     * @param initialSupply Initial supply (6-decimal units) minted to deployer
     */
    constructor(string memory name_, string memory symbol_, uint256 initialSupply) ERC20(name_, symbol_) ERC20Permit(name_) {
        _mint(msg.sender, initialSupply);
    }

    function decimals() public pure override returns (uint8) {
        return DECIMALS;
    }

    // Faucet helpers
    function faucet() external {
        _faucetFor(msg.sender, FAUCET_AMOUNT);
    }

    function faucetAmount(uint256 amount) external {
        _faucetFor(msg.sender, amount);
    }

    function faucetFor(address receiver) external {
        _faucetFor(receiver, FAUCET_AMOUNT);
    }

    function faucetAmountFor(address receiver, uint256 amount) external {
        _faucetFor(receiver, amount);
    }

    function _faucetFor(address receiver, uint256 amount) internal {
        require(block.timestamp > lastRequestTime[receiver] + COOLDOWN_TIME, "COOLDOWN");
        require(amount <= MAX_FAUCET_AMOUNT, "MAX_EXCEEDED");
        _mint(receiver, amount);
        lastRequestTime[receiver] = block.timestamp;
    }
}
