# WERC7575 Multi-Asset Vault System

Implementation of ERC7575 multi-asset vault standard with upgradeable contracts for institutional tokenized assets.

## Setup

### Prerequisites
- [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/sukukfi/security-audits.git
cd security-audits
```

2. Install dependencies:
```bash
forge install OpenZeppelin/openzeppelin-contracts@v5.6.1
forge install OpenZeppelin/openzeppelin-contracts-upgradeable@v5.6.1
forge install foundry-rs/forge-std@v1.10.0
```

3. Build the project:
```bash
forge build
```

## Project Structure

- `src/` - Smart contract source files
  - `interfaces/` - Interface definitions
  - `ERC7575VaultUpgradeable.sol` - Async upgradeable vault (investment layer)
  - `ShareTokenUpgradeable.sol` - Multi-asset share token (investment layer)
  - `WERC7575Vault.sol` - Non-upgradeable settlement vault (settlement layer)
  - `WERC7575ShareToken.sol` - Settlement layer share token
  - Supporting contracts and utilities
- `test/` - Test files

## Documentation

Code4rena audit: 'Code4rena x SukukFi audit report 2025-11.pdf'

## Key Features

- **ERC-7575 Compliant**: Multi-asset vault system with unified share token
- **ERC-7540 Async Operations**: Request → Fulfill → Claim pattern for deposits and redemptions
- **ERC-7887 Cancelations**: Users can cancel pending requests
- **UUPS Upgradeable**: Investment layer supports safe upgrades via proxy pattern
- **KYC Enforcement**: Regulatory compliance for institutional use
- **Permit-Based Transfers**: EIP-712 signature-based approvals
- **Batch Settlement**: Gas-efficient batch operations with netting

## Architecture

Two-layer system:

- **Settlement Layer** (Non-upgradeable): WERC7575Vault + WERC7575ShareToken - Real-time carrier settlements
- **Investment Layer** (Upgradeable): ERC7575VaultUpgradeable + ShareTokenUpgradeable - Capital deployment and yield generation


## Standards Implemented

- ERC-7575: Multi-Asset ERC-4626 Vaults
- ERC-7540: Asynchronous Tokenized Vault Standard
- ERC-7887: Asynchronous Tokenized Vault Cancelation
- ERC-4626: Tokenized Vault Standard
- EIP-712: Typed structured data hashing and signing
- EIP-2612: Permit extension for ERC-20

## Security Notes

- See [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) for documented design decisions and security considerations
- Non-standard ERC-20 behavior: transfers require validator-issued permits
- Not compatible with standard wallets or DEX integrations (intentional for compliance)
- Comprehensive reentrancy protection on all state-changing functions
- ERC-7201 namespaced storage for safe upgrades

