# Known Issues, Exclusions & Protocol Behavior

This document describes the **intentional design decisions**, **known limitations**, and **non-standard behaviors** of the WERC7575 multi-asset vault system. These are documented choices made for an institutional, regulated, tokenized-asset use case.

**These are NOT bugs.** They are deliberate behaviors. The items in [Exclusions](#exclusions--not-considered-vulnerabilities) are explicitly out of scope as security vulnerabilities.

---

## ⚠️ Protocol Behavior Warnings

Integrators and users must understand the following before interacting with the protocol. Treating these tokens like standard ERC-20s will result in failed transactions or unexpected behavior.

### Non-standard ERC-20

- **Transfers require a validator-issued permit (self-allowance).** `transfer()` consumes the caller's *self*-allowance (`_spendAllowance(msg.sender, msg.sender, value)`), which only the validator can grant. A plain `transfer()` with no prior permit reverts.
- **`transferFrom()` requires dual authorization** — both the owner's self-allowance and the caller's delegated allowance.
- **`approve()` blocks self-approval.** `approve(msg.sender, ...)` reverts with `ERC20InvalidSpender`; the permit flow must go through the validator.
- **KYC is mandatory.** Every recipient must be KYC-verified or the transfer reverts with `KycRequired`. The validator controls KYC status.

Because of the above, **standard wallets and tooling will fail**:

```solidity
// What a standard wallet does — REVERTS (no self-allowance):
token.transfer(recipient, amount);

// What is actually required:
validator.permit(user, user, amount, signature); // validator grants self-allowance
token.transfer(recipient, amount);               // now succeeds
```

Affected: MetaMask "Send", Trust Wallet, Ledger Live, and any UI calling `transfer()` directly. The protocol requires a custom interface that performs the permit flow.

### Not compatible with external DeFi

- **DEXs** (Uniswap, Curve, Balancer) will fail — they cannot obtain the required permit signatures.
- **Lending protocols** (Aave, Compound, Morpho) will fail — the token cannot be used as collateral.

This is intentional; the protocol does not claim or support these integrations.

### Other behaviors to be aware of

- **All shares are 18 decimals**, regardless of the underlying asset's decimals (e.g. USDC = 6, DAI = 18).
- **Asynchronous operations (ERC-7540).** Deposits and redemptions follow a request → fulfill → claim pattern. The Investment Manager controls fulfillment timing, and **no on-chain deadlines are enforced**.
- **Pending requests can be cancelled.** The controller (or an approved operator) may cancel a *pending* deposit/redeem request and reclaim assets/shares. Claimable (already fulfilled) requests cannot be cancelled.
- **Up to 1 wei rounding** is possible on conversions, as permitted by integer division and ERC-4626.

---

## Exclusions — Not Considered Vulnerabilities

The following are intentional and are **not** treated as security vulnerabilities.

### 1. Centralized access control

The system has trusted roles that are expected to act in good faith:

- **Owner** — registers/unregisters vaults, sets the Investment Manager (propagates to all vaults), upgrades contracts via UUPS, pauses/unpauses, configures investment parameters.
- **Investment Manager** — controls fulfillment timing (no deadlines), decides when to fulfill deposit/redeem requests, invests idle assets into external vaults, withdraws from positions, runs batch fulfillment.
- **Validator** — controls KYC status and issues permits.
- **Revenue Admin** — records yield/loss via rBalance adjustments.

Built for institutional tokenized assets with regulatory requirements; clear administrative control is required for compliance. Admin actions are assumed intentional and previewed — reckless-admin-mistake scenarios are out of scope.

### 2. Non-standard ERC-20 behavior

The self-allowance transfer gate, dual-allowance `transferFrom`, self-approval block, and mandatory KYC (all described in [Protocol Behavior Warnings](#-protocol-behavior-warnings)) are deliberate compliance controls. No assets are at risk; these are the intended functions.

### 3. External protocol incompatibility

DEX, lending, and standard-wallet incompatibility (see warnings above) are by design. The protocol is intended for institutional use through a custom interface.

### 4. Asynchronous operations & timing

- **No fulfillment deadlines.** The Investment Manager may delay fulfillments; this is the ERC-7540 async design for professional fund management. Pending assets are held securely.
- **Reserved assets are not invested.** Pending/claimable assets sit idle as a liquidity safety buffer — the protocol only commits yield/shares on capital that is actually deployed. This protects APY rather than diluting it.
- **Request cancellation** via:
  - `cancelDepositRequest(uint256 requestId, address controller)` — returns assets to the user.
  - `cancelRedeemRequest(uint256 requestId, address controller)` — returns shares to the user.

  Only the controller or their approved operator can cancel, and only *pending* (not claimable) requests. This is a deliberate user-protection feature beyond ERC-7540, which excludes cancellation.

### 5. Unilateral upgrades

The Owner can upgrade contracts (UUPS) without timelock, governance, or a user exit window. This is the institutional admin model and enables rapid bug fixes and compliance updates.

> Storage corruption or improper upgrade patterns are genuine bugs — see [What WOULD be a vulnerability](#what-would-be-a-vulnerability).

### 6. Decimal normalization

- **All shares are 18 decimals** regardless of underlying decimals. This simplifies multi-asset accounting and aggregation across assets with different decimals. Not required by ERC-7575, but an intentional design choice.
- **Rounding ≤ 1 wei** from integer division is expected and within ERC-4626 tolerance, and is not exploitable for profit.

### 7. Architecture limitations

- **Single vault per asset.** Only one vault may be registered per asset (e.g. one USDC vault), aligned with ERC-7575.
- **Batch size limits.** `MAX_BATCH_SIZE = 100` for settlement batch transfers in `WERC7575ShareToken`; a separate `MAX_BATCH_SIZE = 1000` for investment-vault batch operations in `ERC7575VaultUpgradeable`. Conservative gas-limit protection.
- **Self-transfers skipped.** Batch operations skip `debtor == creditor` transfers as a no-op gas optimization; accounting is unaffected.
- **Batch netting — intra-batch "overdraft" allowed.** Individual transfers within a batch may exceed a sender's balance as long as the **final net result** is valid. Settlement systems process net effects, not sequential individual transfers; final balances are always validated, and the sum of all balances is preserved.

  ```solidity
  // User A balance: 100
  // 1. A → B: 80
  // 2. A → C: 60   (would fail individually — A has 20 left)
  // 3. B → A: 50
  // 4. C → A: 40
  // Net for A: (80 + 60) - (50 + 40) = 50  →  final balance 50 ✓
  ```

### 8. Batch transfer operations & rBalance management

Two batch transfer functions, both `onlyValidator`:

```solidity
// Standard settlement transfers — updates only _balances:
function batchTransfers(address[] calldata debtors, address[] calldata creditors,
    uint256[] calldata amounts) external onlyValidator returns (bool);

// Investment transfers — updates _balances and selectively _rBalances:
function rBatchTransfers(address[] calldata debtors, address[] calldata creditors,
    uint256[] calldata amounts, uint256 rBalanceFlags) external onlyValidator returns (bool);
```

- `rBatchTransfers` gates rBalance updates with a packed `rBalanceFlags` bitmask (one bit per aggregated account), pre-computed off-chain via `computeRBalanceFlags(debtors, creditors, debtorsRBalanceFlags, creditorsRBalanceFlags)`, which packs the per-account `bool[]` arrays into the single `rBalanceFlags` value.
- **rBalance silent truncation.** When a credit operation would reduce an account's rBalance below zero, it is truncated to `0` rather than reverting. rBalance is *informational* tracking of invested capital; user `_balances` always receive the full, correct amount, and the zero-sum invariant is preserved.
- **rBalance adjustments (Revenue Admin).**
  - `adjustrBalance(address account, uint256 ts, uint256 amounti, uint256 amountr)` — records yield/loss; `amounti` = invested, `amountr` = returned. Capped at a 2× return (`amountr ≤ amounti * MAX_RETURN_MULTIPLIER`, `MAX_RETURN_MULTIPLIER = 2`); each `(account, ts)` pair may be adjusted only once.
  - `cancelrBalanceAdjustment(address account, uint256 ts)` — reverses a prior adjustment.

  These never affect user balances.

### 9. Intentional availability controls

The following limit availability **by design** and are not protocol dysfunction:

- Batch size limits (gas protection).
- Investment Manager fulfillment timing (async design).
- KYC blocking non-verified recipients (compliance).
- Pause functionality (emergency control).

### 10. Gas, code style, and operational/economic matters

Gas micro-optimizations, code-style preferences, NatSpec/comment nits, operational-security advice (HSM, multisig, key management), economic/strategy advice, and legal/compliance opinions are out of scope as security vulnerabilities. (Misleading documentation that causes integration errors is a genuine concern.)

---

## What WOULD Be a Vulnerability

The exclusions above are not bugs. The following **are** genuine vulnerabilities and are taken seriously:

- Loss of user funds through a vulnerability.
- Unauthorized minting or burning.
- Asset-theft vectors.
- **Unintended** access-control bypass (e.g. a non-Owner gaining the ability to upgrade, or anyone cancelling another user's request).
- Storage corruption or unsafe storage layout across upgrades.
- Reentrancy that corrupts state (e.g. double-minting on fulfillment, theft during cancellation).
- Signature replay (including cross-chain) enabling unauthorized transfers.
- Accounting errors (e.g. mixing units, incorrect reserved-asset calculation, over-investment).
- Exploitable precision loss (rounding > 1 unit or profitable rounding).
- Incorrect final balance after batch processing, negative balances, or incorrect total supply.
- DOS that permanently locks funds or blocks core functionality at non-trivial cost (as opposed to the intentional availability controls in Exclusion 9).

---

**Last Updated**: 2026-06-02
