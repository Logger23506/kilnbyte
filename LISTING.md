# Kilnbyte (KBY) listing fact sheet

Copy-paste material for exchange and tracker applications. Everything here is true of the code in this repo today.

## Project facts

| | |
|---|---|
| Name / ticker | Kilnbyte / KBY |
| Chain type | Standalone Layer 1, proof of work (SHA-256d), Ed25519 / base58 addresses |
| Max supply | 10,000,000,000 KBY |
| Genesis allocation | 1,000,000,000 KBY (10%) to `5hQMS2A2rDKcfHAMzeJPm2YydiGwRfJ6Yd5uLp1d8vsm` |
| Mined supply | ~9,000,000,000 KBY, 21,428 KBY per block, halving every 210,000 blocks |
| Block time | 400 ms target, retarget every 10 blocks |
| Source code | https://github.com/Logger23506/kilnbyte |
| Explorer | https://kilnbyte-node.onrender.com/explorer |
| Wallet | https://kilnbyte-node.onrender.com/ |
| RPC | JSON-RPC over HTTP (`getBalance`, `getChainInfo`, `getSupply`, `getBlock`, `sendTransaction`, ...) |

## Where this stands

Experimental and unaudited. The public node runs on Render's free plan, which has no persistent disk, so the chain resets when the service restarts. Exchanges and trackers will not list a chain in that state.

## What each kind of listing needs

**Trackers (CoinGecko, CoinMarketCap):** they list a coin only after it trades on an exchange they already track, with real volume. Apply after the first exchange listing.

**DEXs (Uniswap, Raydium, Jupiter):** these trade tokens that live on their own chain (Ethereum, Solana, ...). KBY is its own chain, so it cannot list there unless a wrapped token is issued on another chain. That is a separate project.

**Centralized exchanges:** each runs a business application, usually with a listing fee, legal and KYC review, a security audit, and a working deposit/withdrawal integration. Small PoW coins usually start on smaller exchanges (for example NonKYC, TradeOgre, or similar), which take a formal application.

## Before applying

1. A node with a persistent disk, running 24/7, plus a few independent nodes (needs HTTPS in the peer client).
2. A stable mainnet: no more chain resets.
3. A security review of the consensus and wallet code.
4. A logo (200x200 PNG) and a short whitepaper.
5. Public community channels (X, Discord, or Telegram).
6. Legal advice. Selling a token can fall under securities rules depending on where you and the buyers are.

## Application text (short)

> Kilnbyte (KBY) is an open-source proof-of-work Layer 1 with Bitcoin-style SHA-256d mining and a 400 ms block time. Fixed 10B supply, halving rewards, Ed25519 accounts. Code: https://github.com/Logger23506/kilnbyte. Explorer: https://kilnbyte-node.onrender.com/explorer.
