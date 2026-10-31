# Kilnbyte (KBY)

Bitcoin-style proof-of-work mining at Solana-style speed: SHA-256d mining, a hard-capped supply, halving rewards,
difficulty retargeting, and a 400 ms target block time. Keys and addresses are Ed25519 / base58 (Solana-style).

## Facts

| | |
|---|---|
| Ticker | KBY (1 KBY = 10^8 base units) |
| Max supply | 10,000,000,000 KBY |
| Genesis allocation | 1,000,000,000 KBY (10%) to `5hQMS2A2rDKcfHAMzeJPm2YydiGwRfJ6Yd5uLp1d8vsm` (founder wallet; the founder states it is not for sale) |
| Mined supply | ~9,000,000,000 KBY: 21,428 KBY per block, halving every 210,000 blocks |
| Block time | 400 ms target, retarget every 10 blocks |
| Consensus | Proof of work (SHA-256 double hash), heaviest chain wins |
| Signatures | Ed25519, account/nonce model (replay protection) |
| Max block size | 10,000 transactions |

## Run a node

```bash
cargo build --release
kilnbyte node --public --peer <seed-host>:8899 --advertise <your-public-host>:8899
```

- `--peer` connect to another node (repeatable, or set `KBY_PEERS=a:8899,b:8899`)
- `--advertise` tell peers where to reach you so they sync from you too
- `--miner <ADDR>` address that receives block rewards (defaults to `wallet.key`)
- `--public` listen on all interfaces instead of localhost only
- Browser wallet: `http://<host>:8899/`  Explorer: `http://<host>:8899/explorer`

Data is saved to `chain.dat` (override with `KBY_DATA`).

## Host a node

- **Docker:** `docker build -t kilnbyte .` then `docker run -p 8899:8899 -v kby:/data kilnbyte --miner <ADDR>`
- **GitHub Codespaces:** open the repo in a Codespace, run `./target/release/kilnbyte node --public --miner <ADDR>`,
  and make port 8899 public. Codespaces stop when idle, so use it for testing, not as a permanent seed node.

## Wallet CLI

```bash
kilnbyte wallet new | address | balance [ADDR] | send <ADDR> <AMOUNT>
```

The private key is stored in `wallet.key` (or `KBY_WALLET`). Back it up and never share it.

## JSON-RPC (port 8899)

`getBalance`, `getNextNonce`, `getBlockHeight`, `getChainInfo`, `getSupply`, `getBlock`, `getBlocksRaw`,
`sendTransaction`, `submitBlock`, `addPeer`.

## Status

Experimental. Not audited. No rate limiting on the RPC server.
