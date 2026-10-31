//! Kilnbyte (KBY)
//!
//! Bitcoin's monetary and mining model (SHA-256d proof-of-work, 10B cap, halving, difficulty retarget)
//! run at Solana's cadence (400 ms target block time) with Ed25519 keys, base58 addresses,
//! an account/nonce model, parallel signature verification and a Solana-style JSON-RPC (port 8899).
//!
//! Usage:
//!   kilnbyte node [--miner ADDR] [--port N]   run a mining node + RPC server
//!   kilnbyte wallet new|address|balance [ADDR]|send <ADDR> <AMOUNT>
//!   kilnbyte status
//!   kilnbyte demo [blocks] [tx_per_block]     throughput benchmark

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---- Consensus parameters ------------------------------------------------
const COIN: u64 = 100_000_000; // 1 KBY = 10^8 "bytes" (smallest unit)
const MAX_SUPPLY: u64 = 10_000_000_000 * COIN; // 10B KBY hard cap
const PREMINE: u64 = 1_000_000_000 * COIN; // 1B KBY allocated in genesis
const PREMINE_ADDR: &str = "5hQMS2A2rDKcfHAMzeJPm2YydiGwRfJ6Yd5uLp1d8vsm";
// Halving every 210k blocks sums to ~2 * 210k * reward, so 21,428 KBY mines the other ~9B.
const INITIAL_REWARD: u64 = 21_428 * COIN;
const HALVING_INTERVAL: u64 = 210_000;
const TARGET_BLOCK_MS: u64 = 400; // Solana slot time
const RETARGET_WINDOW: u64 = 10;
const INITIAL_BITS: u32 = 22;
const MAX_TX_PER_BLOCK: usize = 10_000;
const MAX_MEMPOOL: usize = 100_000;
const RPC_PORT: u16 = 8899; // same default port as solana-test-validator
const TX_WIRE: usize = 144; // from32 + to32 + amount8 + nonce8 + sig64
const HEADER_LEN: usize = 124;

type Hash = [u8; 32];
type Addr = [u8; 32];

fn sha(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}
fn dsha(data: &[u8]) -> Hash {
    sha(&sha(data))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}
fn b58(b: &[u8]) -> String {
    bs58::encode(b).into_string()
}
fn short(a: &Addr) -> String {
    b58(a)[..8].to_string()
}
fn parse_addr(s: &str) -> Result<Addr, String> {
    let v = bs58::decode(s.trim()).into_vec().map_err(|_| "invalid base58 address".to_string())?;
    v.try_into().map_err(|_| "address must decode to 32 bytes".to_string())
}
fn fmt_amount(u: u64) -> String {
    format!("{}.{:08}", u / COIN, u % COIN)
}
fn parse_amount(s: &str) -> Result<u64, String> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > 8 || whole.is_empty() && frac.is_empty() {
        return Err("amount has at most 8 decimals".into());
    }
    let w: u64 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| "bad amount")? };
    let f: u64 = if frac.is_empty() { 0 } else { format!("{:0<8}", frac).parse().map_err(|_| "bad amount")? };
    w.checked_mul(COIN).and_then(|x| x.checked_add(f)).ok_or("amount too large".into())
}
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}
fn leading_zero_bits(h: &Hash) -> u32 {
    let mut n = 0;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

// ---- Wallet --------------------------------------------------------------
struct Wallet {
    key: SigningKey,
    addr: Addr,
}

impl Wallet {
    fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let addr = key.verifying_key().to_bytes();
        Wallet { key, addr }
    }
    fn new() -> Self {
        Self::from_seed(rand::random::<[u8; 32]>())
    }
    fn pay(&self, to: Addr, amount: u64, nonce: u64) -> Tx {
        let mut tx = Tx { from: self.addr, to, amount, nonce, sig: [0; 64] };
        tx.sig = self.key.sign(&tx.message()).to_bytes();
        tx
    }
}

// ---- Transactions --------------------------------------------------------
#[derive(Clone)]
struct Tx {
    from: Addr,
    to: Addr,
    amount: u64,
    nonce: u64, // must equal sender's last nonce + 1 (replay protection)
    sig: [u8; 64],
}

impl Tx {
    fn message(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(80);
        m.extend_from_slice(&self.from);
        m.extend_from_slice(&self.to);
        m.extend_from_slice(&self.amount.to_le_bytes());
        m.extend_from_slice(&self.nonce.to_le_bytes());
        m
    }
    fn to_wire(&self) -> Vec<u8> {
        let mut m = self.message();
        m.extend_from_slice(&self.sig);
        m
    }
    fn from_wire(b: &[u8]) -> Option<Tx> {
        if b.len() != TX_WIRE {
            return None;
        }
        Some(Tx {
            from: b[0..32].try_into().ok()?,
            to: b[32..64].try_into().ok()?,
            amount: u64::from_le_bytes(b[64..72].try_into().ok()?),
            nonce: u64::from_le_bytes(b[72..80].try_into().ok()?),
            sig: b[80..144].try_into().ok()?,
        })
    }
    fn id(&self) -> Hash {
        dsha(&self.to_wire())
    }
    fn verify(&self) -> bool {
        match VerifyingKey::from_bytes(&self.from) {
            Ok(vk) => vk.verify(&self.message(), &Signature::from_bytes(&self.sig)).is_ok(),
            Err(_) => false,
        }
    }
}

fn verify_all(txs: &[Tx], threads: usize) -> bool {
    let chunk = (txs.len() / threads.max(1)).max(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = txs.chunks(chunk).map(|c| s.spawn(move || c.iter().all(Tx::verify))).collect();
        handles.into_iter().all(|h| h.join().unwrap())
    })
}

fn merkle_root(txs: &[Tx]) -> Hash {
    if txs.is_empty() {
        return [0; 32];
    }
    let mut level: Vec<Hash> = txs.iter().map(Tx::id).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .chunks(2)
            .map(|p| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&p[0]);
                buf[32..].copy_from_slice(&p[1]);
                dsha(&buf)
            })
            .collect();
    }
    level[0]
}

// ---- Blocks --------------------------------------------------------------
#[derive(Clone)]
struct Block {
    height: u64,
    timestamp: u64,
    prev: Hash,
    merkle: Hash,
    miner: Addr,
    bits: u32, // required leading zero bits of the block hash
    nonce: u64,
    txs: Vec<Tx>,
}

impl Block {
    fn header(&self) -> Vec<u8> {
        let mut h = Vec::with_capacity(HEADER_LEN);
        h.extend_from_slice(&self.height.to_le_bytes());
        h.extend_from_slice(&self.timestamp.to_le_bytes());
        h.extend_from_slice(&self.prev);
        h.extend_from_slice(&self.merkle);
        h.extend_from_slice(&self.miner);
        h.extend_from_slice(&self.bits.to_le_bytes());
        h.extend_from_slice(&self.nonce.to_le_bytes());
        h
    }
    fn hash(&self) -> Hash {
        dsha(&self.header())
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.header();
        v.extend_from_slice(&(self.txs.len() as u32).to_le_bytes());
        for t in &self.txs {
            v.extend_from_slice(&t.to_wire());
        }
        v
    }
}

fn read_blocks(data: &[u8]) -> Vec<Block> {
    let mut out = vec![];
    let mut p = 0;
    while p + HEADER_LEN + 4 <= data.len() {
        let h = &data[p..p + HEADER_LEN];
        let cnt = u32::from_le_bytes(data[p + HEADER_LEN..p + HEADER_LEN + 4].try_into().unwrap()) as usize;
        p += HEADER_LEN + 4;
        if p + cnt * TX_WIRE > data.len() {
            break;
        }
        let txs = (0..cnt).filter_map(|i| Tx::from_wire(&data[p + i * TX_WIRE..p + (i + 1) * TX_WIRE])).collect();
        p += cnt * TX_WIRE;
        out.push(Block {
            height: u64::from_le_bytes(h[0..8].try_into().unwrap()),
            timestamp: u64::from_le_bytes(h[8..16].try_into().unwrap()),
            prev: h[16..48].try_into().unwrap(),
            merkle: h[48..80].try_into().unwrap(),
            miner: h[80..112].try_into().unwrap(),
            bits: u32::from_le_bytes(h[112..116].try_into().unwrap()),
            nonce: u64::from_le_bytes(h[116..124].try_into().unwrap()),
            txs,
        });
    }
    out
}

/// Multi-threaded nonce search (Bitcoin-style mining).
/// Returns None if `cancel` was raised before a valid nonce was found.
fn mine(mut b: Block, threads: usize, cancel: Option<&AtomicBool>) -> Option<Block> {
    let found = AtomicBool::new(false);
    let winner = AtomicU64::new(0);
    let template = b.header();
    let off = template.len() - 8;
    std::thread::scope(|s| {
        for t in 0..threads {
            let (found, winner, mut buf) = (&found, &winner, template.clone());
            let bits = b.bits;
            s.spawn(move || {
                let mut nonce = t as u64;
                while !found.load(Ordering::Relaxed) && !cancel.map_or(false, |c| c.load(Ordering::Relaxed)) {
                    buf[off..].copy_from_slice(&nonce.to_le_bytes());
                    if leading_zero_bits(&dsha(&buf)) >= bits {
                        if !found.swap(true, Ordering::SeqCst) {
                            winner.store(nonce, Ordering::SeqCst);
                        }
                        return;
                    }
                    nonce += threads as u64;
                }
            });
        }
    });
    if !found.load(Ordering::SeqCst) {
        return None;
    }
    b.nonce = winner.load(Ordering::SeqCst);
    Some(b)
}

// ---- Chain state ---------------------------------------------------------
struct Chain {
    blocks: Vec<Block>,
    balances: HashMap<Addr, u64>,
    nonces: HashMap<Addr, u64>,
    supply: u64,
    work: f64, // cumulative proof of work (sum of 2^bits); the heaviest chain wins
    threads: usize,
}

fn block_reward(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 { 0 } else { INITIAL_REWARD >> halvings }
}

impl Chain {
    fn new(threads: usize) -> Self {
        let genesis = Block { height: 0, timestamp: 0, prev: [0; 32], merkle: [0; 32], miner: [0; 32], bits: INITIAL_BITS, nonce: 0, txs: vec![] };
        let mut balances = HashMap::new();
        balances.insert(parse_addr(PREMINE_ADDR).unwrap(), PREMINE);
        Chain { blocks: vec![genesis], balances, nonces: HashMap::new(), supply: PREMINE, work: 2f64.powi(INITIAL_BITS as i32), threads }
    }
    fn tip(&self) -> &Block {
        self.blocks.last().unwrap()
    }
    fn reward_now(&self) -> u64 {
        block_reward(self.tip().height + 1).min(MAX_SUPPLY - self.supply)
    }

    /// Retarget every window: each missing/extra leading zero bit halves/doubles the work.
    fn next_bits(&self) -> u32 {
        let h = self.blocks.len() as u64;
        let last = self.tip();
        if h < RETARGET_WINDOW || h % RETARGET_WINDOW != 0 {
            return last.bits;
        }
        let first = &self.blocks[(h - RETARGET_WINDOW) as usize];
        let actual = last.timestamp.saturating_sub(first.timestamp).max(1) as f64;
        let expected = ((RETARGET_WINDOW - 1) * TARGET_BLOCK_MS) as f64;
        let delta = (expected / actual).log2().round().clamp(-4.0, 4.0) as i32;
        (last.bits as i32 + delta).clamp(1, 255) as u32
    }

    fn template(&self, miner: Addr, txs: Vec<Tx>) -> Block {
        Block {
            height: self.tip().height + 1,
            timestamp: now_ms().max(self.tip().timestamp + 1),
            prev: self.tip().hash(),
            merkle: merkle_root(&txs),
            miner,
            bits: self.next_bits(),
            nonce: 0,
            txs,
        }
    }

    /// Pick mempool txs that are valid in order against current state.
    fn select_txs(&self, pool: &[Tx]) -> Vec<Tx> {
        let mut bal: HashMap<Addr, u64> = HashMap::new();
        let mut non: HashMap<Addr, u64> = HashMap::new();
        let mut out = vec![];
        for tx in pool {
            if out.len() >= MAX_TX_PER_BLOCK {
                break;
            }
            let n = *non.entry(tx.from).or_insert_with(|| *self.nonces.get(&tx.from).unwrap_or(&0));
            let b = *bal.entry(tx.from).or_insert_with(|| *self.balances.get(&tx.from).unwrap_or(&0));
            if tx.nonce != n + 1 || b < tx.amount || tx.amount == 0 {
                continue;
            }
            bal.insert(tx.from, b - tx.amount);
            non.insert(tx.from, n + 1);
            *bal.entry(tx.to).or_insert_with(|| *self.balances.get(&tx.to).unwrap_or(&0)) += tx.amount;
            out.push(tx.clone());
        }
        out
    }

    fn accept(&mut self, b: &Block) -> Result<(), String> {
        let tip = self.tip();
        if b.height != tip.height + 1 { return Err("bad height".into()); }
        if b.prev != tip.hash() { return Err("prev hash mismatch".into()); }
        if b.timestamp <= tip.timestamp { return Err("timestamp not increasing".into()); }
        if b.timestamp > now_ms() + 120_000 { return Err("timestamp too far in the future".into()); }
        if b.bits != self.next_bits() { return Err("wrong difficulty".into()); }
        if b.txs.len() > MAX_TX_PER_BLOCK { return Err("too many txs".into()); }
        if b.merkle != merkle_root(&b.txs) { return Err("bad merkle root".into()); }
        if leading_zero_bits(&b.hash()) < b.bits { return Err("insufficient proof of work".into()); }
        if !verify_all(&b.txs, self.threads) { return Err("invalid signature".into()); }

        let mut balances = self.balances.clone();
        let mut nonces = self.nonces.clone();
        for tx in &b.txs {
            let n = nonces.entry(tx.from).or_insert(0);
            if tx.nonce != *n + 1 { return Err("bad nonce".into()); }
            if tx.amount == 0 { return Err("zero amount".into()); }
            let bal = balances.entry(tx.from).or_insert(0);
            if *bal < tx.amount { return Err("insufficient funds".into()); }
            *bal -= tx.amount;
            *n += 1;
            *balances.entry(tx.to).or_insert(0) += tx.amount;
        }
        let reward = self.reward_now();
        *balances.entry(b.miner).or_insert(0) += reward;
        self.balances = balances;
        self.nonces = nonces;
        self.supply += reward;
        self.work += 2f64.powi(b.bits as i32);
        self.blocks.push(b.clone());
        Ok(())
    }
}

// ---- Node (shared state, miner loop, RPC server) -------------------------
struct Node {
    chain: Chain,
    mempool: Vec<Tx>,
    stale: Arc<AtomicBool>, // raised when the tip changes, so the miner abandons its template
    peers: Vec<String>,     // "host:port" of other nodes' RPC servers
}

type Shared = Arc<Mutex<Node>>;

fn data_path() -> String {
    std::env::var("KBY_DATA").unwrap_or_else(|_| "chain.dat".into())
}

fn append_block(b: &Block) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(data_path()) {
        let _ = f.write_all(&b.to_bytes());
    }
}

fn miner_loop(node: Shared, miner: Addr, threads: usize) {
    loop {
        let (tpl, stale) = {
            let n = node.lock().unwrap();
            let txs = n.chain.select_txs(&n.mempool);
            n.stale.store(false, Ordering::SeqCst);
            (n.chain.template(miner, txs), n.stale.clone())
        };
        let t0 = Instant::now();
        let Some(block) = mine(tpl, threads, Some(&stale)) else { continue };
        let mut guard = node.lock().unwrap();
        let Node { chain, mempool, peers, .. } = &mut *guard;
        match chain.accept(&block) {
            Ok(()) => {
                append_block(&block);
                // Push to peers so miners that only make outbound connections still reach the network.
                let (peers, raw) = (peers.clone(), hex(&block.to_bytes()));
                std::thread::spawn(move || {
                    for peer in peers {
                        let _ = rpc_at(&peer, "submitBlock", json!([raw]));
                    }
                });
                let ids: HashSet<Hash> = block.txs.iter().map(Tx::id).collect();
                mempool.retain(|t| !ids.contains(&t.id()) && t.nonce > *chain.nonces.get(&t.from).unwrap_or(&0));
                println!("#{:<6} bits={:<2} txs={:<5} {:>5} ms  {}", block.height, block.bits, block.txs.len(), t0.elapsed().as_millis(), &hex(&block.hash())[..16]);
            }
            Err(e) => println!("mined block rejected: {}", e),
        }
    }
}

fn admit(n: &mut Node, tx: Tx) -> Result<Hash, String> {
    if tx.amount == 0 { return Err("amount must be positive".into()); }
    if !tx.verify() { return Err("invalid signature".into()); }
    if n.mempool.len() >= MAX_MEMPOOL { return Err("mempool full".into()); }
    if tx.nonce <= *n.chain.nonces.get(&tx.from).unwrap_or(&0) { return Err("nonce already used".into()); }
    if *n.chain.balances.get(&tx.from).unwrap_or(&0) < tx.amount { return Err("insufficient funds".into()); }
    if n.mempool.iter().any(|t| t.from == tx.from && t.nonce == tx.nonce) { return Err("duplicate nonce in mempool".into()); }
    let id = tx.id();
    n.mempool.push(tx);
    Ok(id)
}

fn call(node: &Shared, method: &str, p: &Value) -> Result<Value, String> {
    let mut n = node.lock().unwrap();
    match method {
        "getBalance" => {
            let a = parse_addr(p[0].as_str().ok_or("address required")?)?;
            let v = n.chain.balances.get(&a).copied().unwrap_or(0);
            // "uiAmount" is a string: balances above 2^53 lose precision as JSON numbers in JS.
            Ok(json!({ "value": v, "uiAmount": fmt_amount(v) }))
        }
        "getNextNonce" => {
            let a = parse_addr(p[0].as_str().ok_or("address required")?)?;
            let chain_n = *n.chain.nonces.get(&a).unwrap_or(&0);
            let pending = n.mempool.iter().filter(|t| t.from == a).map(|t| t.nonce).max().unwrap_or(0);
            Ok(json!(chain_n.max(pending) + 1))
        }
        "getBlockHeight" => Ok(json!(n.chain.tip().height)),
        "getChainInfo" => Ok(json!({ "height": n.chain.tip().height, "hash": b58(&n.chain.tip().hash()), "work": n.chain.work, "mempool": n.mempool.len(), "peers": n.peers.len() })),
        "getBlocksRaw" => {
            let from = p[0].as_u64().unwrap_or(1) as usize;
            let cnt = p[1].as_u64().unwrap_or(100).min(200) as usize;
            Ok(json!(n.chain.blocks.iter().skip(from).take(cnt).map(|b| hex(&b.to_bytes())).collect::<Vec<_>>()))
        }
        "getSupply" => Ok(json!({ "value": n.chain.supply, "max": MAX_SUPPLY, "uiAmount": fmt_amount(n.chain.supply), "uiMax": fmt_amount(MAX_SUPPLY) })),
        "getBlock" => {
            let h = p[0].as_u64().unwrap_or(n.chain.tip().height) as usize;
            let b = n.chain.blocks.get(h).ok_or("block not found")?;
            Ok(json!({
                "height": b.height, "hash": b58(&b.hash()), "previousHash": b58(&b.prev),
                "timestamp": b.timestamp, "miner": b58(&b.miner), "bits": b.bits,
                "transactions": b.txs.iter().map(|t| json!({
                    "signature": b58(&t.id()), "from": b58(&t.from), "to": b58(&t.to), "amount": t.amount, "uiAmount": fmt_amount(t.amount), "nonce": t.nonce
                })).collect::<Vec<_>>()
            }))
        }
        "addPeer" => {
            let peer = p[0].as_str().ok_or("host:port required")?.trim().to_string();
            if peer.len() > 100 || peer.rsplit_once(':').map_or(true, |(_, port)| port.parse::<u16>().is_err()) {
                return Err("peer must look like host:port".into());
            }
            if !n.peers.contains(&peer) && n.peers.len() < 32 {
                println!("peer added: {}", peer);
                n.peers.push(peer);
            }
            Ok(json!(true))
        }
        "submitBlock" => {
            let bytes = unhex(p[0].as_str().ok_or("hex block required")?).ok_or("bad hex")?;
            let b = read_blocks(&bytes).into_iter().next().ok_or("malformed block")?;
            let Node { chain, mempool, stale, .. } = &mut *n;
            chain.accept(&b)?;
            append_block(&b);
            stale.store(true, Ordering::SeqCst);
            mempool.retain(|t| t.nonce > *chain.nonces.get(&t.from).unwrap_or(&0));
            Ok(json!(true))
        }
        "sendTransaction" => {
            let wire = bs58::decode(p[0].as_str().ok_or("base58 transaction required")?).into_vec().map_err(|_| "bad base58")?;
            let tx = Tx::from_wire(&wire).ok_or("malformed transaction")?;
            let r = admit(&mut n, tx);
            if r.is_ok() {
                // Gossip newly accepted transactions; peers that already have it reject it, which ends the relay.
                let (peers, wire) = (n.peers.clone(), p[0].as_str().unwrap_or("").to_string());
                std::thread::spawn(move || {
                    for peer in peers {
                        let _ = rpc_at(&peer, "sendTransaction", json!([wire]));
                    }
                });
            }
            r.map(|id| json!(b58(&id)))
        }
        _ => Err(format!("method not found: {}", method)),
    }
}

fn handle_rpc(node: &Shared, req: &Value) -> Value {
    let id = req["id"].clone();
    match call(node, req["method"].as_str().unwrap_or(""), &req["params"]) {
        Ok(v) => json!({ "jsonrpc": "2.0", "result": v, "id": id }),
        Err(e) => json!({ "jsonrpc": "2.0", "error": { "code": -32600, "message": e }, "id": id }),
    }
}

fn handle_conn(node: Shared, mut s: TcpStream) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let (body_start, clen) = loop {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
            let cl = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
            break (p + 4, cl);
        }
        if buf.len() > (1 << 20) { return; }
    };
    if clen > (1 << 20) { return; }
    while buf.len() < body_start + clen {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let cors = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\n";
    let resp = if buf.starts_with(b"GET") {
        let page = if buf.starts_with(b"GET /explorer") { include_str!("../explorer.html") } else { include_str!("../wallet.html") };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", page.len(), page)
    } else if buf.starts_with(b"OPTIONS") {
        format!("HTTP/1.1 204 No Content\r\n{}Connection: close\r\n\r\n", cors)
    } else {
        let out = match serde_json::from_slice::<Value>(&buf[body_start..body_start + clen]) {
            Ok(req) => handle_rpc(&node, &req),
            Err(_) => json!({ "jsonrpc": "2.0", "error": { "code": -32700, "message": "parse error" }, "id": null }),
        }
        .to_string();
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, out.len(), out)
    };
    let _ = s.write_all(resp.as_bytes());
    let _ = s.shutdown(Shutdown::Both);
}

fn run_node(args: &[String]) -> Result<(), String> {
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    // KBY_MINER and PORT let container hosts (Render, Docker) configure the node without CLI args.
    let miner = match flag("--miner").or_else(|| std::env::var("KBY_MINER").ok()) {
        Some(a) => parse_addr(&a)?,
        None => load_wallet()?.addr,
    };
    let port: u16 = flag("--port").or_else(|| std::env::var("PORT").ok()).and_then(|p| p.parse().ok()).unwrap_or(RPC_PORT);
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mine_threads = threads.saturating_sub(1).max(1);

    let mut chain = Chain::new(threads);
    if let Ok(data) = std::fs::read(data_path()) {
        for b in read_blocks(&data) {
            chain.accept(&b).map_err(|e| format!("{} is corrupt at block {}: {}", data_path(), b.height, e))?;
        }
        println!("Loaded {} blocks from {}", chain.blocks.len() - 1, data_path());
    }
    let mut peers: Vec<String> = args.windows(2).filter(|w| w[0] == "--peer").map(|w| w[1].clone()).collect();
    if let Ok(env_peers) = std::env::var("KBY_PEERS") {
        peers.extend(env_peers.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    let node: Shared = Arc::new(Mutex::new(Node { chain, mempool: vec![], stale: Arc::new(AtomicBool::new(false)), peers: peers.clone() }));
    {
        let n = node.clone();
        let advertise = flag("--advertise");
        std::thread::spawn(move || sync_loop(n, threads, advertise));
    }

    let host = if args.iter().any(|a| a == "--public") { "0.0.0.0" } else { "127.0.0.1" };
    let listener = TcpListener::bind((host, port)).map_err(|e| format!("cannot bind port {}: {}", port, e))?;
    println!("Kilnbyte node | wallet http://{h}:{p}/  explorer http://{h}:{p}/explorer | mining to {} | {} mining threads | {} peers", b58(&miner), mine_threads, peers.len(), h = host, p = port);
    let n2 = node.clone();
    std::thread::spawn(move || miner_loop(n2, miner, mine_threads));
    for s in listener.incoming().flatten() {
        let n = node.clone();
        std::thread::spawn(move || handle_conn(n, s));
    }
    Ok(())
}

// ---- Peer sync -----------------------------------------------------------
// Pull-based: every 500 ms ask each peer for its chain work; if it is heavier, fetch and adopt it.

fn fetch_blocks(peer: &str, from: u64, to: u64) -> Result<Vec<Block>, String> {
    let mut out = vec![];
    let mut next = from;
    while next <= to {
        let batch = rpc_at(peer, "getBlocksRaw", json!([next, 200]))?;
        let items = batch.as_array().ok_or("bad batch")?;
        if items.is_empty() {
            break;
        }
        for it in items {
            let bytes = unhex(it.as_str().unwrap_or("")).ok_or("bad block hex")?;
            out.extend(read_blocks(&bytes));
        }
        next = from + out.len() as u64;
    }
    Ok(out)
}

fn rewrite_chain_file(chain: &Chain) {
    let mut data = vec![];
    for b in &chain.blocks[1..] {
        data.extend_from_slice(&b.to_bytes());
    }
    let _ = std::fs::write(data_path(), data);
}

/// Extend our chain with the peer's blocks above our tip. False if they don't attach (a fork).
fn sync_incremental(node: &Shared, peer: &str, our_h: u64, peer_h: u64) -> bool {
    let Ok(blocks) = fetch_blocks(peer, our_h + 1, peer_h) else { return false };
    let mut guard = node.lock().unwrap();
    let Node { chain, mempool, stale, .. } = &mut *guard;
    for b in &blocks {
        if chain.accept(b).is_err() {
            return false;
        }
        append_block(b);
        stale.store(true, Ordering::SeqCst);
    }
    mempool.retain(|t| t.nonce > *chain.nonces.get(&t.from).unwrap_or(&0));
    println!("synced {} block(s) from {} -> height {}", blocks.len(), peer, chain.tip().height);
    true
}

/// Fork resolution: validate the peer's whole chain from genesis and switch if it has more work.
fn sync_full(node: &Shared, peer: &str, threads: usize, peer_h: u64) {
    let Ok(blocks) = fetch_blocks(peer, 1, peer_h) else { return };
    let mut fresh = Chain::new(threads);
    for b in &blocks {
        if fresh.accept(b).is_err() {
            return;
        }
    }
    let mut guard = node.lock().unwrap();
    let Node { chain, mempool, stale, .. } = &mut *guard;
    if fresh.work > chain.work {
        println!("reorg: switching to {}'s chain (height {} -> {})", peer, chain.tip().height, fresh.tip().height);
        *chain = fresh;
        rewrite_chain_file(chain);
        stale.store(true, Ordering::SeqCst);
        mempool.retain(|t| t.nonce > *chain.nonces.get(&t.from).unwrap_or(&0));
    }
}

fn sync_loop(node: Shared, threads: usize, advertise: Option<String>) {
    let mut announced: HashSet<String> = HashSet::new();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let peers = node.lock().unwrap().peers.clone();
        for peer in peers {
            // Tell the peer where to reach us (--advertise) so it syncs from us too.
            if let Some(me) = &advertise {
                if !announced.contains(&peer) && rpc_at(&peer, "addPeer", json!([me])).is_ok() {
                    announced.insert(peer.clone());
                }
            }
            let Ok(info) = rpc_at(&peer, "getChainInfo", json!([])) else { continue };
            let (peer_work, peer_h) = (info["work"].as_f64().unwrap_or(0.0), info["height"].as_u64().unwrap_or(0));
            let (our_work, our_h) = {
                let n = node.lock().unwrap();
                (n.chain.work, n.chain.tip().height)
            };
            if peer_work <= our_work {
                continue;
            }
            if peer_h > our_h && sync_incremental(&node, &peer, our_h, peer_h) {
                continue;
            }
            sync_full(&node, &peer, threads, peer_h);
        }
    }
}

// ---- Wallet CLI ----------------------------------------------------------
fn wallet_path() -> String {
    std::env::var("KBY_WALLET").unwrap_or_else(|_| "wallet.key".into())
}

fn load_wallet() -> Result<Wallet, String> {
    let txt = std::fs::read_to_string(wallet_path()).map_err(|_| format!("no wallet at {}; run `kilnbyte wallet new`", wallet_path()))?;
    let seed: [u8; 32] = unhex(&txt).and_then(|v| v.try_into().ok()).ok_or("wallet file is corrupt")?;
    Ok(Wallet::from_seed(seed))
}

fn rpc(method: &str, params: Value) -> Result<Value, String> {
    let url = std::env::var("KBY_RPC").unwrap_or_else(|_| format!("127.0.0.1:{}", RPC_PORT));
    rpc_at(&url, method, params).map_err(|e| format!("{} (node at {}; start it with `kilnbyte node`)", e, url))
}

fn rpc_at(url: &str, method: &str, params: Value) -> Result<Value, String> {
    let addr = url.to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("unresolvable address")?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| format!("cannot connect: {}", e))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    write!(s, "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", url, body.len(), body).map_err(|e| e.to_string())?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).map_err(|e| e.to_string())?;
    let payload = resp.split_once("\r\n\r\n").ok_or("empty response")?.1;
    let v: Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    match v.get("error") {
        Some(e) => Err(e["message"].as_str().unwrap_or("rpc error").to_string()),
        None => Ok(v["result"].clone()),
    }
}

fn run_wallet(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("new") => {
            if std::path::Path::new(&wallet_path()).exists() {
                return Err(format!("{} already exists; refusing to overwrite", wallet_path()));
            }
            let seed = rand::random::<[u8; 32]>();
            std::fs::write(wallet_path(), hex(&seed)).map_err(|e| e.to_string())?;
            println!("Address: {}", b58(&Wallet::from_seed(seed).addr));
            println!("Private key saved to {} - back it up; anyone with this file controls your KBY.", wallet_path());
        }
        Some("address") => println!("{}", b58(&load_wallet()?.addr)),
        Some("balance") => {
            let a = match args.get(1) {
                Some(a) => parse_addr(a)?,
                None => load_wallet()?.addr,
            };
            let v = rpc("getBalance", json!([b58(&a)]))?;
            println!("{} KBY", fmt_amount(v["value"].as_u64().unwrap_or(0)));
        }
        Some("send") => {
            let to = parse_addr(args.get(1).ok_or("usage: wallet send <ADDR> <AMOUNT>")?)?;
            let amount = parse_amount(args.get(2).ok_or("usage: wallet send <ADDR> <AMOUNT>")?)?;
            let w = load_wallet()?;
            let nonce = rpc("getNextNonce", json!([b58(&w.addr)]))?.as_u64().ok_or("bad nonce")?;
            let tx = w.pay(to, amount, nonce);
            let sig = rpc("sendTransaction", json!([b58(&tx.to_wire())]))?;
            println!("Sent {} KBY to {}\nSignature: {}", fmt_amount(amount), b58(&to), sig.as_str().unwrap_or(""));
        }
        _ => return Err("usage: kilnbyte wallet new|address|balance [ADDR]|send <ADDR> <AMOUNT>".into()),
    }
    Ok(())
}

fn run_status() -> Result<(), String> {
    let h = rpc("getBlockHeight", json!([]))?;
    let s = rpc("getSupply", json!([]))?;
    println!("Height: {}   Supply: {} / {} KBY", h, fmt_amount(s["value"].as_u64().unwrap_or(0)), MAX_SUPPLY / COIN);
    Ok(())
}

// ---- Benchmark -----------------------------------------------------------
fn run_demo(args: &[String]) {
    let n_blocks: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(60);
    let tx_per_block: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);

    println!("Kilnbyte (KBY) | {} mining threads | target block time {} ms | {} blocks x {} tx\n", threads, TARGET_BLOCK_MS, n_blocks, tx_per_block);

    let mut chain = Chain::new(threads);
    let miner = Wallet::new();
    let users: Vec<Wallet> = (0..100).map(|_| Wallet::new()).collect();

    // Bootstrap: mine one block so the miner owns coins to spend.
    let b = mine(chain.template(miner.addr, vec![]), threads, None).unwrap();
    chain.accept(&b).unwrap();

    // Pre-sign every payment (the miner pays random users) and queue them in a mempool.
    let total_tx = (n_blocks as usize) * tx_per_block;
    let mut mempool: Vec<Tx> = (0..total_tx)
        .map(|i| miner.pay(users[i % users.len()].addr, 1 + (i as u64 % 1000), i as u64 + 1))
        .collect();
    mempool.reverse(); // pop from the end in nonce order

    let start = Instant::now();
    let mut confirmed = 0usize;
    for _ in 0..n_blocks {
        let take = tx_per_block.min(mempool.len());
        let txs: Vec<Tx> = (0..take).filter_map(|_| mempool.pop()).collect();
        let t0 = Instant::now();
        let block = mine(chain.template(miner.addr, txs), threads, None).unwrap();
        if let Err(e) = chain.accept(&block) {
            println!("block rejected: {}", e);
            return;
        }
        confirmed += block.txs.len();
        if block.height % 5 == 0 || block.height == 1 {
            println!("#{:<4} bits={:<2} txs={:<5} {:>4} ms  hash={}", block.height, block.bits, block.txs.len(), t0.elapsed().as_millis(), &hex(&block.hash())[..16]);
        }
    }
    let secs = start.elapsed().as_secs_f64();
    let span = (chain.tip().timestamp - chain.blocks[1].timestamp) as f64 / 1000.0;

    println!("\n--- Results ---");
    println!("Blocks: {}   Txs confirmed: {}", chain.blocks.len() - 1, confirmed);
    println!("Avg block time: {:.0} ms   Throughput: {:.0} tx/s", secs * 1000.0 / n_blocks as f64, confirmed as f64 / secs);
    println!("(chain timestamp span {:.1}s, final difficulty {} bits)", span, chain.tip().bits);
    println!("Supply: {:.2} KBY / {}   Miner: {:.2} KBY ({})", chain.supply as f64 / COIN as f64, MAX_SUPPLY / COIN, chain.balances[&miner.addr] as f64 / COIN as f64, short(&miner.addr));

    // Independent verification: replay the whole chain into a fresh node.
    let mut replay = Chain::new(threads);
    let ok = chain.blocks[1..].iter().all(|b| replay.accept(b).is_ok());
    println!("\nFull replay validation: {}", if ok { "VALID" } else { "INVALID" });

    // Tamper test: change one payment amount in block 2.
    let mut forged = Chain::new(threads);
    let mut blocks = chain.blocks[1..].to_vec();
    if let Some(tx) = blocks.get_mut(1).and_then(|b| b.txs.get_mut(0)) {
        tx.amount += 1_000_000;
    }
    let err = blocks.iter().map(|b| forged.accept(b)).find_map(Result::err);
    println!("Tampered chain: {}", err.map(|e| format!("rejected ({})", e)).unwrap_or("ACCEPTED (bug!)".into()));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let result = match args.first().map(String::as_str) {
        Some("node") => run_node(rest),
        Some("wallet") => run_wallet(rest),
        Some("status") => run_status(),
        Some("demo") => {
            run_demo(rest);
            Ok(())
        }
        _ => Err("usage: kilnbyte node [--miner ADDR] [--port N] | wallet new|address|balance|send | status | demo [blocks] [tx]".into()),
    };
    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
