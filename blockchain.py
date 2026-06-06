"""Derive blockchain addresses from a passphrase and query public explorers."""

from __future__ import annotations

import hashlib
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Literal

import base58
import requests
from requests.adapters import HTTPAdapter
from ecdsa import SECP256k1, SigningKey
from eth_account import Account

SOLANA_AVAILABLE = False
Ed25519SigningKey = None
try:
    from nacl.signing import SigningKey as Ed25519SigningKey

    SOLANA_AVAILABLE = True
except ImportError:
    pass

Chain = Literal[
    "Bitcoin",
    "Ethereum",
    "Litecoin",
    "Dogecoin",
    "Bitcoin Cash",
    "Polygon",
    "BNB Chain",
    "Avalanche",
    "Arbitrum",
    "Optimism",
    "Tron",
    "Solana",
]

_BASE_CHAINS: list[Chain] = [
    "Bitcoin",
    "Ethereum",
    "Litecoin",
    "Dogecoin",
    "Bitcoin Cash",
    "Polygon",
    "BNB Chain",
    "Avalanche",
    "Arbitrum",
    "Optimism",
    "Tron",
]

MAJOR_CHAINS: list[Chain] = _BASE_CHAINS + (["Solana"] if SOLANA_AVAILABLE else [])

# OPTIMIZED FOR 10 PASSPHRASES/SECOND - Ultra-aggressive timeouts
TIMEOUT_SECONDS = 0.5
FAST_TIMEOUT_SECONDS = 0.3
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_http_session: requests.Session | None = None


def _get_session() -> requests.Session:
    global _http_session
    if _http_session is None:
        session = requests.Session()
        # Aggressive pooling for rapid-fire requests
        adapter = HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=0,
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        # Disable SSL verification for speed
        session.verify = False
        _http_session = session
    return _http_session

UTXO_APIS: dict[str, list[str]] = {
    "Bitcoin": [
        "https://blockstream.info/api/address/{address}",
        "https://mempool.space/api/address/{address}",
    ],
    "Litecoin": [
        "https://litecoinspace.org/api/address/{address}",
        "https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance",
    ],
    "Dogecoin": [
        "https://dogechain.info/api/v1/address/balance/{address}",
        "https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance",
        "https://api.blockchair.com/dogecoin/dashboards/address/{address}",
    ],
    "Bitcoin Cash": [
        "https://rest.bitcoin.com/v2/address/balance/{address}",
        "https://api.blockchair.com/bitcoin-cash/dashboards/address/{address}",
    ],
}

UTXO_EXPLORERS: dict[str, str] = {
    "Bitcoin": "https://blockstream.info/address/{address}",
    "Litecoin": "https://litecoinspace.org/address/{address}",
    "Dogecoin": "https://dogechain.info/address/{address}",
    "Bitcoin Cash": "https://blockchair.com/bitcoin-cash/address/{address}",
}

UTXO_VERSION_BYTES: dict[str, bytes] = {
    "Bitcoin": b"\x00",
    "Litecoin": b"\x30",
    "Dogecoin": b"\x1e",
    "Bitcoin Cash": b"\x00",
}

EVM_CHAINS: dict[str, dict[str, object]] = {
    "Ethereum": {
        "rpcs": [
            "https://ethereum.publicnode.com",
            "https://1rpc.io/eth",
            "https://rpc.ankr.com/eth",
        ],
        "explorer": "https://etherscan.io/address/{address}",
        "symbol": "ETH",
        "divisor": 10**18,
    },
    "Polygon": {
        "rpcs": [
            "https://polygon-rpc.com",
            "https://1rpc.io/matic",
            "https://rpc.ankr.com/polygon",
        ],
        "explorer": "https://polygonscan.com/address/{address}",
        "symbol": "MATIC",
        "divisor": 10**18,
    },
    "BNB Chain": {
        "rpcs": [
            "https://bsc-dataseed.binance.org",
            "https://1rpc.io/bnb",
            "https://rpc.ankr.com/bsc",
        ],
        "explorer": "https://bscscan.com/address/{address}",
        "symbol": "BNB",
        "divisor": 10**18,
    },
    "Avalanche": {
        "rpcs": [
            "https://api.avax.network/ext/bc/C/rpc",
            "https://1rpc.io/avax/c",
            "https://rpc.ankr.com/avalanche",
        ],
        "explorer": "https://snowtrace.io/address/{address}",
        "symbol": "AVAX",
        "divisor": 10**18,
    },
    "Arbitrum": {
        "rpcs": [
            "https://arb1.arbitrum.io/rpc",
            "https://1rpc.io/arb",
            "https://rpc.ankr.com/arbitrum",
        ],
        "explorer": "https://arbiscan.io/address/{address}",
        "symbol": "ETH",
        "divisor": 10**18,
    },
    "Optimism": {
        "rpcs": [
            "https://mainnet.optimism.io",
            "https://1rpc.io/op",
            "https://rpc.ankr.com/optimism",
        ],
        "explorer": "https://optimistic.etherscan.io/address/{address}",
        "symbol": "ETH",
        "divisor": 10**18,
    },
}

TRON_APIS = [
    "https://api.trongrid.io/v1/accounts/{address}",
]

SOLANA_RPCS = [
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
]


@dataclass
class BlockchainResult:
    chain: Chain
    address: str
    balance: str
    balance_raw: int
    transaction_count: int
    explorer_url: str
    has_activity: bool
    has_balance: bool
    error: str = ""


def passphrase_to_private_key(passphrase: str) -> bytes:
    seed = passphrase.encode("utf-8")
    while True:
        digest = hashlib.sha256(seed).digest()
        key_int = int.from_bytes(digest, "big")
        if 0 < key_int < SECP256K1_ORDER:
            return digest
        seed = digest


def _ripemd160_digest(data: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        from Crypto.Hash import RIPEMD160

        digest = RIPEMD160.new()
        digest.update(data)
        return digest.digest()


def _public_key_hash160(public_key: bytes) -> bytes:
    sha256_digest = hashlib.sha256(public_key).digest()
    return _ripemd160_digest(sha256_digest)


def derive_utxo_address_from_key(private_key: bytes, version_byte: bytes) -> str:
    signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key = b"\x04" + verifying_key.to_string()
    ripemd160_digest = _public_key_hash160(public_key)
    payload = version_byte + ripemd160_digest
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode("ascii")


def derive_utxo_address(passphrase: str, version_byte: bytes) -> str:
    return derive_utxo_address_from_key(passphrase_to_private_key(passphrase), version_byte)


def derive_ethereum_address_from_key(private_key: bytes) -> str:
    return Account.from_key(private_key).address


def derive_ethereum_address(passphrase: str) -> str:
    return derive_ethereum_address_from_key(passphrase_to_private_key(passphrase))


def derive_tron_address_from_eth(eth_address: str) -> str:
    addr_bytes = bytes.fromhex(eth_address[2:])
    payload = b"\x41" + addr_bytes
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode("ascii")


def derive_tron_address(passphrase: str) -> str:
    return derive_tron_address_from_eth(derive_ethereum_address(passphrase))


def derive_solana_address(passphrase: str) -> str:
    if not SOLANA_AVAILABLE or Ed25519SigningKey is None:
        raise RuntimeError("Solana support requires PyNaCl. Run: python -m pip install PyNaCl")
    seed = hashlib.sha256(passphrase.encode("utf-8")).digest()[:32]
    signing_key = Ed25519SigningKey(seed)
    pubkey = bytes(signing_key.verify_key)
    return base58.b58encode(pubkey).decode("ascii")


def derive_address(passphrase: str, chain: Chain) -> str:
    if chain in UTXO_VERSION_BYTES:
        return derive_utxo_address(passphrase, UTXO_VERSION_BYTES[chain])
    if chain in EVM_CHAINS:
        return derive_ethereum_address(passphrase)
    if chain == "Tron":
        return derive_tron_address(passphrase)
    if chain == "Solana":
        return derive_solana_address(passphrase)
    raise ValueError(f"Unsupported chain: {chain}")


def derive_all_addresses(passphrase: str) -> dict[Chain, str]:
    private_key = passphrase_to_private_key(passphrase)
    eth_address = derive_ethereum_address_from_key(private_key)
    addresses: dict[Chain, str] = {}

    for chain, version_byte in UTXO_VERSION_BYTES.items():
        addresses[chain] = derive_utxo_address_from_key(private_key, version_byte)

    for chain in EVM_CHAINS:
        addresses[chain] = eth_address

    addresses["Tron"] = derive_tron_address_from_eth(eth_address)

    if SOLANA_AVAILABLE:
        addresses["Solana"] = derive_solana_address(passphrase)

    return addresses


def _format_coin_amount(raw: int, divisor: int, symbol: str) -> str:
    amount = raw / divisor
    return f"{amount:.8f} {symbol}"


def _btc_stats_from_payload(data: dict) -> tuple[int, int]:
    funded = data["chain_stats"]["funded_txo_sum"]
    spent = data["chain_stats"]["spent_txo_sum"]
    balance_sats = funded - spent
    tx_count = data["chain_stats"]["tx_count"]
    return balance_sats, tx_count


def _check_utxo_mempool_style(
    chain: Chain, address: str, url: str, response: requests.Response
) -> BlockchainResult:
    balance_sats, tx_count = _btc_stats_from_payload(response.json())
    explorer = UTXO_EXPLORERS[chain]
    symbol = "LTC" if chain == "Litecoin" else "DOGE" if chain == "Dogecoin" else "BCH" if chain == "Bitcoin Cash" else "BTC"
    return BlockchainResult(
        chain=chain,
        address=address,
        balance=_format_coin_amount(balance_sats, 100_000_000, symbol),
        balance_raw=balance_sats,
        transaction_count=tx_count,
        explorer_url=explorer.format(address=address),
        has_activity=balance_sats > 0 or tx_count > 0,
        has_balance=balance_sats > 0,
    )


def _fetch_utxo_from_url(chain: Chain, address: str, template: str, timeout: float) -> BlockchainResult:
    url = template.format(address=address)
    session = _get_session()
    response = session.get(url, timeout=timeout)
    response.raise_for_status()
    return _parse_utxo_response(chain, address, url, response)


def check_utxo_address(
    chain: Chain,
    address: str,
    timeout: float = TIMEOUT_SECONDS,
    try_all_apis: bool = True,
) -> BlockchainResult:
    errors: list[str] = []
    templates = UTXO_APIS[chain] if try_all_apis else UTXO_APIS[chain][:1]
    for template in templates:
        try:
            return _fetch_utxo_from_url(chain, address, template, timeout)
        except Exception as exc:
            errors.append(f"{template.format(address=address)}: {exc}")
    raise RuntimeError(f"All {chain} APIs failed. " + " | ".join(errors))


def _parse_utxo_response(
    chain: Chain,
    address: str,
    url: str,
    response: requests.Response,
) -> BlockchainResult:
    payload = response.json()

    if "rest.bitcoin.com" in url:
        balance_sats = int(float(payload.get("confirmed", 0)) * 100_000_000)
        return BlockchainResult(
            chain=chain,
            address=address,
            balance=_format_coin_amount(balance_sats, 100_000_000, "BCH"),
            balance_raw=balance_sats,
            transaction_count=0,
            explorer_url=UTXO_EXPLORERS[chain].format(address=address),
            has_activity=balance_sats > 0,
            has_balance=balance_sats > 0,
        )

    if "blockchair.com" in url:
        address_data = payload["data"][address]["address"]
        balance_sats = int(address_data.get("balance", 0))
        tx_count = int(address_data.get("transaction_count", 0))
        symbol = "BCH" if chain == "Bitcoin Cash" else "DOGE" if chain == "Dogecoin" else "BTC"
        return BlockchainResult(
            chain=chain,
            address=address,
            balance=_format_coin_amount(balance_sats, 100_000_000, symbol),
            balance_raw=balance_sats,
            transaction_count=tx_count,
            explorer_url=UTXO_EXPLORERS[chain].format(address=address),
            has_activity=balance_sats > 0 or tx_count > 0,
            has_balance=balance_sats > 0,
        )

    if "blockcypher.com" in url:
        balance_sats = int(payload.get("balance", 0))
        tx_count = int(payload.get("n_tx", 0))
        symbol = "LTC" if chain == "Litecoin" else "DOGE"
        return BlockchainResult(
            chain=chain,
            address=address,
            balance=_format_coin_amount(balance_sats, 100_000_000, symbol),
            balance_raw=balance_sats,
            transaction_count=tx_count,
            explorer_url=UTXO_EXPLORERS[chain].format(address=address),
            has_activity=balance_sats > 0 or tx_count > 0,
            has_balance=balance_sats > 0,
        )

    if "dogechain.info" in url:
        balance_sats = int(float(payload.get("balance", 0)) * 100_000_000)
        return BlockchainResult(
            chain=chain,
            address=address,
            balance=_format_coin_amount(balance_sats, 100_000_000, "DOGE"),
            balance_raw=balance_sats,
            transaction_count=0,
            explorer_url=UTXO_EXPLORERS[chain].format(address=address),
            has_activity=balance_sats > 0,
            has_balance=balance_sats > 0,
        )

    return _check_utxo_mempool_style(chain, address, url, response)


def _eth_rpc_call(rpc_url: str, method: str, params: list, timeout: float = TIMEOUT_SECONDS) -> str:
    session = _get_session()
    response = session.post(
        rpc_url,
        json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    if "error" in payload:
        raise RuntimeError(payload["error"]["message"])
    return payload["result"]


def _eth_rpc_batch(
    rpc_url: str,
    calls: list[tuple[str, list]],
    timeout: float = TIMEOUT_SECONDS,
) -> list[str]:
    session = _get_session()
    payload = [
        {"jsonrpc": "2.0", "method": method, "params": params, "id": index + 1}
        for index, (method, params) in enumerate(calls)
    ]
    response = session.post(rpc_url, json=payload, timeout=timeout)
    response.raise_for_status()
    results = response.json()
    if not isinstance(results, list):
        raise RuntimeError("Unexpected batch RPC response")
    results.sort(key=lambda item: item["id"])
    values: list[str] = []
    for item in results:
        if "error" in item:
            raise RuntimeError(item["error"]["message"])
        values.append(item["result"])
    return values


def _fetch_evm_from_rpc(
    chain: Chain,
    address: str,
    rpc_url: str,
    timeout: float,
    balance_only: bool,
) -> BlockchainResult:
    config = EVM_CHAINS[chain]
    if balance_only:
        balance_hex = _eth_rpc_call(rpc_url, "eth_getBalance", [address, "latest"], timeout)
        tx_count = 0
    else:
        balance_hex, tx_hex = _eth_rpc_batch(
            rpc_url,
            [
                ("eth_getBalance", [address, "latest"]),
                ("eth_getTransactionCount", [address, "latest"]),
            ],
            timeout,
        )
        tx_count = int(tx_hex, 16)
    wei = int(balance_hex, 16)
    symbol = str(config["symbol"])
    divisor = int(config["divisor"])
    return BlockchainResult(
        chain=chain,
        address=address,
        balance=_format_coin_amount(wei, divisor, symbol),
        balance_raw=wei,
        transaction_count=tx_count,
        explorer_url=str(config["explorer"]).format(address=address),
        has_activity=wei > 0 or tx_count > 0,
        has_balance=wei > 0,
    )


def check_evm_address(
    chain: Chain,
    address: str,
    timeout: float = TIMEOUT_SECONDS,
    balance_only: bool = False,
    try_all_rpcs: bool = True,
) -> BlockchainResult:
    config = EVM_CHAINS[chain]
    errors: list[str] = []
    rpcs = config["rpcs"] if try_all_rpcs else config["rpcs"][:1]

    for rpc_url in rpcs:
        try:
            return _fetch_evm_from_rpc(chain, address, rpc_url, timeout, balance_only)
        except Exception as exc:
            errors.append(f"{rpc_url}: {exc}")

    raise RuntimeError(f"All {chain} RPC endpoints failed. " + " | ".join(errors))


def check_tron_address(address: str, timeout: float = TIMEOUT_SECONDS) -> BlockchainResult:
    errors: list[str] = []
    session = _get_session()

    for template in TRON_APIS:
        url = template.format(address=address)
        try:
            response = session.get(url, timeout=timeout)
            response.raise_for_status()
            payload = response.json()
            accounts = payload.get("data", [])
            balance_sun = 0
            if accounts:
                balance_sun = int(accounts[0].get("balance", 0))
            return BlockchainResult(
                chain="Tron",
                address=address,
                balance=_format_coin_amount(balance_sun, 1_000_000, "TRX"),
                balance_raw=balance_sun,
                transaction_count=0,
                explorer_url=f"https://tronscan.org/#/address/{address}",
                has_activity=balance_sun > 0,
                has_balance=balance_sun > 0,
            )
        except Exception as exc:
            errors.append(f"{url}: {exc}")

    raise RuntimeError("All Tron APIs failed. " + " | ".join(errors))


def check_solana_address(address: str, timeout: float = TIMEOUT_SECONDS) -> BlockchainResult:
    errors: list[str] = []
    session = _get_session()

    for rpc_url in SOLANA_RPCS:
        try:
            response = session.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getBalance",
                    "params": [address],
                },
                timeout=timeout,
            )
            response.raise_for_status()
            payload = response.json()
            if "error" in payload:
                raise RuntimeError(payload["error"]["message"])
            lamports = int(payload["result"]["value"])
            return BlockchainResult(
                chain="Solana",
                address=address,
                balance=_format_coin_amount(lamports, 1_000_000_000, "SOL"),
                balance_raw=lamports,
                transaction_count=0,
                explorer_url=f"https://solscan.io/account/{address}",
                has_activity=lamports > 0,
                has_balance=lamports > 0,
            )
        except Exception as exc:
            errors.append(f"{rpc_url}: {exc}")

    raise RuntimeError("All Solana RPC endpoints failed. " + " | ".join(errors))


def check_address_on_blockchain(
    chain: Chain,
    address: str,
    timeout: float = TIMEOUT_SECONDS,
    balance_only: bool = False,
) -> BlockchainResult:
    fast = balance_only
    if chain in UTXO_VERSION_BYTES:
        return check_utxo_address(chain, address, timeout, try_all_apis=not fast)
    if chain in EVM_CHAINS:
        return check_evm_address(chain, address, timeout, balance_only=balance_only)
    if chain == "Tron":
        return check_tron_address(address, timeout)
    if chain == "Solana":
        return check_solana_address(address, timeout)
    raise ValueError(f"Unsupported chain: {chain}")


def check_passphrase_on_blockchain(
    passphrase: str,
    chain: Chain,
    timeout: float = TIMEOUT_SECONDS,
    balance_only: bool = False,
) -> BlockchainResult:
    address = derive_address(passphrase, chain)
    return check_address_on_blockchain(chain, address, timeout, balance_only=balance_only)


def check_passphrase_all_chains(
    passphrase: str,
    chains: list[Chain] | None = None,
    max_workers: int | None = None,
    early_exit: bool = False,
    balance_only: bool = False,
    timeout: float | None = None,
) -> list[BlockchainResult]:
    target_chains = chains or MAJOR_CHAINS
    # OPTIMIZED: Use many workers for 10/sec throughput
    worker_count = max_workers or min(len(target_chains) * 3, 64)
    # Use ultra-fast timeout
    request_timeout = timeout if timeout is not None else FAST_TIMEOUT_SECONDS

    addresses = derive_all_addresses(passphrase)
    results: list[BlockchainResult] = []
    pending: dict = {}

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        for chain in target_chains:
            future = executor.submit(
                check_address_on_blockchain,
                chain,
                addresses[chain],
                request_timeout,
                balance_only,
            )
            pending[future] = chain

        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                chain = pending.pop(future)
                try:
                    result = future.result()
                    results.append(result)
                    # Aggressive early exit
                    if early_exit and result.has_balance:
                        for remaining in list(pending.keys()):
                            remaining.cancel()
                        pending.clear()
                        break
                except Exception as exc:
                    results.append(
                        BlockchainResult(
                            chain=chain,
                            address=addresses[chain],
                            balance="Error",
                            balance_raw=0,
                            transaction_count=0,
                            explorer_url="",
                            has_activity=False,
                            has_balance=False,
                            error=str(exc),
                        )
                    )

    results.sort(key=lambda item: MAJOR_CHAINS.index(item.chain))
    return results


def find_balance_on_any_chain(results: list[BlockchainResult]) -> BlockchainResult | None:
    for result in results:
        if result.has_balance:
            return result
    return None


def format_result(result: BlockchainResult) -> str:
    if result.error:
        activity = f"Check failed: {result.error}"
    elif result.has_balance:
        activity = "Balance found"
    elif result.has_activity:
        activity = "On-chain activity, no balance"
    else:
        activity = "No balance or transactions found"

    return (
        f"{result.chain} address: {result.address}\n"
        f"Balance: {result.balance}\n"
        f"Transactions: {result.transaction_count}\n"
        f"Status: {activity}"
    )


def format_results_summary(results: list[BlockchainResult]) -> str:
    lines = []
    for result in results:
        if result.error:
            status = f"error ({result.error})"
        elif result.has_balance:
            status = "BALANCE FOUND"
        elif result.has_activity:
            status = "activity, no balance"
        else:
            status = "empty"
        lines.append(f"{result.chain}: {status} | {result.balance}")
    return "\n".join(lines)
