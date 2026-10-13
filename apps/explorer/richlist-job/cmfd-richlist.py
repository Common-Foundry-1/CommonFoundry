#!/usr/bin/env python3
"""Common Foundry mainnet rich list.

Keeps every unspent output in SQLite by reading blocks (getblock verbosity 2) from
the hosted exchange RPC, follows reorganizations with per-block undo records, and
publishes the largest balances as JSON. A list is published only when the tracked
outputs match the node's own gettxoutsetinfo (count and total) at the same block.

Usage: cmfd-richlist.py --state DIR --credentials FILE [--url URL] [--output FILE]
                         [--once] [--interval SECONDS] [--fetch-threads N] [--top N]
The credentials file holds `username=...` and `password=...` lines.
"""
import argparse
import base64
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SCHEMA = 'CMFD_RICHLIST_V1'
UNDO_DEPTH = 1000  # blocks of undo history kept for reorganizations
BATCH = 200        # blocks fetched per backfill round


def log(*parts):
    print(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), *parts, flush=True)


class Rpc:
    def __init__(self, url, credentials):
        fields = dict(line.strip().split('=', 1) for line in Path(credentials).read_text().splitlines() if '=' in line)
        token = base64.b64encode(f"{fields['username']}:{fields['password']}".encode()).decode()
        self.url, self.headers = url, {'Content-Type': 'application/json', 'Authorization': 'Basic ' + token,
                                       'User-Agent': 'cmfd-richlist/1'}
        self.local = threading.local()

    def call(self, method, *params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
        for attempt in range(8):
            try:
                request = urllib.request.Request(self.url, body, self.headers)
                with urllib.request.urlopen(request, timeout=120) as response:
                    reply = json.load(response)
                if reply.get('error'):
                    data = reply['error'].get('data') or {}
                    if data.get('retryable') and attempt < 7:
                        time.sleep(1 + attempt)
                        continue
                    raise RuntimeError(f'{method}: {reply["error"]}')
                return reply['result']
            except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
                if attempt == 7:
                    raise
                if isinstance(error, urllib.error.HTTPError) and error.code not in (429, 500, 502, 503, 504):
                    raise
                time.sleep(1 + 2 * attempt)


def open_state(directory):
    directory.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(directory / 'state.sqlite', isolation_level=None)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=NORMAL')
    db.executescript('''
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY, hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS utxo(txid TEXT NOT NULL, vout INTEGER NOT NULL, dest TEXT,
            value INTEGER NOT NULL, height INTEGER NOT NULL, PRIMARY KEY(txid, vout)) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS utxo_height ON utxo(height);
        CREATE INDEX IF NOT EXISTS utxo_dest ON utxo(dest);
        CREATE TABLE IF NOT EXISTS undo(height INTEGER NOT NULL, txid TEXT NOT NULL, vout INTEGER NOT NULL,
            dest TEXT, value INTEGER NOT NULL, created INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS undo_height ON undo(height);
    ''')
    return db


def tip(db):
    row = db.execute('SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1').fetchone()
    return (row[0], row[1]) if row else (-1, None)


def outputs(document):
    for output in document['vout']:
        dest = output['destination_hex'] if output['lock_type'] == 'key' else None
        yield output['n'], dest, int(output['value_atoms'])


def apply_block(db, block):
    height, block_hash = block['height'], block['hash']
    db.execute('BEGIN')
    try:
        coinbase = block.get('coinbase')
        if coinbase:
            for n, dest, value in outputs(coinbase):
                db.execute('INSERT INTO utxo VALUES (?,?,?,?,?)', (coinbase['outpoint_txid'], n, dest, value, height))
        for tx in block.get('tx', []):
            for spent in tx['vin']:
                row = db.execute('SELECT dest, value, height FROM utxo WHERE txid=? AND vout=?',
                                 (spent['txid'], spent['vout'])).fetchone()
                if row is None:
                    raise RuntimeError(f'block {height}: input {spent["txid"]}:{spent["vout"]} is not a tracked output')
                db.execute('DELETE FROM utxo WHERE txid=? AND vout=?', (spent['txid'], spent['vout']))
                db.execute('INSERT INTO undo VALUES (?,?,?,?,?,?)', (height, spent['txid'], spent['vout'], *row))
            for n, dest, value in outputs(tx):
                db.execute('INSERT INTO utxo VALUES (?,?,?,?,?)', (tx['txid'], n, dest, value, height))
        db.execute('INSERT INTO blocks VALUES (?,?)', (height, block_hash))
        # Undo records below the floor are dropped; blocks at or below it can no longer be disconnected.
        floor = height - UNDO_DEPTH
        db.execute('DELETE FROM undo WHERE height <= ?', (floor,))
        db.execute("INSERT INTO meta VALUES ('undo_floor', ?) ON CONFLICT(key) DO UPDATE SET "
                   "value = MAX(CAST(value AS INTEGER), CAST(excluded.value AS INTEGER))", (str(floor),))
        db.execute('COMMIT')
    except BaseException:
        db.execute('ROLLBACK')
        raise


def disconnect_tip(db):
    height, _ = tip(db)
    floor = db.execute("SELECT value FROM meta WHERE key='undo_floor'").fetchone()
    if height < 0 or (floor is not None and height <= int(floor[0])):
        raise RuntimeError('reorganization deeper than the undo history; rebuild the state')
    db.execute('BEGIN')
    db.execute('DELETE FROM utxo WHERE height=?', (height,))
    db.execute('INSERT INTO utxo SELECT txid, vout, dest, value, created FROM undo WHERE height=?', (height,))
    db.execute('DELETE FROM undo WHERE height=?', (height,))
    db.execute('DELETE FROM blocks WHERE height=?', (height,))
    db.execute('COMMIT')
    log('disconnected block', height)


def fetch_range(rpc, start, end, threads):
    """Blocks start..end inclusive, in order; threads walk contiguous slices via nextblockhash."""
    heights = list(range(start, end + 1))
    size = max(1, -(-len(heights) // threads))
    slices = [heights[i:i + size] for i in range(0, len(heights), size)]

    def walk(part):
        found, block_hash = [], rpc.call('getblockhash', part[0])
        for expected in part:
            block = rpc.call('getblock', block_hash, 2)
            if block['height'] != expected:
                raise RuntimeError(f'expected height {expected}, got {block["height"]}')
            found.append(block)
            block_hash = block.get('nextblockhash')
            if block_hash is None and expected != part[-1]:
                raise RuntimeError('chain ended inside a fetch slice')
        return found

    with ThreadPoolExecutor(len(slices)) as pool:
        for part in pool.map(walk, slices):
            yield from part


def sync(db, rpc, threads):
    node_tip = rpc.call('getblockcount')
    # Follow reorganizations: drop our blocks that are no longer on the endpoint's active chain.
    while True:
        height, block_hash = tip(db)
        if height < 0 or height > node_tip:
            if height > node_tip:
                disconnect_tip(db)
                continue
            break
        if rpc.call('getblockhash', height) == block_hash:
            break
        disconnect_tip(db)
    height, block_hash = tip(db)
    while height < node_tip:
        end = min(node_tip, height + BATCH)
        for block in fetch_range(rpc, height + 1, end, threads if end - height > threads else 1):
            if block['height'] > 0 and block['previousblockhash'] != tip(db)[1]:
                return False  # the chain moved under us; the next round reorganizes
            apply_block(db, block)
        height, block_hash = tip(db)
        log('synced to', height, 'of', node_tip)
    return True


def build_list(db, rpc, top):
    """The list for our tip, or None unless gettxoutsetinfo describes exactly the same block."""
    height, block_hash = tip(db)
    info = rpc.call('gettxoutsetinfo')
    if info['height'] != height or info['bestblock'] != block_hash:
        return None
    count, total = db.execute('SELECT COUNT(*), COALESCE(SUM(value), 0) FROM utxo').fetchone()
    if count != info['txouts'] or str(total) != str(info['total_amount_atoms']):
        raise RuntimeError(f'state disagrees with the node at {height}: {count} outputs / {total} atoms vs '
                           f'{info["txouts"]} / {info["total_amount_atoms"]}')
    holders = db.execute('SELECT COUNT(*) FROM (SELECT dest FROM utxo WHERE dest IS NOT NULL GROUP BY dest)').fetchone()[0]
    unkeyed = db.execute('SELECT COALESCE(SUM(value), 0) FROM utxo WHERE dest IS NULL').fetchone()[0]
    rows = db.execute('''SELECT dest, SUM(value) AS balance, COUNT(*) FROM utxo WHERE dest IS NOT NULL
                         GROUP BY dest ORDER BY balance DESC, dest LIMIT ?''', (top,)).fetchall()
    return {
        'schema': SCHEMA,
        'height': height,
        'block_hash': block_hash,
        'generated_at': int(time.time()),
        'total_supply_atoms': str(total),
        'unspent_outputs': count,
        'addresses_with_balance': holders,
        'unkeyed_atoms': str(unkeyed),
        'verified_against_node': True,
        'top': [{'rank': i + 1, 'address': dest, 'balance_atoms': str(balance), 'outputs': n}
                for i, (dest, balance, n) in enumerate(rows)],
    }


def publish(document, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(document, separators=(',', ':')) + '\n').encode()
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.richlist-')
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--url', default='https://sg-rpc.commonfoundry.ai/mainnet')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--interval', type=float, default=30)
    parser.add_argument('--fetch-threads', type=int, default=2)
    parser.add_argument('--top', type=int, default=250)
    args = parser.parse_args()
    rpc = Rpc(args.url, args.credentials)
    db = open_state(args.state)
    output = args.output or args.state / 'richlist.json'
    while True:
        try:
            if sync(db, rpc, max(1, args.fetch_threads)):
                document = build_list(db, rpc, args.top)
                if document is None:
                    log('node moved during the check; retrying next round')
                else:
                    publish(document, output)
                    log('published height', document['height'], 'holders', document['addresses_with_balance'])
        except Exception as error:  # keep the service alive; the last good list stays published
            log('error:', error)
            if args.once:
                raise
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == '__main__':
    main()
