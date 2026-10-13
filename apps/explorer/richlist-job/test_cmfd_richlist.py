"""Unit tests for cmfd-richlist.py against a fake exchange RPC (python -m unittest)."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('richlist', Path(__file__).with_name('cmfd-richlist.py'))
richlist = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(richlist)

A, B, C, D = ('a' * 64, 'b' * 64, 'c' * 64, 'd' * 64)


def out(n, dest, value, lock='key'):
    return {'n': n, 'destination_hex': dest if lock == 'key' else None, 'lock_type': lock, 'value_atoms': str(value)}


class FakeChain:
    """getblockcount / getblockhash / getblock 2 / gettxoutsetinfo over an editable list of blocks."""

    def __init__(self):
        self.blocks = [{'height': 0, 'hash': 'h0', 'tx': []}]

    def add(self, block_hash, miner, txs=(), value=100):
        height = len(self.blocks)
        self.blocks.append({'height': height, 'hash': block_hash, 'previousblockhash': self.blocks[-1]['hash'],
                            'coinbase': {'outpoint_txid': 'cb-' + block_hash, 'vout': [out(0, miner, value)]},
                            'tx': list(txs)})

    def call(self, method, *params):
        if method == 'getblockcount':
            return len(self.blocks) - 1
        if method == 'getblockhash':
            return self.blocks[params[0]]['hash']
        if method == 'getblock':
            index = next(i for i, b in enumerate(self.blocks) if b['hash'] == params[0])
            block = dict(self.blocks[index])
            if index + 1 < len(self.blocks):
                block['nextblockhash'] = self.blocks[index + 1]['hash']
            return block
        if method == 'gettxoutsetinfo':
            spent = {(i['txid'], i['vout']) for b in self.blocks for t in b['tx'] for i in t['vin']}
            outputs = [(o, t['txid']) for b in self.blocks for t in b['tx'] for o in t['vout']]
            outputs += [(o, b['coinbase']['outpoint_txid']) for b in self.blocks if b.get('coinbase') for o in b['coinbase']['vout']]
            live = [int(o['value_atoms']) for o, txid in outputs if (txid, o['n']) not in spent]
            return {'height': len(self.blocks) - 1, 'bestblock': self.blocks[-1]['hash'],
                    'txouts': len(live), 'total_amount_atoms': str(sum(live))}
        raise AssertionError(method)


def spend(txid, inputs, outputs):
    return {'txid': txid, 'vin': [{'txid': t, 'vout': v} for t, v in inputs], 'vout': outputs}


class RichListTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = richlist.open_state(Path(self.directory.name))
        self.chain = FakeChain()

    def tearDown(self):
        self.db.close()
        self.directory.cleanup()

    def balances(self):
        document = richlist.build_list(self.db, self.chain, 10)
        self.assertIsNotNone(document)
        return {row['address']: int(row['balance_atoms']) for row in document['top']}, document

    def test_balances_follow_spends_and_match_the_node(self):
        self.chain.add('h1', A)
        self.chain.add('h2', B, [spend('t1', [('cb-h1', 0)], [out(0, C, 60), out(1, A, 39)])])
        self.chain.add('h3', A, [spend('t2', [('t1', 0)], [out(0, D, 50), out(1, None, 9, 'channel')])])
        self.assertTrue(richlist.sync(self.db, self.chain, 1))
        balances, document = self.balances()
        self.assertEqual(balances, {A: 139, B: 100, D: 50})
        self.assertEqual(document['height'], 3)
        self.assertEqual(document['addresses_with_balance'], 3)
        self.assertEqual(document['unkeyed_atoms'], '9')
        self.assertEqual([row['rank'] for row in document['top']], [1, 2, 3])

    def test_reorganization_restores_spent_outputs(self):
        self.chain.add('h1', A)
        self.chain.add('h2', B, [spend('t1', [('cb-h1', 0)], [out(0, C, 99)])])
        richlist.sync(self.db, self.chain, 1)
        self.assertEqual(self.balances()[0], {B: 100, C: 99})
        # A heavier branch replaces block 2 and carries a different spend of the same coin.
        del self.chain.blocks[2:]
        self.chain.add('h2x', D, [spend('t1x', [('cb-h1', 0)], [out(0, D, 98)])])
        self.chain.add('h3x', D)
        self.assertTrue(richlist.sync(self.db, self.chain, 2))
        self.assertEqual(self.balances()[0], {D: 298})
        # A shorter active chain drops our extra blocks too.
        del self.chain.blocks[3:]
        richlist.sync(self.db, self.chain, 1)
        self.assertEqual(self.balances()[0], {D: 198})

    def test_disagreement_with_the_node_is_refused(self):
        self.chain.add('h1', A)
        richlist.sync(self.db, self.chain, 1)
        self.db.execute("UPDATE utxo SET value = value + 1")
        with self.assertRaises(RuntimeError):
            richlist.build_list(self.db, self.chain, 10)

    def test_a_reorganization_below_the_undo_history_is_refused(self):
        self.chain.add('h1', A)
        richlist.sync(self.db, self.chain, 1)
        self.db.execute("INSERT INTO meta VALUES ('undo_floor', '1') ON CONFLICT(key) DO UPDATE SET value='1'")
        with self.assertRaises(RuntimeError):
            richlist.disconnect_tip(self.db)


if __name__ == '__main__':
    unittest.main()
