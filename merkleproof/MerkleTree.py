"""
Python library allowing creation of Merkle trees and output receipts in a format consistent with the chainpoint v2
standard. Also allows validation of a Merkle receipt.

This was developed in support of the Blockchain Certificates project (http://www.blockcerts.org/). It supports only
a subset of the Chainpoint v2 standard.
"""
import math
from merkleproof.utils import get_buffer, validate_proof, hexlify
from merkleproof.hash_functions import *


class MerkleTree:
    """
    Enables building a merkle tree, from which you can generate merkle proofs.
    """
    def __init__(self, hash_f=sha256):
        """
        Initialize Merkle tree. Defaults to SHA256.
        """
        self.tree = {}
        self.reset_tree()
        self.hash_f = hash_f

    def reset_tree(self):
        """
        Resets the current tree to empty.
        """
        self.tree = {}
        self.tree['leaves'] = []
        self.tree['levels'] = []
        self.tree['is_ready'] = False

    def add_leaf(self, value, do_hash=False):
        """
        Add a leaf to the tree.
        :param value: hash value (as a Buffer) or hex string
        :param do_hash: whether to hash value
        """
        self.tree['is_ready'] = False
        self._add_leaf(value, do_hash)

    def add_leaves(self, values_array, do_hash=False):
        """
        Add leaves to the tree.

        Similar to chainpoint merkle tree library, this accepts hash values as an array of Buffers or hex strings.
        :param values_array: array of values to add
        :param do_hash: whether to hash the values before inserting
        """
        self.tree['is_ready'] = False
        [self._add_leaf(value, do_hash) for value in values_array]

    def get_leaf(self, index):
        """
        Returns a leaf at the given index.
        :param index:
        :return: leaf (value) at index
        """
        leaf_level_index = len(self.tree['levels']) - 1
        if index < 0 or index > len(self.tree['levels'][leaf_level_index]) - 1:
            # index is out of bounds
            return None
        return self.tree['levels'][leaf_level_index][index]

    def get_leaf_count(self):
        """
        Returns the number of leaves added to the tree.
        :return:
        """
        return len(self.tree['leaves'])

    def get_tree_ready_state(self):
        """
        Returns the ready state of the tree.
        :return:
        """
        return self.tree['is_ready']

    def make_tree(self):
        """
        Generates the merkle tree.
        """
        self.tree['is_ready'] = False
        leaf_count = len(self.tree['leaves'])
        if leaf_count > 0:
            # skip this whole process if there are no leaves added to the tree
            self._unshift(self.tree['levels'], self.tree['leaves'])
            while len(self.tree['levels'][0]) > 1:
                self._unshift(self.tree['levels'], self._calculate_next_level())
        self.tree['is_ready'] = True

    def get_merkle_root(self):
        """
        Returns the merkle root value for the tree
        :return: merkle root value
        """
        if not self.tree['is_ready'] or not self.tree['levels']:
            return None
        return hexlify(self.tree['levels'][0][0])

    def get_proof(self, index):
        """
        Returns the proof for a leaf at the given index as an array of merkle siblings in hex format
        :param index:
        :return:
        """

        if not self.tree['is_ready']:
            return None
        current_row_index = len(self.tree['levels']) - 1
        if index < 0 or index > len(self.tree['levels'][current_row_index]) - 1:
            # the index it out of the bounds of the leaf array
            return None

        proof = []
        for current_level in range(current_row_index, 0, -1):
            current_level_node_count = len(self.tree['levels'][current_level])
            # skip if this is an odd end node
            if index == current_level_node_count - 1 and current_level_node_count % 2 == 1:
                index = int(math.floor(index / 2))
                continue

            # determine the sibling for the current index and get its value
            is_right_node = index % 2
            if is_right_node:
                sibling_index = index - 1
            else:
                sibling_index = index + 1
            sibling = {}

            if is_right_node:
                sibling_position = 'left'
            else:
                sibling_position = 'right'

            sibling_value = self.tree['levels'][current_level][sibling_index]
            sibling[sibling_position] = hexlify(sibling_value)

            proof.append(sibling)

            index = int(math.floor(index / 2))  # set index to the parent index

        return proof

    def make_receipt(self, index, txid):
        receipt = {
            '@context': 'https://w3id.org/chainpoint/v2',
            'type': 'ChainpointSHA256v2',
            'targetHash': hexlify(self.get_leaf(index)),
            'merkleRoot': self.get_merkle_root(),
            'proof': self.get_proof(index),
            'anchors': [
                {
                    'type': 'BTCOpReturn',
                    'sourceId': txid
                }
            ]
        }
        return receipt

    def validate_proof(self, proof, target_hash, merkle_root):
        """
        Takes a proof array, a target hash value, and a merkle root
        Checks the validity of the proof and return true or false
        :param proof:
        :param target_hash:
        :param merkle_root:
        :return:
        """
        return validate_proof(proof, target_hash, merkle_root, self.hash_f)

    def _add_leaf(self, value, do_hash):
        if do_hash:
            value = self.hash_f(value)
        value = get_buffer(value)
        self.tree['leaves'].append(value)

    def _calculate_next_level(self):
        nodes = []
        top_level = self.tree['levels'][0]
        top_level_count = len(top_level)
        for x in range(0, top_level_count, 2):
            if x + 1 <= top_level_count - 1:
                # concatenate and hash the pair, add to the next level array
                nodes.append(get_buffer(self.hash_f(top_level[x] + top_level[x + 1])))
            else:
                # this is an odd ending node, promote up to the next level by itself
                nodes.append(top_level[x])
        return nodes

    def _unshift(self, arg1, arg2):
        """
        TODO: this naive unshift equivalent in python is inefficient; replace with a deque implementation
        :param arg1:
        :param arg2:
        :return:
        """
        arg1.insert(0, arg2)