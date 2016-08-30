"""
These tests cases include the following:
- updated versions of the original (chainpoint v1 library tests)[https://github.com/aantonop/chainpoint].
The results and expectations changed in some cases. The new expectations shown here were validated against Tierion's
merkle-tools nodejs library.
- test cases from merkle-tools nodejs library ported to python. Expectations are the same.

"""
import unittest

from merkleproof.MerkleTree import MerkleTree
from merkleproof.hash_functions import sha256, md5, sha512, sha384, sha224


class MerkleTreeTest(unittest.TestCase):

    def test_two_even_items(self):
        tree = MerkleTree()

        tree.add_leaf('test', True)
        tree.add_leaf(tree.hash_f('test2'))
        tree.make_tree()

        ans = 'a0f6cfae7a24aaf251208954f67cbc0d9b87fb19e07d89a6d157fcce5ca558e9'
        self.assertEqual(tree.get_merkle_root(), ans)


    def test_proof_true(self):
        tree = MerkleTree()

        tree.add_leaf('test', True)
        tree.add_leaf('test2', True)
        tree.add_leaf('test3', True)
        tree.make_tree()

        proof = tree.get_proof(0)
        self.assertTrue(tree.validate_proof(proof, sha256('test'), tree.get_merkle_root()))

    def test_proof_false(self):
        tree = MerkleTree()

        tree.add_leaf('test1', True)
        tree.add_leaf('test2', True)
        tree.add_leaf('test3', True)
        tree.make_tree()

        proof = tree.get_proof(4)
        result = tree.validate_proof(proof, sha256('test'), tree.get_merkle_root())
        self.assertFalse(result)

    def test_proof_single_true(self):
        tree = MerkleTree()
        tree.add_leaf('test', True)
        tree.make_tree()
        proof = tree.get_proof(0)
        target = sha256('test')
        self.assertTrue(tree.validate_proof(proof, target, tree.get_merkle_root()))

    def test_proof_single_false(self):
        tree = MerkleTree()
        tree.add_leaf('test', True)
        tree.make_tree()
        proof = tree.get_proof(1)
        self.assertFalse(tree.validate_proof(proof, sha256('test9'), tree.get_merkle_root()))

    def test_merkle_proof_simple_true(self):
        tree = MerkleTree()
        tree.add_leaf('test', True)
        tree.add_leaf('test2', True)
        tree.make_tree()

        left = sha256('test')

        proof = tree.get_proof(0)
        self.assertTrue(tree.validate_proof(proof, left, tree.get_merkle_root()))

    def test_merkle_proof_simple_false(self):
        tree = MerkleTree()
        tree.add_leaf('test', True)
        tree.add_leaf('test2', True)

        left = sha256('test')
        right = sha256('test2')
        # branch = MerkleBranch(left, right)

        # target = sha256('notinproof')
        # proof = MerkleProof(target, tree)
        # proof.add(branch)
        # tree.make_tree()
        # self.assertFalse(proof.is_valid())

    def test_large_tree(self):
        tree = MerkleTree()
        for i in range(10000):
            tree.add_leaf((str(i)), True)

        tree.make_tree()
        ans = 'e08a41fa2a658af6f552d22570da0e9511230e4c81d421ca7f206e76770045d6'
        self.assertEqual(tree.get_merkle_root(), ans)

    def test_proof_get_json(self):
        tree = MerkleTree()

        tree.add_leaf('test', True)
        tree.add_leaf('test2', True)
        tree.add_leaf('test3', True)
        tree.make_tree()

        json_data = tree.get_proof(0)

        self.assertEqual(json_data[0]["right"], '60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752')
        self.assertEqual(json_data[1]["right"], 'fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13')

    def test_tree_odd_items(self):
        tree = MerkleTree()

        tree.add_leaf('test', True)
        tree.add_leaf('test2', True)
        tree.add_leaf('test3', True)
        tree.make_tree()

        ans = 'ab56cfafe1f1a8c4d5a526a754a07513ab92266ccdc25295e5c6e468b7e8a807'
        self.assertEqual(tree.get_merkle_root(), ans)


class MerkleTreeTest(unittest.TestCase):
    bLeft = bytearray.fromhex('a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb')
    bRight = bytearray.fromhex('cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c')
    mRoot = sha256(bLeft + bRight)

    bLeftmd5 = bytearray.fromhex('0cc175b9c0f1b6a831c399e269772661')
    bRightmd5 = bytearray.fromhex('92eb5ffee6ae2fec3ad71c777531578f')
    mRootmd5 = md5(bLeftmd5 + bRightmd5)

    def test_make_tree_no_leaves(self):
        tree = MerkleTree()
        tree.make_tree()
        self.assertEqual(tree.get_merkle_root(), None, 'merkle root value should be null')

    def test_make_tree_add_leaves_hex(self):
        tree = MerkleTree()
        tree.add_leaves([
            'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb',
            'cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c'
        ])
        tree.make_tree()
        self.assertEqual(tree.get_merkle_root(), self.mRoot, 'merkle root value should be correct')

    def test_make_tree_add_leaves_buffers(self):
        tree = MerkleTree()
        tree.add_leaves([
            self.bLeft,
            self.bRight
        ])
        tree.make_tree()
        self.assertEqual(tree.get_merkle_root(), self.mRoot, 'merkle root value should be correct')

    def test_reset_tree(self):
        tree = MerkleTree()
        tree.add_leaves([
            'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb',
            'cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c'
        ])
        tree.make_tree()
        tree.reset_tree()
        self.assertEqual(tree.get_leaf_count(), 0, 'tree should be empty after reset')
        self.assertFalse(tree.get_tree_ready_state(), 'tree should be empty after reset')

    def test_make_tree_with_add_leaf_hex(self):
        tree = MerkleTree()
        tree.add_leaf('a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb')
        tree.add_leaf('cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c')
        tree.make_tree()

        self.assertEqual(tree.get_merkle_root(), self.mRoot, 'merkle root value should be correct')

        hashes = []
        hashes.append('a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb')
        hashes.append('cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c')

        tree = MerkleTree()
        tree.add_leaves(hashes)
        tree.make_tree()
        targetProof0 = tree.get_proof(0)
        targetProof1 = tree.get_proof(1)

        self.assertEqual(tree.get_merkle_root(), self.mRoot, 'merkle root value should be correct')
        self.assertEqual(len(targetProof0), 1, 'merkle root value should be correct')
        self.assertEqual(len(targetProof1), 1, 'merkle root value should be correct')

    def make_tree_with_add_leaf_buffers(self):
        tree = MerkleTree()
        tree.add_leaf(self.bLeft)
        tree.add_leaf(self.bRight)
        tree.make_tree()

        self.assertEqual(tree.get_merkle_root(), self.mRoot, 'merkle root value should be correct')

    def make_tree_with_add_leaf_bad_hex(self):
        tree = MerkleTree()

        self.assertRaises(Exception, tree.add_leaf('nothexandnothashed'))

    def make_tree_with_1_leaf(self):
        tree = MerkleTree()
        tree.add_leaves([
            'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'
        ])
        tree.make_tree()

        self.assertEqual(tree.get_merkle_root(),
                         'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
                         'merkle root value should be correct')

    def test_make_tree_with_5_leaves(self):
        tree = MerkleTree()
        tree.add_leaves([
            'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
            '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
            '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6',
            '18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4',
            '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea'
        ])
        tree.make_tree()

        self.assertEqual(tree.get_merkle_root(), 'd71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba',
                         'merkle root value should be correct')

    def test_make_tree_with_5_leaves_individually_needing_hashing(self):
        tree = MerkleTree()
        tree.add_leaf('a', True)
        tree.add_leaf('b', True)
        tree.add_leaf('c', True)
        tree.add_leaf('d', True)
        tree.add_leaf('e', True)
        tree.make_tree()

        self.assertEqual(tree.get_merkle_root(), 'd71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba',
                         'merkle root value should be correct')

    def test_make_tree_with_5_leaves_at_once_needing_hashing(self):
        tree = MerkleTree()
        tree.add_leaves(['a', 'b', 'c', 'd', 'e'], True)
        tree.make_tree()

        self.assertEqual(tree.get_merkle_root(), 'd71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba',
                         'merkle root value should be correct')

    def test_make_tree_using_md5(self):
        tree = MerkleTree(md5)
        tree.add_leaves([self.bLeftmd5, self.bRightmd5])
        tree.make_tree()

        self.assertEqual(tree.get_merkle_root(), self.mRootmd5, 'merkle root value should be correct')

    def test_proof_left_node(self):
        tree = MerkleTree()
        tree.add_leaf(self.bLeft)
        tree.add_leaf(self.bRight)
        tree.make_tree()
        proof = tree.get_proof(0)
        self.assertEqual(proof[0]['right'], 'cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c',
                         'proof array should be correct')

    def test_proof_right_node(self):
        tree = MerkleTree()
        tree.add_leaf(self.bLeft)
        tree.add_leaf(self.bRight)
        tree.make_tree()
        proof = tree.get_proof(1)

        self.assertEqual(proof[0]['left'], 'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb',
                         'proof array should be correct')

    def test_proof_one_node(self):
        tree = MerkleTree()
        tree.add_leaf(self.bLeft)
        tree.make_tree()
        proof = tree.get_proof(0)

        self.assertEqual(proof, [], 'proof array should be correct')

    def test_validate_bad_proof_2_leaves(self):
        tree = MerkleTree()
        tree.add_leaf(self.bLeft)
        tree.add_leaf(self.bRight)
        tree.make_tree()
        proof = tree.get_proof(1)
        isValid = tree.validate_proof(proof, self.bRight,
                                      'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb')

        self.assertFalse(isValid, 'proof should be invalid')

    def test_validate_bad_proof_5_leaves(self):
        tree = MerkleTree()
        tree.add_leaves([
            'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
            '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
            '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6',
            '18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4',
            '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea'
        ])
        tree.make_tree()
        proof = tree.get_proof(3)
        isValid = tree.validate_proof(proof, 'badc3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4',
                                      'd71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba')

        self.assertFalse(isValid, 'proof should be invalid')

    def test_validate_good_proof_5_leaves(self):
        tree = MerkleTree()
        tree.add_leaves([
            'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
            '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
            '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6',
            '18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4',
            '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea'
        ])
        tree.make_tree()
        proof = tree.get_proof(4)
        isValid = tree.validate_proof(proof, '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea',
                                      'd71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba')

        self.assertTrue(isValid, 'proof should be valid')

    def test_validate_good_proof_5_leaves_B(self):
        tree = MerkleTree()
        tree.add_leaves([
            'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
            '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
            '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6',
            '18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4',
            '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea'
        ])
        tree.make_tree()
        proof = tree.get_proof(1)
        isValid = tree.validate_proof(proof, '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
                                      'd71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba')

        self.assertTrue(isValid, 'proof should be valid')

    def test_make_SHA224_tree_with_2_leaves(self):
        tree = MerkleTree(sha224)
        tree.add_leaves([
            '90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809',
            '35f757ad7f998eb6dd3dd1cd3b5c6de97348b84a951f13de25355177'
        ])
        tree.make_tree()

        self.validate_merkle_root(tree.get_merkle_root(), 'f48bc49bb77d3a3b1c8f8a70db693f41d879189cd1919f8326067ad7')

        self.validate_proof_array(tree.get_proof(0)[0]['right'],
                                  '35f757ad7f998eb6dd3dd1cd3b5c6de97348b84a951f13de25355177')

        self.validate_proof(tree, 0,
                            '90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809',
                            'f48bc49bb77d3a3b1c8f8a70db693f41d879189cd1919f8326067ad7')

    def test_make_SHA256_tree_with_2_leaves(self):
        tree = MerkleTree()
        tree.add_leaves([
            '1516f000de6cff5c8c63eef081ebcec2ad2fdcf7034db16045d024a90341e07d',
            'e20af19f85f265579ead2578859bf089c92b76a048606983ad83f27ba8f32f1a'
        ])
        tree.make_tree()

        self.validate_merkle_root(tree.get_merkle_root(),
                                  '77c654b3d1605f78ed091cbd420c939c3feff7d57dc30c171fa45a5a3c81fd7d')

        self.validate_proof_array(tree.get_proof(0)[0]['right'],
                                  'e20af19f85f265579ead2578859bf089c92b76a048606983ad83f27ba8f32f1a')

        self.validate_proof(tree, 0,
                            '1516f000de6cff5c8c63eef081ebcec2ad2fdcf7034db16045d024a90341e07d',
                            '77c654b3d1605f78ed091cbd420c939c3feff7d57dc30c171fa45a5a3c81fd7d'),

    def test_make_SHA384_tree_with_2_leaves(self):
        tree = MerkleTree(sha384)
        tree.add_leaves([
            '84ae8c6367d64899aef44a951edfa4833378b9e213f916c5eb8492cc37cb951c726e334dace7dbe4bb1dc80c1efe33d0',
            '368c89a00446010def75ad7b179cea9a3d24f8cbb7e2755a28638d194809e7b614eb45453665032860b6c1a135fb6e8b'
        ])
        tree.make_tree()

        self.validate_merkle_root(tree.get_merkle_root(),
                                  'c363aa3b824e3f3b927034fab826eff61a9bfa2030ae9fc4598992edf9f3e42f8b497d6742946caf7a771429eb1745cf')

        self.validate_proof_array(tree.get_proof(0)[0]['right'],
                                  '368c89a00446010def75ad7b179cea9a3d24f8cbb7e2755a28638d194809e7b614eb45453665032860b6c1a135fb6e8b')

        self.validate_proof(tree, 0,
                            '84ae8c6367d64899aef44a951edfa4833378b9e213f916c5eb8492cc37cb951c726e334dace7dbe4bb1dc80c1efe33d0',
                            'c363aa3b824e3f3b927034fab826eff61a9bfa2030ae9fc4598992edf9f3e42f8b497d6742946caf7a771429eb1745cf')

    def test_make_SHA512_tree_with_2_leaves(self):
        tree = MerkleTree(sha512)
        tree.add_leaves([
            'c0a8907588c1da716ce31cbef05da1a65986ec23afb75cd42327634dd53d754be6c00a22d6862a42be5f51187a8dff695c530a797f7704e4eb4b473a14ab416e',
            'df1e07eccb2a2d4e1b30d11e646ba13ddc426c1aefbefcff3639405762f216fdcc40a684f3d1855e6d465f99fd9547e53fa8a485f18649fedec5448b45963976'
        ])
        tree.make_tree()

        self.validate_merkle_root(tree.get_merkle_root(),
                                  'd9d27704a3a785d204257bfa2b217a1890e55453b6686f091fa1be8aa2b265bc06c285a909459996e093546677c3f392458d7b1fc34a994a86689ed4100e8337')

        self.validate_proof_array(tree.get_proof(0)[0]['right'],
                                  'df1e07eccb2a2d4e1b30d11e646ba13ddc426c1aefbefcff3639405762f216fdcc40a684f3d1855e6d465f99fd9547e53fa8a485f18649fedec5448b45963976')

        self.validate_proof(tree, 0,
                            'c0a8907588c1da716ce31cbef05da1a65986ec23afb75cd42327634dd53d754be6c00a22d6862a42be5f51187a8dff695c530a797f7704e4eb4b473a14ab416e',
                            'd9d27704a3a785d204257bfa2b217a1890e55453b6686f091fa1be8aa2b265bc06c285a909459996e093546677c3f392458d7b1fc34a994a86689ed4100e8337')

    def validate_merkle_root(self, root_value, expected):
        self.assertEqual(root_value, expected, 'merkle root value should be correct')

    def validate_proof_array(self, proof_value, expected):
        self.assertEqual(proof_value, expected, 'proof array should be correct')

    def validate_proof(self, tree, index, target_hash, root):
        self.assertTrue(tree.validate_proof(tree.get_proof(index),
                                            target_hash,
                                            root),
                        'proof should be valid')
