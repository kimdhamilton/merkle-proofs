"""
SHA3 functionality is currently not implemented...
"""
import unittest

from merkleproof.MerkleTree import MerkleTree


class MerkleTreeTest(unittest.TestCase):
    def test_make_SHA3_224_tree_with_2_leaves(self):
        tree = MerkleTree({'hashType': 'SHA3-224'})
        tree.add_leaves([
            '6ed712b9472b671fd70bb950dc4ccfce197c92a7969f6bc2aa6b6d9f',
            '08db5633d406804d044a3e67683e179b5ee51249ed2139c239d1e65a'
        ])
        tree.make_tree()

        self.validate_merkle_root(tree.get_merkle_root(), '674bc9f53d5c666174cdd3ccb9df04768dfb7759655e7d937aef0c3a')

        def validate_proof_array(self, proof_value, expected):
            self.assertEqual(proof_value, expected, 'proof array should be correct')(tree.get_proof(0)[0]['right'],
                                                                                     '08db5633d406804d044a3e67683e179b5ee51249ed2139c239d1e65a')

        self.validate_proof(tree, 0,
                            '6ed712b9472b671fd70bb950dc4ccfce197c92a7969f6bc2aa6b6d9f',
                            '674bc9f53d5c666174cdd3ccb9df04768dfb7759655e7d937aef0c3a')

    def test_make_SHA3_256_tree_with_2_leaves(self):
        tree = MerkleTree({'hashType': 'SHA3-256'})
        tree.add_leaves([
            '1d7d4ea1cc029ca460e486642830c284657ea0921235c46298b51f0ed1bb7bf7',
            '89b9e14eae37e999b096a6f604adefe7feea4dc240ccecb5e4e92785cffc7070'
        ])
        tree.make_tree()

        self.validate_merkle_root(tree.get_merkle_root(),
                                  '6edf674f5ce762e096c3081aee2a0a977732e07f4d704baf34f5e3804db03343')

        self.validate_proof_array(tree.get_proof(0)[0]['right'],
                                  '89b9e14eae37e999b096a6f604adefe7feea4dc240ccecb5e4e92785cffc7070')

        self.validate_proof(tree, 0,
                            '1d7d4ea1cc029ca460e486642830c284657ea0921235c46298b51f0ed1bb7bf7',
                            '6edf674f5ce762e096c3081aee2a0a977732e07f4d704baf34f5e3804db03343')

    def test_make_SHA3_384_tree_with_2_leaves(self):
        tree = MerkleTree({'hashType': 'SHA3-384'})
        tree.add_leaves([
            'e222605f939aa69b964a0a03d7075676bb3dbb40c3bd10b22f0adcb149434e7c1085c206f0e3371470a49817aa6d5b16',
            'ae331b6f8643ed7e404471c81be9a74f73fc84ffd5140a0ec9aa8596fa0d0a2ded5f7b780bb2fbfc4e2226ee2a04a2fa'
        ])
        tree.make_tree()

        self.validate_merkle_root(tree.get_merkle_root(),
                                  'bd54df0015fa0d4fee713fbf5c8ae232c93239c75fb9d41c7dd7a9278711764a6ee83c81766b3945ed94030254537b57')

        self.validate_proof_array(tree.get_proof(0)[0]['right'],
                                  'ae331b6f8643ed7e404471c81be9a74f73fc84ffd5140a0ec9aa8596fa0d0a2ded5f7b780bb2fbfc4e2226ee2a04a2fa')

        self.validate_proof(tree, 0,
                            'e222605f939aa69b964a0a03d7075676bb3dbb40c3bd10b22f0adcb149434e7c1085c206f0e3371470a49817aa6d5b16',
                            'bd54df0015fa0d4fee713fbf5c8ae232c93239c75fb9d41c7dd7a9278711764a6ee83c81766b3945ed94030254537b57')

    def test_make_SHA3_512_tree_with_2leaves(self):
        tree = MerkleTree({'hashType': 'SHA3-512'})
        tree.add_leaves([
            '004a237ea808cd9375ee9db9f85625948a890c54e2c30f736f54c969074eb56f0ff3d43dafb4b40d5d974acc1c2a68c046fa4d7c2c20cab6df956514040d0b8b',
            '0b43a85d08c05252d0e23c96bc6b1bda11dfa787049ff452b3c86f4c6135e870c058c05131f199ef8619cfac937a736bbc936a667e4d96a5bf68e4056ce5fdce'
        ])
        tree.make_tree()

        self.validate_merkle_root(tree.get_merkle_root(),
                                  '3dff3f19b67628591d294cba2c07ed20d20d83e1624af8c1dca8fcf096127b9f86435e2d6a84ca4cee526525cacd1c628bf06ee938983413afafbb4598c5862a')

        self.validate_proof_array(tree.get_proof(0)[0]['right'],
                                  '0b43a85d08c05252d0e23c96bc6b1bda11dfa787049ff452b3c86f4c6135e870c058c05131f199ef8619cfac937a736bbc936a667e4d96a5bf68e4056ce5fdce')

        self.validate_proof(tree, 0,
                            '004a237ea808cd9375ee9db9f85625948a890c54e2c30f736f54c969074eb56f0ff3d43dafb4b40d5d974acc1c2a68c046fa4d7c2c20cab6df956514040d0b8b',
                            '3dff3f19b67628591d294cba2c07ed20d20d83e1624af8c1dca8fcf096127b9f86435e2d6a84ca4cee526525cacd1c628bf06ee938983413afafbb4598c5862a')
