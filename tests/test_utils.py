import unittest
from merkleproof import utils
from merkleproof.MerkleTree import sha256


class UtilsTest(unittest.TestCase):

    def test_valid_proof(self):
        proof = {
            'targetHash': '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
            'merkleRoot': 'd71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba',
            'proof': [{'left': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'},
                      {'right': 'bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b'},
                      {'right': '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea'}],
            'anchors': [
                {'type': 'BTCOpReturn', 'sourceId': 'b84a92f28cc9dbdc4cd51834f6595cf97f018b925167c299097754780d7dea09'}]
        }
        result = utils.validate_proof(proof['proof'], proof['targetHash'], proof['merkleRoot'], sha256)
        self.assertTrue(result)


