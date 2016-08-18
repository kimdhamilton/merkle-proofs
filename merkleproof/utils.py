import binascii
import sys

unhexlify = binascii.unhexlify
hexlify = binascii.hexlify
if sys.version > '3':
    unhexlify = lambda h: binascii.unhexlify(h.encode('utf8'))
    hexlify = lambda b: binascii.hexlify(b).decode('utf8')

def validate_proof(proof, target_hash, merkle_root, hash_f):
    """
    Takes a proof array, a target hash value, and a merkle root
    Checks the validity of the proof and return true or false
    :param proof:
    :param target_hash:
    :param merkle_root:
    :param hash_f:
    :return:
    """

    if not proof:
        # no siblings, single item tree, so the hash should also be the root
        return target_hash == merkle_root

    target_hash = get_buffer(target_hash)
    merkle_root = get_buffer(merkle_root)

    proof_hash = target_hash
    for x in proof:
        if 'left' in x:
            # then the sibling is a left node
            proof_hash = get_buffer(hash_f(get_buffer(x['left']) + proof_hash))
        elif 'right' in x:
            # then the sibling is a right node
            proof_hash = get_buffer(hash_f(proof_hash + get_buffer(x['right'])))
        else:
            # no left or right designation exists, proof is invalid
            return False

    return hexlify(proof_hash) == hexlify(merkle_root)


def unshift(arg1, arg2):
    arg1.insert(0, arg2)


def is_hex(content):
    """Make sure this is actually a valid hex string."""
    hex_digits = '0123456789ABCDEFabcdef'
    for i in range(len(content)):
        if not content[i] in hex_digits:
            return False
    return True


def get_buffer(value):
    if not type(value) is str:
        # we already have a buffer, so
        return value
    elif is_hex(value):
        # the value is a hex string, convert to buffer and return
        return bytearray.fromhex(value)
    else:
        # the value is neither buffer nor hex string, will not process this, throw error
        raise Exception('Bad hex value - \'' + value + '\'')