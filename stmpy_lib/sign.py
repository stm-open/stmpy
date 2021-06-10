from __future__ import print_function
import six
import hashlib
import os
import time
from random import randint
from binascii import hexlify,unhexlify
from ecdsa import curves, SigningKey
from ecdsa.util import sigencode_der
from .serialize import (
    to_bytes, from_bytes, StreamBaseDecoder, serialize_object, fmt_hex)


__all__ = ('sign_transaction', 'signature_for_transaction')


tfFullyCanonicalSig = 0x80000000

def hash256(data):
    """
        operation twice
    """
    one256 = unhexlify(hashlib.sha256(data).hexdigest())
    return hashlib.sha256(one256).hexdigest()

def get_str(l):
    sss = ""
    while(l>0):
        try:
            l, b = divmod(l, 58)
            sss +=  StreamBaseDecoder.alphabet[b:b+1]
        except Exception:
            print ("get_str error:",six.text_type(b))
            return None
    return sss[::-1]


def sign_transaction(transaction, secret, flag_canonical=True):
    """High-level signing function.hexlify

    - Adds a signature (``TxnSignature``) field to the transaction object.
    - By default will set the ``FullyCanonicalSig`` flag to ``
    """
    if flag_canonical:
        transaction['Flags'] = transaction.get('Flags', 0) | tfFullyCanonicalSig
    sig = signature_for_transaction(transaction, secret)
    transaction['TxnSignature'] = sig
    return transaction


def signature_for_transaction(transaction, secret):
    """Calculate the fully-canonical signature of the transaction.

    Will set the ``SigningPubKey`` as appropriate before signing.

    ``transaction`` is a Python object. The result value is what you
    can insert into as ``TxSignature`` into the transaction structure
    you submit.
    """
    seed = parse_seed(secret)
    key = root_key_from_seed(seed)

    # Apparently the pub key is required to be there.
    transaction['SigningPubKey'] = fmt_hex(ecc_point_to_bytes_compressed(
        key.privkey.public_key.point, pad=True))

    # Convert the transaction to a binary representation
    signing_hash = create_signing_hash(transaction)

    # Create a hex-formatted signature.
    return fmt_hex(ecdsa_sign(key, signing_hash))


def parse_seed(secret):
    """Your Stream secret is a seed from which the true private key can
    be derived.

    The ``Seed.parse_json()`` method of stm-lib supports different
    ways of specifying the seed, including a 32-byte hex value. We just
    support the regular base-encoded secret format given to you by the
    client when creating an account.
    """
    assert secret[0] == 's'
    return StreamBaseDecoder.decode(secret)


def root_key_from_seed(seed):
    """This derives your master key the given seed.

    Implemented in stm-lib as ``Seed.prototype.get_key``
    """
    seq = 0
    while True:
        private_gen = from_bytes(first_half_of_sha512(
            b''.join([seed, to_bytes(seq, 4)])))
        seq += 1
        if curves.SECP256k1.order >= private_gen:
            break

    public_gen = curves.SECP256k1.generator * private_gen

    # Now that we have the private and public generators, we apparently
    # have to calculate a secret from them that can be used as a ECDSA
    # signing key.
    secret = i = 0
    public_gen_compressed = ecc_point_to_bytes_compressed(public_gen)
    while True:
        secret = from_bytes(first_half_of_sha512(
            b"".join([
                public_gen_compressed, to_bytes(0, 4), to_bytes(i, 4)])))
        i += 1
        if curves.SECP256k1.order >= secret:
            break
    secret = (secret + private_gen) % curves.SECP256k1.order

    # The ECDSA signing key object will, given this secret, then expose
    # the actual private and public key we are supposed to work with.
    key = SigningKey.from_secret_exponent(secret, curves.SECP256k1)
    # Attach the generators as supplemental data
    key.private_gen = private_gen
    key.public_gen = public_gen
    return key


def ecdsa_sign(key, signing_hash, **kw):
    """Sign the given data. The key is the secret returned by
    :func:`root_key_from_seed`.

    The data will be a binary coded transaction.
    """
    r, s = key.sign_number(int(signing_hash, 16), **kw)
    r, s = ecdsa_make_canonical(r, s)
    # Encode signature in DER format, as in
    # ``sjcl.ecc.ecdsa.secretKey.prototype.encodeDER``
    der_coded = sigencode_der(r, s, None)
    return der_coded


def ecdsa_make_canonical(r, s):
    """
    Make sure the ECDSA signature is the canonical one.
    """
    # For a canonical signature we want the lower of two possible values for s
    # 0 < s <= n/2
    N = curves.SECP256k1.order
    if not N / 2 >= s:
        s = N - s
    return r, s


def get_stream_from_pubkey(pubkey):
    """
    Given a public key, determine the Stream address.
    """
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(pubkey).digest())
    return StreamBaseDecoder.encode(ripemd160.digest())

def get_secret(extra="FSQF5356dsdsqdfEFEQ3fq4q6dq4s5d"):
    """get a random secret"""
    try:
        rnd = hexlify(os.urandom(256))
        tim = time.time()
        data = "%s%s%s%s"%(rnd, tim, randint(100000000000, 1000000000000), extra)
        if six.PY3:
            data = data.encode()
        res = int(hash256(data), 16)
        seed = '21' + str(res)[:32]
        secretKey = hash256(unhexlify(seed))[:8]
        l = int(seed + secretKey, 16)
    except Exception as e:
        print ("get_secret error:",six.text_type(e))
        return None

    return get_str(l)

def get_stream_from_secret(seed):
    """Another helper. Returns the first stream address from the secret."""
    key = root_key_from_seed(parse_seed(seed))
    pubkey = ecc_point_to_bytes_compressed(key.privkey.public_key.point, pad=True)
    return get_stream_from_pubkey(pubkey)


# From stm-lib:hashprefixes.js
HASH_TX_ID = 0x54584E00  # 'TXN'
HASH_TX_SIGN = 0x53545800  # 'STX'
HASH_TX_SIGN_TESTNET = 0x73747800 # 'stx'

def create_signing_hash(transaction, testnet=False):
    """This is the actual value to be signed.

    It consists of a prefix and the binary representation of the
    transaction.
    """
    prefix = HASH_TX_SIGN_TESTNET if testnet else HASH_TX_SIGN
    return hash_transaction(transaction, prefix)


def hash_transaction(transaction, prefix):
    """Create a hash of the transaction and the prefix.
    """
    binary = first_half_of_sha512(
        to_bytes(prefix, 4) +
        serialize_object(transaction, hex=False))
    return hexlify(binary).upper()


def first_half_of_sha512(*bytes):
    """As per spec, this is the hashing function used."""
    hash = hashlib.sha512()
    for part in bytes:
        hash.update(part)
    return hash.digest()[:256//8]


def ecc_point_to_bytes_compressed(point, pad=False):
    """
    In stm-lib, implemented as a prototype extension
    ``sjcl.ecc.point.prototype.toBytesCompressed`` in ``sjcl-custom``.

    Also implemented as ``KeyPair.prototype._pub_bits``, though in
    that case it explicitly first pads the point to the bit length of
    the curve prime order value.
    """

    header = b'\x02' if point.y() % 2 == 0 else b'\x03'
    bytes = to_bytes(
        point.x(),
        curves.SECP256k1.order.bit_length()//8 if pad else None)
    return b"".join([header, bytes])

