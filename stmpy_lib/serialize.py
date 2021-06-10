from binascii import hexlify
from io import BytesIO
from decimal import Decimal
from hashlib import sha256
import types
import six
from six.moves import filter
from six.moves import map
from six.moves import zip
import binascii


__all__ = ('serialize_object',)


##############################################################################
# The following are copied close to verbatim from the stm-lib JavaScript
# source code. We possible could define the types in a simpler way in Python,
# but I want to make it easy to update these structures as the JS lib changes.


# From stm-lib:binformat.js:exports.ledger
LEDGER_ENTRY_TYPES = {
    'AccountRoot': [97],
    'Contract': [99],
    'DirectoryNode': [100],
    'Features': [102],
    'GeneratorMap': [103],
    'LedgerHashes': [104],
    'Nickname': [110],
    'Offer': [111],
    'VStreamState': [114],
    'FeeSettings': [115]
}


# From stm-lib:binformat.js:exports.ter
TRANSACTION_RESULT_VALUES = {
    'tesSUCCESS': 0,
    'tecCLAIM': 100,
    'tecPATH_PARTIAL': 101,
    'tecUNFUNDED_ADD': 102,
    'tecUNFUNDED_OFFER': 103,
    'tecUNFUNDED_PAYMENT': 104,
    'tecFAILED_PROCESSING': 105,
    'tecDIR_FULL': 121,
    'tecINSUF_RESERVE_LINE': 122,
    'tecINSUF_RESERVE_OFFER': 123,
    'tecNO_DST': 124,
    'tecNO_DST_INSUF_STM': 125,
    'tecNO_LINE_INSUF_RESERVE': 126,
    'tecNO_LINE_REDUNDANT': 127,
    'tecPATH_DRY': 128,
    'tecUNFUNDED': 129,
    'tecMASTER_DISABLED': 130,
    'tecNO_REGULAR_KEY': 131,
    'tecOWNERS': 132
}


# From stm-lib:binformat.js:exports.tx, manually constructed
TRANSACTION_TYPES = {
    'AccountSet': 3,
    'TrustSet': 20,
    'OfferCreate': 7,
    'OfferCancel': 8,
    'SetRegularKey': 5,
    'Payment': 0,
    'Contract': 9,
    'RemoveContract': 10,
    'EnableFeature': 100,
    'SetFee': 101
}


# From stm-lib:serializedtypes.js
# Defines the types the binary format supports and the bits
# representing those types.
TYPES_MAP = [
    None,

    # Common:
    'STInt16',    # 1
    'STInt32',    # 2
    'STInt64',    # 3
    'STHash128',  # 4
    'STHash256',  # 5
    'STAmount',   # 6
    'STVL',       # 7
    'STAccount',  # 8

    # 9-13 reserved
    None,    # 9
    None,    # 10
    None,    # 11
    None,    # 12
    None,    # 13

    'STObject',   # 14
    'STArray',    # 15

    # 'Uncommon':
    'STInt8',     # 16
    'STHash160',  # 17
    'STPathSet',  # 18
    'STVector256' # 19
]


# From stm-lib:serializedtypes.js
FIELDS_MAP = {
    # Common types
    1: {# Int16
        1: 'LedgerEntryType',
        2: 'TransactionType'
    },
    2: {# Int32
        2: 'Flags', 3: 'SourceTag', 4: 'Sequence', 5: 'PreviousTxnLgrSeq',
        6: 'LedgerSequence',
        7: 'CloseTime', 8: 'ParentCloseTime', 9: 'SigningTime',
        10: 'Expiration', 11: 'TransferRate',
        12: 'WalletSize', 13: 'OwnerCount', 14: 'DestinationTag',
        # Skip 15
        16: 'HighQualityIn', 17: 'HighQualityOut', 18: 'LowQualityIn',
        19: 'LowQualityOut',
        20: 'QualityIn', 21: 'QualityOut', 22: 'StampEscrow', 23: 'BondAmount',
        24: 'LoadFee',
        25: 'OfferSequence', 26: 'FirstLedgerSequence',
        27: 'LastLedgerSequence', 28: 'TransactionIndex',
        29: 'OperationLimit', 30: 'ReferenceFeeUnits', 31: 'ReserveBase',
        32: 'ReserveIncrement',
        33: 'SetFlag', 34: 'ClearFlag',
    },
    3: {#  Int64
        1: 'IndexNext', 2: 'IndexPrevious', 3: 'BookNode', 4: 'OwnerNode',
        5: 'BaseFee', 6: 'ExchangeRate', 7: 'LowNode', 8: 'HighNode'
    },
    4: {# Hash128
        1: 'EmailHash'
    },
    5: {# Hash256
        1: 'LedgerHash', 2: 'ParentHash', 3: 'TransactionHash',
        4: 'AccountHash', 5: 'PreviousTxnID',
        6: 'LedgerIndex', 7: 'WalletLocator', 8: 'RootIndex',
        16: 'BookDirectory', 17: 'InvoiceID',
        18: 'Nickname', 19: 'Feature'
    },
    6: {# Amount
        1: 'Amount', 2: 'Balance', 3: 'LimitAmount', 4: 'TakerPays',
        5: 'TakerGets', 6: 'LowLimit',
        7: 'HighLimit', 8: 'Fee', 9: 'SendMax', 16: 'MinimumOffer',
        17: 'StreamEscrow'
    },
    7: {# VL
        1: 'PublicKey', 2: 'MessageKey', 3: 'SigningPubKey', 4: 'TxnSignature',
        5: 'Generator',
        6: 'Signature', 7: 'Domain', 8: 'FundCode', 9: 'RemoveCode',
        10: 'ExpireCode', 11: 'CreateCode',12: 'MemoType',13: 'MemoData'
    },
    8: {# Account
        1: 'Account', 2: 'Owner', 3: 'Destination', 4: 'Issuer', 7: 'Target',
        8: 'RegularKey'
    },
    14: {# Object
         1: None,  # end of Object
         2: 'TransactionMetaData', 3: 'CreatedNode', 4: 'DeletedNode',
         5: 'ModifiedNode',
         6: 'PreviousFields', 7: 'FinalFields', 8: 'NewFields',
         9: 'TemplateEntry',10: 'Memo'
    },
    15: {# Array
         1: None, # end of Array
         2: 'SigningAccounts', 3: 'TxnSignatures', 4: 'Signatures',
         5: 'Template',
         6: 'Necessary', 7: 'Sufficient', 8: 'AffectedNodes', 9: 'Memos'
    },

    # Uncommon types
    16: {# Int8
         1: 'CloseResolution', 2: 'TemplateEntryType', 3: 'TransactionResult'
    },
    17: {# Hash160
         1: 'TakerPaysCurrency', 2: 'TakerPaysIssuer', 3: 'TakerGetsCurrency',
         4: 'TakerGetsIssuer'
    },
    18: {# PathSet
         1: 'Paths'
    },
    19: {# Vector256
         1: 'Indexes', 2: 'Hashes', 3: 'Features'
    }
}


INVERSE_FIELDS_MAP = {
    field_name : [type_bit, field_bit]
    for type_bit, fields in FIELDS_MAP.items()
    for field_bit, field_name in fields.items()
}


def serialize_object(obj, hex=True):
    """This is your main entry point to serialize something."""
    stream = BytesIO()
    TypeSerializers.STObject(stream, obj, no_marker=True)
    stream.seek(0)
    bytes = stream.getvalue()
    if hex:
        return fmt_hex(bytes)
    return bytes


def serialize_field(stream, name, value):
    """Binary encode field ``name`` with ``value``, append to ``stream``.
    """
    type_bits, field_bits = INVERSE_FIELDS_MAP[name]
    tag_byte = (type_bits << 4 if type_bits < 16 else 0) | \
               (field_bits if field_bits < 16 else 0)

    if name == 'LedgerEntryType' and isinstance(value, six.string_types):
        value = LEDGER_ENTRY_TYPES[value][0]

    if name == 'TransactionType' and isinstance(value, six.string_types):
        value = TRANSACTION_TYPES[value]

    if name == 'TransactionResult' and isinstance(value, six.string_types):
        value = TRANSACTION_RESULT_VALUES[value]

    if hasattr(value, '__json__'):
        # This indicates it's from our datastructures module, and we
        # need to save the raw value it represents (ex: Amount object).
        value = value.__json__()

    TypeSerializers.STInt8(stream, tag_byte)
    if type_bits >= 16:
        TypeSerializers.STInt8(stream, type_bits)
    if field_bits >= 16:
        TypeSerializers.STInt8(stream, field_bits)

    type_name = TYPES_MAP[type_bits]
    getattr(TypeSerializers, type_name)(stream, value)


def serialize_hex(stream, hexstring):
    """Serialize a hex-encoded value, i.e. '2AE75B908F0'.

    In stm-lib, this is ``serializedtypes.js:serialize_hex()``.
    """
    serialize_bytes(stream, decode_hex(hexstring))


def serialize_bytes(stream, bytes):
    """Serialize a variable length bytestring."""
    serialize_varint(stream, len(bytes))
    stream.write(bytes)


def UInt160(value):
    # In stm-lib, UInt160 is an address. We simply use a string.
    # This helper is the equivalent of UInt160.to_bytes().
    bytes = StreamBaseDecoder.decode(value, 25) # = 20 bytes w/o header??
    return bytes


def serialize_varint(stream, val):
    """
    In stm-lib, this is ``serializedtypes.js:serialize_varint()``.

    Also described here:
        https://stream.com/wiki/Binary_Format#Variable_Length_Data_Encoding
    """
    def rshift(val, n):
        # http://stackoverflow.com/a/5833119/15677
        return (val % 0x100000000) >> n

    assert val >= 0

    bytes = bytearray()
    if val < 192:
        bytes.append(val)
    elif val <= 12480:
        val -= 193
        bytes.append([193 + rshift(val,  8), val & 0xff])
    elif val <= 918744:
        val -= 12481
        bytes.append([
            241 + rshift(val, 16),
            rshift(val, 8) & 0xff,
            val & 0xff
        ])
    else:
        raise ValueError('Variable integer overflow.')

    stream.write(bytes)


class AllStatic(type):
    def __new__(cls, name, bases, attrs):
        for key, value in attrs.items():
            if isinstance(value, types.FunctionType):
                attrs[key] = staticmethod(value)
        return type.__new__(cls, name, bases, attrs)


class TypeSerializers:
    # See stm-lib:serializedtypes.js for the originals.

    __metaclass__ = AllStatic
    def byte_writer(num_bytes):
        def func(stream, value):
            stream.write(to_bytes(int(value), num_bytes))
        return func

    STInt8 = byte_writer(1)
    STInt16 = byte_writer(2)
    STInt32 = byte_writer(4)

    def STAccount(stream, value):
        serialize_bytes(stream, UInt160(value))

    def STAmount(stream, amount):
        if isinstance(amount, dict):
            # non-STM
            hi = 0

            # First bit: non-native
            hi |= 1 << 31

            negative, value, offset = parse_non_native_amount(amount['value'])
            if not value == 0:
                # Second bit: non-negative?
                if not negative:
                    hi |= 1 << 30
                # Next eight bits: offset/exponent
                hi |= ((97 + offset) & 0xff) << 22

            # Remaining 52 bits: mantissa
            # Merge the manually constructed high-bits into the value
            value = value | (hi<<32)

            # Write Amount
            stream.write(to_bytes(value, 8))
            # Write Currency
            TypeSerializers.STCurrency(stream, amount['currency'])
            # Write Issuer
            stream.write(
                StreamBaseDecoder.decode(amount['issuer'], 25))
        else:
            # STM - only support int notation for now, not floats.
            amount = int(amount)

            # Make a 64 bit hex string
            amount_hex = '%x' % abs(amount)
            assert len(amount_hex) <= 16
            amount_hex = amount_hex.zfill(16)

            amount_bytes = bytearray(decode_hex(amount_hex))

            # Clear first bit to indicate STM
            amount_bytes[0] &= 0x3f
            # Clear second bit to indicate negative
            if amount >= 0:
                amount_bytes[0] |= 0x40

            stream.write(amount_bytes)

    def STCurrency(stream, value):
        value = value.upper()
        assert len(value) == 3 and value.isalnum()

        if value == 'STM':
            # Often (like for an Amount object) the currency is not written
            # at all if it is STM. But for example when serializing a path,
            # 'STM' as a currency needs to be indicated, and this is done
            # by 20 empty bytes.
            # Note: As currencies get more complex, demurrage, we will need
            # to introduce a special class; for now we use a simple string.
            # stm-lib:currency.js will help to look at
            stream.write(bytearray(20))

        else:
            data = bytearray(20)
            data[12:15] = map(ord, value)
            stream.write(data)

    def STPathSet(stream, value):
        typeBoundary =  0xff
        typeEnd = 0x00
        typeAccount = 0x01
        typeCurrency = 0x10
        typeIssuer = 0x20
        # A list of paths, mainly used when sending a payment.
        for idx, path in enumerate(value):
            if not idx == 0:
                TypeSerializers.STInt8(stream, typeBoundary)

            for entry in path:
                # For now, the path sets we work with come from
                # streamd directly, with the "type" already set.
                # Still, calculate it new in order to validate.
                type = 0
                if ('account' in entry):
                    type |= typeAccount
                if ('currency' in entry):
                    type |= typeCurrency
                if ('issuer' in entry):
                    type |= typeIssuer
                assert type == entry['type']

                TypeSerializers.STInt8(stream, entry['type'])
                if entry['type'] & typeAccount:
                    stream.write(UInt160(entry['account']))
                if entry['type'] & typeCurrency:
                    TypeSerializers.STCurrency(stream, entry['currency'])
                if entry['type'] & typeIssuer:
                    stream.write(UInt160(entry['issuer']))

        TypeSerializers.STInt8(stream, typeEnd)

    def STVL(stream, value):
        # A variable length string, hex-encoded
        serialize_hex(stream, value)

    def STObject(stream, value, no_marker=False):
        # Ignore lower case field names - non-serializable by convention
        keys = filter(lambda k: not k.islower(), value.keys())
        # Keys need to be sorted
        keys = sort_fields(list(keys))

        for key in keys:
            serialize_field(stream, key, value[key])
        if not no_marker:
            TypeSerializers.STInt8(stream, 0xe1)  # Object ending marker

    def STArray(stream, value):
        for idx, array in enumerate(value):
            keys =  array.keys()
            if (len(keys) != 1):
                raise ValueError("Cannot serialize an array containing non-single-key objects")
            field_name = list(keys)[0];
            val = value[idx][field_name];
            serialize_field(stream, field_name, val)
        TypeSerializers.STInt8(stream, 0xf1);

def sort_fields(keys):
    def sort_key(a):
        type_bits, field_bits = INVERSE_FIELDS_MAP[a]
        return type_bits, field_bits
    keys = keys[:]
    keys.sort(key=sort_key)
    return keys


def parse_non_native_amount(string):
    """Like ``Amount.parse_human()`` in stm-lib, will parse the
    given value into an integer and exponent offset.
    """
    amount = Decimal(string)
    # This will remove trailing zeros
    amount = amount.normalize()

    parts = amount.as_tuple()
    offset = parts.exponent

    # Shift everything such that '10' because '1000000....'
    value = ''.join(map(str, parts.digits))
    full_value = value.ljust(len('9999999999999999'), '0')
    offset -= len(full_value) - len(value)
    full_value = int(full_value)

    # This is special cased
    if full_value == 0:
        offset = -100

    return parts.sign, full_value, offset


def to_bytes(number, length=None, endianess='big'):
    """Will take an integer and serialize it to a string of bytes.

    Python 3 has this, this is originally a backport to Python 2, from:
        http://stackoverflow.com/a/16022710/15677

    We use it for Python 3 as well, because Python 3's builtin version
    needs to be given an explicit length, which means our base decoder
    API would have to ask for an explicit length, which just isn't as nice.

    Alternative implementation here:
       https://github.com/nederhoed/python-bitcoinaddress/blob/c3db56f0a2d4b2a069198e2db22b7f607158518c/bitcoinaddress/__init__.py#L26
    """
    h = '%x' % number
    s = ('0'*(len(h) % 2) + h)
    if length:
        if len(s) > length*2:
            raise ValueError('number of large for {} bytes'.format(length))
        s = s.zfill(length*2)
    s = decode_hex(s)
    return s if endianess == 'big' else s[::-1]


def from_bytes(bytes):
    """Reverse of to_bytes()."""
    # binascii works on all versions of Python, the hex encoding does not
    return int(binascii.hexlify(bytes), 16)


def fmt_hex(bytes):
    """Format the bytes as a hex string, return upper-case version.
    """
    # This is a separate function so as to not make the mistake of
    # using the '%X' format string with an ints, which will not
    # guarantee an even-length string.
    #
    # binascii works on all versions of Python, the hex encoding does not.
    hex = binascii.hexlify(bytes)
    hex = hex.decode()  # Returns bytes, which makes no sense to me
    return hex.upper()


def decode_hex(hex_string):
    """Decode a string like "fa4b21" to actual bytes."""
    if six.PY3:
        return bytes.fromhex(hex_string)
    else:
        return hex_string.decode('hex')


class StreamBaseDecoder(object):
    """Decodes Stream's base58 alphabet.

    This is what stm-lib does in ``base.js``.
    """

    alphabet = 'vpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1turAxyz'

    @classmethod
    def decode(cls, *a, **kw):
        """Apply base58 decode, verify checksum, return payload.
        """
        decoded = cls.decode_base(*a, **kw)
        assert cls.verify_checksum(decoded)
        payload = decoded[:-4] # remove the checksum
        payload = payload[1:]  # remove first byte, a version number
        return payload

    @classmethod
    def decode_base(cls, encoded, pad_length=None):
        """Decode a base encoded string with the Stream alphabet."""
        n = 0
        base = len(cls.alphabet)
        for char in encoded:
            n = n * base + cls.alphabet.index(char)
        return to_bytes(n, pad_length, 'big')

    @classmethod
    def verify_checksum(cls, bytes):
        """These stream byte sequences have a checksum builtin.
        """
        valid = bytes[-4:] == sha256(sha256(bytes[:-4]).digest()).digest()[:4]
        return valid

    @staticmethod
    def as_ints(bytes):
        return list([ord(c) for c in bytes])

    @classmethod
    def encode(cls, data):
        """Apply base58 encode including version, checksum."""
        version = b'\x00'
        bytes = version + data
        bytes += sha256(sha256(bytes).digest()).digest()[:4]   # checksum
        return cls.encode_base(bytes)

    @classmethod
    def encode_base(cls, data):
        # https://github.com/jgarzik/python-bitcoinlib/blob/master/bitcoin/base58.py
        # Convert big-endian bytes to integer
        n = int(hexlify(data).decode('utf8'), 16)

        # Divide that integer into base58
        res = []
        while n > 0:
            n, r = divmod(n, len(cls.alphabet))
            res.append(cls.alphabet[r])
        res = ''.join(res[::-1])

        # Encode leading zeros as base58 zeros
        czero = 0 if six.PY3 else b'\x00'
        pad = 0
        for c in data:
            if c == czero:
                pad += 1
            else:
                break
        return cls.alphabet[0] * pad + res


def call_encoder(func, *a, **kw):
    """Test/debug helper to make the stream-based encoder API
    more accessible.

    Equivalent on the stm-lib JS side:

        function encoder(what, value) {
            var SerializedObject = require('../src/js/stream/serializedobject').SerializedObject;
            s = require('../src/js/stream/serializedtypes')
            b = new SerializedObject()
            s[what].serialize(b, value)
            return b.to_hex()
        }
        encoder('Account', 'v3kmLJN5D28dHuH8vZNUZpMC43pEHpaocV')
    """
    def call_util(*a, **kw):
        buffer = BytesIO()
        func(buffer, *a, **kw)
        buffer.seek(0)
        return fmt_hex(buffer.getvalue())
    if a or kw:
        return call_util(*a, **kw)
    return call_util
