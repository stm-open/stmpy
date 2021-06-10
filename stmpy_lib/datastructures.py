from decimal import Decimal
import six
import json
if six.PY2:
    import __builtin__ as builtins
else:
    import builtins
from six.moves import filter


# During debugging, this helps with the StreamPrimitive __getattr__
# problem, described further down below.
#class property(property):
#    def __get__(self, obj, cls):
#        try:
#            return super(property, self).__get__(obj, cls)
#        except AttributeError, e:
#            import traceback
#            traceback.print_exc()
#            import sys
#            sys.exit(1)


class StreamPrimitive(dict):
    """Dict that allows attribute access."""

    def __init__(self, data):
        dict.__init__(self, **data)

    def __getattr__(self, item):
        try:
            value = self[item]
            # Convert nested dicts into StreamPrimitives on the fly on access
            if isinstance(value, dict) and not isinstance(value, StreamPrimitive):
                value = StreamPrimitive(value)
                self[item] = value
            return value
        except KeyError:
            # XXX: This keeps hiding real AttributeErrors that occur during
            # handling of a @property; if property "foo" somehow triggers
            # an AttributeError, this will be called and will expose the
            # exception we raise here instead of the original one. See also
            # discussed here amongst other places:
            # http://stackoverflow.com/questions/15401180/using-getattr-and-meeting-expected-behaviour-for-subclasses
            # (see also the related Python bug report).
            # One possible way to fix this might be implementing
            # __getattribute__ instead and check if a property exists.
            # Until then, enable the hack on top of this file.
            raise AttributeError(item)

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, dict.__repr__(self))

    def __unicode__(self):
        return json.dumps(self.__json__())

    def __json__(self):
        return dict.copy(self)

    def copy(self):
        return StreamPrimitive(self)


class tupledict(list):
    """A list of 2-tuples that can be used as a dict."""
    def __getitem__(self, item):
        for key, value in self:
            if key == item:
                return value
        return list.__getitem__(self, item)


class VStreamStateEntry(StreamPrimitive):
    """Stream state entries exist when one account sets a credit limit
    to another account in a particular currency or if an account holds
    the IOUs of another account. Each entry is shared between two accounts.
    """

    def affects_account(self, account):
        try:
            if self.counter_party(account):
                return True
        except ValueError:
            return False

    def counter_party(self, account):
        if self.LowLimit.issuer == account:
            return self.HighLimit.issuer
        if self.HighLimit.issuer == account:
            return self.LowLimit.issuer
        raise ValueError('%s is not a party' % account)

    def balance(self, account):
        """Return the balance from the perspective of the given account.
        """
        if self.LowLimit.issuer == account:
            return Decimal(self.Balance.value)
        if self.HighLimit.issuer == account:
            return -Decimal(self.Balance.value)
        raise ValueError('%s is not a party' % account)

    def trust_limit(self, account):
        """Return the trust limit from the perspective of the given account.
        """
        if self.LowLimit.issuer == account:
            return Decimal(self.LowLimit.value)
        if self.HighLimit.issuer == account:
            return Decimal(self.HighLimit.value)
        raise ValueError('%s is not a party' % account)


class Amount(object):
    """Represents a Stream amount. The datastructure behind this will
    either be a dict with amount/currency/issuer keys, or a natural
    number, in which case we are dealing with STM.

    Usage/Features:

    - The properties are used to normalize access.
    - Supports arithmetic.
    - Can be initialized with with special formats:
        Decimal('1') for STM for drops, for example.

    Note: This ideally should inherit StreamPrimitive, but then we have
    trouble serializing it to an integer in the STM case, since
    StreamPrimitive as a dict, and Python's json module does not provide
    any hook to change how basic types are handled.
    """

    def __init__(self, data):
        # In Stream data structures, data is either a IOU dict, or
        # STM drops in int. We want to allow the developer to init
        # an Amount object with other values.
        if isinstance(data, six.string_types):
            # Treat as STM, convert to drops, if there is a decimal
            # point. Otherwise we have to support this as drops, since
            # streamd often returns drops as string objects.
            if '.' in data:
                data = Decimal(data)
                # Fall-through

        if isinstance(data, Decimal):
            # If a decimal is given,
            data = Decimal(data) * stm_base
            assert int(data) == data
            data = int(data)

        self.data = data

    @property
    def currency(self):
        if isinstance(self.data, dict):
            return self.data['currency']
        else:
            return 'STM'

    @property
    def issuer(self):
        if isinstance(self.data, dict):
            return self.data['issuer']
        else:
            return None

    def _get_value(self):
        if isinstance(self.data, dict):
            return Decimal(self.data['value'])
        else:
            return stm(self.data)
    def _set_value(self, v):
        if isinstance(self.data, dict):
            self.data['value'] = '%s' % v
        else:
            self.data = int(Decimal(v) * stm_base)
    value = property(_get_value, _set_value)

    def copy(self, new_value=None):
        copy = Amount(self.data.copy() if isinstance(self.data, dict) else self.data)
        if new_value is not None:
            copy.value = new_value
        return copy

    def __unicode__(self):
        return '%s' % self.value

    def __json__(self):
        return self.data

    def __contains__(self, item):
        return item in self.data

    def __getitem__(self, item):
        return self.data[item]

    def __setitem__(self, key, value):
        self.data[key] = value

    def _assert_compat_other(self, other):
        """For arithmetic with the Amount class, check that the ``other``
        object can be handled.
        """
        if isinstance(other, str):
            return Decimal(other)
        if isinstance(other, Decimal):
            return other
        assert other.currency == self.currency
        return other.value

    def __add__(self, other):
        other_value = self._assert_compat_other(other)
        new_value = self.value + other_value
        return self.copy(new_value)

    def __sub__(self, other):
        other_value = self._assert_compat_other(other)
        new_value = self.value - other_value
        return self.copy(new_value)

    def __div__(self, other):
        other_value = self._assert_compat_other(other)
        new_value = self.value / other_value
        return self.copy(new_value)

    def __rdiv__(self, other):
        return Amount.__truediv__(other, self)



class AccountRootEntry(StreamPrimitive):
    """An account root entry exists for each account. It holds its STM
    balance, last transaction sequence number, and related information.
    """

    def affects_account(self, account):
        if not 'Account' in self:
            # A transactions AffectedNodes can contain an AccountRoot
            # node entry without fields, so account for this.
            return False
        return self.Account == account


class OfferEntry(StreamPrimitive):
    """A offer entry specifies the terms of exchange between two currencies.
    """

    def affects_account(self, account):
        # Does not return True if the account's IOUs are being traded
        return self.Account == account


class DirectoryNodeEntry(StreamPrimitive):

    def affects_account(self, account):
        return False


LedgerEntries = {
    'AccountRoot': AccountRootEntry,
    'VStreamState': VStreamStateEntry,
    'Offer': OfferEntry,
    'DirectoryNode': DirectoryNodeEntry,
}


def shadow(front, back):
    # For now this is a hard-merge, but I'd prefer a transient fall-through.
    result = back.copy()
    result.update(front)
    return result


class NodeModification(StreamPrimitive):
    """An entry in the ``AffectedNodes`` key of a processed transaction.
    """

    def __init__(self, data):
        StreamPrimitive.__init__(self, data)
        node_class = LedgerEntries[data['LedgerEntryType']]
        self.new = node_class(data.get('FinalFields', {}))
        if 'PreviousFields' in data:
            self.old = node_class(
                # PreviousFields only contains parts, presumably those
                # that changed, so add a fallback to the shared data).
                shadow(data['PreviousFields'], data.get('FinalFields', {})))
        else:
            self.old = None
        self.type = type(self.new)

    def __getattr__(self, item):
        return getattr(self.new, item)


class NodeCreation(NodeModification):
    """An entry in the ``AffectedNodes`` key of a processed transaction.
    """

    def __init__(self, data):
        StreamPrimitive.__init__(self, data)
        node_class = LedgerEntries[data['LedgerEntryType']]
        self.new = node_class(data['NewFields'])
        self.old = None
        self.type = type(self.new)


class NodeDeletion(NodeModification):
    """An entry in the ``AffectedNodes`` key of a processed transaction.
    """


class Transaction(StreamPrimitive):
    """Makes data from a stream transaction structure accessible.

    ``meta`` can be given if the transaction data has no ``metaData``
    key. This is because the Stream server will hand out different
    formats: When querying a ledger, the meta that is in said key.
    When subscribing to the transaction feed, the metadata is given
    separately from the transaction.
    """

    def __init__(self, data, meta=None):
        StreamPrimitive.__init__(self, data)
        self.meta = meta

        # __new__ could also be used for this I suppose
        subclass = {
            'Payment': PaymentTransaction,
            'OfferCreate': OfferCreateTransaction,
            'OfferCancel': OfferCancelTransaction,
            'TrustSet': TrustSetTransaction,
            'AccountSet': AccountSetTransaction,
            'SetRegularKey': SetRegularKeyTransaction,
            'EnableAmendment': EnableAmendmentTransaction,
            'SeeFee': SetFeeTransaction,
            'SignerListSet': SignerListSetTransaction,
            'PaymentChannelFund': PaymentChannelFundTransaction,
            'PaymentChannelCreate': PaymentChannelCreateTransaction,
            'PaymentChannelClaim': PaymentChannelClaimTransaction,
            'EscrowFinish': EscrowFinishTransaction,
            'EscrowCreate': EscrowCreateTransaction,
            'EscrowCancel': EscrowCancelTransaction,
        }.get(data['TransactionType'], UnknownTransaction)
        self.__class__ = subclass

    @property
    def type(self):
        return type(self)

    def _get_meta(self):
        return self._meta or self.metaData
    def _set_meta(self, value):
        self._meta = StreamPrimitive(value) if value else value
    meta = property(_get_meta, _set_meta)

    @property
    def successful(self):
        return self.meta.TransactionResult == 'tesSUCCESS'

    @property
    def affected_nodes(self):
        for node in self.meta.AffectedNodes:
            assert len(list(node.keys())) == 1
            change_type = list(node.keys())[0]
            node_class = {
                'CreatedNode': NodeCreation,
                'ModifiedNode': NodeModification,
                'DeletedNode': NodeDeletion}[change_type]
            yield node_class(list(node.values())[0])

    def _get_nodes(self, account=None, type=None):
        """Return affected nodes matching the filters."""
        result = self.affected_nodes
        if account:
            # Allow to filter by multiple accounts
            if not isinstance(account, list):
                account = [account]
            result = filter(
                lambda n: all([n.affects_account(a) for a in account]), result)
        if type:
            result = filter(lambda n: n.type == type, result)
        return list(result)

    def _get_node(self, account=None, type=None):
        """Return a affected node matching the filters, and make sure
        there is only one."""
        result = self._get_nodes(account, type)
        assert len(result) == 1, 'One node expected, found %s' % len(result)
        return result[0]


stm_base = Decimal('1000000')

def stm(s):
    """STM is given in the API as a large int, convert to a decimal.
    """
    return Decimal(s) / stm_base

def stm_drops(s):
    """convert STM to large int.
    """
    return (Decimal(s) * stm_base).quantize(Decimal('1'))


class first(object):
    """Provide a simplified accessor for a property that returns
    multiple values.

    Assumes the property value has the following format::

        [(key, value), (key, value)]

    Will return prop[0].value if there is a single item, or raise an error.
    """
    def __init__(self, attr):
        self.attr = attr
    def __get__(self, instance, owner):
        multiple = getattr(instance, self.attr)
        if len(multiple) > 1:
            raise ValueError('More than one issuer on recipient side, '
                             'use the multi-value access property')
        elif len(multiple) == 0:
            return None
        else:
            return multiple[0][1]


class PaymentTransaction(Transaction):

    @property
    def num_received_issuers(self):
        """The number of different issuers received.

        Returns 0 in case of STM.
        """
        if self.is_stm_received:
            return 0
        return len(self.currencies_received[1])

    @property
    def currencies_received(self):
        """Returns a 2-tuple (code, issuer) indicating the currency
        that was received. In case of STM, ``('STM', None)`` is returned.

        What it does:

        The currency itself is readily available in ``Amount.currency``
        (or in case of STM, ``Amount`` will be an integer). The issuer
        of that currency is a bit more complicated. Here are some places
        where we do not find it:

        - ``Amount.issuer`` - always seems to be the account of the recipient.
        - The last element of ``Paths``. Frequently, multiple paths are
          listed, and it's not clear which one the transaction took.

        All in all, it it seems as if that part of the transaction is verbatim
        what the client submitted. Instead, we look into ``metaData``.

        There, we find a list of AffectedNodes, and we just find the one
        that relates to the account of the recipient.
        """
        if self.is_stm_received:
            # This means STM was received.
            return ('STM', None)
        else:
            return (
                self.Amount.currency,
                [node.counter_party(self.Destination) for node in self._get_nodes(
                    account=self.Destination, type=VStreamStateEntry)]
            )

    @property
    def amounts_received(self):
        """A list of all the amounts received by issuer.

        If there is only one issuer, the output is similar to what you'd
        see from :prop:`amount_received`.
        """
        result = []
        for node in self._get_nodes(
                account=self.Destination, type=VStreamStateEntry):
            result.append((
                node.new.balance(self.Destination)
                    - node.old.balance(self.Destination),
                self.Amount.currency,
                node.counter_party(self.Destination)))
        return result

    @property
    def amount_received(self):
        """3-tuple of (amount, currency, issuers), representing the full
        amount received.
        """
        if self.meta.get('DeliveredAmount'):
            amount = self.meta.DeliveredAmount.value \
                if isinstance(self.meta.DeliveredAmount, dict) \
                else stm(self.meta.DeliveredAmount)
        else:
            amount = self.Amount.value \
                if isinstance(self.Amount, dict) else stm(self.Amount)
        return tuple(
            [amount] + list(self.currencies_received)
        )

    @property
    def is_stm_received(self):
        # Looking at this field is the only way. It should be reliable.
        # In complex routings, in don't thing AffectedNodes can conclusively
        # tell us; or, it's really hard.
        return not isinstance(self.Amount, dict)

    @property
    def is_stm_sent(self):
        return not isinstance(self.SendMax, dict)

    def get_balances(self, who, previous=False):
        """Returns the previous balances with each issuer.
        """
        where = 'old' if previous else 'new'
        if self.is_stm_received:
            # If it is a STM payment, there should be one AccountRoot change
            node = self._get_node(account=who, type=AccountRootEntry)
            return [(None, stm(getattr(node, where).Balance))]
        else:
            # Otherwise, there should be one or more VStreamState entries
            # for each issuer.
            nodes = self._get_nodes(account=who, type=VStreamStateEntry)
            return tupledict(
                [(node.counter_party(self.Destination),
                 getattr(node, where).balance(who)) for node in nodes])

    @property
    def recipient_balances(self):
        return self.get_balances(self.Destination)

    @property
    def recipient_previous_balances(self):
        return self.get_balances(self.Destination, previous=True)

    @property
    def recipient_trust_limits(self):
        if self.is_stm_received:
            return []
        else:
            nodes = self._get_nodes(account=self.Destination, type=VStreamStateEntry)
            return tupledict(
                [(node.counter_party(self.Destination),
                 node.new.trust_limit(self.Destination)) for node in nodes])

    @property
    def sender_trust_limits(self):
        """The trust limits of the sender changed in this transaction.

        Multiple of a sender's trust limits may have changed during the
        transaction, because the full amount of currency sent may be
        a combination of different balances.

        """
        nodes = self._get_nodes(account=self.Account, type=VStreamStateEntry)
        return tupledict(
            [(node.counter_party(self.Account),
             node.new.trust_limit(self.Account)) for node in nodes])

    # If there is only one issuer being received, make access easier.
    # These raise an exception when more than one issuer is involved.
    recipient_balance = first('recipient_balances')
    recipient_previous_balance = first('recipient_previous_balances')
    recipient_trust_limit = first('recipient_trust_limits')
    sender_trust_limit = first('sender_trust_limits')

    def analyze_path(self):
        """This will give you some information about how the payment was
        routed.

        Specifically, the return value is a dict that looks like this::

            {'intermediaries': 2, 'offers': 1}

        If intermediaries is 0, there was a trust set between the two parties
        (or its a direct STM payment).
        If intermediaries is 1, both parties trust the same third party.
        If intermediaries is 2, one additional user helped.
        And so on.

        ``offers`` specifies the number of market offers that were fully
        or partially executed during payment routing. This is always included
        in ``intermediaries``.

        So the following may be true:

            intermediaries - offers - 1 = streams involved

        ----

        How is this done? Drawing automated conclusions from the set of
        unlinked node changes can be a bit of a challenge. For example, an
        AccountRoot node may be modified when someone pays in STM, when
        a fee is claimed during an IOU payment, or when your offer gets
        resolved during a third party's payment.
        Presumably, this can be vastly improved.

        TODO: In particular, in cases where the recipient receives currency
        from multiple issuers, there really should be a way to make
        this info more accessible - maybe see the individual paths
        separately.
        """

        # list() used once exhausts the generator, it's tiring..
        filter = lambda f, d: list(builtins.filter(f, d))

        # Ignore all DirectoryNodes, not sure what they do, it seems
        # like upkeep.
        nodes = filter(lambda n: n.type != DirectoryNodeEntry, self.affected_nodes)

        # Ignore all STM acounting nodes. These either indicate a fee,
        # or a direct payment, which would mean no intermediaries.
        nodes = filter(lambda n: n.type != AccountRootEntry, nodes)

        # Ignore all nodes involving the recipient. If its a direct payment,
        # it will delete the sender's state node as well. If we are dealing
        # with a third party IOUs, the sender's balance node will be left to
        # be counted as our "one" hop
        nodes = filter(lambda n: not n.new.affects_account(self.Destination), nodes)

        # Count the offer nodes. These are easy, each such node indicates
        # one offer that was involved.
        offers = filter(lambda n: n.type == OfferEntry, nodes)

        # Each offer comes with AccountRoot and VStreamStateEntry nodes
        # for the accounts of the offerer, so we need to filter those
        # out as well.
        for offer in offers:
            nodes = filter(lambda n: not n.affects_account(offer.Account), nodes)

        # What is left is the payee VStreamState + one VStreamState for each
        # true intermediary that was involved.
        # For validation, make sure all the nodes left are VStreamState entries
        assert len(filter(lambda n: n.type != VStreamStateEntry, nodes)) == 0

        return {
            'intermediaries': len(nodes) + len(offers),
            'offers': len(offers)
        }


class OfferCreateTransaction(Transaction):
    pass


class OfferCancelTransaction(Transaction):
    pass


class TrustSetTransaction(Transaction):
    pass


class AccountSetTransaction(Transaction):
    pass


class SetRegularKeyTransaction(Transaction):
    pass


class EnableAmendmentTransaction(Transaction):
    pass


class SetFeeTransaction(Transaction):
    pass


class SignerListSetTransaction(Transaction):
    pass


class EscrowCreateTransaction(Transaction):
    pass


class EscrowCancelTransaction(Transaction):
    pass


class EscrowFinishTransaction(Transaction):
    pass


class PaymentChannelClaimTransaction(Transaction):
    pass


class PaymentChannelCreateTransaction(Transaction):
    pass


class PaymentChannelFundTransaction(Transaction):
    pass


class UnknownTransaction(Transaction):
    pass



class TransactionSubscriptionMessage(StreamPrimitive):
    """The data structure returned by the server when subscribing to
    transaction updates.
    """

    @property
    def transaction(self):
        return Transaction(self['transaction'], meta=self['meta'])
