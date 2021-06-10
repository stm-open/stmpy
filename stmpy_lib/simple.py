from __future__ import print_function
import six
if six.PY2:
    import urllib as parse
else:
    import urllib.parse as parse
import os
import json
import time
import datetime
from decimal import Decimal
from .sign import get_secret,get_stream_from_secret
from .client import Remote, ResponseError,transaction_hash
from .datastructures import Amount,stm,stm_drops

LOCAL_SIGNING = int(os.environ.get('LOCAL_SIGNING', 1))
TESTNET = int(os.environ.get('testnet', 0))
WSS_URL= 'wss://node.labs.stream'
if TESTNET == 1:
    WSS_URL = 'wss://sa.labs.stream'

def generate():
    '''
    generate new address and secret pair
    '''
    secret = get_secret()
    output = {
        'address': get_stream_from_secret(secret),
        'secret': secret
    }
    return output

def send(secret, destination, amount, memo=None, dt=None):
    '''
    send in stream network
    '''
    remote = Remote(WSS_URL,secret)
    result = remote.send_payment(destination,amount,memo,dt)
    try:
        result = result.wait()
    except ResponseError as e:
        result = e.response
    if True:
        res = {}
        if 'transaction' in result:
            tx = result['transaction']
        else:
            tx = result['tx_json']
        res['from'] = tx['Account']
        res['to'] = tx['Destination']
        res['amount'] = {}
        amount = Amount(tx['Amount'])
        res['amount']['currency'] = amount.currency
        res['amount']['value'] = str(amount.value)
        res['amount']['issuer'] = amount.issuer
        if dt:
            res['dt'] = dt
        if memo:
            res['memo'] = memo
        res['tx'] = {}
        res['tx']['engine_result'] = result['engine_result']
        res['tx']['engine_result_message'] = result['engine_result_message']
        res['tx']['hash'] = tx['hash']
        return res

def toLocaltime(rpepoch):
    '''
    convert strem time to localtime
    '''
    timeStamp =  rpepoch + 0x386D4380
    value = time.localtime(timeStamp)
    formatedTime = time.strftime('%Y-%m-%d %H:%M:%S',value)
    return formatedTime

def parseAmount(amount):
    result = {}
    if isinstance(amount,dict):
        result['currency'] = amount['currency']
        result['issuer'] = amount['issuer']
        result['value'] = amount['value']
    elif isinstance(amount,(six.binary_type,six.text_type,int)):
        result['currency'] = 'STM'
        result['issuer'] = ''
        result['value'] = str(stm(amount))
    return result

def subtractAmount(amount1,amount2):
    result = {}
    if(amount1['currency'] == amount2['currency'] and amount1['issuer'] == amount2['issuer']):
        result['currency'] = amount1['currency']
        result['issuer'] = amount1['issuer']
        result['value'] = str(float(amount1['value'])-float(amount2['value']))
    return result

def processNodes(AffectedNodes):
    effects = []
    for nodes in AffectedNodes:
        effect = {}
        for key in nodes:
            if(key  == 'CreatedNode' or key == 'ModifiedNode' or key == 'DeletedNode'):
                effect['diffType'] = key
                effect['entryType'] = nodes[key]['LedgerEntryType']
                effect['ledgerIndex'] = nodes[key]['LedgerIndex']
                effect['fields'] = {}
                if 'PreviousFields' in  nodes[key]:
                    effect['PreviousFields'] = nodes[key]['PreviousFields']
                    effect['fields'].update(nodes[key]['PreviousFields'])
                if 'FinalFields' in nodes[key]:
                    effect['FinalFields'] = nodes[key]['FinalFields']
                    effect['fields'].update(nodes[key]['FinalFields'])
                if 'NewFields' in nodes[key]:
                    effect['NewFields'] = nodes[key]['NewFields']
                    effect['fields'].update(nodes[key]['NewFields'])
                effects.append(effect)
    return effects

def processTxn(tx, meta, address):
    '''
    parse the transaction detail
    '''
    obj = {}
    obj['effects'] = []

    ## Main transaction
    if (tx['Account'] == address or ('Destination' in tx and tx['Destination'] == address)):
        if 'tesSUCCESS' == meta['TransactionResult']:
            if tx['TransactionType'] == 'Payment':
                obj['account'] = address
                if tx['Account'] == address:
                    if tx['Destination'] == address:
                        obj['type'] = 'exchange'
                    else:
                        obj['type'] = 'sent'
                        obj['counterparty'] = tx['Destination']
                        counterparty = tx['Destination']
                else:
                    obj['type'] = 'received'
                    obj['counterparty'] = tx['Account']
                    counterparty = tx['Account']
                delivered_amount = meta['delivered_amount']
                if (type(delivered_amount) == type({}) and 'currency' in delivered_amount):
                    obj['amount'] = meta['delivered_amount']['value']
                    obj['currency'] = meta['delivered_amount']['currency']
                else:
                    obj['amount'] = str(Decimal(meta['delivered_amount'])/1000000)
                    obj['currency'] = 'STM'

                for affectedNode in meta['AffectedNodes']:
                    if 'ModifiedNode' in affectedNode:
                        ModifiedNode = affectedNode['ModifiedNode']
                        if (type(ModifiedNode) == type({}) and ModifiedNode['LedgerEntryType'] == 'VStreamState' and (ModifiedNode['FinalFields']['HighLimit']['issuer'] == counterparty or ModifiedNode['FinalFields']['LowLimit']['issuer'] == counterparty) and ModifiedNode['FinalFields']['Balance']['currency'] == obj['currency']):
                            if ModifiedNode['FinalFields']['HighLimit']['issuer']==counterparty:
                                obj['issuer'] = ModifiedNode['FinalFields']['LowLimit']['issuer']
                            else:
                                obj['issuer'] = ModifiedNode['FinalFields']['HighLimit']['issuer']

                if 'DestinationTag' in tx:
                    obj['DestinationTag'] = str(tx['DestinationTag'])

                if ('Memos' in tx and tx['Memos'][0]) :
                    data = str(bytearray.fromhex(tx['Memos'][0]['Memo']['MemoData']).decode())
                    obj['memoData'] = parse.unquote(data)
            if tx['TransactionType'] == 'OfferCreate':
                obj['type'] = 'offernew'
                obj['offer'] = {}
                obj['offer']['sequence'] = tx['Sequence']

                obj['offer']['Flags'] = tx['Flags']
                obj['offer']['buy'] = parseAmount(tx['TakerPays'])
                obj['offer']['sell'] = parseAmount(tx['TakerGets'])
            if tx['TransactionType'] == 'OfferCancel':
                obj['type'] = 'offercancel'

    if 'tesSUCCESS' == meta['TransactionResult']:

        nodes = processNodes(meta['AffectedNodes'])
        obj['funded'] = 'none'
        for node in nodes:
            effect = {}
            effect['offer'] = {}
            if node['entryType'] == 'Offer':
                fieldSet = node['fields']
                if node['fields']['Account'] == address:
                    if(node['diffType'] == 'ModifiedNode' or (node['diffType'] == 'DeletedNode' and 'PreviousFields' in node and 'TakerGets' in node['PreviousFields'] and parseAmount(node['FinalFields']['TakerGets']))):
                        effect['type'] = 'offer_partially_funded'
                        if node['diffType'] == 'DeletedNode':
                            obj['funded'] = 'full'
                    else:
                        if node['diffType'] == 'CreatedNode':
                            effect['type'] = 'offer_created'
                        elif('PreviousFields' in node and 'TakerPays' in node['PreviousFields']):
                            effect['type'] = 'offer_funded'
                        else:
                            effect['type'] = 'offer_cancelled'
                        if effect['type'] == 'offer_funded':
                            fieldSet = node['PreviousFields']
                        if(effect['type'] == 'offer_cancelled' and obj['type'] == 'offercancel'):
                            if 'offer' not in obj:
                                obj['offer'] = {}
                            obj['offer']['sell'] = parseAmount(fieldSet['TakerGets'])
                            obj['offer']['buy'] = parseAmount(fieldSet['TakerPays'])

                elif(tx['Account'] == address and 'PreviousFields' in node and node['PreviousFields']):
                    effect['type'] = 'offer_bought'
                if 'type' in effect:
                    if 'remaining' not in effect:
                        effect['remaining'] = {}
                    effect['remaining']['sell'] = parseAmount(fieldSet['TakerGets'])
                    effect['remaining']['buy'] = parseAmount(fieldSet['TakerPays'])
                    if effect['remaining']['sell']['value'] =='0' and effect['remaining']['buy']['value'] == '0':
                        del effect['remaining']
                    if(effect['type'] == 'offer_partially_funded' or effect['type'] == 'offer_bought'):
                        if 'offer' not in obj:
                            obj['offer'] = {}
                        obj['offer']['sequence'] = fieldSet['Sequence']
                        if 'fulfilled' not in effect:
                            effect['fulfilled'] = {}
                        obj['funded'] = 'partial'
                        effect['fulfilled']['got'] = subtractAmount(parseAmount(node['PreviousFields']['TakerGets']),parseAmount(node['fields']['TakerGets']))
                        effect['fulfilled']['paid'] = subtractAmount(parseAmount(node['PreviousFields']['TakerPays']),parseAmount(node['fields']['TakerPays']))
                if 'offer' in obj:
                    if 'PreviousTxnID' in fieldSet:
                        obj['offer']['hash'] = fieldSet['PreviousTxnID']
                    elif 'buy' in obj['offer']:
                        obj['offer']['hash'] = str(tx['hash'])
                    if 'sequence' not in obj['offer']:
                        obj['offer']['sequence'] = fieldSet['Sequence']
            if 'offer' in effect and not effect['offer']:
                del effect['offer']
            if 'type' in effect:
                obj['effects'].append(effect)

    obj['hash'] = str(tx['hash'])
    obj['date'] = tx['date']
    obj['time'] = toLocaltime(tx['date'])
    obj['ledger_index'] = tx['ledger_index']
    obj['tx_type'] = tx['TransactionType']

    if ('effects' in obj and len(obj['effects']) == 0):
        del obj['effects']
    return obj

def getPaymentHistory(address,ledger_index_min = -1,ledger_index_max = -1):
    '''
    get history from stream network
    '''
    remote = Remote(WSS_URL,'')
    result = remote.account_tx(address,ledger_index_min,ledger_index_max)
    transactions = []
    for transaction in result['transactions']:
        tx = processTxn(transaction['tx'],transaction['meta'],address)
        if tx and tx['tx_type'] == 'Payment':
            transactions.append(tx)
    res = {}
    res['account'] = address
    res['ledger_index_max'] = result['ledger_index_max']
    res['transactions'] = transactions
    return res

def getOfferHistory(address,ledger_index_min = -1,ledger_index_max = -1):
    '''
    get history from stream network
    '''
    remote = Remote(WSS_URL,'')
    result = remote.account_tx(address,ledger_index_min,ledger_index_max)
    transactions = []
    for transaction in result['transactions']:
        tx = processTxn(transaction['tx'],transaction['meta'],address)
        if tx and (tx['tx_type'] == 'OfferCancel' or tx['tx_type'] == 'OfferCreate'):
            transactions.append(tx)
    res = {}
    res['account'] = address
    res['ledger_index_max'] = result['ledger_index_max']
    res['transactions'] = transactions
    return res

def getLines(address):
    '''
    get trustlines and stm balance from stream network
    '''
    remote = Remote(WSS_URL,'')
    lines = remote.account_lines(address)
    stmline = remote.account_info(address)
    res = {}
    res['account'] = address
    res['balance'] = str(stm(stmline['Balance']))
    res['trustLines'] = []
    for line in lines:
        oneLine = {}
        oneLine['issuer'] = line['account']
        oneLine['balance'] = line['balance']
        oneLine['currency'] = line['currency']
        oneLine['limit'] = line['limit']
        res['trustLines'].append(oneLine)
    return res

def book_offers(sell,buy):
    '''
    get 10 offers from stream network
    '''
    remote = Remote(WSS_URL,'')
    offerResult = remote.book_offers(sell,buy,10)
    offers = []
    for offerLine in offerResult['offers']:
        offer = {}
        offer['sell'] = parseAmount(offerLine['TakerGets'])
        offer['buy'] = parseAmount(offerLine['TakerPays'])
        if offer['sell']['currency'] == 'STM':
            offer['price'] = str(stm_drops(offerLine['quality']))
        elif offer['buy']['currency'] == 'STM':
            offer['price'] = str(stm(offerLine['quality']))
        else:
            offer['price'] = str(Decimal(offerLine['quality']))
        if offer['sell']['value'] != '0' and offer['buy']['value'] != '0':
            offers.append(offer)
    return offers

def market_offers(pair_counterparty,pair_base):
    '''
    get offers from stream newwork
    '''
    buy = book_offers(pair_base,pair_counterparty)
    sell = book_offers(pair_counterparty,pair_base)
    result = {}
    result['pair'] = pair_counterparty['currency']+'/'+pair_counterparty['issuer']+'_'+pair_base['currency']+'/'+pair_base['issuer']
    if len(buy) > 0:
        result['buy'] = []
        for offer in buy:
            buyoffer = {}
            buyoffer['amount'] = offer['buy']['value']
            buyoffer['price'] = str(Decimal(offer['sell']['value'])/Decimal(offer['buy']['value']))
            result['buy'].append(buyoffer)
    if len(sell) > 0:
        result['sell'] = []
        for offer in sell:
            selloffer = {}
            selloffer['amount'] = offer['sell']['value']
            selloffer['price'] = str(Decimal(offer['buy']['value'])/Decimal(offer['sell']['value']))
            result['sell'].append(selloffer)
    return result

def account_offers(address):
    '''
    get offers of the account from stream network
    '''
    remote = Remote(WSS_URL,'')
    offerResult = remote.account_offers(address)
    offers = []
    for offerLine in offerResult['offers']:
        offer = {}
        offer['sequence'] = offerLine['seq']
        offer['sell'] = parseAmount(offerLine['taker_gets'])
        offer['buy'] = parseAmount(offerLine['taker_pays'])
        if offer['buy']['value'] != '0' or offer['sell']['value'] != '0':
            offers.append(offer)
    return offers

def create_offer(secret,sell,buy):
    '''
    create a offer
    '''
    remote = Remote(WSS_URL,secret)
    result = remote.create_offer(sell,buy)
    try:
        result = result.wait()
    except ResponseError as e:
        result = e.response

    if True:
        res = {}
        res['tx'] = {}
        res['tx']['offer'] = {}
        res['tx']['offer']['TakerGets'] = sell
        res['tx']['offer']['TakerPays'] = buy
        res['tx']['engine_result'] = result['engine_result']
        res['tx']['engine_result_message'] = result['engine_result_message']
        if result['engine_result'] == 'tesSUCCESS':
            res['tx']['hash'] = result['transaction']['hash']
            res['tx']['sequence'] = result['transaction']['Sequence']
        return res

def cancel_offer(secret, sequence):
    '''
    cancel a offer with the sequence in stream network
    '''
    remote = Remote(WSS_URL,secret)
    result = remote.cancel_offer(sequence)
    try:
        result = result.wait()
    except ResponseError as e:
        result = e.response

    if True:
        res = {}
        res['tx'] = {}
        res['tx']['engine_result'] = result['engine_result']
        res['tx']['engine_result_message'] = result['engine_result_message']
        if result['engine_result'] == 'tesSUCCESS':
            res['tx']['sequence'] = sequence
            res['tx']['hash'] = result['transaction']['hash']
        return res

def tx(address,transaction):
    '''
    get the detail of a tx
    '''
    remote = Remote(WSS_URL,'')
    detail = remote.tx(transaction)
    return processTxn(detail,detail['meta'],address)
