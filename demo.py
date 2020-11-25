#!/usr/bin/python
#coding:utf-8
import stmpy
import json

def main():
    # generate new wallet
    wallet = stmpy.generate()
    print(wallet)

    # # get stm balance and trust lines
    # # stmpy.getLines('stream地址')
    lines = stmpy.getLines('address')
    formatted_json = json.dumps(lines, sort_keys=True, indent=4)
    print(formatted_json)

    # # get history
    # # stmpy.getPaymentHistory('stream地址'[,开始账本号][,结束账本号])(账本号-1为默认)
    history = stmpy.getPaymentHistory('address',-1,-1)
    formatted_json = json.dumps(history, sort_keys=True, indent=4)
    print(formatted_json)

    # # get tx history
    # # stmpy.getOfferHistory('stream地址'[,开始账本号][,结束账本号])(账本号-1为默认)
    history = stmpy.getOfferHistory('address',-1,-1)
    formatted_json = json.dumps(history, sort_keys=True, indent=4)
    print(formatted_json)

    # # send
    # # stmpy.send('转账的源地址的密钥', '转账的目的地址', {"currency":"资产","value":"金额","issuer":"资产的端口，若转账资产为STM,则为空"},"附言","数字标签(只能为整型)");
    sendresult = stmpy.send('secret', 'src', {"currency":"currency","value":"value","issuer":"issuer"},"memo","dt")
    formatted_json = json.dumps(sendresult, sort_keys=True, indent=4)
    print(formatted_json)

    # # market offers
    # #stmpy.book_offers({"currency":"目标资产","issuer":"目标资产的端口，若转基准产为STM,则为空"},{"currency":"基准资产","issuer":"基准资产的端口，若基准资产为STM,则为空"})
    market_offers = stmpy.market_offers({"currency":"CNY","issuer":"vLr8y2q1SZjZYvitHoLjQzsm7U7wJbU1vh"},{"currency":"STM","issuer":""})
    formatted_json = json.dumps(market_offers, sort_keys=True, indent=4)
    print(formatted_json)

    # # get tx
    # #stmpy.tx('address','hash')
    market_offers = stmpy.tx('v3gevP2nZnJEYsnh8V5WEhcTE8522BEyLK','B5DC0DF666B8B7AA70A5271D4B269C1D3B838EC6F704127DC4E772EC91B40DAB')
    formatted_json = json.dumps(market_offers, sort_keys=True, indent=4)
    print(formatted_json)

    # # account offers
    # #stmpy.account_offers('stream地址');
    # #获取地址的市场挂单信息，其中sequence供取消订单用
    account_offers = stmpy.account_offers('address')
    formatted_json = json.dumps(account_offers, sort_keys=True, indent=4)
    print(formatted_json)

    # create offer
    # stmpy.create_offer('挂单账户的密钥',{"currency":"卖出的资产","issuer":"卖出资产的端口，若转账资产为STM,则为空","value": "卖出资产的数量"},{"currency":"买入的资产","issuer":"买入资产的端口，若转账资产为STM,则为空","value":"买入资产的数量"})
    offerCreate = stmpy.create_offer('secret',{"currency":"STM","value":"1","issuer":""},{"currency":"CNY","value":"1","issuer":"vLr8y2q1SZjZYvitHoLjQzsm7U7wJbU1vh"})
    formatted_json = json.dumps(offerCreate, sort_keys=True, indent=4)
    print(formatted_json)

    # cancel offer
    # stmpy.cancel_offer('挂单账户的密钥',要取消订单的sequence)
    offerCancel = stmpy.cancel_offer('secret',seq)
    formatted_json = json.dumps(offerCancel, sort_keys=True, indent=4)
    print(formatted_json)


main()