# -*- coding: utf-8 -*-
# !/usr/bin/env python
"""
-------------------------------------------------
   File Name：     GetFreeProxy.py
   Description :  通过关键字扫描censys.io中的疑似的代理IP
   Author :       JHao
   date：          2016/11/25
-------------------------------------------------
   Change Activity:
                   2017/06/15: 通过关键字扫描censys.io中的疑似ip
-------------------------------------------------
"""

from Util.LogHandler import LogHandler
from Util.utilFunction import getHtmlTree

API_URL = "https://www.censys.io/ipv4/_search?q={k}&page={p}"

KEY_WORD = ['Squid', 'CCProxy', 'Tinyproxy', 'Wingate', 'Pound', 'Proxy', 'Mikrotik']

PORT = [8080, 3128, 8123, 80, 8081]


class GetFreeProxy(object):
    """
    proxy getter
    """

    def __init__(self):
        self.log = LogHandler('get_free_proxy')

    @staticmethod
    def censys_scanner():
        """
        根据关键字搜索ip
        :return:
        """
        for key in KEY_WORD:
            for page in range(1, 11):
                url = API_URL.format(k=key, p=page)
                tree = getHtmlTree(url)
                if not tree:
                    continue
                for ip in tree.xpath('//span[@class="dns"]/@id'):
                    for port in PORT:
                        yield '{ip}:{port}'.format(ip=ip, port=port)
                from time import sleep
                sleep(2)


if __name__ == '__main__':
    gfp = GetFreeProxy()
    for each in gfp.censys_scanner():
        print(each)
