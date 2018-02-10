=======
GetDNS
=======

.. image:: https://travis-ci.org/dnsdb-team/getdns.svg?branch=master
    :target: https://travis-ci.org/dnsdb-team/getdns
.. image:: https://img.shields.io/pypi/v/dnsdb-getdns.svg
    :target: https://pypi.python.org/pypi/dnsdb-getdns
.. image:: https://img.shields.io/pypi/pyversions/dnsdb-getdns.svg
    :target: https://pypi.python.org/pypi/dnsdb-getdns
.. image:: https://img.shields.io/pypi/l/dnsdb-getdns.svg
    :target: https://pypi.python.org/pypi/dnsdb-getdns

**GetDNS** 是一个使用DnsDB API查询DNS记录命令行工具。

Dependencies
=============

* `DnsDB Python SDK <https://pysdk.dnsdb.io>`_ >= 0.1.2b2

Install
========

::

    pip install --upgrade dnsdb-getdns


Usage
======

查看帮助

::

    getdns -h


Commands
------------
可用子命令


* config 更改配置
* search 查询DNS
* bulk-search 批量查询DNS
* resources 获取当前账号资源信息(API剩余请求次数)

查看子命令帮助

::

    getdns <command> -h


config
>>>>>>>

``config`` 命令用于配置默认的用户名和密码(DnsDB账号)，配置该项可以让您在使用 ``search`` ， ``api_user`` 命令时无需再次输入 ``API ID`` 和 ``API Key``

::

    getdns config -u <your username> -p <your password>


查看当前配置

::

    getdns config --show


恢复默认配置

::

    getdns config --reset


配置代理:

1. HTTP代理

::

    getdns config --proxy http://user:pass@host:port


2. SOCKS5代理

::

    getdns config --proxy socks5://user:pass@host:port

search
>>>>>>>

``search`` 命令用于查询dns记录。没有使用 ``-a`` 或 ``--all`` 参数时，该命令每成功执行一次扣除当前账号一次API请求次数,  且每次执行最多返回50条查询结果

::

    getdns search --domain example.com

``-o`` 参数用于指定输出位置, 默认为 ``-`` , 表示输出到标准输出( ``stdout`` ), 也可以输入到文件中

::

    getdns search --domain example.com -o dns-output.txt

``a`` 或 ``--all`` 参数将会返回全部查询结果, 每次查询会根据结果数扣除当前账号的API请求次数

::

    getdns search --domain example.com  -a -o dns-output.txt


``-m`` 或 ``--max`` 参数限制最多输出查询结果数量。例如限制最多输出5条查询结果：

::

    getdns search --domain example.com -a --max 5


输出格式

``search`` 命令可以通过以下参数改变输出格式

* ``--json`` 指定输出格式为 ``JSON`` ，这是默认选项。
* ``--csv`` 指定输出格式为 ``CSV`` 。
* ``--format <format-string>`` 自定义输出格式。在 ``<format-string>`` 中， ``#{host}`` 将会被DNS记录的host替换， ``#{type}`` 将会被DNS记录的type替换， ``#{value}`` 将会被DNS记录的value替换，其他内容将会被保留。例如:

::

    getdns search --domain exmpale.com --format "host:#{host}, type:#{type}, value:#{value}"

输出结果

::

    host:a1.example.com, type:a, value:1.1.1.1
    host:a2.example.com, type:a, value:1.1.1.2
    host:a3.example.com, type:a, value:1.1.1.3
    host:a4.example.com, type:a, value:1.1.1.4
    ......

只输出IPv4地址

::

    getdns search --domain example.com --type a --format "#{value}"

输出结果

::

    1.1.1.1
    1.1.1.2
    1.1.1.3
    1.1.1.4
    ......

api_user
>>>>>>>>

查看剩余API请求次数

::

    getdns api_user

FAQ
====

1. Mac OS X 使用getdns命令遇到下面错误，您可以查看 `这里 <https://github.com/dnsdb-team/dnsdb-python-sdk/wiki/Tutorials#%E5%AE%89%E8%A3%85%E5%88%B0mac-os-x>`_

::

    requests.exceptions.SSLError: [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:590)

Links
=====

* `DNSDB Official Website <https://dnsdb.io>`_
* `DNSDB Python SDK <https://pysdk.dnsdb.io>`_
* `DNSDB API <https://dnsdb.io/api_introduce>`_
