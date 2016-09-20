# GetDNS

[![Join the chat at https://gitter.im/getdns/Lobby](https://badges.gitter.im/getdns/Lobby.svg)](https://gitter.im/getdns/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[![pypi-version]][pypi]
[![python-version]][pypi]
[![license]][pypi]

**GetDNS** 是一个使用DnsDB API查询DNS记录命令行工具。

# Dependencies

* [DnsDB Python SDK](https://pysdk.dnsdb.io)

# Install

```shell
pip install --upgrade dnsdb-getdns
```

# Usage

1. 查看帮助

    ```shell
getdns -h
    ```

# Commands

可用子命令

* config 更改配置
* search 查询DNS
* bulk-search 批量查询DNS
* resources 获取当前账号资源信息(API剩余请求次数)

查看子命令帮助

```shell
getdns <command> -h
```

## config

`config`命令用于配置默认的用户名和密码(DnsDB账号)，配置该项可以让您在使用`search`，`bulk-search`，`resources`命令时无需再次输入用户名和密码

```shell
getdns config -u <your username> -p <your password>
```

查看当前配置

```shell
getdns config --show
```

恢复默认配置

```shell
getdns config --reset
```

配置代理:

1. HTTP代理

    ```shell
    getdns config --proxy http://user:pass@host:port
    ```

2. SOCKS5代理

    ```shell
    getdns config --proxy socks5://user:pass@host:port
    ```

## search

`search`命令用于查询dns记录。没有使用`-a`或`--all`参数时，该命令每成功执行一次扣除当前账号一次API请求次数,  且每次执行最多返回30条查询结果

```shell
getdns search --domain example.com
```

`-o`参数用于指定输出位置, 默认为`-`, 表示输出到标准输出(`stdout`), 也可以输入到文件中

```shell
getdns search --domain example.com -o dns-output.txt
```

`a`或`--all`参数将会返回全部查询结果, 每次查询会根据结果数扣除当前账号的API请求次数

```shell
getdns search --domain example.com  -a -o dns-output.txt
```

`-m`或`--max`参数限制最多输出查询结果数量。例如限制最多输出5条查询结果：

```shell
getdns search --domain example.com -a --max 5
```

### Output Format

`search`命令可以通过以下参数改变输出格式(`bulk-search`命令同样适用以下参数)

* `--json`指定输出格式为`JSON`，这是默认选项。
* `--csv`指定输出格式为`CSV`。
* `--format <format-string>`自定义输出格式。在`<format-string>`中，`#{host}`将会被DNS记录的host替换，`#{type}`将会被DNS记录的type替换，`#{value}`将会被DNS记录的value替换，其他内容将会被保留。例如:
    
    ```shell
    getdns search --domain exmpale.com --format "host:#{host}, type:#{type}, value:#{value}"
    ```

## bulk-search

`bulk-search`用于批量查询DNS记录。

`bulk-search`针对每次查询默认输出全部查询结果，可以通过`--max`限制每次查询输出的最大查询结果数量。

`bulk-search`默认通过标准输入(`stdin`)获取查询条件, 每行表示一个查询条件, 可以通过`-i`参数指定其他文件作为输入文件。

`--data-type`指定输入条件的类型, 默认为`domain`, 其他可选值为`host`, `ip`。

通过标准输入(`stdin`)查询域名

```shell
getdns bulk-search
stdin>>example.com
```

以文件查询输入条件

假设存在一个domain.txt文件， 内容如下:

```
a.com
b.com
c.com
```

批量查询该文件中的域名的DNS记录

```shell
getdns bulk-search -i domain.txt -o output.txt
```
或

```shell
cat domain.txt | getdns bulk-search -o output.txt
```

根据IP批量查询解析到该IP的DNS记录
假设有文件ip.txt, 内容如下：
```
111.111.111.111
222.222.222.222
```

```shell
getdns bulk-search -i domain.txt -o output.txt --data-type ip
```
或

```shell
cat domain.txt | getdns bulk-search -o output.txt --data-type ip
```

### Output Format

同`search`命令

## resources

查看剩余API请求次数

```shell
getdns resources
```

# FAQ

1. Mac OS X 使用getdns命令遇到下面错误，您可以查看[这里](https://github.com/dnsdb-team/dnsdb-python-sdk/wiki/Tutorials#%E5%AE%89%E8%A3%85%E5%88%B0mac-os-x)

    ```shell
requests.exceptions.SSLError: [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:590)
    ```

# 相关链接

* [DnsDB 官网](https://dnsdb.io)
* [DnsDB Python SDK](https://pysdk.dnsdb.io)
* [DnsDB API服务](https://dnsdb.io/apiservice)

[pypi-version]: https://img.shields.io/pypi/v/dnsdb-getdns.svg
[pypi]: https://pypi.python.org/pypi/dnsdb-getdns
[python-version]: https://img.shields.io/pypi/pyversions/dnsdb-getdns.svg
[license]: https://img.shields.io/pypi/l/dnsdb-getdns.svg