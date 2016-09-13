# getdns

**getdns** 是一个使用DnsDB API查询DNS记录命令行工具。

# Dependencies

* [DnsDB Python SDK](https://pysdk.dnsdb.io)

# Install

1. 安装dnsdb-python-sdk, 查看[这里](https://github.com/dnsdb-team/dnsdb-python-sdk/wiki/Tutorials)
2. 克隆项目

    ```shell
git clone https://github.com/dnsdb-team/getdns.git
    ```
3. 安装

    ```shell
cd getdns
[sudo] python setup.py install
    ```

# Usage

1. 查看帮助

    ```shell
getdns -h
    ```

# 子命令

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

`config` 可用用于配置默认的用户名和密码(DnsDB账号)

```shell
getdns config -u <your username> -p <your password>
```

## search 

`search`命令用于查询dns记录, 该命令没成功执行一次会扣除当前账号的API请求次数, 没有使用`-a`或`--all`参数时， 每次执行最多返回30条查询结果

```shell
getdns search --domain example.com
```

`-o`参数用于指定输出位置, 默认为`-`, 表示输出到标准输出(`stdout`), 也可以输入到文件中

```shell
getdns search --domain example.com -o dns-output.txt
```

`a`或`-all`参数将会返回全部查询结果, 每次查询会根据结果数扣除当前账号的API请求次数

```shell
getdns search --domain example.com  -a -o dns-output.txt
```

## bulk-search

`bulk-search`用于批量查询DNS记录。

`bulk-search`默认通过标准输入(`stdin`)获取查询条件, 每行表示一个查询条件, 可以通过`-i`参数指定其他文件作为输入文件。

`--data-type`指定输入条件的类型, 默认为`domain`, 其他可选值为`host`, `ip`, `type`

通过标准输入(stdin)查询域名

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


## resources

查看剩余API请求次数

```shell
getdns resources
```
# 相关链接

* [DnsDB 官网](https://dnsdb.io)
* [DnsDB Python SDK](https://pysdk.dnsdb.io)
* [DnsDB API服务](https://dnsdb.io/apiservice)