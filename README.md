<div align="center">

# Wayfind

**对着一台域控扫一遍，当前身份能走到哪，一目了然。**

[CLI](https://github.com/yanxinwu946/wayfind)
·
[控制台](https://github.com/yanxinwu946/wayfind-console)
·
[在线看结果](https://wayfind.569888.xyz)

[![Python](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![nxc](https://img.shields.io/badge/wraps-NetExec-1a1a1a?style=flat-square)](https://github.com/Pennyw0rth/NetExec)
[![certipy](https://img.shields.io/badge/wraps-Certipy-1a1a1a?style=flat-square)](https://github.com/ly4k/Certipy)

</div>

一次枚举，只看不打。谁对谁有权、下一步怎么走、这条发现怎么复现，都写进一份 `findings.json`。

把文件丢进 [控制台](https://wayfind.569888.xyz)，路径、发现、凭据摊开看。

## 界面

```text
$ wayfind -d corp.local -dc <DC> -u analyst -p '...' --ldaps

[+] Domain audit started
[*] Profile: audit
[*] bloodhound  … ACL / hop
[*] adcs        … ESC templates
[*] gpp         … cpassword
[*] roasting    … SPN list (no TGS)
[+] wrote findings.json
```

```text
$ wayfind -h

 Usage: wayfind [OPTIONS]

 Active Directory domain scan

 -d,  --domain              Domain (corp.local)
 -dc, --dc-ip               Domain controller IP
 -u,  --username            Username
 -p,  --password            Password
 -H,  --hashes              NTLM hash (NT or LM:NT)
      --ldaps               Use LDAPS
      --profile             recon | audit | offensive
 -c,  --check               One check or category
 -L,  --list                List profiles and checks
 -o,  --output              Output directory
```

扫完打开控制台，导入同一份 `findings.json`：

```text
概览     这条身份现在能走几步
攻击路径  当前可达的下一跳
发现      全部条目
凭据      GPP / gMSA / loot
```

在线： [wayfind.569888.xyz](https://wayfind.569888.xyz)
源码： [yanxinwu946/wayfind-console](https://github.com/yanxinwu946/wayfind-console)

## 安装

需要本机已有 [`nxc`](https://github.com/Pennyw0rth/NetExec) 和 [`certipy`](https://github.com/ly4k/Certipy)。

```bash
uv tool install --python 3.12 git+https://github.com/yanxinwu946/wayfind
```

## 用法

```bash
# 默认 audit：只读目录，列 SPN，不申请票据
wayfind -d corp.local -dc <DC> -u analyst -p '...' --ldaps

# 匿名：还不需要域账号
wayfind --profile recon -d corp.local -dc <DC>
wayfind --check anonymous -d corp.local -dc <DC>

# 单查一项
wayfind --check gpp -d corp.local -dc <DC> -u analyst -p '...' --ldaps
wayfind --check adcs -d corp.local -dc <DC> -u analyst -p '...' --ldaps

# 看有哪些检查
wayfind -L
```

## 三种走法

| 画像 | 走多远 |
| --- | --- |
| `recon` | 匿名。Timeroast、SMB 空口令、LDAP 匿名绑定 |
| `audit` | 默认。目录只读：ACL、GPP、ADCS、LAPS、gMSA、共享、委派… |
| `offensive` | 匿名 + 目录 + 主机面 + Zerologon / NoPac，会申请 TGS |

`--check anonymous` / `directory` / `host` / `probe` 也可以单独跑一类。

## 留下什么

一次扫描写出 `findings.json`。控制台只吃这一份文件。

里面是稳定的发现 ID、当前身份、域、DC，以及每条发现怎么复现。标题给人读，字段给程序用。

默认不改系统 DNS、不转储 NTDS、不自动利用。
