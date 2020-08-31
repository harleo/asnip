我是光年实验室高级招聘经理。
我在github上访问了你的开源项目，你的代码超赞。你最近有没有在看工作机会，我们在招软件开发工程师，拉钩和BOSS等招聘网站也发布了相关岗位，有公司和职位的详细信息。
我们公司在杭州，业务主要做流量增长，是很多大型互联网公司的流量顾问。公司弹性工作制，福利齐全，发展潜力大，良好的办公环境和学习氛围。
公司官网是http://www.gnlab.com,公司地址是杭州市西湖区古墩路紫金广场B座，若你感兴趣，欢迎与我联系，
电话是0571-88839161，手机号：18668131388，微信号：echo 'bGhsaGxoMTEyNAo='|base64 -D ,静待佳音。如有打扰，还请见谅，祝生活愉快工作顺利。


## Asnip
Asnip retrieves all IPs of a target organization&mdash;used for attack surface mapping in reconnaissance phases.

It uses the IP or domain name and looks up the Autonomous System Number (ASN), retrieves the Classless Inter-Domain Routing (CIDR) subnet masks and converts them to IPs.

>IP / Domain &rarr; ASN &rarr; CIDRs &rarr; IPs

Please note that this technique only makes sense if the target has its own ASN. It is also advised to not perform tests on IP ranges that you do not have permission to.

### Installation
`go get -v github.com/harleo/asnip`

_This tool requires [golang](https://golang.org/)_

### Update
`go get -u github.com/harleo/asnip`

### Options

```console
Usage:
  -t string
        Domain or IP address (Required)
  -p string
        Print results to console
```

### Example

```console
$ asnip -t google.com -p

[:] ASN: 15169 ORG: GOOGLE
8.8.4.0/24
--- snip ---
[:] Writing 599 CIDRs to file...
[:] Converting to IPs...
8.8.8.1
--- snip ---
[:] Writing 14502226 IPs to file...
[:] Done.
```

### Disclaimer
This tool must use an external API (which is subject to rate limiting) courtesy of HackerTarget to retrieve relevant data. The conversion of CIDRs to IPs will be done locally.

_Asnip is work in progress, if you make optimization changes yourself, you are invited to create a pull request or check the GitHub issues page&mdash;help is always appreciated._

---

&copy; 2020 github.com/harleo &mdash; MIT License
