# energyCTF2025
2025年能源网络安全大赛 【社会组】【电网 发电 油气组】题目附件

# 社会组

## Web

### 这网页怪怪的

> 这网页怎么怪怪的？

```bash
# yunnuuu.php
<?php
include("flaaaaaaag.php");
highlight_file(__FILE__);
$tmp1=$_POST['tmp1'];
$tmp2=$_GET['tmp2'];
$secret=289114;
if(is_numeric($tmp1)){
    exit('Too early');}
else{

    if($tmp1==$secret){
        include($tmp2);
    }else{
        echo('you are close');
    }
}
```

### easy_node

> try to rce

```bash
const express = require('express');
const app = express();
const fs = require("fs")
const mergeValue = require("merge-value")
const bodyParser = require('body-parser')
const handlebars = require("handlebars");
app.use(bodyParser.json())

/*
"dependencies": {
    "body-parser": "^1.19.0",
    "express": "^4.17.1",
    "merge-value": "^1.0",
    "handlebars": "^4.7.7"
  }
 */
app.post('/template', function (req, res) {
    let defaultTemplate = {
        "text": {
            "title": "WriteUp"
        },
        "template": "{{this.title}}{{this.body}}",
        "waf": {
            "black1": "__",
            "black2": "program"
        }
    }
    //禁止覆盖原始的waf值
    if(req.body.wafkey && req.body.wafdata) {
        if (defaultTemplate["waf"][req.body.wafkey]) {
            defaultTemplate["waf"]["custom" + req.body.wafkey] = req.body.wafdata[req.body.wafkey]
        } else {
            defaultTemplate["waf"][req.body.wafkey] = req.body.wafData[req.body.wafkey]
        }
    }
    //取出所有的waf值
    let waf = defaultTemplate["waf"]
    let wafList = []
    for(let wafWord in waf){
        wafList.push(waf[wafWord])
    }
    for(let requestKey in req.body){
        if(typeof req.body[requestKey] === 'string'){
            for(let index in wafList){
                if(req.body[requestKey].toLowerCase().endsWith(wafList[index])){
                    res.send("waf");
                    return;
                }
            }
        }
    }
    let templateData = mergeValue(defaultTemplate,req.body.pathKey,req.body.data)
    let template = handlebars.compile(templateData["template"]);
    res.send(template(templateData["text"]));
});

app.get('/', function (req, res) {
    res.send('see `/src`');
});


app.get('/src', function (req, res) {
    var data = fs.readFileSync('app.js');
    res.send(data.toString());
});

app.listen(3000, function () {
    console.log('start listening on port 3000');
});
```

### EasyInstall

> easylogin 附件:https://nengy.oss-cn-hangzhou.aliyuncs.com/html.zip

详细见题目附件

### Web_DSDDD

> 小明编写了一个非常简单的大语言模型平台，但是只实现了最基本的模型载入功能，不过某个功能点存在漏洞，你能帮小明找出漏洞吗？

## Crypto

### NumberTheory

详细见题目附件

### easy_lwe

> 如何在格中找出和给定向量最接近的一个向量呢？

详细见题目附件

## PWN

### pwn_milk

详细见题目附件

### Pwn_harker

> 附件:https://nengy.oss-cn-hangzhou.aliyuncs.com/harker.zip

详细见题目附件

## 数据安全

### 数据脱敏

详细见题目附件

为了抵抗黑客攻击导致数据拖库等问题，需要将敏感数据识别并脱敏存储成⼀个表。给定脱敏算法逻辑，要求选⼿⽣成脱敏后的数据表数据（所有数据均为随机⽣成，与现实世界⽆任何联系）。为了防⽌⼀些隐私数据泄漏，现需要对该数据表进⾏脱敏操作，请按照指定要求对各字段进⾏脱敏处理，并按照先行后列拼接字符串（不包含标题行），对此字符串进行md5计算，得到答案。 

**脱敏要求：**

**编号**：⽆需脱敏。 

**姓名**：⼆字姓名对最后⼀位字使⽤ * 进⾏替换，三字姓名对中间⼀位字使⽤ * 进⾏替换，四字姓名对中间两位字使⽤ * 进⾏替换。 

**手机号**：请对中间五位信息使⽤ * 进⾏替换。 

**身份证号码**：请对除了前6位信息使⽤ * 进⾏替换。 

**银⾏卡**：请对前四位和后十位信息使⽤ * 进⾏替换。 

**Email**：请对字符 @ 前除 . 外的字符使⽤ * 进⾏替换。 

**性别**：替换成未知。 

**微信号**：请对为字符的信息使用 * 进行替换。

### 结构化数据识别

详细见题目附件

请参赛选手对给定的结构化文件《data.xlsx》进行处理，文件中包括手机号、身份证号码、银行卡号、邮箱等四类敏感数据以及干扰的脏数据（数据不满足特征）。具体数据检测规则可参考下文。参赛选手需要对数据进行清洗，编写规则，识别其中正确的敏感数据，并输出识别结果。仅当一行中所有的数据命中数据类型的规则时，才认为该行命中某一数据类型。 请参赛选手编写程序对数据进行识别，计算全部都命中的行数，计算答案的 MD5 值（MD5 值英文字符全小写，长度 32 个字符；计算答案的 MD5 值时，用 UTF-8 字符编码），并将答案的 MD5 值提交至平台。 

1. 手机号是指11 位纯数字的民用手机号， 具体规则为：a) 1-3 位—— 138——运营商网络识别号，运营商包括中国移动、中国联通、中国电信、中国广电b) 4-7 位——8888——地区编码或其他（无规律）c) 8-11 位——8888——用户编码 
2. 身份证号码是指18 位二代身份证号码， 具体规则为：a) 1-6 位—— 140521——为行政区代码（不定年份有修订）b) 7-14 位—— 19701231——为出生年月日，出生年月日不早于 1930 年1 月 1 日， 不晚于当前日期c) 15-17 位——543——顺序码，任意 3 位数字，第 17 位奇数为男性，偶数位女性d) 18 位——2——校验位，取值范围为 0~9 或 X。身份证号校验算法参照国标GB11643-1999《公民身份号码》。 
3. 银行卡号是指19 位纯数字的银行卡号， 具体规则为：银行卡号规则是银行卡号由发卡银行标识、账户标识、校验位等部分组成。发卡银行标识为开头的6 位数字，不同的银行有不同的BIN。银行卡号的中间部分用于标识持卡人的账户信息，包括账户类型、账户分行等，通常包含12 位数字。银行卡号的最后一位通常是校验位，用于检查卡号是否合法，计算方法按照一定的算法生成。银行卡号校验位采用Luhn 算法。
4. 邮箱由用户名@域名组成，不限制长度，例如：123456789@163.com 具体规则为：用户名@域名，用户名可由字母、数字、下划线构成，不以下划线开始；域名：至少包含一个"."，以最后一个"."分割为两个部分，前半部分由字母、数字或"."构成，"."不能在最前面；后半部分由字母或数字构成。

 正确答案示例：2323行，md5后答案提交为：flag{149815eb972b3c370dee3b89d645ae14}

### 数据加密

给定一个包含敏感信息的文件《data.xlsx》，文件中有多个数据列，每列代表不同的敏感数据类型，如手机号、身份证号码、银行卡号和邮箱等。参赛选手需要对文件中的每一个数据进行加密处理，并输出加密后的数据。 

数据加密应使用对称加密算法 AES (Advanced Encryption Standard)，采用CBC模式并应用自定义填充方式（见下文），加密后的结果应以16进制字符串的形式保存。

参赛选手需要使用给定的密钥和初始iv，并使用该密钥对每个数据进行加密。加密后的数据最后按先行后列顺序拼接计算md5。 

自定义填充方案：

第一层：数据长度字节：在填充开始部分添加表示原始数据长度的字节数。 

第二层：固定字节序列：使用固定字节序列0xBB以增加填充的层次。 

第三层：填充长度字节：填充内容的末尾添加表示填充长度的字节。 

取舍：若只缺少一位填充，则只填充第一层，若只缺少两位填充，则只填充第一层第三层。

例子：块大小为16，当前值为11，填充内容：0x0b+0xBB*3+0x5 

数据AES加密的密钥为：b'0123456789abcdef'，初始IV为：b'abcdef0987654321'。

详细见题目附件

## 能源行业

### lava

> 得到值用flag{}包裹

详细见题目附件

### easymodbus

详细见题目附件

## MISC

### black_white

> 黑白相间

详细见题目附件

### Knn

> 新能源车A车由于销售量较好，被新能源B车模仿，从外观和logo看均完全无法分辨，仅能从性能评分上进行分别。现有历史A车和B车的评分数据，请根据历史评分数据，分析待检测的新能源车是A车还是B车，并得到最终数据。

详细见题目附件

# 能源组

## 数据安全

### 数据完整性校验

给定一个Excel   文件《data.xlsx》，其中包含多个数据列，每一列的数据代表某一类记录。

文件中的数据可能在传输、存储或处理的过程中发生了丢失或篡改。

参赛选手需要对文件中的数据进行完整性校验，识别哪些列中的数据存在完整性问题，并输出校验结果。    

A列B列的数据在文件生成时有对应的一列校验和（Checksum）数据。参赛选手需要根据原始数据列计算校验和，并与文件中的校验和列进行比较。

如果两者不一致，则认为该行的数据存在完整性问题。

参赛选手需要根据校验列推导使用的校验算法并编写程序对数据进行校验，并输出识别结果。输出格式“A列-不匹配的行数;B列-不匹配的行数”。    

请参赛选手编写程序对《data.xlsx》中的A列B列数据进行完整性校验，构造上述格式的答案，并将答案的 MD5 值（MD5  值英文字符全小写，长度 32 个字符；计算答案的 MD5 值时，用 UTF-8 字符编码）提交至平台。    

**正确答案示例**：A列-30;B列-40，提交结果示例：4d1c5c9b4757f2ff5d453b375c18254b

详细见题目附件

### 超期账号未回收

在数据库管理中，账号管理是确保系统安全性的重要环节。为了避免安全风险，通常要求在特定时间段内未使用或已过期的账号应被及时回收或禁用。然而，部分账号可能由于管理疏忽未能及时回收，存在安全隐患。    参赛选手需要编写程序，检测数据库系统中哪些用户账号已经过期但未被回收（禁用或删除）。检测的目标是识别出那些在指定的最后使用日期后仍然处于活跃状态的用户账号，并生成答案。    数据文件说明：    

**账号信息文件 (accounts.csv)**：       

包含所有用户账号的相关信息，包括用户名、创建日期、最后使用日期和当前状态等。     

文件列说明：       

`Username`: 用户名。       

`CreatedAt`: 账号创建日期（格式：YYYY-MM-DD）。       

`LastUsedAt`: 账号最后一次使用日期（格式：YYYY-MM-DD）。       

`Status`: 账号当前状态（`Active` 表示账号活跃，`Inactive` 表示账号已禁用，`Deleted` 表示账号已删除）。  `ExpiryDate`: 账号应回收的日期（格式：YYYY-MM-DD），该日期之后若账号未禁用或删除即视为超期。  

**检测任务**：     

检查所有账号，识别哪些账号的 `ExpiryDate` 已经过期且当前状态仍为 `Active`。     

统计超期账号个数，并提交个数给平台。    示例：    假设《accounts.csv》文件内容如下：    

Username,CreatedAt,LastUsedAt,Status,ExpiryDate  alice,2022-01-15,2024-06-10,Active,2024-06-01  bob,2021-05-20,2023-09-25,Inactive,2023-10-01  charlie,2020-11-30,2023-07-15,Active,2023-07-01  dave,2019-03-10,2024-02-20,Active,2024-03-01  eve,2023-04-12,2023-12-01,Deleted,2023-12-15

**示例报告**：    

1. 用户名: alice
   1. 创建日期: 2023-01-15
   2. 最后使用日期: 2024-06-10
   3. 当前状态: Active
   4. 应回收日期: 2024-06-01
2. 用户名: charlie
   1. 创建日期: 2020-11-30
   2. 最后使用日期: 2023-07-15
   3. 当前状态: Active
   4. 应回收日期: 2023-07-01

**示例答案**：flag{2}

详细见题目附件

### 数据库审计

数据库系统中的审计日志记录了用户的登录尝试、查询操作以及权限设置等活动。为了确保数据库的安全性，需要对这些日志进行深入分析，以检测潜在的违规操作。以下任务包括对用户权限的验证、操作合法性的检查以及异常活动的监测。

给定一份数据库操作日志文件《database_logs.txt》和一份用户权限配置文件《user_permissions.txt》，参赛选手需要编写程序进行以下分析和检测：

1. **解析用户权限配置文件**：该文件包含用户、数据表及用户对该表的SQL权限（如SELECT、INSERT、UPDATE、DELETE），以及用户是否为root权限。
2. **解析操作日志文件**：日志文件记录了用户登录、查询操作、权限设置等信息，包括操作时间、用户、数据表、SQL语句、IP地址等。
3. **违规操作检测**：设计并实现一个检测算法，识别以下违规操作：

| 违规码 | 违规名称             | 违规内容                                         |
| ------ | -------------------- | ------------------------------------------------ |
| 1      | 不存在的账号执行操作 | 用户在日志中执行了操作但不在权限配置文件中列出。 |
| 2      | 无权操作的表         | 用户对其无权限的数据表进行操作。                 |
| 3      | 超权限操作           | 用户对表执行了不属于其权限的操作。               |
| 4      | 非root权限操作       | 非root用户进行了权限设置操作。                   |

**数据文件说明**：

1. **用户权限配置文件 (user_permissions.txt)**：
   1. 格式：用户 表格 sql权限 是否为root用户
   2. 说明：每行记录一个用户对数据表的权限和用户类型（root或非root），权限以分号分隔。
2. **操作日志文件 (database_logs.txt)**：
   1. 格式：日期 时间 用户 操作 内容
   2. 说明：每行记录一次数据库操作，包括时间、用户、操作类型、数据表、SQL语句、IP地址等。

**生成答案**：输出所有检测到的违规操作记录，设置违规码1、2、3、4分别表示不存在的账号执行操作、无权操作的表、超权限操作、非root用户进行权限操作（见上表），若发现日志某行出现违规操作，构建违规码-编号。多个恶意操作之间用逗号(,)隔开即可，拼接顺序：将违规操作1、2、3、4按照在database_logs.txt表中的编号顺序从小到大进行排序，最后将拼接后的内容进行32位小写md5加密后提交至平台。

**题目示例**：

权限配置文件《user_permissions.txt》内容如下：

```sql
1, user1, table4;table2, SELECT;DELETE;UPDATE, non-root
2, user2, table3, INSERT;UPDATE;DELETE, root
3, user3, table1, INSERT;UPDATE, non-sroot
```

操作日志文件《database_logs.txt》内容如下：

```python
1 2024-11-15 20:06:41 user1 QUERY table1 operation=INSERT
2 2024-11-15 20:06:41 user2 QUERY table3 operation=SELECT
3 2024-04-07 05:13:37 user4 QUERY table4 operation=DELETE
4 2024-03-04 22:05:29 user1 GRANT UNKONW
5 2024-02-10 07:48:13 user3 LOGIN_FAILED IP=192.168.1.177
...
15 2024-02-10 07:48:13 user3 LOGIN_FAILED IP=192.168.1.177
```

**违规检测：**

- user1对table1进行了操作，触发违规操作2，2-1
- user2对table3进行了SELECT操作，触发违规操作3，3-2
- 出现user4，触发违规操作1，1-3
- user1进行了权限操作，触发违规操作5，4-4

**生成答案**：按顺序组建2-1,3-2,1-3,4-4，提交答案d3200df57ff44a4d9e563e46474a0479

详细见题目附件

## Web

### Web_EEEEEE

> 小陈编写了一种很特殊的API结构，你能帮他进行安全测试吗？

### Web_EasyXSS

> 一道SQL注入题目

### Web_phsys

> 文件上传绕过

### MIRROR

> 命令执行

### Internal-JDBC-Hack

> 附件：https://nengy.oss-cn-hangzhou.aliyuncs.com/ajar.zip 
>
> 研发部门在服务器上搭建的DBC测试环境经常被监到有外连恶意服务器的行为，小明作为公司的网络安全工程师认为这可能爱到了黑客攻击，因此他禁止了这个服务器向外部发起的任何网络连接，以确保服务器的安全。但是在一次安全试中该服务器依然被攻击成功，希望你能帮他分析原因。

详细见题目附件

## PWN

### Pwn_cfc

hash：851ee32c00b76e9c421d65a78c8e3839

详细见题目附件

## Pwn_vm

> 虚拟机逃逸 侧信道爆破

hash：

详细见题目附件

## Crypto

### simpleSignin

> 来签到吧

详细见题目附件

### easy_crypto

> 格密码

详细见题目附件

## 能源行业

### upload

小明是一家能源公司的WAF监控人员，今天发现了WAF出现了一条告警，内部关键设备被攻击者利用任意文件读取漏洞读取了关键信息。请根据维修人员捕获的流量包，分析攻击者读取了什么信息。

hash：670cb8f9bc1329da56bd2abd34e02d80

详细见题目附件

### balls

> 得到的值用flag{}包裹

详细见题目附件

## MISC

### alarm_clock

详细见题目附件

### Bluetooth

> 可疑的蓝牙设备

详细见题目附件

### USB

> 小明是一家新能源汽车制造厂的运维人员，每天的工作是在电脑前对数据进行运维，由于操作失误，导致系统出现故障。请根据维修人员捕获的流量包，分析当天小明执行了什么指令，导致的系统故障。
>
> flag格式为：flag{执行指令}。
>
> 例如执行的指令为ipconfig /all，则答案为flag{ipconfig /all}

详细见题目附件
