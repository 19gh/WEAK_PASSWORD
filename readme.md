# WEAK_PASSWORD 后台弱口令 poc

### 安装

```
pip3 install -r requirement.txt
```

### 使用参考

```
1. 单个url
pocsuite -r pocs/xxx.py -u http://www.xxx.com/ --verify

2. 批量检测
pocsuite -r pocs/xxx.py -f xxx.txt --verify

3. 攻击模式
pocsuite -r pocs/xxx.py -u http://www.xxx.com/ --attack

4. shell模式
pocsuite -r pocs/xxx.py -u http://www.xxx.com --shell

5. 线程数
使用多线程，默认线程数为1
pocsuite -r pocs/xxx.py -f xxx.txt --verify --threads 10

... ...

pocsuite -h 可查看使用详情
```

### 免责声明

```
未经事先双方同意，使用 pocsuite3 攻击目标是非法的。
pocsuite3 仅用于安全测试目的
```

