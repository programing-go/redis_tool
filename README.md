# redis_tool
一个简单的redis数据迁移工具

## 使用方法

```
功能说明:
        支持redis全类型数据迁移工具
使用方法:
        redis_tool -src source -dst destination -p pattern

参数说明:
        -src            : 原始库redis的地址
        -dst            : 目标库redis的地址
        -p|-pattern: redis的key的匹配规则
        -delete: 是否删除redis的数据,默认不删除，请谨慎使用!
        -maxCount: 单次SCAN提取的记录数,防止数据量过多导致redis连接超时
```

## 支持的URI格式

- 非加密的连接格式: `redis://[user:pass@]sshhost:port/db`
- SSH隧道连接格式: `redissh://[user:pass@]sshhost:port/db`

## 安装方法

源码安装方法：
```
go install github.com/learnhard-cn/redis_tool@latest
```


## 实现功能

- [x] 支持SSH隧道连接方式(通过`sshhost`查找`$HOME/.ssh/config`配置): URI格式 `redissh://[user:pass@]sshhost:port/db`
- [x] 支持在B主机执行 redis_tool 拷贝 A 主机redis数据到 C主机（包括SSH隧道连接方式)
