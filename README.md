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

## 安装方法

源码安装方法：
```
go install github.com/learnhard-cn/redis_tool@latest
```


