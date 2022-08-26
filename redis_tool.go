// Redis 数据迁移命令
// redis_tool -src source -dst destination -p pattern

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-redis/redis/v8"
)

var (
	ctx      context.Context = context.Background()
	rdb_src  *redis.Client
	rdb_dst  *redis.Client
	pattern  string // redis的key的匹配规则
	isDelete bool   // 是否删除redis的数据
	maxCount int    // 每次迁移的数据量
	srcKey   string // 源redis的Key名称
	dstKey   string // 目标redis的Key名称
	srcUri   string // 源redis的uri
	dstUri   string // 目标redis的uri
	mode     string // 迁移模式 跨库 或 同库迁移模式，默认为跨库迁移模式，

)

func decodeRedisUri(uri string) (addr, pass string, db int) {
	u, err := url.Parse(uri)
	if err != nil {
		log.Println("redis uri 解析失败!", err)
		os.Exit(1)
	}
	addr = u.Host
	pass = u.User.String()
	if u.Path == "" || u.Path == "/" {
		log.Println("没有识别到redis的db!")
		os.Exit(1)
	} else {
		db, err = strconv.Atoi(u.Path[1:])
		if err != nil {
			log.Println("redis uri 解析失败!", err)
			os.Exit(1)
		}
	}
	return
}

func init() {

	// 功能说明： 支持redis全类型数据迁移工具
	flag.Usage = func() {
		fmt.Println("功能说明:")
		fmt.Println("\t支持redis全类型数据迁移工具")
		fmt.Println("使用方法:")
		fmt.Println("\t批量key跨库拷贝: redis_tool -src source -dst destination -p pattern\n")
		fmt.Println("\t单Key重命名拷贝: redis_tool -src source -dst destination -r srckey,dstkey\n")
		fmt.Println("参数说明:")
		fmt.Println("\t-src		: 原始库redis的地址,默认: redis://localhost:6379/0")
		fmt.Println("\t-dst		: 目标库redis的地址,默认: redis://localhost:6379/1")
		fmt.Println("\t-d|-delete      : 是否删除redis的数据,默认不删除，请谨慎使用!,默认: false")
		fmt.Println("\t-maxCount       : 单次SCAN提取的记录数,防止数据量过多导致redis连接超时,默认: 100")
		fmt.Println("\t-p|-pattern     : 批量key跨库拷贝。redis的key的匹配规则,默认: 空, 可以使用通配符: *,?,例如: xxx*")
		fmt.Println("\t-r|-rename      : 单Key重命名拷贝式。重命名redis的srckey和dstkey,冒号分隔,默认: 空，例如 srckey,dstkey")

	}
	// 参数说明：
	flag.StringVar(&srcUri, "src", "redis://localhost:6379/0", "原始库redis的地址")
	flag.StringVar(&dstUri, "dst", "redis://localhost:6379/1", "目标库redis的地址")
	flag.StringVar(&pattern, "p", "", "跨库迁移,redis的key的匹配规则")
	flag.StringVar(&pattern, "pattern", "", "跨库迁移,redis的key的匹配规则")
	flag.BoolVar(&isDelete, "delete", false, "是否删除redis的数据")
	flag.BoolVar(&isDelete, "d", false, "是否删除redis的数据")
	flag.IntVar(&maxCount, "maxCount", 100, "单次SCAN提取的记录数,防止数据量过多导致redis连接超时.")
	var renameVar string
	flag.StringVar(&renameVar, "rename", "", "同库迁移,重命名redis的srckey和dstkey,冒号分隔,默认: 空，例如 srckey,dstkey")
	flag.StringVar(&renameVar, "r", "", "同库迁移,重命名redis的srckey和dstkey,逗号分隔,默认: 空，例如 srckey,dstkey")
	flag.Parse()
	// redis_tool -src redis://localhost:6379/0 -dst redis://localhost:6379/0 -r "Aliyun:shareIDRemBack,Aliyun:shareIDRemBack1"
	if pattern == "" && renameVar == "" {
		log.Println("匹配规则pattern或rename参数不能为空!")
		os.Exit(1)
	}
	mode = "cross"
	if renameVar != "" {
		mode = "rename"
		keyList := strings.Split(renameVar, ",")
		if len(keyList) != 2 {
			log.Println("rename参数格式错误!")
			os.Exit(1)
		}
		srcKey = keyList[0]
		dstKey = keyList[1]
		if srcKey == "" || dstKey == "" {
			log.Println("重命名redis的srckey和dstkey参数不能为空!")
			os.Exit(1)
		}
		if srcKey == dstKey {
			log.Println("重命名redis的srckey和dstkey参数不能相同!请使用 pattern复制模式")
			os.Exit(1)
		}
	}
	if dstUri == "" {
		log.Println("请输入目标库redis的地址")
		os.Exit(1)
	}
	if srcUri == "" {
		log.Println("请输入原始库redis的地址")
		os.Exit(1)
	}
	if maxCount <= 0 {
		log.Println("请输入每次迁移的数据量")
		os.Exit(1)
	}
	sAddr, sPass, sDb := decodeRedisUri(srcUri)
	dAddr, dPass, dDb := decodeRedisUri(dstUri)

	rdb_src = redis.NewClient(&redis.Options{
		Addr:     sAddr,
		Password: sPass,
		DB:       sDb,
	})
	//检查 redis 连接
	if _, err := rdb_src.Ping(ctx).Result(); err != nil {
		log.Println("输入源:", srcUri, ", redis连接失败!原因:", err)
		os.Exit(2)
	}
	rdb_dst = redis.NewClient(&redis.Options{
		Addr:     dAddr,
		Password: dPass,
		DB:       dDb,
	})
	if _, err := rdb_dst.Ping(ctx).Result(); err != nil {
		log.Println("输出源:", dstUri, ", redis连接失败!原因:", err)
		os.Exit(2)
	}
	log.Println("redis连接成功!")
}

func CopyRedisData(oldKey, newKey string) error {
	// rdb_src 的 oldKey 复制到 rdb_dst 的 newKey，如果 newKey 已经存在，则会被覆盖。
	skey, err := rdb_src.Keys(ctx, oldKey).Result()

	if err != nil {
		return errors.New("获取oldKey失败, " + err.Error())
	}
	if len(skey) == 0 {
		return errors.New("oldKey不存在")
	}
	if len(skey) > 1 {
		return fmt.Errorf("oldKey存在[ %d ]个, oldKey:[%s]", len(skey), oldKey)
	}
	// 判断oldKey类型
	rtype, err := rdb_src.Type(ctx, oldKey).Result()
	if err != nil {
		return errors.New("获取oldKey类型失败, " + err.Error())
	}
	if rtype != "string" && rtype != "hash" && rtype != "list" && rtype != "set" && rtype != "zset" {
		return errors.New("oldKey类型不支持")
	}
	srcType := rtype
	// 判断newKey是否存在
	dkey, _ := rdb_dst.Keys(ctx, newKey).Result()
	if len(dkey) == 1 {
		// newKey 存在时,需要判断两个库相同并且 oldKey 不能与 newKey 相同
		if oldKey == newKey && srcUri == dstUri {
			return errors.New("oldKey和newKey相同,不能复制到相同的库")
		}
		// 判断newKey类型
		rtype, err = rdb_dst.Type(ctx, newKey).Result()
		if err != nil {
			return errors.New("获取newKey类型失败, " + err.Error())
		}
		// 判断newKey是否与oldKey类型一致
		if rtype != srcType {
			return errors.New("newKey类型与oldKey类型不一致!无法迁移数据")
		}
	}

	total := 0 // 记录操作记录的总数
	// 开始根据srcType类型迁移数据
	if srcType == "string" {
		// 获取key的值
		data, err := rdb_src.Get(ctx, oldKey).Result()
		if err != nil {
			return errors.New("获取oldKey值失败, " + err.Error())
		}
		// 添加数据
		err = rdb_dst.Set(ctx, newKey, data, 0).Err()
		if err != nil {
			return errors.New("添加newKey值失败, " + err.Error())
		}
		total++
	} else if srcType == "hash" {
		// 获取key的值
		data, err := rdb_src.HGetAll(ctx, oldKey).Result()
		if err != nil {
			return errors.New("获取oldKey值失败, " + err.Error())
		}
		// 添加数据
		err = rdb_dst.HMSet(ctx, newKey, data).Err()
		if err != nil {
			return errors.New("添加newKey值失败, " + err.Error())
		}
		total += len(data)
	} else if srcType == "list" {
		// 获取key的值
		// 循环 获取数据，每次获取maxCount个数据
		var cursor int64 = 0
		for {
			data, err := rdb_src.LRange(ctx, oldKey, cursor, cursor+int64(maxCount)).Result()
			if err != nil {
				return errors.New("获取oldKey值失败, " + err.Error())
			}
			if len(data) == 0 {
				break
			}
			// 添加数据
			tmp := make([]interface{}, len(data))
			for i, v := range data {
				tmp[i] = v
			}
			err = rdb_dst.LPush(ctx, newKey, tmp...).Err()
			if err != nil {
				return errors.New("添加newKey值失败, " + err.Error())
			}
			total += len(data)
			cursor += int64(len(data))
		}

	} else if srcType == "set" {
		// 获取key的值
		var cursor uint64 = 0
		for {
			data, next_cursor, err := rdb_src.SScan(ctx, oldKey, cursor, "", int64(maxCount)).Result()
			if err != nil {
				return errors.New("获取oldKey值失败, " + err.Error())
			}
			if len(data) == 0 {
				break
			}
			// 添加数据
			tmp := make([]interface{}, len(data))
			for i, v := range data {
				tmp[i] = v
			}
			err = rdb_dst.SAdd(ctx, newKey, tmp...).Err()
			if err != nil {
				return errors.New("添加newKey值失败, " + err.Error())
			}
			total += len(data)
			if next_cursor == 0 {
				break
			}
			cursor = next_cursor
		}
	} else if srcType == "zset" {
		// 获取key的值
		var cursor int64 = 0
		for {
			data, err := rdb_src.ZRangeWithScores(ctx, srcKey, cursor, cursor+int64(maxCount)).Result()

			if err != nil {
				return errors.New("获取oldKey值失败, " + err.Error())
			}
			if len(data) == 0 {
				break
			}
			// 添加数据
			tmp := make([]*redis.Z, len(data))
			for i, v := range data {
				tmp[i] = &v
			}
			err = rdb_dst.ZAdd(ctx, newKey, tmp...).Err()
			if err != nil {
				return errors.New("添加newKey值失败, " + err.Error())
			}
			total += len(data)
			cursor += int64(len(tmp))
		}
	} else {
		return errors.New("oldKey类型不支持")
	}
	if isDelete {
		// 删除oldKey
		err = rdb_src.Del(ctx, oldKey).Err()
		if err != nil {
			return errors.New("删除oldKey失败, " + err.Error())
		}
	}
	log.Printf("迁移%d条数据成功\n", total)
	return nil
}

func MoveRedisData() {
	// 根据pattern 获取 keys
	log.Println("模式: cross")
	keys, err := rdb_src.Keys(ctx, pattern).Result()
	if err != nil {
		log.Println(err)
		return
	}
	if len(keys) == 0 {
		log.Println("没有需要处理的数据")
		return
	}
	// 批量添加数据
	for _, key := range keys {
		err := CopyRedisData(key, key)
		if err != nil {
			log.Println(err)
			return // 只要有一条失败，就退出
		}
	}
}

func RenameRedisData() {
	log.Println("模式: rename")
	err := CopyRedisData(srcKey, dstKey)
	if err != nil {
		log.Println(err)
		return
	}
}
func main() {
	if mode == "cross" {
		MoveRedisData()
	} else if mode == "rename" {
		RenameRedisData()
	}
}
