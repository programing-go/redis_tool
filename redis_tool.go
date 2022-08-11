// Redis 数据迁移命令
// redis_tool -src source -dst destination -p pattern

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"

	"github.com/go-redis/redis/v8"
)

var (
	ctx      context.Context = context.Background()
	rdb_src  *redis.Client
	rdb_dst  *redis.Client
	pattern  string // redis的key的匹配规则
	isDelete bool   // 是否删除redis的数据
	maxCount int    // 每次迁移的数据量

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

	uri_src := flag.String("src", "redis://localhost:6379/0", "原始库redis的地址")
	uri_dst := flag.String("dst", "", "目标库redis的地址")

	// 功能说明： 支持redis全类型数据迁移工具
	flag.Usage = func() {
		fmt.Println("功能说明:")
		fmt.Println("\t支持redis全类型数据迁移工具")
		fmt.Println("使用方法:")
		fmt.Println("\tredis_tool -src source -dst destination -p pattern\n")
		fmt.Println("参数说明:")
		fmt.Println("\t-src		: 原始库redis的地址")
		fmt.Println("\t-dst		: 目标库redis的地址")
		fmt.Println("\t-p|-pattern: redis的key的匹配规则")
		fmt.Println("\t-delete: 是否删除redis的数据,默认不删除，请谨慎使用!")
		fmt.Println("\t-maxCount: 单次SCAN提取的记录数,防止数据量过多导致redis连接超时")
	}
	// 参数说明：
	flag.StringVar(&pattern, "p", "", "redis的key的匹配规则")
	flag.StringVar(&pattern, "pattern", "", "redis的key的匹配规则")
	flag.BoolVar(&isDelete, "delete", false, "是否删除redis的数据")
	flag.IntVar(&maxCount, "maxCount", 100, "单次SCAN提取的记录数,防止数据量过多导致redis连接超时.")
	flag.Parse()

	if pattern == "" {
		fmt.Println("请输入redis的key的匹配规则")
		os.Exit(1)
	}
	if *uri_dst == "" {
		fmt.Println("请输入目标库redis的地址")
		os.Exit(1)
	}
	if *uri_src == "" {
		fmt.Println("请输入原始库redis的地址")
		os.Exit(1)
	}
	if maxCount <= 0 {
		fmt.Println("请输入每次迁移的数据量")
		os.Exit(1)
	}
	sAddr, sPass, sDb := decodeRedisUri(*uri_src)
	dAddr, dPass, dDb := decodeRedisUri(*uri_dst)

	rdb_src = redis.NewClient(&redis.Options{
		Addr:     sAddr,
		Password: sPass,
		DB:       sDb,
	})
	//检查 redis 连接
	if _, err := rdb_src.Ping(ctx).Result(); err != nil {
		log.Println("输入源:", *uri_src, ", redis连接失败!原因:", err)
		os.Exit(2)
	}
	rdb_dst = redis.NewClient(&redis.Options{
		Addr:     dAddr,
		Password: dPass,
		DB:       dDb,
	})
	if _, err := rdb_dst.Ping(ctx).Result(); err != nil {
		log.Println("输出源:", *uri_dst, ", redis连接失败!原因:", err)
		os.Exit(2)
	}
	log.Println("redis连接成功!")
}

func MoveRedisData() {
	// 根据pattern 获取 keys
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
		// 判断key 类型
		rtype, err := rdb_src.Type(ctx, key).Result()
		if err != nil {
			log.Println(err)
			return
		}

		total := 0
		if rtype == "string" {
			// 获取key的值
			data, err := rdb_src.Get(ctx, key).Result()
			if err != nil {
				log.Println(err)
				return
			}
			// 添加数据
			err = rdb_dst.Set(ctx, key, data, 0).Err()
			if err != nil {
				log.Println(err)
				return
			}
			total += 1
		} else if rtype == "hash" {
			// 获取key的值
			data, err := rdb_src.HGetAll(ctx, key).Result()
			if err != nil {
				log.Println(err)
				return
			}
			// 添加数据
			err = rdb_dst.HMSet(ctx, key, data).Err()
			if err != nil {
				log.Println(err)
				return
			}
			total += len(data)
		} else if rtype == "list" {
			// 获取key的值
			// 循环 获取数据，每次获取maxCount个数据
			var cursor int64 = 0
			for {
				data, err := rdb_src.LRange(ctx, key, cursor, cursor+int64(maxCount)).Result()
				if err != nil {
					log.Println(err)
					return
				}
				if len(data) == 0 {
					break
				}
				// 添加数据
				tmp := make([]interface{}, len(data))
				for i, v := range data {
					tmp[i] = v
				}
				err = rdb_dst.LPush(ctx, key, tmp...).Err()
				if err != nil {
					log.Println(err)
					return
				}
				total += len(data)
				cursor += int64(len(data))
			}
		} else if rtype == "set" {
			// 获取key的值
			// data, err := rdb_src.SMembers(ctx, key).Result()
			var cursor uint64 = 0
			for {
				data, next_cursor, err := rdb_src.SScan(ctx, key, cursor, "", int64(maxCount)).Result()
				if err != nil {
					log.Println(err)
					return
				}
				if len(data) == 0 {
					break
				}
				// 添加数据
				tmp := make([]interface{}, len(data))
				for i, v := range data {
					tmp[i] = v
				}
				err = rdb_dst.SAdd(ctx, key, tmp...).Err()
				if err != nil {
					log.Println(err)
					return
				}
				total += len(tmp)
				if next_cursor == 0 {
					break
				}
				cursor = next_cursor
			}
		} else if rtype == "zset" {
			// 获取key的值
			var cursor int64 = 0
			for {
				data, err := rdb_src.ZRangeWithScores(ctx, key, cursor, cursor+int64(maxCount)).Result()

				if err != nil {
					log.Println(err)
					return
				}
				if len(data) == 0 {
					break
				}
				// 添加数据
				tmp := make([]*redis.Z, len(data))
				for i, v := range data {
					tmp[i] = &v
				}
				err = rdb_dst.ZAdd(ctx, key, tmp...).Err()
				if err != nil {
					log.Println(err)
					return
				}
				total += len(tmp)
				cursor += int64(len(tmp))
			}
		} else {
			log.Println("redis类型不支持!", rtype)
			return
		}
		log.Println(rtype, key, "成功传输", total, "条数据.")
		if isDelete {
			// 删除数据
			err = rdb_src.Del(ctx, key).Err()
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
}

func main() {
	MoveRedisData()
}
