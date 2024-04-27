// Redis 数据迁移命令
// redis_tool -src source -dst destination -p pattern

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"
	redis "github.com/redis/go-redis/v9"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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
	loadFile string // load模式导入的数据
	tbName   string // load模式导入的table
	outFile  string // 导出输出文件
	commit   string // 提交版本信息
)

type SSHInfo struct {
	Host         string
	Port         string
	User         string
	Password     string
	IdentityFile string
	Passphrase   string
}

func errCallBack(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func connectRedis(rHost, rPort, rPass string, rDb int) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     net.JoinHostPort(rHost, rPort),
		Password: rPass,
		DB:       rDb,
	})
}

// "redis://<user>:<pass>@localhost:6379/<db>"
// "redissh://<user>:<pass>@sshhost:6379/<db>"
func InitDB(redisURL string, sshInfo *SSHInfo) (rdb *redis.Client) {

	u, err := url.Parse(redisURL)
	if err != nil {
		log.Fatal(err)
	}
	rHost := u.Hostname()
	rPort := u.Port()
	rPass, _ := u.User.Password()
	rDb, _ := strconv.Atoi(u.Path[1:])
	switch u.Scheme {
	case "redis":
		rdb = connectRedis(rHost, rPort, rPass, rDb)
	case "redissh":
		sshHost := rHost
		sshPort := ""
		sshUser := ""
		sshPass := ""
		sshFile := ""
		sshPassphrase := ""
		if sshInfo != nil {
			if sshInfo.Host != "" { // 默认使用redis_URI的Host
				sshHost = sshInfo.Host
			}
			sshPort = sshInfo.Port
			sshUser = sshInfo.User
			sshPass = sshInfo.Password
			sshFile = sshInfo.IdentityFile
			sshPassphrase = sshInfo.Passphrase
		}
		rdb = connectRedisWithSSH(rDb, "127.0.0.1", rPort, rPass, sshHost, sshPort, sshUser, sshPass, sshFile, sshPassphrase)
	default:
		return nil
	}
	//检查 redis 连接
	if _, err := rdb.Ping(ctx).Result(); err != nil {
		log.Fatal(err)
	}
	return rdb
}

func expandTilde(path string) string {
	// 如果路径不以 `~` 开头，直接返回
	if len(path) < 2 || path[:1] != "~" {
		return path
	}

	// 获取当前用户信息
	usr, err := user.Current()
	if err != nil {
		return ""
	}

	// 将 `~` 替换为当前用户的主目录
	return filepath.Join(usr.HomeDir, path[1:])
}

// SSH 方式连接 redis
func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func createKnownHosts() {
	f, fErr := os.OpenFile(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"), os.O_CREATE|os.O_APPEND, 0600)
	errCallBack(fErr)
	f.Close()
}
func checkKnownHosts() ssh.HostKeyCallback {
	createKnownHosts()
	kh, e := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	errCallBack(e)
	return kh
}
func addHostKey(remote net.Addr, pubKey ssh.PublicKey) error {
	// add host key if host is not found in known_hosts, error object is return, if nil then connection proceeds,
	// if not nil then connection stops.
	khFilePath := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")

	f, fErr := os.OpenFile(khFilePath, os.O_APPEND|os.O_WRONLY, 0600)
	if fErr != nil {
		return fErr
	}
	defer f.Close()

	knownHosts := knownhosts.Normalize(remote.String())
	_, fileErr := f.WriteString(knownhosts.Line([]string{knownHosts}, pubKey))
	return fileErr
}

// 支持多种Redis连接方式
// 普通方式:URI redis://:password@host:port
// SSH方式: user+pwd / ssh_key + passphrase
func connectRedisWithSSH(rDb int, rHost, rPort, rPass,
	sshHost, sshPort, sshUser, sshPass, sshKey, sshPassphrase string) (rdb *redis.Client) {

	f, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "config"))
	if err != nil {
		log.Fatal(err, "请为 sshHost配置 ~/.ssh/config")
	}
	cfg, err := ssh_config.Decode(f)
	errCallBack(err) // 限制必须配置 ssh_config
	sHost, _ := cfg.Get(sshHost, "Hostname")
	sPort, _ := cfg.Get(sshHost, "Port")
	sUser, _ := cfg.Get(sshHost, "User")
	sFile, _ := cfg.Get(sshHost, "IdentityFile")
	if sPort == "" { // 没有配置取默认22端口
		sPort = "22"
	}
	if sshPort != "" {
		sPort = sshPort
	}
	sFile = expandTilde(sFile)
	if sFile == "" { //默认
		sFile = filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa")
	}
	sAddr := sHost + ":" + sPort

	if sshUser != "" {
		sUser = sshUser
	}
	if sUser == "" { // 没有指定任何用户，取默认登录用户名
		usr, _ := user.Current()
		sUser = usr.Username
	}

	if sshKey != "" {
		sFile = sshKey
	}

	var authMethods []ssh.AuthMethod
	var keyErr *knownhosts.KeyError
	if sshPass != "" {
		// 优先使用密码方式
		authMethods = append(authMethods, ssh.Password(sshPass))
	}
	if fileExists(sFile) { // 使用密钥连接
		key, err := os.ReadFile(sFile)
		if err != nil {
			log.Fatalf("unable to read private key: %v", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			log.Fatalf("unable to parse private key: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	sshConfig := &ssh.ClientConfig{
		User: sUser,
		Auth: authMethods,
		HostKeyCallback: ssh.HostKeyCallback(func(host string, remote net.Addr, pubKey ssh.PublicKey) error {
			kh := checkKnownHosts()
			hErr := kh(host, remote, pubKey)
			// Reference: https://blog.golang.org/go1.13-errors
			// To understand what errors.As is.
			if errors.As(hErr, &keyErr) && len(keyErr.Want) > 0 {
				// Reference: https://www.godoc.org/golang.org/x/crypto/ssh/knownhosts#KeyError
				// if keyErr.Want slice is empty then host is unknown, if keyErr.Want is not empty
				// and if host is known then there is key mismatch the connection is then rejected.
				return keyErr
			} else if errors.As(hErr, &keyErr) && len(keyErr.Want) == 0 {
				// host key not found in known_hosts then give a warning and continue to connect.
				return addHostKey(remote, pubKey)
			}
			log.Printf("Pub key exists for %s.", host)
			return nil
		}),
	}

	// Connect to the remote server and perform the SSH handshake.
	sshClient, err := ssh.Dial("tcp", sAddr, sshConfig)
	errCallBack(err)
	rdb = redis.NewClient(&redis.Options{
		Addr:     net.JoinHostPort(rHost, rPort),
		Password: rPass,
		DB:       rDb,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sshClient.Dial(network, addr)
		},
		// Disable timeouts, because SSH does not support deadlines.
		ReadTimeout:  -2,
		WriteTimeout: -2,
	})

	return
}

func init() {
	var renameVar string
	var version bool

	// 功能说明： 支持redis全类型数据迁移工具
	program_name := os.Args[0]
	flag.Usage = func() {
		fmt.Println("功能说明:")
		fmt.Println("\t支持redis全类型数据迁移工具")
		fmt.Println("使用方法:")
		fmt.Printf("\t批量key跨库拷贝: %s -src source -dst destination -p pattern\n", program_name)
		fmt.Printf("\t单Key重命名拷贝: %s -src source -dst destination -r srckey,dstkey\n", program_name)
		fmt.Printf("\t批量导入Set数据: %s -src source -l file -table myset\n", program_name)
		fmt.Printf("\t批量导出Set数据: %s -src source -o file -table myset\n", program_name)
		fmt.Println("参数说明:")
		fmt.Println("  -src            : 原始库redis的地址,默认: redis://localhost:6379/0， 支持URI格式: redis://[:password@]localhost:6379/0 或SSH方式 redissh://[:password@]localhost:6379/0")
		fmt.Println("  -dst            : 目标库redis的地址,默认: 空")
		fmt.Println("  -d|-delete      : 是否删除redis的数据,默认不删除，请谨慎使用!,默认: false")
		fmt.Println("  -maxCount       : 单次SCAN提取的记录数,防止数据量过多导致redis连接超时,默认: 100")
		fmt.Println("  -p|-pattern     : 批量key跨库拷贝。redis的key的匹配规则,默认: 空, 可以使用通配符: *,?,例如: xxx*")
		fmt.Println("  -r|-rename      : 单Key重命名拷贝式。重命名redis的srckey和dstkey,冒号分隔,默认: 空，例如 srckey,dstkey")
		fmt.Println("  -l|-load <file> : 导入SET数据")
		fmt.Println("  -table <name>   : 导入SET表名")
		fmt.Println("  -o outfile      : 导出数据到文件")
		fmt.Println("  -v|-version     : 版本号信息")
	}
	// 参数说明：
	flag.StringVar(&srcUri, "src", "redis://localhost:6379/0", "原始库redis的地址")
	flag.StringVar(&dstUri, "dst", "", "目标库redis的地址")
	flag.StringVar(&pattern, "p", "", "跨库迁移,redis的key的匹配规则")
	flag.StringVar(&pattern, "pattern", "", "跨库迁移,redis的key的匹配规则")
	flag.BoolVar(&isDelete, "delete", false, "是否删除redis的数据")
	flag.BoolVar(&isDelete, "d", false, "是否删除redis的数据")
	flag.IntVar(&maxCount, "maxCount", 100, "单次SCAN提取的记录数,防止数据量过多导致redis连接超时.")
	flag.StringVar(&renameVar, "rename", "", "同库迁移,重命名redis的srckey和dstkey,冒号分隔,默认: 空，例如 srckey,dstkey")
	flag.StringVar(&renameVar, "r", "", "同库迁移,重命名redis的srckey和dstkey,逗号分隔,默认: 空，例如 srckey,dstkey")

	flag.StringVar(&loadFile, "l", "", "导入SET数据.")
	flag.StringVar(&loadFile, "load", "", "导入SET数据.")
	flag.StringVar(&tbName, "table", "", "导入/导出的表名")
	flag.StringVar(&outFile, "o", "", "导出文件名")
	flag.BoolVar(&version, "v", false, "显示版本信息")
	flag.BoolVar(&version, "version", false, "显示版本信息")
	flag.Parse()

	if version {
		fmt.Println("redis_tool version: ", commit)
		os.Exit(0)
	}

	// redis_tool -src redis://localhost:6379/0 -dst redis://localhost:6379/0 -r "Aliyun:shareIDRemBack,Aliyun:shareIDRemBack1"
	if pattern == "" && renameVar == "" && loadFile == "" && outFile == "" {
		log.Println("匹配规则 pattern rename 或 loadFile 参数不能都为空!")
		os.Exit(1)
	}
	// 工作模式: cross / rename / export /rename
	mode = "cross"
	if outFile != "" {
		mode = "export"
	} else if renameVar != "" { //rename mode
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
	} else if loadFile != "" {
		mode = "loader"
	}
	if srcUri == "" {
		log.Println("请输入原始库redis的地址")
		os.Exit(1)
	}
	if maxCount <= 0 {
		log.Println("请输入每次迁移的数据量")
		os.Exit(1)
	}
	rdb_src = InitDB(srcUri, nil)
	log.Println("redis_src连接成功!")

	if mode == "cross" || mode == "rename" {
		if dstUri == "" {
			log.Println("请输入目标库redis的地址")
			os.Exit(1)
		}
		rdb_dst = InitDB(dstUri, nil)
		log.Println("redis_dst连接成功!")
	}
}

func ExportRedisData() error {
	file, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	skey, err := rdb_src.Keys(ctx, tbName).Result()

	if err != nil {
		return errors.New("获取oldKey失败, " + err.Error())
	}
	if len(skey) == 0 {
		return errors.New("oldKey不存在")
	}
	if len(skey) > 1 {
		return fmt.Errorf("oldKey存在[ %d ]个, oldKey:[%s]", len(skey), tbName)
	}
	// 判断oldKey类型
	rtype, err := rdb_src.Type(ctx, tbName).Result()
	if err != nil {
		return errors.New("获取oldKey类型失败, " + err.Error())
	}
	if rtype != "string" && rtype != "hash" && rtype != "list" && rtype != "set" && rtype != "zset" {
		return errors.New("oldKey类型不支持")
	}
	srcType := rtype
	total := 0 // 记录操作记录的总数
	// 开始根据srcType类型迁移数据
	if srcType == "string" {
		// 获取key的值
		data, err := rdb_src.Get(ctx, tbName).Result()
		if err != nil {
			return errors.New("获取oldKey值失败, " + err.Error())
		}
		//
		fmt.Println(data)
		total++
	} else if srcType == "hash" {
		// 获取key的值
		data, err := rdb_src.HGetAll(ctx, tbName).Result()
		if err != nil {
			return errors.New("获取oldKey值失败, " + err.Error())
		}
		for _, v := range data {
			fmt.Println(v)
		}
		total += len(data)
	} else if srcType == "list" {
		// 获取key的值
		// 循环 获取数据，每次获取maxCount个数据
		var cursor int64 = 0
		for {
			data, err := rdb_src.LRange(ctx, tbName, cursor, cursor+int64(maxCount)).Result()
			if err != nil {
				return errors.New("获取oldKey值失败, " + err.Error())
			}
			if len(data) == 0 {
				break
			}
			for _, v := range data {
				file.WriteString(v)
				file.WriteString("\n")
			}
			total += len(data)
			cursor += int64(len(data))
		}

	} else if srcType == "set" {
		// 获取key的值
		var cursor uint64 = 0
		for {
			data, next_cursor, err := rdb_src.SScan(ctx, tbName, cursor, "", int64(maxCount)).Result()
			if err != nil {
				return errors.New("获取oldKey值失败, " + err.Error())
			}
			if len(data) == 0 {
				break
			}
			for _, v := range data {
				file.WriteString(v)
				file.WriteString("\n")
				if isDelete {
					rdb_src.SRem(ctx, tbName, data)
				}
			}
			total += len(data)
			if next_cursor == 0 {
				break
			}
			cursor = next_cursor
		}
	} else {
		return errors.New("oldKey类型不支持")
	}
	return nil
}

// 支持Set类型数据导入
func LoadFileData() {
	file, err := os.OpenFile(loadFile, os.O_RDONLY, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	loadData := strings.Split(string(content), "\n")
	var data []interface{}
	for _, v := range loadData {
		if strings.Trim(v, " ") != "" {
			data = append(data, v)
		}
	}
	err = rdb_src.SAdd(ctx, tbName, data...).Err()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("导入数据完成:len:", len(data))
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
			err = rdb_dst.ZAdd(ctx, newKey, data...).Err()
			if err != nil {
				return errors.New("添加newKey值失败, " + err.Error())
			}
			total += len(data)
			cursor += int64(len(data))
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
	// 表类型、名称、操作记录数
	log.Printf("类型: %5s , 名称: %25s ,成功迁移数据: %15d 条!\n", srcType, oldKey, total)
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
	if srcUri == dstUri {
		// 不跨库, rename 操作即可
		status := rdb_src.Rename(ctx, srcKey, dstKey)
		log.Println(status)
		return
	}
	err := CopyRedisData(srcKey, dstKey)
	if err != nil {
		log.Println(err)
		return
	}
}
func main() {
	if mode == "export" {
		// export data
		ExportRedisData()
	} else if mode == "cross" {
		MoveRedisData()
	} else if mode == "rename" {
		RenameRedisData()
	} else if mode == "loader" {
		LoadFileData()
	} else {
		log.Println("啥也没干...")
	}
}
