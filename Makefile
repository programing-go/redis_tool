#
# aliyun_spider: 负责爬虫采集数据 --> 依赖redis服务 + 高匿名代理池
# aliyun_transfer: 负责处理采集结果数据 --> 依赖redis服务 + mongoDB服务
# aliyun_web: 负责前端提供搜索功能 ---> 依赖 ES 提供搜索服务 , Redis 保存用户主动分享的 资源链接


bindir = ./release
LDFLAGS = '-w -extldflags "-static"

All: amd64 armv5 armv7 arm64 gzip

redis_tool:redis_tool.go
	CGO_ENABLED=0 go build -o ${bindir}/$@ $< ${LDFALGS}

amd64:
	GOARCH=amd64 GOOS=linux go build -o ${bindir}/redis_tool_linux_amd64    redis_tool.go ${LDFALGS}
armv5:
	GOARCH=arm  GOARM=5 GOOS=linux go build -o ${bindir}/redis_tool_linux_armv5    redis_tool.go ${LDFALGS}
armv7:
	GOARCH=arm  GOARM=7 GOOS=linux go build -o ${bindir}/redis_tool_linux_armv7    redis_tool.go ${LDFALGS}
arm64:
	GOARCH=arm64 GOOS=linux go build -o ${bindir}/redis_tool_linux_arm64    redis_tool.go ${LDFALGS}

gzip: ${bindir}/*
	rm -f ${bindir}/*.gz
	gzip -9 ${bindir}/*

clean:
	-rm -f ${bindir}/redis_tool*


