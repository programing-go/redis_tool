#
# aliyun_spider: 负责爬虫采集数据 --> 依赖redis服务 + 高匿名代理池
# aliyun_transfer: 负责处理采集结果数据 --> 依赖redis服务 + mongoDB服务
# aliyun_web: 负责前端提供搜索功能 ---> 依赖 ES 提供搜索服务 , Redis 保存用户主动分享的 资源链接


bindir = .
LDFLAGS = '-w -extldflags "-static"

All: redis_tool

redis_tool:redis_tool.go
	CGO_ENABLED=0 go build -o ${bindir}/$@ $< ${LDFALGS}

clean:
	-rm -f ${bindir}/redis_tool


