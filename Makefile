bindir = ./release

VERSION = $(shell git rev-parse --short HEAD)
LDFALGS = -ldflags "-X main.commit=${VERSION}"

GOBUILD = CGO_ENABLED=0 go build

All: redis_tool

redis_tool:redis_tool.go
	CGO_ENABLED=0 go build ${LDFALGS} -o $@ $< 

amd64:
	GOARCH=amd64 GOOS=linux ${GOBUILD} ${LDFALGS} -o ${bindir}/redis_tool_linux_amd64    redis_tool.go

gzip: ${bindir}/*
	rm -f ${bindir}/*.gz
	gzip -9 ${bindir}/*

clean:
	-rm -f ${bindir}/redis_tool* redis_tool


