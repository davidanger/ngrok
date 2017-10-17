package server

import (
	"crypto/tls"
	"fmt"
	vhost "github.com/inconshreveable/go-vhost"
	//"net"
	"ngrok/conn"
	"ngrok/log"
	"strings"
	"time"
	"crypto/md5"
	"strconv"
	"runtime/debug"
	"encoding/json"
)

const (
	NotAuthorized = `HTTP/1.0 401 Not Authorized
WWW-Authenticate: Basic realm="ngrok"
Content-Length: 23

Authorization required
`

	NotKeyAuthorized = `HTTP/1.0 401 Unauthorized
Content-Length: 34
Content-type: text/html; charset=utf-8

未授权客户机访问数据。
`

	NotFound = `HTTP/1.0 404 Not Found
Content-Length: %d

Tunnel %s not found
`

	BadRequest = `HTTP/1.0 400 Bad Request
Content-Length: 12

Bad Request
`
	OkRequest = `HTTP/1.0 200 Ok
Content-Length: %d
Content-type: text/html; charset=utf-8

%s
`
)


// Listens for new http(s) connections from the public internet
func startHttpListener(addr string, tlsCfg *tls.Config) (listener *conn.Listener) {
	// bind/listen for incoming connections
	var err error
	if listener, err = conn.Listen(addr, "pub", tlsCfg); err != nil {
		panic(err)
	}

	proto := "http"
	if tlsCfg != nil {
		proto = "https"
	}

	log.Info("监听公共 %s 连接 %v", proto, listener.Addr.String())
	go func() {
		for conn := range listener.Conns {
			go httpHandler(conn, proto)
		}
	}()

	return
}

// Handles a new http connection from the public internet
func httpHandler(c conn.Conn, proto string) {
	defer c.Close()
	defer func() {
		// recover from failures
		if r := recover(); r != nil {
			c.Warn("http处理失败，出现错误 %v: %s", r, debug.Stack())
		}
	}()

	// Make sure we detect dead connections while we decide how to multiplex
	c.SetDeadline(time.Now().Add(connReadTimeout))

	// multiplex by extracting the Host header, the vhost library
	vhostConn, err := vhost.HTTP(c)
	if err != nil {
		c.Warn("无法读取有效的 %s 请求: %v", proto, err)
		c.Write([]byte(BadRequest))
		return
	}

	// read out the Host header and auth from the request
	host := strings.ToLower(vhostConn.Host())
	auth := vhostConn.Request.Header.Get("Authorization")

	//输出隧道的在线域名列表
	subDomain := strings.Split(host,".")[0]
	if subDomain == "status" {
		c.Info("获取隧道域名列表请求 host: %v", host)
		batch := make(map[string]string)

		//循环连接控制类
		for _, cc := range controlRegistry.controls {
			//循环隧道类获得url
			for k, t := range cc.tunnels{
				mapKey := fmt.Sprintf("%d", k)
				batch[mapKey] = t.url
			}
		}

		//url数组json化后输出
		payload, _ := json.Marshal(batch)
		c.Write([]byte(fmt.Sprintf(OkRequest, len(payload), payload)))
		return
	}

	//接受参数
	CookieKey, err := vhostConn.Request.Cookie("tunnels-key")
	CookieTime, err := vhostConn.Request.Cookie("tunnels-time")

	if opts.signatureKey != "" && err != nil {
		c.Warn("无法读取Cookie: %v", err)
		c.Write([]byte(NotKeyAuthorized))
		return
	}

	// done reading mux data, free up the request memory
	vhostConn.Free()

	// We need to read from the vhost conn now since it mucked around reading the stream
	c = conn.Wrap(vhostConn, "pub")

	// multiplex to find the right backend host
	c.Debug("在请求中找到hostname %s ", host)
	tunnel := tunnelRegistry.Get(fmt.Sprintf("%s://%s", proto, host))
	if tunnel == nil {
		c.Info("找不到 hostname %s 的隧道", host)
		c.Write([]byte(fmt.Sprintf(NotFound, len(host)+18, host)))
		return
	}

	//添加cookie签名验证,过期时间为1天
	//没有配置signatureKey参数不使用此功能
	if opts.signatureKey != "" {
		//检查时间是否过期
		CookieTimeInt64, _ := strconv.ParseInt(CookieTime.Value, 10, 64)
		isExpire := CookieTimeInt64 <= (time.Now().Unix() - 86400)

		//生成签名
		md5Byte := md5.Sum( []byte(fmt.Sprintf("%s%s", opts.signatureKey, CookieTime.Value)) )
		signString := fmt.Sprintf("%x", md5Byte)

		//对比验证
		if signString != CookieKey.Value || isExpire {
			c.Info("签名验证失败: %s, 时间戳: %s, 是否过期:%t, 正确签名: %s", CookieKey.Value, CookieTime.Value, isExpire, signString)
			c.Write([]byte(NotKeyAuthorized))
			return
		}
	}

	// If the client specified http auth and it doesn't match this request's auth
	// then fail the request with 401 Not Authorized and request the client reissue the
	// request with basic authdeny the request
	if tunnel.req.HttpAuth != "" && auth != tunnel.req.HttpAuth {
		c.Info("Auth验证失败: %s", auth)
		c.Write([]byte(NotAuthorized))
		return
	}

	// dead connections will now be handled by tunnel heartbeating and the client
	c.SetDeadline(time.Time{})

	// let the tunnel handle the connection now
	tunnel.HandlePublicConnection(c)
}
