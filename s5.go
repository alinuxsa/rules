package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

var err error
var n int

type SocksProtocol struct {
	client net.Conn
	target net.Conn
}

func (p *SocksProtocol) Auth() error {

	/*
		协商阶段,客户端向socks5服务端发送请求，报文如下

		+----+----------+----------+
		|VER | NMETHODS | METHODS  |
		+----+----------+----------+
		| 1  |    1     | 1 to 255 |
		+----+----------+----------+

		此时服务端判断前两个字节即可，如果VER不是0x05,则拒绝连接
		NMETHODS表示客户端支持多少种认证方法，NMETHODS表示METHODS的长度
		如果客户端提供的NMETHODS=0，则表示客户端不支持认证。

	*/
	buf := make([]byte, 256)
	n, err = io.ReadFull(p.client, buf[:2])
	if err != nil {
		log.Println("读取协商信息失败, ", err)
		p.client.Close()
		return err
	}
	if n != 2 || buf[0] != 0x05 {
		p.client.Close()
		return errors.New("不是socks5协议,断开连接")
	}
	nMethods := buf[1]
	// 读取METHODS
	_, err = io.ReadFull(p.client, buf[:nMethods])
	if err != nil {
		return err
	}
	/*
		返回给客户端，不需要认证
		+----+--------+
		|VER | METHOD |
		+----+--------+
		| 1  |   1    |
		+----+--------+
	*/
	resp := []byte{0x05, 0x00}
	_, err = p.client.Write(resp)
	if err != nil {
		return err
	}
	return nil
}

// 读取目标地址，并建立连接
func (p *SocksProtocol) Connect() error {
	buf := make([]byte, 256)

	n, err = io.ReadFull(p.client, buf[:4])

	/*
		通过协商之后开始处理客户端发送过来的请求

		+----+-----+-------+------+----------+----------+
		|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+

		CMD 的取值有三种
		0x01 表示CONNECT请求
		0x02 表示BIND请求
		0x03 表示UDP转发

		RSV 为保留字段，不用管它

		ATYP 表示目标的地址类型，DST.ADDR的数据由ATYP的值决定
		0x01 表示IPv4地址 DST.ADDR为4个字节
		0x03 表示域名 DST.ADDR是一个可变长度的域名
		0x04表示IPv6地址，DST.ADDR为16个字节长度

		DST.ADDR 一个可变长度的值
		DST.PORT 目标端口，固定2个字节
	*/
	if n != 4 {
		return errors.New("读取ATYP失败")
	}
	if err != nil {
		return err
	}
	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 0x05 || cmd != 0x01 {
		p.client.Close()
		return errors.New("无效的ver/cmd,断开连接")
	}
	addr := ""

	switch atyp {
	case 0x01:
		// IPv4
		n, err = io.ReadFull(p.client, buf[:4])
		if n != 4 {
			p.client.Close()
			return errors.New("无效的IPv4地址: " + err.Error())
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		log.Printf("目标IPv4地址为: %s\n", addr)
	case 0x03:
		/*
			在SOCKS5协议中，atyp字段用于表示dst.addr的地址类型。
			当atyp的值为3时，表示dst.addr是一个域名地址，而不是IPv4或IPv6地址。
			在这种情况下，dst.addr的长度是由接下来的一个字节确定的，这个字节表示域名的长度。
			这个长度字节后面紧跟着域名本身，之后是端口号。
			因此，当atyp为3时，你需要读取紧接着的一个字节来确定dst.addr的长度。
			这个长度值是指域名本身的字节数，不包括长度字节本身和端口号。然后，你可以根据这个长度值读取相应字节数的数据，得到完整的域名地址。
		*/
		n, err = io.ReadFull(p.client, buf[:1])
		if n <= 1 || err != nil {
			p.client.Close()
			return errors.New("读取域名长度失败: " + err.Error())
		}
		addrLen := int(buf[0]) // 读取1个字节 读取出域名长度

		n, err = io.ReadFull(p.client, buf[:addrLen]) // 根据长度读取域名

		if err != nil || n != addrLen {
			p.client.Close()
			return errors.New("读取hostname出错: " + err.Error())
		}
		addr = string(buf[:addrLen])
		log.Printf("目标hostname为: %s\n", addr)
	default:
		p.client.Close()
		return errors.New("其它atyp暂未实现,断开连接")
	}
	// 读取最后两字节端口
	n, err = io.ReadFull(p.client, buf[:2])
	if n != 2 || err != nil {
		p.client.Close()
		return errors.New("读取目标端口失败: " + err.Error())
	}
	port := binary.BigEndian.Uint16(buf[:2])
	log.Printf("读取到目标端口: %d\n", port)

	// 与目标地址建立连接
	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		return errors.New("连接到目标地址错误: " + err.Error())
	}
	p.target = dest
	/*
		回复客户端，已连接到target
		响应格式如下
		+----+-----+-------+------+----------+----------+
		|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+---------
		VER socks版本，这里为0x05
		REP Relay field,内容取值如下
		    X’00’ succeeded
		    X’01’ general SOCKS server failure
		    X’02’ connection not allowed by ruleset
		    X’03’ Network unreachable
		    X’04’ Host unreachable
		    X’05’ Connection refused
		    X’06’ TTL expired
		    X’07’ Command not supported
		    X’08’ Address type not supported
		    X’09’ to X’FF’ unassigned
		RSV 保留字段
		ATYPE 同请求的ATYPE
		BND.ADDR 服务绑定的地址
		BND.PORT 服务绑定的端口DST.PORT

	*/
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	p.client.Write(resp)
	return nil
}

func (p *SocksProtocol) Forward() {
	var wg sync.WaitGroup
	forward := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		io.Copy(src, dest)
		wg.Done()
	}
	wg.Add(2)
	go forward(p.client, p.target)
	go forward(p.target, p.client)
	wg.Wait()
}

func main() {
	log.Println("Server开始运行,监听 127.0.0.1:10999 ")
	l, err := net.Listen("tcp", "127.0.0.1:10999")
	if err != nil {
		log.Println("监听错误: " + err.Error())
		return
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println("接收连接出错: " + err.Error())
			continue
		}
		go process(conn)
	}
}

func process(client net.Conn) {
	defer client.Close()
	p := &SocksProtocol{
		client: client,
	}
	clientAddr := p.client.RemoteAddr().String()
	log.Printf("接收到来自 %s 的连接\n", clientAddr)
	err = p.Auth()
	if err != nil {
		log.Println(err)
		return
	}
	err := p.Connect()
	if err != nil {
		log.Println(err)
		return
	}
	// 拿到dest之后，开始转发数据
	p.Forward()

}
