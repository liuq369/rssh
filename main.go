package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/kylelemons/go-gypsy/yaml"
	"golang.org/x/crypto/ssh"
)

// 基本验证信息
type keyPassInfo struct {
	hostname, username, keyFile, keyPass string
}

func errorr(errs ...error) {

	l := len(errs)
	for i := 0; i < l; i++ {
		err := errs[i]
		if err != nil {
			fmt.Println("Error:", err)
		}
	}

	if errs[l-1] != nil {
		os.Exit(1)
	}
}

// 私钥密码 验证执行ssh
func sshKeyPassExec(k keyPassInfo, s string) (out string, err error) {

	// 读取密钥
	pemBytes, err := ioutil.ReadFile(k.keyFile)
	if err != nil {
		return "", err
	}

	// 解析密钥
	signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(k.keyPass))
	if err != nil {
		return "", err
	}
	method := ssh.PublicKeys(signer)

	// 鉴权方式
	sshs := []ssh.AuthMethod{}
	auths := append(sshs, method)

	// 执行连接
	config := &ssh.ClientConfig{
		User: k.username,
		Auth: auths,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// 建立握手
	client, err := ssh.Dial("tcp", k.hostname, config)
	if err != nil {
		return "", err
	}
	defer client.Close()

	// 创建连接
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	// 执行命令
	buf, err := session.CombinedOutput(s)
	if err != nil {
		return "", err
	}

	// 返回结果
	return string(buf), nil
}

// scp上传文件，存在则覆盖
func scpFileKeyPass(k keyPassInfo, f []string) error {

	// 读取密钥
	pemBytes, err := ioutil.ReadFile(k.keyFile)
	if err != nil {
		return err
	}

	// 解析密钥
	signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(k.keyPass))
	if err != nil {
		return err
	}
	method := ssh.PublicKeys(signer)

	// 鉴权方式
	auths := append([]ssh.AuthMethod{}, method)

	// 执行连接
	config := &ssh.ClientConfig{
		User: k.username,
		Auth: auths,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// 建立握手
	clientt, err := ssh.Dial("tcp", k.hostname, config)
	if err != nil {
		return err
	}
	defer clientt.Close()

	// 创建连接
	session, err := clientt.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// 打开文件
	file, err := os.Open(f[0])
	if err != nil {
		return err
	}
	defer file.Close()

	// 获得字节
	contentsBytes, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}
	bytesReader := bytes.NewReader(contentsBytes)

	// 获得路径及文件名
	remoteDir, remoteFile := path.Split(f[1])

	go func() {

		// 创建管道
		w, _ := session.StdinPipe()
		defer w.Close()

		// 写入管道 目录umask码 长度 目录
		// fmt.Fprintln(w, "D0755", 0, "") // mkdir

		// 写入管道 文件umask码 长度 文件
		fmt.Fprintln(w, "C0644", len(contentsBytes), remoteFile)
		io.Copy(w, bytesReader)
		fmt.Fprint(w, "\x00") // 移除以 \x00 结尾
	}()
	err = session.Run("/usr/bin/scp -tr " + remoteDir)
	return err
}

func scpGo(ch chan int, s keyPassInfo, f []string) {
	var check interface{}
	if err := scpFileKeyPass(s, f); err != nil {
		check = err
	} else {
		check = "OK"
	}
	fmt.Println(f[0]+" --> "+s.hostname+":"+f[1], check)
	ch <- 1
}

func sshGo(ch chan int, s keyPassInfo, e string) {
	out, err := sshKeyPassExec(s, e)
	fmt.Printf("%c[1;40;32m%s%c[0m", 0x1B, "> ", 0x1B)
	if err != nil {
		fmt.Println(s.hostname+"\n", err)
	} else {
		if len(out) == 0 {
			fmt.Println(s.hostname + "\n OK")
		} else {
			fmt.Println(s.hostname + "\n" + out)
		}
	}

	ch <- 1
}

func main() {

	//记录开始时间
	start := time.Now()

	var host, exec, grou, file string
	var root, example bool
	flag.StringVar(&host, "config", "./config.yml", "config file for yaml list")
	flag.StringVar(&exec, "exec", "id", "exec shell command")
	flag.StringVar(&grou, "host", "", "select host group name")
	flag.StringVar(&file, "file", "", "upload file /etc/hosts:/root/hosts")
	flag.BoolVar(&example, "example", false, "write example config file")
	flag.BoolVar(&root, "root", false, "enable root privilege")
	flag.Parse()

	if len(os.Args) == 1 {
		errorr(fmt.Errorf("need running -h, see help"))
	}

	if example {
		file, err := os.OpenFile(host, os.O_WRONLY|os.O_TRUNC|os.O_EXCL|os.O_CREATE, 0600)
		if err != nil {
			errorr(err)
		}
		defer file.Close()

		outputWriter := bufio.NewWriter(file)
		outputWriter.WriteString(`Auth:
    user: user
    file: /home/liuq369/.ssh/id_rsa-test-auto-login
    pass: passwd

Host:
    website:
        - 192.168.100.201:22
        - 192.168.100.202:22
    test:
        - 192.168.100.203:22`)
		outputWriter.Flush()
		os.Exit(0)
	}

	if len(grou) == 0 {
		errorr(fmt.Errorf("need specified running group -g"))
	}

	hostList, err := yaml.ReadFile(host)
	if err != nil {
		errorr(err)
	}

	// 获取验证信息
	fileUser, err1 := hostList.Get("Auth.user")
	fileKye, err2 := hostList.Get("Auth.file")
	filePass, err3 := hostList.Get("Auth.pass")
	errorr(err1, err2, err3)

	// 警告特权用户执行
	if fileUser == "root" && !(root) {
		errorr(fmt.Errorf("prevent (root) privileged from executing, or enable -root"))
	}
	if root {
		fileUser = "root"
	}

	// 遍历获取所有主机
	var hosts []string
	var i = 0
	for {
		stat, err := hostList.Get("Host." + grou + "[" + strconv.Itoa(i) + "]")
		if err != nil {
			break
		}
		hosts = append(hosts, stat)
		i++
	}
	hr := len(hosts)

	// 获取 []keyPassInfo
	var baseAuthInfo []keyPassInfo
	for i := 0; i < hr; i++ {
		baseAuthInfo = append(baseAuthInfo, keyPassInfo{
			hostname: hosts[i],
			username: fileUser,
			keyFile:  fileKye,
			keyPass:  filePass,
		})
	}

	r := len(baseAuthInfo)
	if len(file) != 0 {

		// scp 方式
		f := strings.Fields(strings.Replace(file, ":", " ", -1))
		if len(f) != 2 {
			errorr(fmt.Errorf("example /etc/hosts:/home/user/hosts"))
		}

		// 上传至目标目录白名单
		if path.Dir(path.Dir(f[1])) != "/home" && !(root) {
			errorr(fmt.Errorf("only allow uploads to $HOME, or enable -root"))
		}

		chs := make([]chan int, r)
		for i := 0; i < r; i++ {
			chs[i] = make(chan int)
			go scpGo(chs[i], baseAuthInfo[i], f)
		}

		for _, ch := range chs {
			<-ch
		}

		//输出执行时间
		fmt.Println("---\ntime:", time.Since(start))

	} else {

		// ssh 方式
		chs := make([]chan int, r)
		fmt.Println()
		for i := 0; i < r; i++ {
			chs[i] = make(chan int)
			go sshGo(chs[i], baseAuthInfo[i], exec)
		}

		for _, ch := range chs {
			<-ch
		}

		//输出执行时间
		fmt.Println("---\ntime:", time.Since(start))
	}
}
