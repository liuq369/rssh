package main

import (
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
	"golang.org/x/crypto/ssh/terminal"
)

type argsInfo struct {
	cmd map[string]string // c, h, e, f 参数
	mod bool              // ssh 或 scp 模式
}

type authInfo struct {
	host string // 主机
	user string // 用户名
	key  string // 密钥路径
	pass string // 密码
	mod  bool   // 密钥/密码 验证
}

type fileInfo struct {
	yaml  *yaml.File
	hosts map[string]string
}

func (a *argsInfo) args() *bool {

	var c = flag.String("c", "./config.yml", "config file for yaml list")
	var h = flag.String("h", "", "exec host group name")
	var e = flag.String("e", "", "exec shell command")
	var f = flag.String("f", "", "upload file, example /etc/hosts:/home/user/hosts")
	var example = flag.Bool("example", false, "write example config file")
	flag.Parse()

	a.cmd = make(map[string]string)
	a.cmd["c"] = *c
	a.cmd["h"] = *h
	a.cmd["e"] = *e
	a.cmd["f"] = *f
	return example
}

func (a argsInfo) examp() error {

	var err error
	if a.mod {

		fmt.Println("write example file: ", a.cmd["c"])
		var mode, t string

		for {
			fmt.Printf("auth mode (key/pass)? ")
			fmt.Scanln(&mode)

			if mode == "key" {
				t = "    file: /home/liuq369/.ssh/releases\n\n"
				break
			}
			if mode == "pass" {
				break
			}
		}

		var t1 = "Auth:\n    user: user\n" + t
		var t2 = "\nHost:\n    website:\n        - 192.168.100.201\n    	- 192.168.100.202\n    test:\n        - 192.168.100.203\n"
		text := []byte(t1 + t2)

		err = ioutil.WriteFile(a.cmd["c"], text, 0600)
		if err == nil {
			err = fmt.Errorf("ok")
		}
	}
	return err
}

func (a *argsInfo) filter() error {

	if len(os.Args) == 1 {
		return fmt.Errorf("need running '-help', see help")
	}

	if len(a.cmd["h"]) == 0 {
		return fmt.Errorf("need args '-h'")
	}

	if len(a.cmd["e"]) == 0 && len(a.cmd["f"]) == 0 {
		return fmt.Errorf("choose one of two, '-e' '-f'")
	}

	if len(a.cmd["e"]) != 0 && len(a.cmd["f"]) != 0 {
		return fmt.Errorf("choose one of two, '-e' '-f'")
	}

	if len(a.cmd["e"]) > 0 {
		a.mod = true
	} else {
		a.mod = false
	}

	return nil
}

func (a *fileInfo) yml(in string) error {

	y, err := yaml.ReadFile(in)
	if err != nil {
		return err
	}

	a.yaml = y
	return nil
}

// 通用基本验证信息
func (a fileInfo) auth() ([]string, bool, error) {

	var mod bool
	user, err := a.yaml.Get("Auth.user")
	if err != nil {
		return nil, mod, err
	}

	key, err := a.yaml.Get("Auth.file")
	if err != nil {
		mod = false
	} else {
		mod = true
	}

	var pass string
	for i := 0; i < 2; i++ {

		fmt.Fprint(os.Stderr, "Password: ")
		pw, err := terminal.ReadPassword(0)
		if err != nil {
			return nil, true, err
		}
		if pw != nil {
			print("\n")
			pass = string(pw)
			break
		}
		print("\n")
	}
	if len(pass) == 0 {
		return nil, mod, fmt.Errorf("password is nil")
	}

	var auth []string
	auth = append(auth, user)
	auth = append(auth, key)
	auth = append(auth, pass)

	return auth, mod, nil
}

// 获取所有主机
func (a fileInfo) hostss(host string) ([]string, error) {

	var hosts []string
	var i = 0
	for {
		stat, err := a.yaml.Get("Host." + host + "[" + strconv.Itoa(i) + "]")
		if err != nil {
			if i == 0 {
				return nil, fmt.Errorf("host list file is nil")
			}
			break
		}

		hosts = append(hosts, stat)
		i++
	}

	return hosts, nil
}

// 默认使用22端口
func (a fileInfo) port(hosts []string) []string {

	var host string
	var err error
	var hostports []string
	for _, v := range hosts {
		_, _, err = net.SplitHostPort(v)
		if err != nil {
			host = net.JoinHostPort(v, "22")
		} else {
			host = v
		}
		hostports = append(hostports, host)
	}

	return hostports
}

// 解密
func (a authInfo) dec(c bool) ([]ssh.AuthMethod, error) {

	var auths []ssh.AuthMethod
	if c {

		// 读取密钥
		pemBytes, err := ioutil.ReadFile(a.key)
		if err != nil {
			return nil, err
		}

		// 解析密钥
		signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(a.pass))
		if err != nil {
			return nil, err
		}
		method := ssh.PublicKeys(signer)

		// 鉴权方式
		sshs := []ssh.AuthMethod{}
		auths = append(sshs, method)
	} else {

		// 鉴权方式
		auths = []ssh.AuthMethod{ssh.Password(a.pass)}
	}

	return auths, nil
}

// 执行
func (a authInfo) ssh(s []ssh.AuthMethod, cmd string) (string, error) {

	// 执行连接
	config := &ssh.ClientConfig{
		User: a.user,
		Auth: s,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// 建立握手
	client, err := ssh.Dial("tcp", a.host, config)
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
	buf, err := session.CombinedOutput(cmd)
	if err != nil {
		return "", err
	}

	// 返回结果
	out := string(buf)
	return out, nil
}

// 上传
func (a authInfo) scp(s []ssh.AuthMethod, sf, df string) error {

	// 执行连接
	config := &ssh.ClientConfig{
		User: a.user,
		Auth: s,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// 建立握手
	client, err := ssh.Dial("tcp", a.host, config)
	if err != nil {
		return err
	}
	defer client.Close()

	// 创建连接
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// 打开文件
	file, err := os.Open(sf)
	if err != nil {
		return err
	}
	defer file.Close()

	// 获得字节
	contentsBytes, _ := ioutil.ReadAll(file)
	bytesReader := bytes.NewReader(contentsBytes)

	// 获得路径及文件名
	remoteDir, remoteFile := path.Split(df)

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

	if err := session.Run("/usr/bin/scp -tr " + remoteDir); err != nil {
		return err
	}

	return nil
}

func main() {

	// 获取命令行参数
	args := &argsInfo{}
	exam := args.args()

	// 是否写入配置文件（存在则覆盖）
	if *exam {
		if err := args.examp(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			os.Exit(0)
		}
	}

	// 必须的命令行参数
	if err := args.filter(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// 为解析yml做铺垫
	yml := &fileInfo{}
	if err := yml.yml(args.cmd["c"]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// 获取 用户名，密钥路径，密码，是否使用密钥验证
	ukp, mod, err := yml.auth()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// 需要执行的主机列表
	hosts, err := yml.hostss(args.cmd["h"])
	if err != nil {
		fmt.Println(err)
	}
	hostports := yml.port(hosts)

	// 解密信息
	auth := &authInfo{
		user: ukp[0],
		key:  ukp[1],
		pass: ukp[2],
	}
	dec, err := auth.dec(mod)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	//记录开始时间
	start := time.Now()

	// 执行
	r := len(hostports)
	chs := make([]chan bool, r)
	fmt.Print("---\n")

	for i := 0; i < r; i++ {
		a := authInfo{
			user: auth.user,
			key:  auth.key,
			pass: auth.pass,
			host: hostports[i],
		}

		chs[i] = make(chan bool)
		ch := chs[i]
		go func() {

			if args.mod {

				// ssh
				out1, err := a.ssh(dec, "echo $HOSTNAME; "+args.cmd["e"])
				if err != nil {
					out2, err := a.ssh(dec, "echo $HOSTNAME; "+args.cmd["e"])
					if err != nil {
						fmt.Printf("%c[1;40;31m%s%c[0m", 0x1B, "\n> "+a.host+fmt.Sprintln("", err)+out2, 0x1B)
					} else {
						fmt.Printf("%c[1;40;32m%s%c[0m", 0x1B, "\n> ", 0x1B)
						fmt.Print(out2)
					}

				} else {
					fmt.Printf("%c[1;40;32m%s%c[0m", 0x1B, "\n> ", 0x1B)
					fmt.Print(out1)
				}
			} else {

				// scp
				ff := strings.Replace(args.cmd["f"], ":", " ", -1)
				f := strings.Fields(ff)

				var errr error
				err := a.scp(dec, f[0], f[1])
				if err != nil {
					err := a.scp(dec, f[0], f[1])
					if err != nil {
						errr = err
					} else {
						errr = fmt.Errorf("ok")
					}
				} else {
					errr = fmt.Errorf("ok")
				}
				fmt.Println(f[0], a.host, "->", f[1], errr)
			}
			ch <- true
		}()
	}

	for j := 0; j < r; j++ {
		<-chs[j]
	}

	if args.mod {
		fmt.Println("\n---")
	} else {
		fmt.Println("---")
	}

	//输出执行时间
	fmt.Println("time:", time.Since(start))
}
