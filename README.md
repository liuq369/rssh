##### 命令参数列表

```
shell> ./rssh -h
Usage of ./rssh:
  -config string
       config file for yaml list (default "./config.yml")
  -example
       write example config file
  -exec string
       exec shell command (default "id")
  -file string
       upload file, example /etc/hosts:/home/user/hosts
  -host string
       exec host group name
  -root
       enable root privilege
```


##### 执行命令

```
shell> ./rssh -host website -exec 'df -h /'

> 192.168.100.201:22
Filesystem Size Used Avail Use% Mounted on
/dev/mapper/VolGroup-lv_root
50G 5.9G 41G 13% /

> 192.168.100.202:22
Filesystem Size Used Avail Use% Mounted on
/dev/mapper/VolGroup-lv_root
50G 5.9G 41G 13% /

---
time: 102.160669ms
```


##### 上传文件

```
shell> ./rssh -host website -file '/etc/hosts:/home/user/hosts'
/etc/hosts --> 192.168.100.202:22:/home/user/hosts OK
/etc/hosts --> 192.168.100.201:22:/home/user/hosts OK
---
time: 84.508462ms
```



