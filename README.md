##### 命令参数列表

```
shell> ./rssh -help
Usage of ./rssh:
  -c string
       config file for yaml list (default "./config.yml")
  -e string
       exec shell command
  -example
       write example config file
  -f string
       upload file, example /etc/hosts:/home/user/hosts
  -h string
       exec host group name
```


##### 执行命令

```
shell> ./rssh -host website -e 'df -h /'
Password:
---

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
shell> ./rssh -host website -f '/etc/hosts:/home/user/hosts'
Password:
---
/etc/hosts 192.168.100.202:22 -> /home/user/hosts OK
/etc/hosts 192.168.100.201:22 -> /home/user/hosts OK
---
time: 84.508462ms
```



