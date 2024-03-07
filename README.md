# 计网 Lab2 Router

## 个人信息

唐子涵 2021013540 tzh21@mails.tsinghua.edu.cn

## 项目参考和引用

无参考和引用

## 环境配置

```bash
sudo bash setup.sh
```

由于不可抗力，setup.sh 中的 `sudo git clone -b eel http://github.com/noxrepo/pox /opt/pox` 会失败，用配置网络、手动拷贝等方法代替

## 运行

> 最好按照下面的顺序运行，否则可能出现问题

### 运行 pox

```bash
./pox.sh
```

或

```bash
python /opt/pox/pox.py --verbose ucla_cs118
```

### 运行 router

```bash
./router.sh
```

或

```bash
sudo make clean
make -j4
./router
```

### 运行 mininet

```bash
./mininet.sh
```

或

```bash
sudo python run.py
```

### 退出

mininet 用 `exit` 退出，其他用 `ctrl+C`

## 问题

### router: 段错误已转储

> 状态：已解决

路由器会接收到目的 ip 为 224.0.0.251 的包。这个 ip 不是任何主机的 ip，而是一个广播 ip

接收到这个 ip 的包应该直接抛弃

### Module not found: ucla-cs118

> 状态：已解决

运行 pox.py 时，注意用 `ucla_cs118` 而不是 `ucla-cs118`，虽然 `pip install ucla-cs118` 确实用了短横线而不是下划线。

原因未知，可能是 `--verbose` 的偏好

### MAC 地址的数据类型

> 状态：已解决

在 `ethernet_hdr` 中，MAC 地址用 `uint8_t [6]` 表示，而在 `Interface` 中，MAC 地址用 `vector<unsigned_char>` 表示

实际上，`unsigned_char` 和 `uint8_t` 等价，可以认为 `Interface` 没有限制 MAC 地址的位数

### 字节序转换

> 状态：已解决，修改程序时需要注意

主机上的数字写入网络数据包时，需要考虑转换字节序

`htons` 用于 `uint16_t`，`htonl` 用于 `uint32_t`

## 网络拓扑结构

```
                                              +----------------+ server1-eth0
                                              |                  192.168.2.2/24
                                              +                   +-----------+
                                          192.168.2.1/24          |           |
                                          sw0-eth1                |  server1  |
+----------+                +------------------+                  |           |
|          |                |                  |                  +-----------+
|  client  |                |   SimpleRouter   |
|          |                |      (sw0)       |
+----------+                |                  |
   client-eth0              +------------------+                  +-----------+
   10.0.1.100/8           sw0-eth3        sw0-eth2                |           |
      +                 10.0.1.1/8        172.64.3.1/16           |  server2  |
      |                      +                +                   |           |
      |                      |                |                   +-----------+
      |                      |                |                  server2-eth0
      +----------------------+                +----------------+ 172.64.3.10/16
```