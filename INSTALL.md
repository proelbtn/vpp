# VPP for ICTSC2019

ICTSC2019のコアネットワークで利用するためにいくつかの変更を加えたVPP。


## インストール方法

### コアパッケージのインストール

```
$ git clone https://github.com/proelbtn/vpp
$ make install-dep
$ make pkg-deb -j16
$ sudo apt install -y python3-cffi python3-pycparser
$ sudo dpkg -i \
	libvppinfra_19.08.1-4~gda38d9390_amd64.deb \
	vpp_19.08.1-4~gda38d9390_amd64.deb \
	vpp-plugin-core_19.08.1-4~gda38d9390_amd64.deb \
	vpp-plugin-dpdk_19.08.1-4~gda38d9390_amd64.deb \
	python3-vpp-api_19.08.1-4~gda38d9390_amd64.deb
```

### router-pluginのインストール

```
$ cd build-root
$ make netlink-install -j16
$ make router-install -j16
$ sudo cp install-native/netlink/lib64/librtnl.so /usr/lib/x86_64-linux-gnu/vpp_plugins/
$ sudo cp install-native/router/lib64/router.so /usr/lib/x86_64-linux-gnu/vpp_plugins/
```


## tap-injectの使い方

vppctl内でtap-injectを行うことでLinux側にtapデバイスを生やすことが出来る。これをFRRなどで掴むことでBGPのピアを張ったりする。

```
$ enable tap-inject
```

