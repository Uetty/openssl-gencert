该文件夹是使用到的库文件

bcprov.jar	pcks12和bks互转时使用的，根据pom文件bcprov.jar的定义，将该bcprov.jar文件加入到本地maven仓库中

libLhtwSSL.so	在centos7中使用jni文件夹下c源码编译的动态链接库，可通过ldd命令查看依赖
需安装openssl，主要依赖libssl.so.10和libcrypto.so.10链接库，如果链接库路径不对，使用软连接连接动态链接库
ls -al 查看软连接

libcrypto.so.10	libLhtwSSL.so编译时系统环境中的libcrypto.so.10库
libssl.so.10	libLhtwSSL.so编译时系统环境中的libssl.so.10库