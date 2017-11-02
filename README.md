# lhtw-openssl
使用openssl api生成基于私有ca的自签名证书
resources/jni中的.cpp文件为c++调用openssl api的源码
编译后的.so文件为libs/libLhtwSSL.so
编译依赖的动态链接库也在libs/文件夹下，见.so.10文件
bcprov.jar是用于将pcks12（p12）格式的文件转为bks格式的文件使用，java编写的安卓程序只能使用bks格式文件
