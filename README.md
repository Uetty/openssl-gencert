# lhtw-openssl
## 使用说明
###
   1. 使用openssl api生成基于私有ca的自签名证书
   
   2. resources/jni中的.cpp文件为c++调用openssl api的源码
   
   3. 编译后的.so文件为libs/libLhtwSSL.so
   
   4. 编译依赖的动态链接库也在libs/文件夹下，见.so.10文件
   
   5. bcprov.jar是用于将pcks12（p12）格式的文件转为bks格式的文件使用，java编写的安卓程序只能使用bks格式文件
   
   6. 将c++源码编译为动态链接库需安装openssl开发版，以及jdk开发版（不是jre），jdk中需要有jni.h等c头文件，我使用eclipse编译的，编译时需指定jni.h和openssl的两个.h头文件

## 参考资料
###
   nginx搭建参考http://tchuairen.blog.51cto.com/3848118/1782945/
