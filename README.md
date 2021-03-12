# 飞机订票系统（航空订票系统）

## 介绍
飞机订票系统（航空订票系统）

相关博客：[https://blog.csdn.net/Ikaros_521/article/details/94864773](https://blog.csdn.net/Ikaros_521/article/details/94864773)

登录需要的账号和密码存储在passenger.txt文件中

单机版直接运行exe即可

联网版 编译追加 -lwsock32

即 gcc server.c -lwsock32 -o server

使用就是先开 server 再开 client。