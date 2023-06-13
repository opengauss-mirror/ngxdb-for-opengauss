# 欢迎使用 NGXDB FOR OPENGAUSS开发套件

------

#　　会sql就能做后端

------

##一、介绍

    本开发框架为专为opengauss开发，能完成编写代码、接口文档、单元测试、部署，可以只用纯sql语句完成全套系统从开发到部署，完全开源。
	
文件目录

ngxdb-for-opengauss

|--extension  opengauss扩展

|--opengauss nginx插件

|--python_test python的测试代码

&nbsp;readme.md
<<<<<<< HEAD

&nbsp;License
=======
>>>>>>> 2907a26b8405956d8d783107aff60d3c19852e90

##二、安装步骤

###1、安装opengauss
详见官网，建议安装极简版练习
*请将opengauss安装目录设为/opt/software/openGauss，以便后续步骤不用修改opengauss依赖
*安装完修改/opt/software/openGauss/data/single_node/postgresql.conf
···
session_timeout=86400 #避免测试长时间没有连接，再次使用时连接出错
···
增加
···
# Add settings for extensions here
support_extended_features=on #打开自定义的扩展功能
···

###2、下载ngxdb-for-opengauss 0.1版源码
```linux
git clone -b 0.1 --single-branch https://gitee.com/opengauss/ngxdb-for-opengauss.git
```

###3、nginx编译安装
下载nginx源码，以nginx24.0为例
```linux
wget https://nginx.org/download/nginx-1.24.0.tar.gz
tar zxf nginx-1.24.0.tar.gz
cd nginx-1.24.0
cd src
cp -r ../../ngxdb-for-opengauss/opengauss .
cd ..
make & make install
cd ..
```
*如果opengauss的安装目录不是/opt/software/openGauss，会提示有文件找不到，请将src/opengauss/config文件里的/opt/software/openGauss替换为opengauss的安装目录
*nginx默认安装目录为/usr/local/nginx，安装完nginx后请核对
*最后的cd ..是回到下载软件的目录，以便后续操作

###4、安装opengauss扩展示例
```linux
cp ngxdb-for-opengauss/extension/*.* /opt/software/openGauss/share/postgresql/extension/
<<<<<<< HEAD
gs_ctl start
=======
gs_ctl restart
>>>>>>> 2907a26b8405956d8d783107aff60d3c19852e90
gsql
create extension opengauss_login;
\q
```

###5、配置nginx
```linux
vi /usr/local/nginx/conf/nginx.conf
```
找到如下代码段
```linux
    server {
        listen       80;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {
            root   html;
            index  index.html index.htm;
        }

        #error_page  404              /404.html;
```
插入代码
```linux
       location /func {
          opengaussconn "host=127.0.0.1 dbname=postgres user=conn password=Gao12345 port=5432";
          rewrite ^/func/(.*)$ /$1 break;
       }

        location /help {
            opengausshelp "host=127.0.0.1 dbname=postgres user=conn password=Gao12345 port=5432";
            break;
        }

```
最终代码为
```linux
    server {
        listen       80;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

       location /func {
          opengaussconn "host=127.0.0.1 dbname=postgres user=conn password=Gao12345 port=5432";
          rewrite ^/func/(.*)$ /$1 break;
       }

        location /help {
            opengausshelp "host=127.0.0.1 dbname=postgres user=conn password=Gao12345 port=5432";
            break;
        }

        location / {
            root   html;
            index  index.html index.htm;
        }

        #error_page  404              /404.html;

```
在vi中输入wq回车，保存
运行nginx
```linux
/usr/local/nginx/sbin/nginx
```

###6、测试

####使用测试代码
```linux
python python_test\testfun.py
```
运行大约耗时10分钟，会测试正常登录、token验证、10分钟内超过5次非法登录将锁定账号10分钟，10次非法登录将锁定3小时。
如果运行完演示
总用例:16 成功:16 失败:0
则表示安装成功。

####使用浏览器
在本机打开浏览器，在地址栏输入http://127.0.0.1/help
可以看到后端接口的帮助文档
在本机打开浏览器，在地址栏输入http://127.0.0.1/sysinfo/login?loginname=admin&pass=123456
可以看到浏览器返回json字符串，详见帮助文档

##三、说明
本版本为0.1，仅供熟悉本框架的初学者练习，下一版本为可实用的版本

