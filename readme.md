# 欢迎使用 NGXDB FOR OPENGAUSS开发套件

------

#    会sql就能做后端

------

## 一、介绍
 本开发框架为专为opengauss开发，能完成编写代码、接口文档、单元测试、部署，可以只用纯sql语句完成全套系统从开发到部署，完全开源。
 
 ngxdb for opengaus八大优势https://www.toutiao.com/article/7274971705632784907/
 
 0.1版本为学习版，让使用者学会安装使用
 
 1.0版本可以使用，该版本提供了多系统使用及维护的功能，能设置子系统、每个子系统设置功能权限、小程序登录、设置机构等
 
文件目录

|--django  python django服务器代码

&nbsp;--extension  opengauss扩展

&nbsp;--html 前端代码

&nbsp;&nbsp;|--bootstrap 基于bootstrap

&nbsp;--opengauss nginx插件

&nbsp;--python_test python的测试代码

&nbsp;--QT 基于QT的前端代码

readme.md

## 二、安装步骤
 本安装在openeuler22下测试通过，其它操作系统也许会报错。
 下载源码后，后述安装代码都在install.sh里，可以直接运行install.sh完成安装
### 1、下载源码
```linux
git clone -b 1.0 --single-branch https://gitee.com/opengauss/ngxdb-for-opengauss.git
```
### 2、源码编译opengauss 5.1.0
详见官网，因为需要增加--with-python选项，所以要源码编译
* 请将opengauss安装目录设为/opt/software/openGauss，以便后续步骤不用修改opengauss依赖
```opengauss
#判断是否下载了openGauss 5.1.0
echo "clone opengauss"
if [ -d openGauss-server ]; then 
  echo "opengauss exist"
else
  git clone --branch 5.1.0 https://gitee.com/opengauss/openGauss-server.git 
fi
#判断cpu架构
arch=$(grep -oP 'Architecture:\s+\K.+' <<<`lscpu` | head -n1)
if [ -z "$arch" ]; then 
  arch=$(grep -oP '架构：\s+\K.+' <<<`lscpu` | head -n1)
fi
echo "$arch"
#判断是否下载了第三方软件，根据cpu架构下载相应软件 
if [ -d "binarylibs" ]; then
  echo "binarylibs exist"
else
  case $arch in
    "x86_64") 
      echo "x86":
      wget http://opengauss.obs.cn-south-1.myhuaweicloud.com/5.1.0/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_2203_x86_64.tar.gz
      tar -xvf openGauss-third_party_binarylibs_openEuler_2203_x86_64.tar.gz 
      mv openGauss-third_party_binarylibs_openEuler_2203_x86_64 binarylibs
    ;;
    "*") 
      echo "arm"
      wget https://opengauss.obs.cn-south-1.myhuaweicloud.com/5.1.0/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_2203_arm.tar.gz
      tar -xvf openGauss-third_party_binarylibs_openEuler_2203_arm.tar.gz
      mv openGauss-third_party_binarylibs_openEuler_2203_arm binarylibs 
      ;;
  esac
fi

#下载python3.9,目前只支持python3.9
python=`python3 --version`
echo $python
if [ ${python:1:4} = "bash" ]; then
  yum -y install python3.9 
else
  if [ ${python:7:3} = "3.9" ]; then
    echo "python exist"
  else
    yum remove python${python:7:3} -y
    yum install python3.9 -y
  fi
fi

#下载python依赖
pip install -i https://mirrors.huaweicloud.com/repository/pypi/simple psycopg2-binary django

rm /usr/bin/python
ln -s /usr/bin/python3 /usr/bin/python

#下载编译依赖
yum -y install readline readline-devel python3-devel libaio-devel

#判断是否安装opengauss，否则编译安装
if [ -d "/opt/software/openGauss" ]; then
  echo "openGauss exist"
else
  cd openGauss-server
  ./configure --prefix=/opt/software/openGauss --enable-thread-safety --gcc-version=10.3.1 CC=g++ CFLAGS='-O2 -g3' --with-3rdpartydir=/root/ngxdb-for-opengauss/binarylibs --with-libxml --enable-cassert --with-readline --with-python
  make && make install
  useradd opengauss
  echo "gao@12345!" | passwd --stdin opengauss
  cp ../extension/*.* /opt/software/openGauss/share/postgresql/extension/
  chown opengauss /opt/software/openGauss -R
  cd ..
fi
```
### 3、启动数据库并安装扩展 
```
#修改环境变量，启动数据库并安装扩展
lines=$(grep -c "export GAUSSHOME=/opt/software/openGauss" /etc/profile)
if [ $lines = 0 ]; then
    echo 'export GAUSSHOME=/opt/software/openGauss'>>/home/opengauss/.bashrc
    echo 'export GAUSSDATA=$GAUSSHOME/data'>>/home/opengauss/.bashrc
    echo 'export PGDATA=$GAUSSDATA'>>/home/opengauss/.bashrc
    echo 'export LD_LIBRARY_PATH=$GAUSSHOME/lib:$LD_LIBRARY_PATH'>>/home/opengauss/.bashrc
    echo 'export PATH=$GAUSSHOME/bin:$PATH'>>/home/opengauss/.bashrc
    echo 'export GAUSSHOME=/opt/software/openGauss'>>/etc/profile
    echo 'export LD_LIBRARY_PATH=$GAUSSHOME/lib:$LD_LIBRARY_PATH'>>/etc/profile
    echo 'export PATH=$GAUSSHOME/bin:$PATH'>>/etc/profile
fi
su - opengauss << EOF
gs_initdb --nodename=gao
sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /opt/software/openGauss/data/postgresql.conf
sed -i 's/#password_encryption_type=2/password_encryption_type=1/' /opt/software/openGauss/data/postgresql.conf
sed -i '/# IPv6/i\host    all             all             127.0.0.1/32            md5' /opt/software/openGauss/data/pg_hba.conf
gs_ctl start 
gsql -d postgres
alter role "opengauss" password 'gao@12345!';
create extension plpython3u;
create extension opengauss_ngx;
\q
exit
EOF
```
### 3、nginx编译安装
下载nginx源码，以nginx24.0为例，下载编译完成后，在nginx.conf里增加
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
opengaussconn "opengauss连接字符"：用于访问扩展
opengausshelp "opengauss连接字符"：用于访问帮助
```nginx
#下载并编译安装nginx，修改nginx配置文件
nginx="nginx-1.24.0"
if [ -d "/usr/local/nginx" ]; then
  echo "nginx exist"
else
  wget http://nginx.org/download/${nginx}.tar.gz
  tar -zxvf nginx-1.24.0.tar.gz 
  cd $nginx
  ./configure --add-module=../opengauss --prefix=/usr/local/nginx
  make && make install
  cp ../bootstrap /usr/local/nginx/html/ -r
  cd ..
  sed -i '/error_page/i\        location /func {' /usr/local/nginx/conf/nginx.conf
  sed -i '/error_page/i\            opengaussconn "host=127.0.0.1 dbname=opengauss user=conn password=Gao12345 port=5432";' /usr/local/nginx/conf/nginx.conf     
  sed -i '/error_page/i\            rewrite ^func/(.*)$ /$1 break;' /usr/local/nginx/conf/nginx.conf
  sed -i '/error_page/i\        }' /usr/local/nginx/conf/nginx.conf
  sed -i '/error_page/i\        ' /usr/local/nginx/conf/nginx.conf
  sed -i '/error_page/i\        location /help {' /usr/local/nginx/conf/nginx.conf
  sed -i '/error_page/i\            opengausshelp "host=127.0.0.1 dbname=opengauss user=conn password=Gao12345 port=5432";' /usr/local/nginx/conf/nginx.conf
  sed -i '/error_page/i\            break;' /usr/local/nginx/conf/nginx.conf
  sed -i '/error_page/i\        }' /usr/local/nginx/conf/nginx.conf
  sed -i '/error_page/i\        ' /usr/local/nginx/conf/nginx.conf  
fi
```
* 如果opengauss的安装目录不是/opt/software/openGauss，会提示有文件找不到，请将src/opengauss/config文件里的/opt/software/openGauss替换为opengauss的安装目录
* nginx默认安装目录为/usr/local/nginx，安装完nginx后请核对
### 4、启动nginx
```
#启动nginx
firewall-cmd --zone=public --add-port=80/tcp --permanent
firewall-cmd --zone=public --add-port=5432/tcp --permanent
firewall-cmd --zone=public --add-port=8000/tcp --permanent

export GAUSSHOME=/opt/software/openGauss
export LD_LIBRARY_PATH=$GAUSSHOME/lib:$LD_LIBRARY_PATH
export PATH=$GAUSSHOME/bin:$PATH
/usr/local/nginx/sbin/nginx
```
### 5、测试
#### 使用测试代码
```linux
python python_test\testfun.py
```
 运行大约耗时10分钟，会测试正常登录、token验证、10分钟内超过5次非法登录将锁定账号10分钟，10次非法登录将锁定3小时。
 如果运行完演示
 总用例:XX 成功:XX 失败:0
 则表示安装成功。
#### 使用浏览器
 在本机打开浏览器，在地址栏输入http://127.0.0.1/help ，可以看到后端接口的帮助文档
 
 在本机打开浏览器，在地址栏输入http://127.0.0.1/sysinfo/login?loginname=admin&pass=123456 ，可以看到浏览器返回json字符串，详见帮助文档
### 6、其它
运行QT
 运行QT，打开QT目录下的qt.pro
 
运行django服务
```
#运行django
python django/manage.py runserver --noreload --nothreading
```
 在本机打开浏览器，在地址栏输入http://127.0.0.1:8000/help ，可以看到后端接口的帮助文档
 
 在本机打开浏览器，在地址栏输入http://127.0.0.1:8000/sysinfo/login?loginname=admin&pass=123456 ，可以看到浏览器返回json字符串，详见帮助文档

