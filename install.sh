#!/bin/sh
xpu=(lscpu)
echo "install git"
yum -y install git

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
sed -i '/# IPv6/i\host    all             all             0.0.0.0/0            md5' /opt/software/openGauss/data/pg_hba.conf
gs_ctl start 
gsql -d postgres
alter role "opengauss" password 'gao@12345!';
create extension plpython3u;
create extension opengauss_ngx;
\q
exit
EOF

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

#启动nginx
GAUSSHOME=/opt/software/openGauss
LD_LIBRARY_PATH=$GAUSSHOME/lib:$LD_LIBRARY_PATH
PATH=$GAUSSHOME/bin:$PATH
/usr/local/nginx/sbin/nginx
#运行接口测试
python python_test/testfun.py
#运行django
python django/manage.py runserver --noreload --nothreading



