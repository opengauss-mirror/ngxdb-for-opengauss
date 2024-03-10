#!/bin/sh
xpu=(lscpu)
echo "install git"
yum -y install git

echo "clone opengauss"
if [ -d openGauss-server ]; then
  echo "opengauss exist"
else
  git clone --branch 5.1.0 https://gitee.com/opengauss/openGauss-server.git 
fi

arch=$(grep -oP 'Architecture:\s+\K.+' <<<`lscpu` | head -n1)
echo "$arch"
 
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

rm /usr/bin/python
ln -s /usr/bin/python3 /usr/bin/python

yum -y install readline readline-devel python3-devel libaio-devel

if [ -d "/opt/software/openGauss" ]; then
  echo "openGauss exist"
else
  cd openGauss-server
  ./configure --prefix=/opt/software/openGauss --enable-thread-safety --gcc-version=10.3.1 CC=g++ CFLAGS='-O2 -g3' --with-3rdpartydir=/root/ngxdb-for-opengauss/binarylibs --with-libxml --enable-cassert --with-readline --with-python
  make && make install
  useradd opengauss
  passwd opengauss
  gao@12345!
  gao@12345!
  chown opengauss /opt/software/openGauss -R
  lines=$(grep -c "export GAUSSHOME=/opt/software/openGauss" /etc/profile)
  if [ $lines =0 ]; then
    echo 'export GAUSSHOME=/opt/software/openGauss'>>/home/opengauss/.bashrc
    echo 'export GAUSSDATA=$GAUSSHOME/data'>>/home/opengauss/.bashrc
    echo 'export PGDATA=$GAUSSDATA'>>/home/opengauss/.bashrc
    echo 'export LD_LIBRARY_PATH=$GAUSSHOME/lib:$LD_LIBRARY_PATH'>>/home/opengauss/.bashrc
    echo 'export PATH=$GAUSSHOME/bin:$PATH'>>/home/opengauss/.bashrc
    echo 'export GAUSSHOME=/opt/software/openGauss'>>/etc/profile
    echo 'export LD_LIBRARY_PATH=$GAUSSHOME/lib:$LD_LIBRARY_PATH'>>/etc/profile
    echo 'export PATH=$GAUSSHOME/bin:$PATH'>>/etc/profile
    source /etc/profile
  fi
  cp ../extension/*.* /opt/software/openGauss/share/postgresql/extension/
  su opengauss
  gs_initdb --nodename=gao
  gs_ctl start  
  gsql
  create extension plpython3u;
  create extension opengauss_login;
  \q
  exit
  cd ..
fi

nginx="nginx-1.24.0"
if [ -d $nginx ]; then
  echo "nginx exist"
else
  wget http://nginx.org/download/${nginx}.tar.gz
  tar -zxvf nginx-1.24.0.tar.gz 
  cd $nginx
  ./configure --add-module=../opengauss
  make && make install
  cd ..
  sed '/error_page/i\        location /func {' /usr/local/nginx/conf/nginx.conf
  sed '/error_page/i\            opengaussconn "host=127.0.0.1 dbname=opengauss user=conn password=Gao12345 port=5432";' /usr/local/nginx/conf/nginx.conf     
  sed '/error_page/i\            rewrite ^func/(.*)$ /$1 break;' /usr/local/nginx/conf/nginx.conf
  sed '/error_page/i\        }' /usr/local/nginx/conf/nginx.conf
  sed '/error_page/i\        ' /usr/local/nginx/conf/nginx.conf
  sed '/error_page/i\        location /help {' /usr/local/nginx/conf/nginx.conf
  sed '/error_page/i\            opengausshelp "host=127.0.0.1 dbname=opengauss user=conn password=Gao12345 port=5432";' /usr/local/nginx/conf/nginx.conf
  sed '/error_page/i\            break;' /usr/local/nginx/conf/nginx.conf
  sed '/error_page/i\        }' /user/local/nginx/conf/nginx.conf
  sed '/error_page/i\        ' /usr/local/nginx/conf/nginx.conf  
  /usr/local/nginx/sbin/nginx
fi

python python_test\testfun.py


