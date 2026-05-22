# Welcome to NGXDB for openGauss Development Kit

------

#    Build a Backend Just Using SQL

------

## 1. Introduction
 This development framework is designed for openGauss. It allows you to write code, create API documentation, run unit tests, and deploy a system entirely using SQL, from development to deployment. It is fully open-source.
 
 Eight advantages of NGXDB for openGauss: https://www.toutiao.com/article/7274971705632784907/
 
 Version 0.1 – Learning version to help users install and get started.
 
 Version 1.0 – Full version for practical use. Features include multi-system support, subsystem configuration, function permissions, mini-program login, and organizational settings.
 
File directory

|--Django Python Django server code

&nbsp;--extension openGauss extension

&nbsp;--HTML Frontend code

&nbsp;&nbsp;|--bootstrap Bootstrap-based

&nbsp;--openGauss Nginx plug-in

&nbsp;--python_test Python test code

&nbsp;--QT QT-based frontend code

readme.md

## 2. Installation
 This installation has been tested on OpenEuler 22. Other operating systems may encounter errors.
 After downloading the source code, all installation commands are included in `install.sh`. You can run it directly to complete the installation.
### 1. Download the source code.
```linux
git clone -b 1.0 --single-branch https://gitee.com/opengauss/ngxdb-for-opengauss.git
```
### 2. Compile openGauss 5.1.0 from source.
For details, see the official website. The source code needs to be compiled because the `--with-python` option needs to be added.
* Set the openGauss installation directory to `/opt/software/openGauss` to avoid modifying dependencies later.
```opengauss
#Check if openGauss 5.1.0 is downloaded.
echo "clone opengauss"
if [ -d openGauss-server ]; then 
  echo "opengauss exist"
else
  git clone --branch 5.1.0 https://gitee.com/opengauss/openGauss-server.git 
fi
#Check the CPU architecture.
arch=$(grep -oP 'Architecture:\s+\K.+' <<<`lscpu` | head -n1)
if [ -z "$arch" ]; then 
  arch=$(grep -oP 'Architecture: \s+\K.+' <<<`lscpu` | head -n1)
fi
echo "$arch"
#Check whether third-party software has been downloaded and download the corresponding software based on the CPU architecture.
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

#Install Python 3.9 (currently only supported version).
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

#Download the Python dependency.
pip install -i https://mirrors.huaweicloud.com/repository/pypi/simple psycopg2-binary django

rm /usr/bin/python
ln -s /usr/bin/python3 /usr/bin/python

#Download compilation dependencies.
yum -y install readline readline-devel python3-devel libaio-devel

#Compile and install openGauss if not already installed.
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
### 3. Start the database and install extensions.
```
#Update environment variables, start the database, and install extensions
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
### 3. Compile and install Nginx.
Download Nginx source (example: nginx24.0). After installation and compilation, add the following to `nginx.conf`:
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
opengaussconn "opengauss connection string": used to access extensions.

opengausshelp "opengauss connection string": used to access help center.
```nginx
#Download, compile, and install Nginx, and modify the Nginx configuration file.
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
  sed -i '/ \{6,\}location \/ {/i\        location /func {' /usr/local/nginx/conf/nginx.conf
  sed -i '/ \{6,\}location \/ {/i\            opengaussconn "host=127.0.0.1 dbname=postgres user=conn password=gao@12345 port=5432";' /usr/local/nginx/conf/nginx.conf     
  sed -i '/ \{6,\}location \/ {/i\            rewrite ^/func/(.*)$ /$1 break;' /usr/local/nginx/conf/nginx.conf
  sed -i '/ \{6,\}location \/ {/i\        }' /usr/local/nginx/conf/nginx.conf
  sed -i '/ \{6,\}location \/ {/i\        ' /usr/local/nginx/conf/nginx.conf
  sed -i '/ \{6,\}location \/ {/i\        location /help {' /usr/local/nginx/conf/nginx.conf
  sed -i '/ \{6,\}location \/ {/i\            opengausshelp "host=127.0.0.1 dbname=postgres user=conn password=gao@12345 port=5432";' /usr/local/nginx/conf/nginx.conf
  sed -i '/ \{6,\}location \/ {/i\            break;' /usr/local/nginx/conf/nginx.conf
  sed -i '/ \{6,\}location \/ {/i\        }' /usr/local/nginx/conf/nginx.conf
  sed -i '/ \{6,\}location \/ {/i\        ' /usr/local/nginx/conf/nginx.conf  
fi
```
* If the openGauss installation directory is not `/opt/software/openGauss`, a message is displayed indicating that some files cannot be found. In this case, replace `/opt/software/openGauss` in the `src/opengauss/config` file with the actual openGauss installation directory.
* The default Nginx installation directory is `/usr/local/nginx`. After installing Nginx, check the directory.
### 4. Start Nginx.
```
#Start Nginx.
firewall-cmd --zone=public --add-port=80/tcp --permanent
firewall-cmd --zone=public --add-port=5432/tcp --permanent
firewall-cmd --zone=public --add-port=8000/tcp --permanent
systemctl reload firewalld

export GAUSSHOME=/opt/software/openGauss
export LD_LIBRARY_PATH=$GAUSSHOME/lib:$LD_LIBRARY_PATH
export PATH=$GAUSSHOME/bin:$PATH
/usr/local/nginx/sbin/nginx
```
### 5. Conduct a test.
#### Using the test script
```linux
python python_test\testfun.py
```
 Running this script takes approximately 10 minutes. It tests normal login, token verification, and account locking. If more than 5 invalid login attempts occur within 10 minutes, the account will be locked for 10 minutes. If 10 invalid login attempts occur, the account will be locked for 3 hours.
 After the script finishes, if the output shows:
 total cases: XX; success: XX; failed: 0,
 the installation is successful.
#### Using a web browser
 Open a browser on the local machine and enter `http://127.0.0.1/help` in the address bar. This will display the backend API help documentation.
 
 Open a browser on the local machine and enter `http://127.0.0.1/sysinfo/login?loginname=admin&pass=123456` in the address bar. The browser will return a JSON string. Refer to the help documentation for details.
### 6. Other
Running QT
 Run QT and open the `qt.pro` file in the QT directory.
 
Running the Django service
```
#Run Django.
python django/manage.py runserver 0.0.0.0:8000 --noreload --nothreading
```
 Open a browser on the local machine and enter `http://127.0.0.1:8000/help` in the address bar. This will display the backend API help documentation.
 
 Open a browser on the local machine and enter `http://127.0.0.1:8000/sysinfo/login?loginname=admin&pass=123456` in the address bar. The browser will return a JSON string. Refer to the help documentation for details.
