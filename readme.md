NGXDB-FOR-OPENGAUSS
会sql就能做后端

本开发框架专为opengauss开发，能完成编写代码、接口文档、单元测试、部署，可以只用纯sql语句完成全套系统从开发到部署，详见示例sql
本插件基于nginx，需要下载nginx源码编译，编译后在nginx的配置文件里加入

       location /func {
          opengaussconn "host=127.0.0.1 dbname=opengauss user=conn password=Gao12345 port=5432";
          rewrite ^/func/(.*)$ /$1 break;
       }

        location /help {
            opengausshelp "host=127.0.0.1 dbname=opengauss user=conn password=Gao12345 port=5432";
            break;
        }
		
在opengauss数据库里执行示例sql后，启动nginx。

在浏览器输入http://127.0.0.1/help 可以看到系统管理相关接口的文档说明

在浏览器输入http://127.0.0.1/func/sysinfo/login?loginname=admin&pass=123456可以看到系统登录后的token和登录账号相关信息，完成系统登录功能


