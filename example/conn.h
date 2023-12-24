#ifndef CONN_H
#define CONN_H

#include <string.h>
#include <stdlib.h>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QNetworkReply>
#include <QCoreApplication>
#include "include/libpq-fe.h"

struct s_param {
    char *storedprocname;
    char *command;
    int nParams;
    char **paramnames;
};

static class cngxdb {
    char* connurl;
    bool direct=false;
    PGconn *conn;
    int storednum;
    s_param *params;

    void setparam(unsigned int len,char *c,int index,char** paramValues,struct s_param *params) {
        unsigned int i=0;
        while (i<=len) {
            char *j=(char *)memchr(c+i,'&',len-i);
            if (j==NULL) j=c+len-1;
            else j--;
            char *k=(char *)memchr(c+i,'=',j-c-i+1);
            char * arg=(char *)malloc(k-c-i+1);
            memcpy(arg,c+i,k-c-i);
            arg[k-c-i]=0;
            if (k!=NULL&&j-k>=1) {
                for (int i1=0;i1<params[index].nParams;i1++) {
                    if (strcmp(params[index].paramnames[i1],arg)==0) {
                        paramValues[i1]=(char*)malloc(j-k+1);
                        int i2=0,i3=0;
                        while (i2<j-k) {
                            char *ch=k+1+i2,ch1=0,ch2=0;
                            switch(*ch) {
                            case '+':
                                paramValues[i1][i3]=' ';
                                i2++;
                                i3++;
                                break;
                            case '%':
                                if (*(ch+1)>='0'&&*(ch+1)<='9') ch1=*(ch+1)-'0';
                                else if (*(ch+1)>='a'&&*(ch+1)<='z') ch1=*(ch+1)-'a'+10;
                                else if (*(ch+1)>='A'&&*(ch+1)<='Z') ch1=*(ch+1)-'A'+10;
                                else { i2+=2;break; }
                                if (*(ch+2)>='0'&&*(ch+2)<='9') ch2=*(ch+2)-'0';
                                else if (*(ch+2)>='a'&&*(ch+2)<='z') ch2=*(ch+2)-'a'+10;
                                else if (*(ch+2)>='A'&&*(ch+2)<='Z') ch2=*(ch+2)-'A'+10;
                                else { i2+=3;break; }
                                paramValues[i1][i3]=(char)((ch1<<4)|ch2);
                                i3++;
                                i2+=3;
                                break;
                            default:
                                paramValues[i1][i3]=*ch;
                                i2++;
                                i3++;
                                break;
                            }
                        }
                        paramValues[i1][i3]=0;
                    }

                }
            }
            i=j-c+2;
            free(arg);
        }

    }

    public:
    void seturl(char* url) {
        connurl=url;
        direct=false;
    }
    int init(char* connstr) {
        PQfinish(conn);
        conn=PQconnectdb(connstr);
        int re=PQstatus(conn);
        if (re==CONNECTION_OK) {
            PGresult *res=PQexec(conn,"select count(*) from gm.nginx;");
            if (PQresultStatus(res)!=PGRES_TUPLES_OK) {
                PQclear(res);
                PQfinish(conn);
                return -1;
            }
            storednum=atoi(PQgetvalue(res,0,0));
            params=(struct s_param *)malloc(sizeof(struct s_param)*storednum);
            PQclear(res);
            res=PQexec(conn,"select * from gm.nginx;");
            if (PQresultStatus(res)!=PGRES_TUPLES_OK) {
                PQclear(res);
                PQfinish(conn);
                return -1;
            }
            for (unsigned int i=0;i<storednum;i++) {
                char *temp1 = PQgetvalue(res,i,1);
                int len1 = strlen(temp1);
                char *temp3=strstr(temp1,"\".\"");
                int len3=temp3-temp1;
                params[i].storedprocname=(char*)malloc(len1-3);
                params[i].storedprocname[0]=47;
                memcpy(params[i].storedprocname+1,temp1+2,len3-1);
                params[i].storedprocname[len3-1]=47;
                memcpy(params[i].storedprocname+len3,temp3+3,len1-len3-4);
                params[i].storedprocname[len1-4]=0;
                params[i].nParams=atoi(PQgetvalue(res,i,3));
                char *temp2 = PQgetvalue(res,i,0);
                int len2 = strlen(temp2);
                params[i].command=(char*)malloc(9+len1+len2);
                params[i].command[8+len1+len2]=0;
                memcpy(params[i].command,"select",6);
                memcpy(params[i].command+6,temp1,len1);
                params[i].command[6+len1]='(';
                memcpy(params[i].command+7+len1,temp2,len2);
                params[i].command[7+len1+len2]=')';
                params[i].paramnames=(char**)malloc(params[i].nParams*sizeof(char*));
                char *k=PQgetvalue(res,i,2);
                for (int j=0;j<params[i].nParams;j++) {
                    char *k1=strchr(k,',');
                    params[i].paramnames[j]=(char*)malloc(k1-k-1);
                    memcpy(params[i].paramnames[j],k+2,k1-k-2);
                    params[i].paramnames[j][k1-k-2]=0;
                    k=k1+1;
                }
            }
            PQclear(res);
            direct=true;
        }
        return re;
    }

    char* get(char* url,char* param) {
        if (direct) {
            unsigned int len=strlen(url);
            for (unsigned int i=0;i<len;i++) {
                if ((*(url+i))>='A'&&(*(url+i))<='Z') url[i]+=32;
            }
            int index=0,low=0,high=storednum-1,cmp=0;
            while (low<=high) {
                index=(low+high)/2;
                cmp=strcmp(url,params[index].storedprocname);
                if (cmp==0) break;
                if (cmp>0) low=index+1;
                else high=index-1;
            }
            if (cmp!=0) {return nullptr;}
            char **paramValues;
            unsigned int i=0;
            paramValues=(char**)calloc(params[index].nParams,sizeof(char*));
            setparam(strlen(param),param,index,paramValues,params);
            PGresult *res=PQexecParams(conn,params[index].command,params[index].nParams,NULL, (const char *const *)paramValues,NULL,NULL,0);
            ExecStatusType et=PQresultStatus(res);
            char *aa;
            if (et!=PGRES_TUPLES_OK) {
                i=strlen(PQresultErrorMessage(res));
                aa=(char*)malloc(i+35);
                aa[i]=0;
                aa[i+34]=0;
                memcpy(aa,"{\"errorcode\":-1,\"message\":\"",32);
                memcpy(aa,PQresultErrorMessage(res),strlen(PQresultErrorMessage(res)));
                memcpy(aa+32+i,"\"}",2);
            } else {
                i=strlen(PQgetvalue(res,0,0));
                aa=(char*)malloc(i+1);
                aa[i]=0;
                memcpy(aa,PQgetvalue(res,0,0),strlen(PQgetvalue(res,0,0)));
            }
            return aa;
        } else {
            QNetworkAccessManager *m_manager= new QNetworkAccessManager();
            QEventLoop loop;
            qDebug()<<"get"<<QString(connurl)+QString(url)+"?"+QString(param);
            QNetworkReply *reply=m_manager->get(QNetworkRequest(QUrl(QString(connurl)+QString(url)+"?"+QString(param))));
            QObject::connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
            loop.exec();
            QByteArray b=reply->readAll();
            if (b.length()==0)
                return nullptr;
            else {
                char *r=(char*)malloc(b.length()+1);
                memcpy(r,b.data(),b.length());
                r[b.length()]=0;
                reply->deleteLater();
                return r;
            }
        }
    }



} ngxdb;

#endif // CONN_H
