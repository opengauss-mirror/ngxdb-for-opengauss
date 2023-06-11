import json
import random
import threading
import time
import sys
import psycopg2
import requests
from base64 import b64encode 
from datetime import datetime



url='http://127.0.0.1:80/func/'
loginname='admin'  #账号1
passward='123456' #密码1
conn=psycopg2.connect(database="opengauss", user="gm", password="gao@12345", host="192.168.1.94", port="5432")
cur=conn.cursor()


icount=0
isucc=0
testreport=[]
starttime=datetime.now()

def report(detail=False):
    global icount,isucc,testreport
    if detail:
        for i in range(0,icount):
            print(testreport[i][0],testreport[i][1],testreport[i][2],testreport[i][3])
    print("开始时间:%s 结束时间:%s 耗时:%r秒" %(starttime,endtime,format(endtime-starttime)))
    print("总用例:%i 成功:%i 失败:%i" %(icount,isucc,icount-isucc))

def getfun(funcname,param,report=True):
    global icount,testreport,isucc
    re=requests.get(url+funcname,param)
    testreport
    try:
        rejson=re.json()
    except: 
        print(re.text)
        if report:
            testreport.append([funcname,param,None,False])
        return None
    if (rejson["errorcode"]!=0):
        print(rejson["message"])
        if report:
            icount+=1
            testreport.append([funcname,param,re.text,False])
    else:
        if report:
            isucc=isucc+1
            icount+=1
            testreport.append([funcname,param,re.text,True])
    return rejson

def login(loginname,passw,system=None,report=True):
    rj=getfun("sysinfo/login",{"loginname":loginname,"pass":passw,"system":system},report)
    return rj

def test_sysinfo_login():
    global isucc,testreport,icount,token
    param={"loginname":"asasf","pass":"sdfsdf"}    
    for i in range(6):
        icount+=1
        rj=getfun("sysinfo/login",param,False)
        if rj==None:
            testreport.append(["sysinfo/login",param,None,True])
        else: 
            if rj["errorcode"]==100001:
                isucc=isucc+1
                testreport.append(["sysinfo/login",param,rj,True])
            else:
                testreport.append(["sysinfo/login",param,rj,False])
    
    rj=getfun("sysinfo/login",param,False)
    icount+=1
    if rj==None:
        testreport[icount]={"sysinfo/login",param,None,True}
    else: 
        if rj["errorcode"]==100002:
            isucc=isucc+1
            testreport.append(["sysinfo/login",param,rj,True])
        else:
            testreport.append(["sysinfo/login",param,rj,False])
    time.sleep(60*10)
    for i in range(5):
        icount+=1
        rj=getfun("sysinfo/login",param,False)
        if rj==None:
            testreport[icount]={"sysinfo/login",param,None,True}
        else: 
            if rj["errorcode"]==100001:
                isucc=isucc+1
                testreport.append(["sysinfo/login",param,rj,True])
            else:
                testreport.append(["sysinfo/login",param,rj,False])    
    rj=getfun("sysinfo/login",param,False)
    icount+=1
    if rj==None:
        testreport[icount]={"sysinfo/login",param,None,True}
    else: 
        if rj["errorcode"]==100003:
            isucc=isucc+1
            testreport.append(["sysinfo/login",param,rj,True])
        else:
            testreport.append(["sysinfo/login",param,rj,False])

def test_gm_check_login():
    global icount,cur,isucc,testreport
    cur.callproc('gm.check_login',['asdaddd'+token,100])
    re=cur.fetchall()[0][0]
    icount+=1
    if re['errorcode']==100005:
        isucc+=1
        testreport.append(['gm.check_login',['asdaddd'+token,100],re,True])
    else:
        testreport.append(['gm.check_login',['asdaddd'+token,100],re,False])

    cur.callproc('gm.check_login',[token,100])
    re=cur.fetchall()[0][0]
    icount+=1
    if re['errorcode']==0:
        isucc+=1
        testreport.append(['gm.check_login',[token,100],re,True])
    else:
        testreport.append(['gm.check_login',[token,100],re,False])

test_sysinfo_login()
param={"loginname":loginname,"pass":passward}
rj=getfun("sysinfo/login",param,True)
token=rj['info']['token']
test_gm_check_login()
endtime=datetime.now()
report(True)
conn.close