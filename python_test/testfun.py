import json
import random
import threading
import time
import sys
from urllib.parse import urlencode
import psycopg2
import requests
from base64 import b64encode 
from datetime import datetime

import urllib3



url='http://192.168.1.96:80/func/'
loginname='admin'  #账号1
passward='123456' #密码1

def report(detail=False):
    global icount,isucc,testreport
    if detail:
        for i in range(0,icount):
            print(testreport[i][0],testreport[i][1],testreport[i][2],testreport[i][3])
    print("开始时间:%s 结束时间:%s 耗时:%r秒" %(starttime,endtime,format(endtime-starttime)))
    print("总用例:%i 成功:%i 失败:%i" %(icount,isucc,icount-isucc))

def getfun(funcname,param,report=True):
    global icount,testreport,isucc
    data=''
    # for item in param:
    #     print(item)
    #     data+=(item+'='+urlencode(value))
    data=''.join([f'{key}={value}&' for key,value in param.items()])[:-1]
    print(urlencode(param))
    # funcname=funcname.replace('/','.')
    # print(funcname)
    # cur.execute("select "+funcname+"("+data+");")
    # re=cur.fetchall()[0][0]
    # print(re)
    re=requests.post(url+funcname,params=urlencode(param))
    # testreport
    try:
        rejson=re.json()
        print(rejson)
        # rejson=re.json()
        # print(re.text)
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
        time.sleep(60)
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
    time.sleep(60*4)
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
    global icount,isucc
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

def test_sysinfo_systeminfo():
    global icount,isucc,token,testreport
    def check(testparam):
        cur.execute("select systemid,systemname,adminid,algorithm,loginname,prikey from sysinfo.systeminfo where systemid="+str(testparam['systemid']))
        re=cur.fetchall()[0]
        if  re[0]==testparam["systemid"] and re[1]==testparam["systemname"] and re[2]==testparam["adminid"] and re[3]==testparam["algorithm"] and re[4]==testparam["loginname"] and re[5]==testparam["prikey"] :
            return True
        else:
            return False
    systemid=99
    systemname="KIe7MTjJn0CB4DBWyBUBtEFyRbVasTfhbSVxeb9m3yN3UVJCcV7rTIoa9xx3GPy3fKA4XfZ5hpspJmR02ICprb6Q6loTaJCqah4L6vh7E614tuLSpCx42ofs4FejZZj9KoIiGZp86aNtKwIBtKZjWppzaJL1d7jXvrdhAfbQ5kmcIit3WjRolS7URZaAGLhWSueWOXXiH75p1AQ6xIUYUXHao3Ek8n9Xi5sFQZIegbJmyMJaG7UQK8Do9qdkzef"
    adminid=100000
    orgcode="4XGFIc2kaPW7fmmvzODkHedr0GmHSUygCqdqruHdmpqiNMIIF2S1wQ8NtU1PQowDTHQinxLSxxjRwZICNqIKnrE3c9YTigoCs1bL3grLzN78rvmrk7NfpXQuHv5MfzDUG8PIOLw4LntHpd21f4P57kR2brnBEfMuwl1vCzicaJcZKQTIY1VUnoDSiHMDlXAPgC4UJjUESiWRsxtSbk2tsHavoL81HHsVI6XU28EiCx4UryRp9hVy1DJjfVEH0wy"
    algorithm=1
    loginname="zqokZ53BjSSEt00q"
    prikey="iXzQqs8jlWLySAi8"
    cur.execute("delete from sysinfo.systeminfo where systemid="+str(systemid))
    conn.commit()
    time.sleep(1)
    icount+=1
    param={"token":token,"systemid":systemid,"systemname":systemname,"adminid":adminid,"orgcode":orgcode,"algorithm":algorithm,"loginname":loginname,"prikey":prikey}
    rj=getfun("sysinfo/systeminfo_add",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.systeminfo_add',param,rj,True])
    else:
        testreport.append(['sysinfo.systeminfo_add',param,rj,False])
    icount+=1
    param={"token":token,"systemid":systemid,"systemname":systemname,"adminid":adminid,"orgcode":orgcode,"algorithm":algorithm,"loginname":loginname,"prikey":prikey}
    rj=getfun("sysinfo/systeminfo_edit",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.systeminfo_edit',param,rj,True])
    else:
        testreport.append(['sysinfo.systeminfo_edit',param,rj,False])
    icount+=1
    param={"token":token,"systemid":systemid,"systemname":systemname,"adminid":adminid,"orgcode":orgcode,"algorithm":algorithm,"loginname":loginname,"prikey":prikey}
    rj=getfun("sysinfo/systeminfo_merge",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.systeminfo_merge',param,rj,True])
    else:
        testreport.append(['sysinfo.systeminfo_merge',param,rj,False])
    icount+=1
    param={"token":token,"systemid":systemid}
    rj=getfun("sysinfo/systeminfo_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.systeminfo_query',param,rj,True])
    else:
        testreport.append(['sysinfo.systeminfo_query',param,rj,False])
    icount+=1
    param={"token":token,"systemid":systemid,"rows":1,"page":1}
    rj=getfun("sysinfo/systeminfo_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.systeminfo_query',param,rj,True])
    else:
        testreport.append(['sysinfo.systeminfo_query',param,rj,False])
    icount+=1
    param={"token":token,"systemid":systemid}
    rj=getfun("sysinfo/systeminfo_del",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.systeminfo where systemid="+str(systemid)+" and isused=0")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.systeminfo_del',param,rj,True])
    else:
        testreport.append(['sysinfo.systeminfo_del',param,rj,False])
    icount+=1
    param={"token":token,"systemid":systemid}
    rj=getfun("sysinfo/systeminfo_undel",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.systeminfo where systemid="+str(systemid)+" and isused=1")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.systeminfo_undel',param,rj,True])
    else:
        testreport.append(['sysinfo.systeminfo_undel',param,rj,False])
    cur.execute("delete from sysinfo.systeminfo where systemid="+str(systemid))
    conn.commit()
    time.sleep(1)

def test_sysinfo_sysaction():
    global icount,isucc,token,testreport
    def check(testparam):
        cur.execute("select upid,params,sysactionid,sysactionname,actionid,isdefault,systemid from sysinfo.sysaction where sysactionid="+str(testparam['sysactionid']))
        re=cur.fetchall()[0]
        if  re[0]==testparam["upid"] and re[1]==testparam["params"] and re[2]==testparam["sysactionid"] and re[3]==testparam["sysactionname"] and re[4]==testparam["actionid"] and re[5]==testparam["isdefault"] and re[6]==testparam["systemid"]:
            return True
        else:
            return False
    upid=100
    params="eMK0vQDjwjVOFevffqKfeiCm39MU6SZoH71HhkSXGpNMzgBnad8xqDgRxFqIhm8RB4qHwfKgNPETR7sQZFtR7CdwRB3sjAusKBIwX7Suq5zJ8s93Fdr89OWfQkTNP0UPJpi17EfurOzV1lbgMfhVOj6YMrddzytik1gfXHUjrXOwD6sftp4aPRFJDi2v3zGHMdUI3J4MHHCXceYoqd6qxKNGLCVFrVU05joHs2QPYnUKRVZtkECSYG8zyHJHVoK"
    sysactionid=99
    sysactionname="fxSRMZoND6OSEQfOH2Q6qbdevejBCJmkdUDepIinOYNugTaQRG4UIEvm07ZZ71gQ5ITEm5f3UQQBVamGVriNheAO5YIYHSmccolKLQLMvW0Oef8acv8OkuTaB6x73zymAM8mMbcwxuXHVMUZJl4S79UclNxyZUCn4qkEx5MloEigsSHfyqoiZUbMexsF8Tf2tCibsg8zmp9tE2kZ9XMfkbDYcxhfstkpwCHakOK4O8WMz3z7TJe2rUNT6ddVfLg"
    actionid=99
    isdefault=1
    systemid=100
    cur.execute("delete from sysinfo.actions where actionid=99")
    cur.execute("insert into sysinfo.actions(isused,actionid,actionname) values(1,99,'测试')")
    cur.execute("delete from sysinfo.sysaction where sysactionid="+str(sysactionid))

    conn.commit()
    time.sleep(1)
    icount+=1
    param={"token":token,"upid":upid,"params":params,"sysactionid":sysactionid,"sysactionname":sysactionname,"actionid":actionid,"isdefault":isdefault,"systemid":systemid}
    rj=getfun("sysinfo/sysaction_add",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.sysaction_add',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_add',param,rj,False])
    icount+=1
    param={"token":token,"upid":upid,"params":params,"sysactionid":sysactionid,"sysactionname":sysactionname,"actionid":actionid,"isdefault":isdefault,"systemid":systemid}
    rj=getfun("sysinfo/sysaction_edit",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.sysaction_edit',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_edit',param,rj,False])
    icount+=1
    param={"token":token,"upid":upid,"params":params,"sysactionid":sysactionid,"sysactionname":sysactionname,"actionid":actionid,"isdefault":isdefault,"systemid":systemid}
    rj=getfun("sysinfo/sysaction_merge",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.sysaction_merge',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_merge',param,rj,False])
    icount+=1
    param={"token":token,"sysactionid":sysactionid}
    rj=getfun("sysinfo/sysaction_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.sysaction_query',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_query',param,rj,False])
    icount+=1
    param={"token":token,"sysactionid":sysactionid,"rows":1,"page":1}
    rj=getfun("sysinfo/sysaction_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.sysaction_query',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_query',param,rj,False])
    icount+=1
    param={"token":token,"sysactionid":sysactionid}
    rj=getfun("sysinfo/sysaction_del",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.sysaction where sysactionid="+str(sysactionid)+" and isused=0")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.sysaction_del',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_del',param,rj,False])
    icount+=1
    param={"token":token,"sysactionid":sysactionid}
    rj=getfun("sysinfo/sysaction_undel",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.sysaction where sysactionid="+str(sysactionid)+" and isused=1")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.sysaction_undel',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_undel',param,rj,False])
    cur.execute("delete from sysinfo.sysaction where sysactionid="+str(sysactionid))
    cur.execute("delete from sysinfo.actions where actionid=99")
    conn.commit()
    time.sleep(1)

def test_sysinfo_orgtype():
    global icount,isucc,token,testreport
    def check(testparam):
        cur.execute("select orgtypeid,orgtypename,description from sysinfo.orgtype where orgtypeid="+str(testparam['orgtypeid']))
        re=cur.fetchall()[0]
        if  re[0]==testparam["orgtypeid"] and re[1]==testparam["orgtypename"] and re[2]==testparam["description"] :
            return True
        else:
            return False
    orgtypeid=99
    orgtypename="Kz9AZXrk0IcCd7Ewp37tGBmNN1b6k5MkKkIqbpdidOjk4yVEEGIjsqcdAII6TPyCAElC4Ll3RRJ2hz7lDKBQVuxY7oOxlrl9m6WGLYzybnuADXGLhDf0fLgRDMczb1kxq9yTgLGxbI6Jzw4zhfn4KI1xoesJjtsxMdHiF0mVhKxuZSt7PcoBnP2Ra4MzpCdhvSrWQLkClnheolJ7xnk0N0pptTuDqaNDFkDiU5u8Z4lvYrmP8VDr5krU0rx7e4G"
    description="YzjhMSYw1rYgIA8NWZQN3cN1fin85oUdlOaH6BsFtBetSBpy4W3uqVnzgC3RsQigEONXEADL2JPhVMyYiMyG1gVQWzqkcTrCmpsIWrf6sSVczvt3RTQAi2xXInvZZngT2mZOzHpOWGw3keTWKjJGzo4BQjemjZOvPrc0No5XTeigobWSDR8x2BqEr6n8mZbpNCqBkGKyMXi8ggNcXmD1w1Oe1K7go8BjPZtWN8t1qlC680ItLn2OWsnGisrfKDC"
    cur.execute("delete from sysinfo.orgtype where orgtypeid="+str(orgtypeid))
    conn.commit()
    time.sleep(1)
    icount+=1
    param={"token":token,"orgtypeid":orgtypeid,"orgtypename":orgtypename,"description":description}
    rj=getfun("sysinfo/orgtype_add",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.orgtype_add',param,rj,True])
    else:
        testreport.append(['sysinfo.orgtype_add',param,rj,False])
    icount+=1
    param={"token":token,"orgtypeid":orgtypeid,"orgtypename":orgtypename,"description":description}
    rj=getfun("sysinfo/orgtype_edit",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.orgtype_edit',param,rj,True])
    else:
        testreport.append(['sysinfo.orgtype_edit',param,rj,False])
    icount+=1
    param={"token":token,"orgtypeid":orgtypeid,"orgtypename":orgtypename,"description":description}
    rj=getfun("sysinfo/orgtype_merge",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.orgtype_merge',param,rj,True])
    else:
        testreport.append(['sysinfo.orgtype_merge',param,rj,False])
    icount+=1
    param={"token":token,"orgtypeid":orgtypeid}
    rj=getfun("sysinfo/orgtype_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.orgtype_query',param,rj,True])
    else:
        testreport.append(['sysinfo.orgtype_query',param,rj,False])
    icount+=1
    param={"token":token,"orgtypeid":orgtypeid,"rows":1,"page":1}
    rj=getfun("sysinfo/orgtype_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.orgtype_query',param,rj,True])
    else:
        testreport.append(['sysinfo.orgtype_query',param,rj,False])
    icount+=1
    param={"token":token,"orgtypeid":orgtypeid}
    rj=getfun("sysinfo/orgtype_del",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.orgtype where orgtypeid="+str(orgtypeid)+" and isused=0")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.orgtype_del',param,rj,True])
    else:
        testreport.append(['sysinfo.orgtype_del',param,rj,False])
    icount+=1
    param={"token":token,"orgtypeid":orgtypeid}
    rj=getfun("sysinfo/orgtype_undel",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.orgtype where orgtypeid="+str(orgtypeid)+" and isused=1")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.orgtype_undel',param,rj,True])
    else:
        testreport.append(['sysinfo.orgtype_undel',param,rj,False])
    cur.execute("delete from sysinfo.orgtype where orgtypeid="+str(orgtypeid))
    conn.commit()
    time.sleep(1)

def test_sysinfo_sysorg():
    global icount,isucc,token,testreport
    def check(testparam):
        cur.execute("select upid,sysorgid,sysorgname,description,orgtype from sysinfo.sysorg where sysorgid="+str(testparam['sysorgid']))
        re=cur.fetchall()[0]
        if  re[0]==testparam["upid"] and re[1]==testparam["sysorgid"] and re[2]==testparam["sysorgname"] and re[3]==testparam["description"] and re[4]==testparam["orgtype"] :
            return True
        else:
            return False
    upid=100
    sysorgid=99
    sysorgname="QKb2Ab55xYreVmDuGdIYencPv7fm0ydoDiVnsjP9FwQcrU0RL0jDQPpMl54OnWUiytnVeXoVGepCtJ7v9X9xoVlHIpL6JV3kj4vGG50OK31WwaO07XO7LydYeccLzQlg25DLRW9iWq8qrWh6y2qc43z2ZPScER1tZk3SJSPo611jmIVx6YUjyXsW9NlqnNTDdw7OaoWqcfGU4S35vrjIJeG9Hc5hdjKKirvq6RQwBbAEpKsaJzaBMRyTUhV22tt"
    description="3xHB2wzPzSSI3N5GV28e0IlrLbeyQhwgFdwBpLUeiGeQkkwSV3yUjQ19WjmrbsGsvTk8mvJqAzZmGAFoyZDoyogiAH5hPS6lIScLopf9TZkhdisjKjF2cCOiUJuSsBWzz9FzKEtd60wRM4zrhisKb1ZA1fo7Vwcds0aJq0ZSr8Ev7q8Y5U0BjlK4wV2eQ0rd0Ycz5mNyelIiz5v7ZNAwcVirpDGbGMieGK4iiarrg2QAmpaBnE0mS9HA8tLBSb6"
    orgtype=100
    cur.execute("delete from sysinfo.sysorg where sysorgid="+str(sysorgid))
    conn.commit()
    time.sleep(1)
    icount+=1
    param={"token":token,"upid":upid,"sysorgid":sysorgid,"sysorgname":sysorgname,"description":description,"orgtype":orgtype}
    rj=getfun("sysinfo/sysorg_add",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.sysorg_add',param,rj,True])
    else:
        testreport.append(['sysinfo.sysorg_add',param,rj,False])
    icount+=1
    param={"token":token,"upid":upid,"sysorgid":sysorgid,"sysorgname":sysorgname,"description":description,"orgtype":orgtype}
    rj=getfun("sysinfo/sysorg_edit",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.sysorg_edit',param,rj,True])
    else:
        testreport.append(['sysinfo.sysorg_edit',param,rj,False])
    icount+=1
    param={"token":token,"upid":upid,"sysorgid":sysorgid,"sysorgname":sysorgname,"description":description,"orgtype":orgtype}
    rj=getfun("sysinfo/sysorg_merge",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.sysorg_merge',param,rj,True])
    else:
        testreport.append(['sysinfo.sysorg_merge',param,rj,False])
    icount+=1
    param={"token":token,"sysorgid":99}
    rj=getfun("sysinfo/sysorg_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.sysorg_query',param,rj,True])
    else:
        testreport.append(['sysinfo.sysorg_query',param,rj,False])
    icount+=1
    param={"token":token,"sysorgid":sysorgid,"rows":1,"page":1}
    rj=getfun("sysinfo/sysorg_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.sysorg_query',param,rj,True])
    else:
        testreport.append(['sysinfo.sysorg_query',param,rj,False])
    icount+=1
    param={"token":token,"sysorgid":sysorgid}
    rj=getfun("sysinfo/sysorg_del",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.sysorg where sysorgid="+str(sysorgid)+" and isused=0")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.sysorg_del',param,rj,True])
    else:
        testreport.append(['sysinfo.sysorg_del',param,rj,False])
    icount+=1
    param={"token":token,"sysorgid":sysorgid}
    rj=getfun("sysinfo/sysorg_undel",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.sysorg where sysorgid="+str(sysorgid)+" and isused=1")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.sysorg_undel',param,rj,True])
    else:
        testreport.append(['sysinfo.sysorg_undel',param,rj,False])
    cur.execute("delete from sysinfo.sysorg where sysorgid="+str(sysorgid))
    conn.commit()
    time.sleep(1)

def test_sysinfo_operinfo():
    global icount,isucc,token,testreport
    def check(testparam):
        cur.execute("select operatorid,operatorname,sex,phone,accounts,memo,upcode,headimgurl,nickname,birthday,tokentype,tokeninterval from sysinfo.operinfo where operatorid="+str(testparam['operatorid']))
        re=cur.fetchall()[0]
        if  re[0]==testparam["operatorid"] and re[1]==testparam["operatorname"] and re[10]==testparam["tokentype"] and re[11]==testparam["tokeninterval"] :
            return True
        else:
            return False
    operatorid=99
    operatorname="hJZ7wMX7XZbhlVReB57aRfIAstv1HYellspF4WgelEDMXp8jRGKvpq8thSR7qd4qPCPpFZtWEGwit3eshPJxU0B5D9alEiwYTlqd0mtgWRrKjT33Aju5UV9LOAf3qvyiLcc2jGwfvjTbKj64bWYGEMtxqux4dIjcuSna9iHMrrC5dcNq3UVVH686VyUuup76cKReJVxDMUqMiH425GonurGiuWGCW8rNXbI4S22eSGQTCvSF6p8yFVSgo6aOjpT"
    sysoperjson='[{"systemid":100}]'
    tokentype=1
    tokeninterval=180
    cur.execute("delete from sysinfo.operinfo where operatorid="+str(operatorid))
    cur.execute("delete from sysinfo.sysoper where operatorid="+str(operatorid))
    conn.commit()
    time.sleep(1)
    icount+=1
    param={"token":token,"operatorid":operatorid,"operatorname":operatorname,"tokentype":tokentype,"tokeninterval":tokeninterval,"sysoperjson":sysoperjson}
    rj=getfun("sysinfo/operinfo_add",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.operinfo_add',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfo_add',param,rj,False])
    icount+=1
    param={"token":token,"operatorid":operatorid,"operatorname":operatorname,"tokentype":tokentype,"tokeninterval":tokeninterval,"sysoperjson":sysoperjson}
    rj=getfun("sysinfo/operinfo_edit",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.operinfo_edit',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfo_edit',param,rj,False])
    icount+=1
    param={"token":token,"operatorid":operatorid,"operatorname":operatorname,"tokentype":tokentype,"tokeninterval":tokeninterval,"sysoperjson":sysoperjson}
    rj=getfun("sysinfo/operinfo_merge",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.operinfo_merge',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfo_merge',param,rj,False])
    icount+=1
    param={"token":token,"operatorid":99}
    rj=getfun("sysinfo/operinfo_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.operinfo_query',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfo_query',param,rj,False])
    icount+=1
    param={"token":token,"operatorid":operatorid,"rows":1,"page":1}
    rj=getfun("sysinfo/operinfo_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.operinfo_query',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfo_query',param,rj,False])
    icount+=1
    param={"token":token,"operatorid":operatorid}
    rj=getfun("sysinfo/operinfo_del",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.operinfo where operatorid="+str(operatorid)+" and isused=0")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.operinfo_del',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfo_del',param,rj,False])
    icount+=1
    param={"token":token,"operatorid":operatorid}
    rj=getfun("sysinfo/operinfo_undel",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.operinfo where operatorid="+str(operatorid)+" and isused=1")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.operinfo_undel',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfo_undel',param,rj,False])
    cur.execute("delete from sysinfo.operinfo where operatorid="+str(operatorid))
    cur.execute("delete from sysinfo.sysoper where operatorid=99")
    conn.commit()
    time.sleep(1)

def test_sysinfo_roleinfo():
    global icount,isucc,token,testreport
    def check(testparam):
        cur.execute("select roleinfoid,roleinfoname,description from sysinfo.roleinfo where roleinfoid="+str(testparam['roleinfoid']))
        re=cur.fetchall()[0]
        if  re[0]==testparam["roleinfoid"] and re[1]==testparam["roleinfoname"] and re[2]==testparam["description"] :
            return True
        else:
            return False
    roleinfoid=99
    roleinfoname="XoMcVvANBZr5TjTSIIo1sdk9fP814IQUTl9gNET0dr9m7ZCFdZ5T64WraJIFwVlxDD8rzcSSHOkIIBJQMnP4Opji02j0iv6sDTIbXwo3nyKbvjzwWqMcljgH3PW6SqSk6bOIU5KCsWkUFT8w57ezJ27xXkyG686ZdJzTWyYshLInuOKCZTVygiQX4qEZOunl5XNoZCCADIOwmYNrM3qKik96XHlFwBiwnQbGDUR4XGaSJ9NU9Cv1sYYLf1Kv4xf"
    description="6ujGgDuivoUzxkyALu1H3UXMvuRrHST2ES1o8zX6pgUFUEgJWUgEywbKN5s7DDqkl5yxToRfSkzqiyYtQWUwNuvEzXZt0NQlTdjDOdNyDr16qnPaAAo65dGPAqXzDCFo2aenNac2VxCbSK1V66hqibVtAyEZ2R8bDSP9gsVBXJpPtmXakRGIRaKjfUbg9fBhgsem0hMKRbZlBnKZJTt8S0pBIjo4yeBxc2pPSGxjLrRunUXUk4saq4l2zcasUUf"
    rolepermissionjson='[{"roleid":99,"permissionid":99,"permissiontype":99,"ifpermission":99,"permissionorder":99,"params":"MEBUOHhInjN0P9JnIb10BhsYkKE8iDIPFoepKNIYx83ipuNg0cxyqnyM3bBx7NpYLenYtnvoGeL21xWvWUCshDLSt0vqm6zUw1QxKUn7Xi6VYhTYeXFn5rVGcADU2bbkpS1M9B3OVxuAZWB8u7Z3YTN5jCheOyj34uRgy34uMWvqRlAJhNF3O3tFxma73eW8oPVevf2S2RRGXwU95Bk0QVllbWFEIXRqE4GCfVaMVfG7eNSoh7wEkdG7oiSf7FJ","params":99,"sysactionid":99,"systemid":100}]'
    cur.execute("delete from sysinfo.roleinfo where roleinfoid="+str(roleinfoid))
    cur.execute("delete from sysinfo.rolepermission where permissionid=99")
    conn.commit()
    time.sleep(1)
    icount+=1
    param={"token":token,"roleinfoid":roleinfoid,"roleinfoname":roleinfoname,"description":description,"rolepermissionjson":rolepermissionjson}
    rj=getfun("sysinfo/roleinfo_add",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.roleinfo_add',param,rj,True])
    else:
        testreport.append(['sysinfo.roleinfo_add',param,rj,False])
    icount+=1
    param={"token":token,"roleinfoid":roleinfoid,"roleinfoname":roleinfoname,"description":description,"rolepermissionjson":rolepermissionjson}
    rj=getfun("sysinfo/roleinfo_edit",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.roleinfo_edit',param,rj,True])
    else:
        testreport.append(['sysinfo.roleinfo_edit',param,rj,False])
    icount+=1
    param={"token":token,"roleinfoid":roleinfoid,"roleinfoname":roleinfoname,"description":description,"rolepermissionjson":rolepermissionjson}
    rj=getfun("sysinfo/roleinfo_merge",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.roleinfo_merge',param,rj,True])
    else:
        testreport.append(['sysinfo.roleinfo_merge',param,rj,False])
    icount+=1
    param={"token":token,"roleinfoid":99}
    rj=getfun("sysinfo/roleinfo_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.roleinfo_query',param,rj,True])
    else:
        testreport.append(['sysinfo.roleinfo_query',param,rj,False])
    icount+=1
    param={"token":token,"roleinfoid":roleinfoid,"rows":1,"page":1}
    rj=getfun("sysinfo/roleinfo_query",param,False)
    if rj['errorcode']==0 and rj['info']['total']==1:
        isucc+=1
        testreport.append(['sysinfo.roleinfo_query',param,rj,True])
    else:
        testreport.append(['sysinfo.roleinfo_query',param,rj,False])
    icount+=1
    param={"token":token,"roleinfoid":roleinfoid}
    rj=getfun("sysinfo/roleinfo_del",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.roleinfo where roleinfoid="+str(roleinfoid)+" and isused=0")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.roleinfo_del',param,rj,True])
    else:
        testreport.append(['sysinfo.roleinfo_del',param,rj,False])
    icount+=1
    param={"token":token,"roleinfoid":roleinfoid}
    rj=getfun("sysinfo/roleinfo_undel",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.roleinfo where roleinfoid="+str(roleinfoid)+" and isused=1")
    lines=cur.fetchall()
    if rj['errorcode']==0 and lines[0][0]==1:
        isucc+=1
        testreport.append(['sysinfo.roleinfo_undel',param,rj,True])
    else:
        testreport.append(['sysinfo.roleinfo_undel',param,rj,False])
    cur.execute("delete from sysinfo.roleinfo where roleinfoid="+str(roleinfoid))
    cur.execute("delete from sysinfo.rolepermission where permissionid=99")
    conn.commit()
    time.sleep(1)

def test_sysinfo_operinfopermission():
    global icount,isucc,token,testreport
    def check(testparam):
        cur.execute("select operatorid from sysinfo.operinfo where operatorid="+str(testparam['operatorid']))
        re=cur.fetchall()[0]
        if  re[0]==testparam["operatorid"] :
            return True
        else:
            return False
    operatorid=99
    operpermissionjson='[{"permissiontype":99,"ifpermission":99,"permissionorder":99,"sysactionid":99,"permissionid":99,"systemid":100}]'
    cur.execute("delete from sysinfo.operinfo where operatorid="+str(operatorid))
    cur.execute("delete from sysinfo.operpermission where operatorid=99")
    cur.execute('delete from sysinfo.sysoper where operatorid=99')
    cur.execute('delete from sysinfo.sysaction where systemid=99')
    cur.execute("insert into sysinfo.operinfo(operatorid,operatorname,isused) values(99,'测试',1)")
    cur.execute("insert into sysinfo.sysoper(operatorid,systemid) values(99,100)")
    conn.commit()
    time.sleep(1)
    icount+=1
    # token='8EcynEywtr/G6ig2ovkYwG3nF0fYfGQIenrK/x8EEkhlJH43yYNdruOofwiNR4QzEFCk3ecXvZI7yeC9auMvgJ3etFZ2+km08R18H7081G/hOesq6s6c8nsvH3PKqAUGXHsmcQxyw4pRFnLcI9832/Jnmp+EEyAU8PVFPD+xLJhmTibwLj4u5A34kgHi4fU/RPiZ5DySgDR1jvTPBuYSMFUNfGwkeqQSTMJ+17qwsZoslk82hSpCQ2xspFeaPGCbadnQLLsjk4BNsBPa/jjXKqUAS3TTp8SBle84l8XJ6qQitSmqrKbmlwwD1f9VsicUykWnvkgp7ikLNjsVQv0euVBrvso34lLSAUfRn8JsjW3dQbUYsHQrYM5stKoUbtyxOacp5w=='
    param={"token":token,"operatorid":operatorid,"operpermissionjson":operpermissionjson}
    rj=getfun("sysinfo/operinfopermission_add",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.operinfopermission_add',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfopermission_add',param,rj,False])
    icount+=1
    param={"token":token,"operatorid":operatorid,"operpermissionjson":operpermissionjson}
    rj=getfun("sysinfo/operinfopermission_edit",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.operinfopermission_edit',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfopermission_edit',param,rj,False])
    icount+=1
    param={"token":token,"operatorid":operatorid,"operpermissionjson":operpermissionjson}
    rj=getfun("sysinfo/operinfopermission_merge",param,False)
    if rj['errorcode']==0 and check(param):
        isucc+=1
        testreport.append(['sysinfo.operinfopermission_merge',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfopermission_merge',param,rj,False])
    icount+=1
    param={"token":token,"operatorid":99}
    # rj=getfun("sysinfo/operinfopermission_query",param,False)
    # if rj['errorcode']==0 and rj['info']['total']==1:
    #     isucc+=1
    #     testreport.append(['sysinfo.operinfopermission_query',param,rj,True])
    # else:
    #     testreport.append(['sysinfo.operinfopermission_query',param,rj,False])
    # icount+=1
    # param={"token":token,"operatorid":operatorid,"rows":1,"page":1}
    # rj=getfun("sysinfo/operinfopermission_query",param,False)
    # if rj['errorcode']==0 and rj['info']['total']==1:
    #     isucc+=1
    #     testreport.append(['sysinfo.operinfopermission_query',param,rj,True])
    # else:
    #     testreport.append(['sysinfo.operinfopermission_query',param,rj,False])
    # icount+=1
    param={"token":token,"operatorid":operatorid}
    rj=getfun("sysinfo/operinfopermission_del",param,False)
    time.sleep(1)
    cur.execute("select count(*) from sysinfo.operpermission where operatorid="+str(operatorid))
    lines=cur.fetchall()
    print(lines[0][0])
    if rj['errorcode']==0 and lines[0][0]==0:
        isucc+=1
        testreport.append(['sysinfo.operinfopermission_del',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfopermission_del',param,rj,False])
    cur.execute("delete from sysinfo.operinfo where operatorid="+str(operatorid))
    cur.execute("delete from sysinfo.operpermission where operatorid=99")
    cur.execute('delete from sysinfo.sysoper where operatorid=99')
    conn.commit()
    time.sleep(1)

def test_1_0():
    global icount,isucc,token,testreport
    def cleardata():
        cur.execute("delete from sysinfo.operinfo where operatorid=99 or operatorid=98")
        cur.execute("delete from sysinfo.sysaction where systemid=99")
        cur.execute("delete from sysinfo.sysoper where operatorid=99 or operatorid=98")
        cur.execute("delete from sysinfo.sysoperorg where operatorid=99 or operatorid=98")
        cur.execute("delete from sysinfo.orgtype where orgtypeid=99")
        cur.execute("delete from sysinfo.sysorg where sysorgid=99")
        cur.execute("delete from sysinfo.systeminfo where systemid=99")
        cur.execute("delete from sysinfo.operpermission where operatorid=99")
        conn.commit()
    operatorid=99
    operpermissionjson='[{"permissiontype":99,"ifpermission":99,"permissionorder":99,"sysactionid":99,"permissionid":99,"systemid":100}]'
    cleardata()
    time.sleep(1)
    icount+=1
    param={"token":token,"operatorid":99,"opeatorname":"测试人员","accounts":"test","tokentype":1,"tokeninterval":180,"sysoperjson":'[{"systemid":100}]'}
    rj=getfun("sysinfo/operinfo_add",param,False)
    mypass=rj['info']['pass']
    if rj['errorcode']==0 :
        isucc+=1
        testreport.append(['sysinfo.operinfo_add',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfo_add',param,rj,False])
    icount+=1
    param={"token":token,"systemid":99,"systemname":"测试系统","adminid":99,"algrithm":1,"loginname":"test","prikey":"Gao@12345"}
    rj=getfun("sysinfo/systeminfo_add",param,False)
    if rj['errorcode']==0 :
        isucc+=1
        testreport.append(['sysinfo.systeminfo_add',param,rj,True])
    else:
        testreport.append(['sysinfo.systeminfo_add',param,rj,False])
    icount+=1
    param={"token":token,"sysactionid":99,"sysactionname":"测试系统权限","systemid":99}
    rj=getfun("sysinfo/sysaction_add",param,False)
    if rj['errorcode']==0 :
        isucc+=1
        testreport.append(['sysinfo.sysaction_add',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_add',param,rj,False])
    icount+=1
    param={"token":token,"upid":99,"sysactionid":98,"sysactionname":"新增部门类型","actionid":120,"systemid":99}
    rj=getfun("sysinfo/sysaction_add",param,False)
    if rj['errorcode']==0 :
        isucc+=1
        testreport.append(['sysinfo.sysaction_add',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_add',param,rj,False])
    icount+=1
    param={"token":token,"upid":99,"sysactionid":97,"sysactionname":"新增部门","actionid":114,"systemid":99}
    rj=getfun("sysinfo/sysaction_add",param,False)
    if rj['errorcode']==0 :
        isucc+=1
        testreport.append(['sysinfo.sysaction_add',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_add',param,rj,False])
    icount+=1
    param={"token":token,"upid":99,"sysactionid":96,"sysactionname":"新增员工","actionid":126,"systemid":99}
    rj=getfun("sysinfo/sysaction_add",param,False)
    if rj['errorcode']==0 :
        isucc+=1
        testreport.append(['sysinfo.sysaction_add',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_add',param,rj,False])
    icount+=1
    param={"token":token,"upid":99,"sysactionid":95,"sysactionname":"新增员工权限","actionid":138,"systemid":99}
    rj=getfun("sysinfo/sysaction_add",param,False)
    if rj['errorcode']==0 :
        isucc+=1
        testreport.append(['sysinfo.sysaction_add',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_add',param,rj,False])
    icount+=1    
    param={"token":token,"upid":99,"sysactionid":94,"sysactionname":"新增员工权限","actionid":144,"systemid":99}
    rj=getfun("sysinfo/sysaction_add",param,False)
    if rj['errorcode']==0 :
        isucc+=1
        testreport.append(['sysinfo.sysaction_add',param,rj,True])
    else:
        testreport.append(['sysinfo.sysaction_add',param,rj,False])
    icount+=1    
    param={"loginname":"test","pass":mypass,"system":"test"}
    rj=getfun("sysinfo/login",param,False)
    if rj['errorcode']==0:
        isucc+=1
        testreport.append(['sysinfo.login',param,rj,True])
    else:
        testreport.append(['sysinfo.login',param,rj,False])
    token=rj["info"]['token']
    icount+=1
    param={"token":token,"operatorid":99,"operpermissionjson":'[{"permissiontype":1,"permissionid":99,"systemid":99,"sysactionid":114},{"permissiontype":1,"permissionid":99,"systemid":99,"sysactionid":100}]'}
    rj=getfun("sysinfo/operinfopermission_add",param,False)
    if rj['errorcode']==0:
        isucc+=1
        testreport.append(['sysinfo.operinfopermission_add',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfopermission_add',param,rj,False])
    icount+=1    
    param={"token":token,"orgtypename":"一般部门","orgtypeid":99,"description":"测试"}
    rj=getfun("sysinfo/orgtype_add",param,False)
    if rj['errorcode']==0:
        isucc+=1
        testreport.append(['sysinfo.orgtype_add',param,rj,True])
    else:
        testreport.append(['sysinfo.orgtype_add',param,rj,False])
    icount+=1    
    param={"token":token,"sysorgname":"测试公司","sysorgid":99,"description":"测试","orgtype":99}
    rj=getfun("sysinfo/sysorg_add",param,False)
    if rj['errorcode']==0:
        isucc+=1
        testreport.append(['sysinfo.sysorg_add',param,rj,True])
    else:
        testreport.append(['sysinfo.sysorg_add',param,rj,False])
    icount+=1    
    param={"token":token,"operatorid":98,"operatorname":"测试","sex":1,"phone":"1300","accounts":"test1","sysoperorgjson":'[{"sysorgid":99}]'}
    rj=getfun("sysinfo/operinfoorg_add",param,False)
    if rj['errorcode']==0:
        isucc+=1
        testreport.append(['sysinfo.operinfoorg_add',param,rj,True])
    else:
        testreport.append(['sysinfo.operinfoorg_add',param,rj,False])
    cleardata()

conn=psycopg2.connect(database="opengauss", user="gm", password="gao@12345", host="192.168.1.96", port="5432")
cur=conn.cursor()
icount=0
isucc=0
testreport=[]
starttime=datetime.now()
param={"loginname":loginname,"pass":passward}
rj=getfun("sysinfo/login",param,True)
token=rj['info']['token']
# test_gm_check_login()
# test_sysinfo_login()
test_sysinfo_systeminfo()
test_sysinfo_sysaction()
test_sysinfo_orgtype()
test_sysinfo_sysorg()
test_sysinfo_operinfo()
test_sysinfo_roleinfo()
test_sysinfo_operinfopermission()
test_1_0()
endtime=datetime.now()
report(True)
conn.close