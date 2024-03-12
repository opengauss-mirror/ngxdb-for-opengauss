# from django.http import HttpResponse
from django.http import HttpResponse
from django.shortcuts import render
# from pathlib import Path
import psycopg2
import math
import json

# Create your views here.

def opengauss(request):
    if request.method=="POST":
        param=request.POST
    else:
        param=request.GET
    # print("params",param)
    urlname='"'+request.path.replace("/func/","").replace("/",'"."')+'"'
    funcparam=func[urlname]
    if funcparam==None:
        return None
    strparam=""
    # print(funcparam,len(funcparam))
    for i in range(0,len(funcparam)):
        p=param.get(funcparam[i][0])
        if p==None:
            strparam+=",null::"+funcparam[i][1]
        else:
            strparam+=",'"+p+"'::"+funcparam[i][1]
        # print(funcparam[i][0],strparam,p,i)
    print(urlname,"select * from "+urlname+"("+strparam[1:]+")\n")
    cur.execute("select * from "+urlname+"("+strparam[1:]+")")
    re=cur.fetchall()
    print(urlname,"re",json.dumps(re),"\n")
    conn.commit()
    return HttpResponse((json.dumps(re[0][0])))

def getfunc():
    global func
    cur.execute("select * from gm.nginx")
    re=cur.fetchall()
    for item in re:
        funcname=item[1][1:]
        proctype=item[0].split(",")
        procname=item[2].split(",")
        param=[]
        for i in range(0,item[3]):
            # print(proctype[i],procname[i])
            param.append([procname[i][2:],proctype[i][int(math.log10(i+1))+4:]])
        func[funcname]=param
    conn.commit()

conn=psycopg2.connect(host="127.0.0.1",database="postgres",user="conn",password="Gao@12345")
cur=conn.cursor()
func={}
getfunc()
print(func)
