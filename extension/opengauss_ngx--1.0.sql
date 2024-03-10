drop schema if exists "conn" cascade;
drop schema if exists "sysinfo" cascade;
drop schema if exists "gm" cascade;

do
$do$
BEGIN
  IF NOT EXISTS ( SELECT * FROM pg_user WHERE usename = 'conn') THEN
    CREATE user conn  PASSWORD 'Gao@12345';
  END IF;
  IF NOT EXISTS ( SELECT * FROM pg_user WHERE usename = 'gm') THEN
    CREATE user gm  PASSWORD 'Gao@12345';
  END IF;
END
$do$;

--
--

SET statement_timeout = 0;
SET xmloption = content;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET session_replication_role = replica;
SET client_min_messages = warning;

--
-- Name: postgres; Type: COMMENT; Schema: -; Owner: opengauss
--

COMMENT ON DATABASE postgres IS 'default administrative connection database';


--
-- Name: conn; Type: SCHEMA; Schema: -; Owner: conn
--

CREATE SCHEMA conn;


ALTER SCHEMA conn OWNER TO conn;

--
-- Name: gm; Type: SCHEMA; Schema: -; Owner: gm
--

CREATE SCHEMA gm;


ALTER SCHEMA gm OWNER TO gm;

--
-- Name: sysinfo; Type: SCHEMA; Schema: -; Owner: gm
--

CREATE SCHEMA sysinfo;


ALTER SCHEMA sysinfo OWNER TO gm;

SET search_path = gm;

--
-- Name: actionupdate(); Type: FUNCTION; Schema: gm; Owner: gm
--

CREATE FUNCTION actionupdate() RETURNS boolean
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$BEGIN
  
	update sysinfo.sysaction set isused=1 where isused is null;
  with recursive tree as
  ( select sysactionid,upid,1 as idlevel,coalesce(actionid,sysactionid)::varchar as idpath,t1.systemid from sysinfo.sysaction t1 where upid=0
  union
  select t1.sysactionid,t1.upid,t2.idlevel+1,t2.idpath||'.'||coalesce(t1.actionid,t1.sysactionid),t1.systemid from sysinfo.sysaction t1 inner join tree t2 on t2.sysactionid=t1.upid and t2.systemid=t1.systemid where isused<>0) 
  update sysinfo.sysaction t set idpath=t1.idpath,idlevel=t1.idlevel,idcount=coalesce(cc,0) from tree t1 left join (select upid,count(*) cc,systemid from sysinfo.sysaction where isused<>0 group by upid,systemid) t2 on t1.sysactionid=t2.upid and t1.systemid=t2.systemid
  where t.sysactionid=t1.sysactionid;
  return true;
END
$$;


ALTER FUNCTION gm.actionupdate() OWNER TO gm;

--
-- Name: check_login(character varying, integer); Type: FUNCTION; Schema: gm; Owner: gm
--

CREATE FUNCTION check_login(p_token character varying, p_actionid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
	declare 
	  v_code varchar; 
		v_c int4;
		v_return json;
		v_token json;
		v_operatorid int;
		v_operjson json;
		v_systemid int;
		v_tokenstr varchar;
	BEGIN
    if p_actionid is null then return returnjson(0); end if;
		if p_token is null then return returnjson(100005); end if;
		select params into v_tokenstr from sysinfo.actions where actionid=101;
		v_token:=gs_decrypt_aes128(p_token, v_tokenstr)::json;
		v_systemid:=(v_token->>'systemid')::integer;
		select row_to_json(t) into v_return from sysinfo.systeminfo t where v_systemid=systemid and isused=1 ;
		if v_return is null then return gm.returnjson(100012); end if;--子系统信息出错！
		v_token:=case (v_return->>'algorithm')::integer
		  when 1 then gs_decrypt(v_token->>'token',(v_return->>'prikey')::text,'aes128')
			when 2 then gs_decrypt(v_token->>'token',(v_return->>'prikey')::text,'sm4')
		end;		
    v_operatorid:=(v_token->>'operatorno')::integer;
		select array_to_json(array_agg(row_to_json(t))) into v_operjson from sysinfo.operinfo t where operatorid=v_operatorid and isused=1;
		if v_operjson is null or json_array_length(v_operjson)>1 then return gm.returnjson(100011); end if;--操作员信息出错！
		select count(*) into v_c from sysinfo.sysoper where operatorid=v_operatorid and systemid=v_systemid ;
		if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！
		v_operjson:=v_operjson->0;
		case (v_operjson->>'tokentype')::integer 
		    when 1 then --1、单人登录
				  if v_operjson->>'tokenkey'!=p_token or (v_operjson->>'tokentime')::timestamp<now() then return gm.returnjson(100006);end if;--登录已失效！
				when 2 then --2、多人登录，不比较tokenkey
				  if (v_operjson->>'tokentime')::timestamp<now() then return gm.returnjson(100006);end if;--登录已失效！
				else 
				  return gm.returnjson(100006);--登录已失效！ 
		end case;
		select count(*) into v_c from sysinfo.sysaction where coalesce(actionid,sysactionid) = p_actionid and systemid=v_systemid;
		if v_c=0 then return gm.returnjson(100008);end if; --'无此权限！';--10008
    select '.' || idpath || '.',isdefault into v_code,v_c from sysinfo.sysaction where coalesce(actionid,sysactionid) = p_actionid and systemid=v_systemid limit 1;
		if v_c=1 then return gm.returnjson(0,json_build_object('operatorid',v_operatorid,'systemid',v_systemid,'orgid',v_token->>'orgid'));end if;
    select count(*)
      into v_c
      from sysinfo.operpermission c left join sysinfo.sysaction c1 on c1.sysactionid=c.sysactionid and c1.systemid=v_systemid
     where c.operatorid = v_operatorid and c1.systemid=v_systemid
       and position( '.' || coalesce(c1.actionid,c1.sysactionid) || '.' in v_code) > 0
       and permissiontype = 1;
    if v_c > 0 then
			update sysinfo.operinfo set tokentime=now()+ (interval '1 minute')*tokeninterval where operatorid=v_operatorid;
      return gm.returnjson(0,json_build_object('operatorid',v_operatorid,'systemid',v_systemid,'orgid',v_token->>'orgid'));
    end if;
		with recursive c as (
	select c3.sysactionid,c3.permissiontype from sysinfo.operpermission c2 left join sysinfo.rolepermission c3 on c2.actionid=c3.roleinfoid left join sysinfo.sysaction c4 on c2.sysactionid=c4.sysactionid where c2.permissiontype=2 and c2.operatorid=v_operatorid and c4.systemid=v_systemid
	union 
	select c3.sysactionid,c3.permissiontype from c left join sysinfo.rolepermission c3 on c.actionid=c3.roleinfoid left join sysinfo.sysaction c4 on c3.sysactionid=c4.sysactionid where c.permissiontype=2 and c3.systemid=v_systemid
	)
    select count(*)
      into v_c
      from c left join sysinfo.sysaction c1 on c1.sysactionid=c.sysactionid and c1.sysemid=v_systemid
     where permissiontype = 1 and position( '.' || coalesce(c1.actionid,c1.sysactionid) || '.' in v_code) > 0;
    if v_c > 0 then
			update sysinfo.operinfo set tokentime=now()+ (interval '1 minute')*tokeninterval where operatorid=v_operatorid;
      return gm.returnjson(0,json_build_object('operatorid',v_operatorid,'systemid',v_systemid,'orgid',v_token->>'orgid'));
    end if;
    return gm.returnjson(100008); --'无此权限！';--10008
  exception when others then return gm.returnjson(100005);--非法登录！
	
END
$$;


ALTER FUNCTION gm.check_login(p_token character varying, p_actionid integer) OWNER TO gm;

--
-- Name: gethelp(); Type: FUNCTION; Schema: gm; Owner: gm
--

CREATE FUNCTION gethelp() RETURNS text
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
	declare v_return text; 
BEGIN
   select html1||aa||html2 into v_return from sysinfo.funchtml,(select array_to_json(array_agg(row_to_json(t))) aa from (select nspname a,proname b,description c from pg_proc t1 left join pg_namespace t2 on t1.pronamespace=t2.oid left join pg_description t3 on t1.oid=t3.objoid where t2.nspname in ('public','sysinfo') order by nspname,proname) t) t1 where htmlid=100;
	RETURN v_return;
END$$;


ALTER FUNCTION gm.gethelp() OWNER TO gm;

--
-- Name: gettoken(); Type: FUNCTION; Schema: gm; Owner: gm
--

CREATE FUNCTION gettoken() RETURNS void
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
	declare v_return jsonb;v_ok bool;
begin
  v_ok:=true;
  for v_cur in select appid,params from sysinfo.appparams where typeid=101 loop
	  v_return:=gm.http_get('https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&'||v_cur.params);
		if v_return?'access_token' then 
		  update sysinfo.appparams set accesstoken=v_return->>'access_token',tokentime=now() where appid=v_cur.appid;
		else
		  v_ok:=false;
		end if;
	end loop;
	--create event gettoken on schedule 1 hour do gm.gettoken; 
	if v_ok then 
		PERFORM pkg_service.job_finish(101,true,null);
	else 
	  PERFORM pkg_service.job_finish(101,false,sysdate+1.0/288);
	end if;
  return;
END$$;


ALTER FUNCTION gm.gettoken() OWNER TO gm;

--
-- Name: gettokene(); Type: FUNCTION; Schema: gm; Owner: gm
--

CREATE FUNCTION gettokene() RETURNS void
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
	declare v_return jsonb;v_ok bool;
begin
  v_ok:=true;
  for v_cur in select appid,params from sysinfo.appparams where typeid=101 loop
	  v_return:=gm.http_get('https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&'||v_cur.params);
		if v_return?'access_token' then 
		  update sysinfo.appparams set accesstoken=v_return->>'access_token',tokentime=now() where appid=v_cur.appid;
		else
		  v_ok:=false;
		end if;
	end loop;
	--create event gettoken on schedule 1 hour do gm.gettoken; 
	if v_ok then 
		PERFORM pkg_service.job_finish(100,false,sysdate+1.0/24);
	end if;
return;
END$$;


ALTER FUNCTION gm.gettokene() OWNER TO gm;

--
-- Name: http_get(character varying); Type: FUNCTION; Schema: gm; Owner: gm
--

CREATE FUNCTION http_get(p_https character varying) RETURNS character varying
    LANGUAGE plpython3u NOT SHIPPABLE SECURITY DEFINER
 AS $$

	import requests
		
	rv=requests.get(p_https)
	plpy.notice(rv.text)
	return rv.text
$$;


ALTER FUNCTION gm.http_get(p_https character varying) OWNER TO gm;

--
-- Name: http_post(character varying, character varying, character varying); Type: FUNCTION; Schema: gm; Owner: gm
--

CREATE FUNCTION http_post(p_https character varying, p_content character varying, p_contenttype character varying) RETURNS character varying
    LANGUAGE plpython3u NOT SHIPPABLE SECURITY DEFINER
 AS $$

	import requests
	if p_contenttype:	
	  rv=requests.post(p_https,p_content,headers={'content-type':p_contenttype})
	else:
	  rv=requests.post(p_https,p_content)
	plpy.notice(rv.text)
	return rv.text
$$;


ALTER FUNCTION gm.http_post(p_https character varying, p_content character varying, p_contenttype character varying) OWNER TO gm;

--
-- Name: returnjson(integer, json); Type: FUNCTION; Schema: gm; Owner: gm
--

CREATE FUNCTION returnjson(p_code integer, p_jsonvar json DEFAULT NULL::json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
	 declare v_message varchar;v_c int;
	BEGIN
		select count(*) into v_c from sysinfo.errorcode where errorcode=p_code;
		
		if v_c=0 or v_c>1 then return json_build_object('errorcode',p_code,'message','未知错误'); end if;
		select message into v_message from sysinfo.errorcode where errorcode=p_code;
		if p_jsonvar is null then 
		   return json_build_object('errorcode',p_code,'message',v_message);
		else
		   return json_build_object('errorcode',p_code,'message',v_message,'info',p_jsonvar);
		end if;
	END
$$;


ALTER FUNCTION gm.returnjson(p_code integer, p_jsonvar json) OWNER TO gm;

SET search_path = sysinfo;

--
-- Name: actions_query(character varying, integer, integer, integer, integer, character varying, character varying, character varying, character varying, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION actions_query(p_token character varying, p_rows integer, p_page integer, p_isused integer, p_actionid integer, p_actionname character varying, p_description character varying, p_params character varying, p_actionurl character varying, p_code character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_return json;v_check json;
begin
  v_check:=gm.check_login(p_token,180);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_rows is null then
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.isused,t1.actionid,t1.actionname,t1.description,t1.params,t1.actionurl,t1.code from sysinfo.actions t1 where  (p_isused is null or p_isused=t1.isused) and (p_actionid is null or p_actionid=t1.actionid) and (p_actionname is null or position(p_actionname in t1.actionname )>0) and (p_description is null or position(p_description in t1.description )>0) and (p_params is null or position(p_params in t1.params )>0) and (p_actionurl is null or position(p_actionurl in t1.actionurl )>0) and (p_code is null or position(p_code in t1.code )>0) order by t1.actionid) t;
    v_c:=coalesce(json_array_length(v_return),0);
  else
    select count(*) into v_c from sysinfo.actions t1 where  (p_isused is null or p_isused=t1.isused) and (p_actionid is null or p_actionid=t1.actionid) and (p_actionname is null or position(p_actionname in t1.actionname )>0) and (p_description is null or position(p_description in t1.description )>0) and (p_params is null or position(p_params in t1.params )>0) and (p_actionurl is null or position(p_actionurl in t1.actionurl )>0) and (p_code is null or position(p_code in t1.code )>0);
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.isused,t1.actionid,t1.actionname,t1.description,t1.params,t1.actionurl,t1.code from sysinfo.actions t1 where  (p_isused is null or p_isused=t1.isused) and (p_actionid is null or p_actionid=t1.actionid) and (p_actionname is null or position(p_actionname in t1.actionname )>0) and (p_description is null or position(p_description in t1.description )>0) and (p_params is null or position(p_params in t1.params )>0) and (p_actionurl is null or position(p_actionurl in t1.actionurl )>0) and (p_code is null or position(p_code in t1.code )>0) order by t1.actionid limit greatest(p_rows,1) offset greatest(least((p_page-1)*p_rows,(v_c/p_rows-1+abs(v_c % p_rows))*p_rows),0) ) t;
  end if;
  return gm.returnjson(0,json_build_object('total',v_c,'rows',v_return));
end;
$$;


ALTER FUNCTION sysinfo.actions_query(p_token character varying, p_rows integer, p_page integer, p_isused integer, p_actionid integer, p_actionname character varying, p_description character varying, p_params character varying, p_actionurl character varying, p_code character varying) OWNER TO gm;

--
-- Name: FUNCTION actions_query(p_token character varying, p_rows integer, p_page integer, p_isused integer, p_actionid integer, p_actionname character varying, p_description character varying, p_params character varying, p_actionurl character varying, p_code character varying) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION actions_query(p_token character varying, p_rows integer, p_page integer, p_isused integer, p_actionid integer, p_actionname character varying, p_description character varying, p_params character varying, p_actionurl character varying, p_code character varying)
 IS '查询权限名
isused:是否使用
actionid:权限编号
actionname:权限名
description:说明
params:参数
actionurl:权限路径
code:编码
返回:{"total":总记录数,"rows":[{"isused":使用,"actionid":权限编号,"actionname":权限名,"description":说明,"params":参数,"actionurl":权限路径,"code":编码}]}';


--
-- Name: errorcode_query(character varying, integer, integer, character varying, integer, character varying, integer, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION errorcode_query(p_token character varying, p_rows integer, p_page integer, p_message character varying, p_errorcode integer, p_primekey character varying, p_isused integer, p_schema character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_return json;v_check json;
begin
  v_check:=gm.check_login(p_token,181);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_rows is null then
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.message,t1.errorcode,t1.primekey,t1.isused,t1.schema from sysinfo.errorcode t1 where  (p_message is null or position(p_message in t1.message )>0) and (p_errorcode is null or p_errorcode=t1.errorcode) and (p_primekey is null or position(p_primekey in t1.primekey )>0) and (p_isused is null or p_isused=t1.isused) and (p_schema is null or position(p_schema in t1.schema )>0) order by t1.errorcode) t;
    v_c:=coalesce(json_array_length(v_return),0);
  else
    select count(*) into v_c from sysinfo.errorcode t1 where  (p_message is null or position(p_message in t1.message )>0) and (p_errorcode is null or p_errorcode=t1.errorcode) and (p_primekey is null or position(p_primekey in t1.primekey )>0) and (p_isused is null or p_isused=t1.isused) and (p_schema is null or position(p_schema in t1.schema )>0);
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.message,t1.errorcode,t1.primekey,t1.isused,t1.schema from sysinfo.errorcode t1 where  (p_message is null or position(p_message in t1.message )>0) and (p_errorcode is null or p_errorcode=t1.errorcode) and (p_primekey is null or position(p_primekey in t1.primekey )>0) and (p_isused is null or p_isused=t1.isused) and (p_schema is null or position(p_schema in t1.schema )>0) order by t1.errorcode limit greatest(p_rows,1) offset greatest(least((p_page-1)*p_rows,(v_c/p_rows-1+abs(v_c % p_rows))*p_rows),0) ) t;
  end if;
  return gm.returnjson(0,json_build_object('total',v_c,'rows',v_return));
end;
$$;


ALTER FUNCTION sysinfo.errorcode_query(p_token character varying, p_rows integer, p_page integer, p_message character varying, p_errorcode integer, p_primekey character varying, p_isused integer, p_schema character varying) OWNER TO gm;

--
-- Name: FUNCTION errorcode_query(p_token character varying, p_rows integer, p_page integer, p_message character varying, p_errorcode integer, p_primekey character varying, p_isused integer, p_schema character varying) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION errorcode_query(p_token character varying, p_rows integer, p_page integer, p_message character varying, p_errorcode integer, p_primekey character varying, p_isused integer, p_schema character varying)
 IS '查询出错代码
message:信息
errorcode:出错代码
primekey:主键
isused:是否使用
schema:模式
返回:{"total":总记录数,"rows":[{"message":信息,"errorcode":出错代码,"primekey":主键,"isused":使用,"schema":模式}]}';


--
-- Name: login(character varying, character varying, inet, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION login(p_loginname character varying, p_pass character varying, p_ip inet, p_system character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
	declare v_c int;v_token varchar;v_pass varchar;v_return json;v_systemid int;v_keystr varchar;v_orgjson json;v_operatorid int;
	begin		
	  if p_loginname is null then 
		  return gm.returnjson(100009) ;
		end if; --账号不能为空
		if p_pass is null then 
	    return gm.returnjson(100010);
		end if; --密码不能为空
		select count(*) into v_c from sysinfo.loginlog where (accounts=p_loginname) and logintime>now()-interval '10 minute' ;
		if v_c>5 then return gm.returnjson(100002); end if;--登录错误超过5次，帐号锁定10分钟！
		select count(*) into v_c from sysinfo.loginlog where (accounts=p_loginname) and logintime>now()-interval '3 hour' ;
		if v_c>10 then return gm.returnjson(100003); end if;--登录错误超过10次，帐号锁定3小时！
		if p_system is null then 
		  v_systemid=100;
		else
		  select count(*) into v_c from sysinfo.systeminfo where loginname=p_system and isused=1;
			if v_c=1 then 
			  select systemid into v_systemid from sysinfo.systeminfo where loginname=p_system;
			else 
			  return gm.returnjson(100001); --帐号密码错误
			end if;
		end if;
		select count(*) into v_c from sysinfo.operinfo where accounts=p_loginname and pass=p_pass and isused=1;
		if v_c<>1 then 
		  insert into sysinfo.loginlog values(nextval('sysinfo.loginlog_logid_seq'),now(),(v_return->>'operatorid')::integer,p_pass,p_ip,p_loginname,v_systemid);
      return gm.returnjson(100001);--帐号密码错误
		end if;
		select operatorid into v_operatorid from sysinfo.operinfo where accounts=p_loginname and pass=p_pass and isused=1;
		select count(*) into v_c from sysinfo.sysoper where operatorid=v_operatorid and systemid=v_systemid;
		  if v_c=0 then 
		    insert into sysinfo.loginlog values(nextval('sysinfo.loginlog_logid_seq'),now(),(v_return->>'operatorid')::integer,p_pass,p_ip,p_loginname,v_systemid);
        return gm.returnjson(100001);--帐号密码错误
			end if;
		select array_to_json(array_agg(row_to_json(t))) into v_orgjson from (select t1.sysorgid,t1.sysorgname from sysinfo.sysorg t1 left join sysinfo.sysoperorg t2 on t1.sysorgid=t2.sysorgid where t2.operatorid=v_operatorid and t1.systemid=v_systemid ) t;
		select array_to_json(array_agg(row_to_json(t))) into v_return from (select t2.operatorid,t3.systemid,t2.operatorname,t2.sex,t2.phone,t2.memo,t2.mycode,t2.upcode,t2.headimgurl,t2.nickname,t2.tokeninterval,t3.systemname,t3.algorithm,t3.prikey from sysinfo.operinfo t2,sysinfo.systeminfo t3 where t2.operatorid=v_operatorid and t3.systemid=v_systemid) t; 
		v_return:=v_return->0;
		select params into v_keystr from sysinfo.actions where actionid=101;
		v_token:=case (v_return->>'algorithm')::integer
		  when 1 then gs_encrypt_aes128(json_build_object('systemid',v_return->'systemid','token',gs_encrypt(json_build_object('operatorno',v_return->'operatorid','tokentime',now()::varchar,'tokeninterval',v_return->>'tokeninterval')::text,(v_return->>'prikey')::text,'aes128'))::text,v_keystr)
			when 2 then gs_encrypt_aes128(json_build_object('systemid',v_return->'systemid','token',gs_encrypt(json_build_object('operatorno',v_return->'operatorid','systemid',v_return->'systemid','tokentime',now()::varchar,'tokeninterval',v_return->>'tokeninterval')::text,(v_return->>'prikey')::text,'sm4'))::text,v_keystr)
		end;
  update sysinfo.operinfo set tokenkey=v_token,tokentime = now()::timestamp + (interval '1 minute')*tokeninterval where operatorid = (v_return->>'operatorid')::integer;
select json_build_object('token',v_token,'operator',json_build_object('sex',v_return->>'sex','memo',v_return->>'memo','org',v_return->>'org','mycode',v_return->>'mycode','upcode',v_return->>'upcode','birthday',v_return->>'birthday','headimgurl',v_return->>'headimgurl','operatorname',v_return->>'operatorname','systemname',v_return->>'systemname','org',v_orgjson),'actions',array_to_json(array_agg(actionid))) into v_return from (
select distinct coalesce(t1.sysactionid,t1.actionid) actionid from sysinfo.sysaction t1,(
select distinct '.'||idpath||'.' actioncode from (
with recursive c as (
	select c3.sysactionid,c3.permissiontype from sysinfo.operpermission c2 left join sysinfo.rolepermission c3 on c2.sysactionid=c3.roleinfoid left join sysinfo.sysaction c4 on c2.sysactionid=c4.sysactionid where c2.permissiontype=2 and c2.operatorid=(v_return->>'operatorid')::integer and c4.systemid=(v_return->>'systemid')::integer
	union 
	select c3.sysactionid,c3.permissiontype from c left join sysinfo.rolepermission c3 on c.sysactionid=c3.roleinfoid left join sysinfo.sysaction c4 on c3.sysactionid=c4.sysactionid where c.permissiontype=2 and c4.systemid=(v_return->>'systemid')::integer
	) select sysactionid from c
  union
	select t1.sysactionid from sysinfo.operpermission t1 left join sysinfo.sysaction c4 on t1.sysactionid=c4.sysactionid where t1.operatorid=(v_return->>'operatorid')::integer and t1.permissiontype=1 and c4.systemid=(v_return->>'systemid')::integer
) t1
left join sysinfo.sysaction t2 on t1.sysactionid=t2.sysactionid where  systemid=(v_return->>'systemid')::integer) t2
where position('.'||t1.idpath||'.' in t2.actioncode)>0 
   or position(t2.actioncode in '.'||t1.idpath||'.')>0
	 order by actionid) t;
	 
		
	
	return gm.returnjson(0,v_return);

END$$;


ALTER FUNCTION sysinfo.login(p_loginname character varying, p_pass character varying, p_ip inet, p_system character varying) OWNER TO gm;

--
-- Name: FUNCTION login(p_loginname character varying, p_pass character varying, p_ip inet, p_system character varying) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION login(p_loginname character varying, p_pass character varying, p_ip inet, p_system character varying)
 IS 'sysinfo.login
loginname:登录名
pass:密码
system:系统名,为空表示顶级系统';


--
-- Name: loginaccount(character varying, character varying, character varying, integer, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION loginaccount(p_loginname character varying, p_system character varying, p_ip character varying, p_accounttype integer, p_appid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
	declare 
		v_c numeric;v_isused integer;v_operatorid integer;v_token varchar;v_pass varchar;	v_tokentime timestamp;v_return json;v_systemid int;v_orgjson json;v_keystr varchar;
	begin		
		if p_system is null then 
		  v_systemid=100;
		else
		  select count(*) into v_c from sysinfo.systeminfo where loginname=p_system and isused=1;
			if v_c=1 then 
			  select systemid into v_systemid from sysinfo.systeminfo where loginname=p_system;
			else 
			  return gm.returnjson(100001); --帐号密码错误
			end if;
		end if;
		case p_accounttype
		  when 101 then--微信小程序		
			  select count(*) into v_c from sysinfo.appparams where appid=p_appid and isused=1;
				if v_c=0 then return gm.returnjson(100001);end if; --帐号密码错误
				select 'https://api.weixin.qq.com/sns/jscode2session?grant_type=authorization_code&'||params||'&js_code='||p_loginname into v_pass from sysinfo.appparams where appid=p_appid;				
				--return json_build_object('message',v_pass);
				v_return:=gm.http_get(v_pass);
				if not v_return::jsonb?'openid' then return gm.returnjson(100001);end if; --帐号密码错误
				v_pass=v_return->>'openid';
				select count(*) into v_c from sysinfo.operaccounts where accounts=v_pass and typeid=101 and isused<>0 and isused=1;
				if v_c=0 then return gm.returnjson(100001);end if; --帐号密码错误
				select operatorid into v_operatorid from sysinfo.operaccounts where accounts=v_pass and typeid=101 and isused=1 ;
				if v_return::jsonb?'unionid' then
				  update sysinfo.operaccounts set unionid=v_return->>'unionid' where operatorid=v_operatorid and appid=p_appid and typeid=101;					        
        end if;
			else 
				return gm.returnjson(100001); --帐号密码错误
		end case; 
		select count(*) into v_c from sysinfo.sysorg t1 left join sysinfo.sysoperorg t2 on t1.sysorgid=t2.sysorgid where t2.operatorid=v_operatorid and t1.systemid=v_systemid and t1.isused=1 and t2.isused=1;
		if v_c=0 then 
		select count(*) into v_c from sysinfo.sysoper where operatorid=v_operatorid and systemid=v_systemid;
		  if v_c=0 then 
		    insert into sysinfo.loginlog values(nextval('sysinfo.loginlog_logid_seq'),now(),(v_return->>'operatorid')::integer,p_pass,p_ip,p_loginname,v_systemid);
        return gm.returnjson(100001);--帐号密码错误
			end if;
		end if;
		select array_to_json(array_agg(row_to_json(t))) into v_orgjson from (select t1.sysorgid,t1.sysorgname from sysinfo.sysorg t1 left join sysinfo.sysoperorg t2 on t1.sysorgid=t2.sysorgid where t2.operatorid=v_operatorid and t1.systemid=v_systemid and t1.isused=1 and t2.isused=1) t;
		select array_to_json(array_agg(row_to_json(t))) into v_return from (select t2.operatorid,t3.systemid,t2.operatorname,t2.sex,t2.phone,t2.memo,t2.mycode,t2.upcode,t2.headimgurl,t2.nickname,t2.tokeninterval,t3.systemname,t3.algorithm,t3.prikey from sysinfo.operinfo t2,sysinfo.systeminfo t3 where t2.operatorid=v_operatorid and t3.systemid=v_systemid) t; 
		v_return:=v_return->0;
		--select orgid,orgname,orgtype,orgtypename from sysinfo.sysorg t1 left join 
		select params into v_keystr from sysinfo.actions where actionid=101;
		v_token:=case (v_return->>'algorithm')::integer
		  when 1 then gs_encrypt_aes128(json_build_object('systemid',v_return->'systemid','token',gs_encrypt(json_build_object('operatorno',v_return->'operatorid','tokentime',now()::varchar,'tokeninterval',v_return->>'tokeninterval')::text,(v_return->>'prikey')::text,'aes128'))::text,v_keystr)
			when 2 then gs_encrypt_aes128(json_build_object('systemid',v_return->'systemid','token',gs_encrypt(json_build_object('operatorno',v_return->'operatorid','systemid',v_return->'systemid','tokentime',now()::varchar,'tokeninterval',v_return->>'tokeninterval')::text,(v_return->>'prikey')::text,'sm4'))::text,v_keystr)
--		  when 3 then encode(private.hmac(json_build_object('operatorno',v_return->'operatorid','systemid',v_return->'systemid','orgid',v_return->'orgid','tokentime',now()::varchar)::text,v_return->>'prikey','sha512'),'hex')		
--			else null
		end;

  update sysinfo.operinfo set tokentime = now()::timestamp + (interval '1 minute')*tokeninterval where operatorid = (v_return->>'operatorid')::integer;
select json_build_object('token',v_token,'operator',json_build_object('sex',v_return->>'sex','memo',v_return->>'memo','org',v_return->>'org','mycode',v_return->>'mycode','upcode',v_return->>'upcode','birthday',v_return->>'birthday','headimgurl',v_return->>'headimgurl','operatorname',v_return->>'operatorname','systemname',v_return->>'systemname','org',v_orgjson),'actions',array_to_json(array_agg(actionid))) into v_return from (
select distinct coalesce(t1.sysactionid,t1.actionid) actionid from sysinfo.sysaction t1,(
select distinct '.'||idpath||'.' actioncode from (
with recursive c as (
	select c3.sysactionid,c3.permissiontype from sysinfo.operpermission c2 left join sysinfo.rolepermission c3 on c2.sysactionid=c3.roleinfoid where c2.permissiontype=2 and c2.operatorid=(v_return->>'operatorid')::integer and c2.systemid=(v_return->>'systemid')::integer
	union 
	select c3.sysactionid,c3.permissiontype from c left join sysinfo.rolepermission c3 on c.sysactionid=c3.roleinfoid where c.permissiontype=2
	) select sysactionid from c
  union
	select t1.sysactionid from sysinfo.operpermission t1 where t1.operatorid=(v_return->>'operatorid')::integer and t1.permissiontype=1 and t1.systemid=(v_return->>'systemid')::integer
) t1
--select t2.actionid from sysinfo.operpermission t1 left join sysinfo.rolepermission t2 on t1.actionid=t2.roleinfoid and t2.systemid=(v_return->>'systemid')::integer where operatorid=(v_return->>'operatorid')::integer and t2.permissiontype=2 and t1.systemid=(v_return->>'systemid')::integer ) t1
left join sysinfo.sysaction t2 on t1.sysactionid=t2.sysactionid where  systemid=(v_return->>'systemid')::integer) t2
where position('.'||t1.idpath||'.' in t2.actioncode)>0 
   or position(t2.actioncode in '.'||t1.idpath||'.')>0
	 order by actionid) t;
	 
		
	
	return gm.returnjson(0,v_return);
END$$;


ALTER FUNCTION sysinfo.loginaccount(p_loginname character varying, p_system character varying, p_ip character varying, p_accounttype integer, p_appid integer) OWNER TO gm;

--
-- Name: operinfo_add(character varying, bigint, character varying, character varying, smallint, integer, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfo_add(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;v_pass varchar;v_mycode int;
begin
  v_check:=gm.check_login(p_token,126);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.operinfo where accounts=p_accounts and operatorid<>p_operatorid;
	if v_c>0 then return gm.returnjson(100022);end if;--账号不能重复！
	if p_tokentype<>1 then p_tokentype:=2;end if;
  if p_operatorid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval('sysinfo.operinfo_operatorid_seq');
      select count(*) into v_c from sysinfo.operinfo where operatorid=v_id;
    end loop;
  else
    select count(*) into v_c from sysinfo.operinfo where operatorid=p_operatorid;
    if v_c>0 then return gm.returnjson(100011); end if;--操作员信息出错！
    v_id:=p_operatorid;
  end if;
	v_pass:=substring(md5(random()::varchar),2,8);
	if p_tokentype!=1 then p_tokentype:=2;end if;
	delete from sysinfo.sysoper where operatorid=v_id ;
  insert into sysinfo.sysoper( operatorid,systemid) select v_id,systemid  from (select distinct systemid from json_to_recordset(p_sysoperjson::json,true) as t(systemid int4) where systemid in (select systemid from sysinfo.systeminfo where isused=1)) t;
  insert into sysinfo.operinfo( operatorid,operatorname,accounts,pass,isused,tokentype,tokeninterval,createoperator,createtime) values(v_id,p_operatorname,p_accounts,v_pass,1,p_tokentype,p_tokeninterval,(v_check->'info'->>'operatorid')::integer,now() );
  return gm.returnjson(0,json_build_object('id',v_id,'pass',v_pass));
end; 
$$;


ALTER FUNCTION sysinfo.operinfo_add(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json) OWNER TO gm;

--
-- Name: FUNCTION operinfo_add(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfo_add(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json)
 IS '新增员工
operatorid:员工编号
operatorname:员工姓名
tokentype:令牌类型1默认单人登录2多人登录
tokeninterval:令牌时长默认180分钟
sysoperjson:操作员所属系统{"systemid":系统id,}
返回：{"errorcode":0,"message":"执行成功！","info":{"id":id,"pass":密码}'';';


--
-- Name: operinfo_del(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfo_del(p_token character varying, p_operatorid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,126);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.operinfo where operatorid=p_operatorid;
  if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！
  delete from sysinfo.sysoper where operatorid=p_operatorid;
  update sysinfo.operinfo set isused=0,deloperator=(v_check->'info'->>'operatorid')::integer,deltime=now() where operatorid=p_operatorid;
  return gm.returnjson(0); 
end;
$$;


ALTER FUNCTION sysinfo.operinfo_del(p_token character varying, p_operatorid integer) OWNER TO gm;

--
-- Name: FUNCTION operinfo_del(p_token character varying, p_operatorid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfo_del(p_token character varying, p_operatorid integer)
 IS '删除员工
operatorid:id';


--
-- Name: operinfo_edit(character varying, bigint, character varying, character varying, smallint, integer, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfo_edit(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,126);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.operinfo where accounts=p_accounts and operatorid<>p_operatorid;
	if v_c>0 then return gm.returnjson(100022);end if;--账号不能重复！	
  select count(*) into v_c from sysinfo.operinfo where operatorid=p_operatorid and isused=1;
  if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！
	if p_tokentype<>1 then p_tokentype:=2;end if;
  delete from sysinfo.sysoper where operatorid=p_operatorid ;
  insert into sysinfo.sysoper( operatorid,systemid) select p_operatorid,systemid  from (select distinct systemid from json_to_recordset(p_sysoperjson::json,true) as t(systemid int4) where systemid in (select systemid from sysinfo.systeminfo where isused=1) ) t;
  update sysinfo.operinfo set operatorname=p_operatorname,accounts=p_accounts,tokentype=p_tokentype,tokeninterval=p_tokeninterval,updateoperator=(v_check->'info'->>'operatorid')::integer,updatetime=now() where operatorid=p_operatorid;
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.operinfo_edit(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json) OWNER TO gm;

--
-- Name: FUNCTION operinfo_edit(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfo_edit(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json)
 IS '修改员工
operatorid:员工编号
operatorname:员工姓名
tokentype:令牌类型1默认单人登录2多人登录
tokeninterval:令牌时长默认180分钟
sysoperjson:操作员所属系统{"systemid":系统id,}
返回：{"errorcode":0,"message":"执行成功！","info":{"id":id,"pass":密码}'';';


--
-- Name: operinfo_merge(character varying, bigint, character varying, character varying, smallint, integer, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfo_merge(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,126);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.operinfo where accounts=p_accounts and operatorid<>p_operatorid;
	if v_c>0 then return gm.returnjson(100022);end if;--账号不能重复！
	if p_tokentype<>1 then p_tokentype:=2;end if;
  if p_operatorid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval('sysinfo.operinfo_operatorid_seq');
      select count(*) into v_c from sysinfo.operinfo where operatorid=v_id;
    end loop;
  else
    v_id:=p_operatorid;
  end if;
  delete from sysinfo.sysoper where operatorid=v_id ;
  insert into sysinfo.sysoper( operatorid,systemid) select v_id,systemid  from (select distinct systemid from json_to_recordset(p_sysoperjson::json,true) as t(systemid int4) where systemid in (select systemid from sysinfo.systeminfo where isused=1) ) t;
  with "te" as (update sysinfo.operinfo set operatorname=p_operatorname,accounts=p_accounts,tokentype=p_tokentype,tokeninterval=p_tokeninterval,updateoperator=(v_check->'info'->>'operatorid')::integer,updatetime=now()  where operatorid=v_id returning *)
  insert into sysinfo.operinfo ( operatorid,operatorname,accounts,isused,tokentype,tokeninterval,createoperator,createtime) select v_id,p_operatorname,p_accounts,1,p_tokentype,p_tokeninterval,(v_check->'info'->>'operatorid')::integer,now() where (select count(*) from te) = 0;
  return gm.returnjson(0,json_build_object('id',v_id));
end; 
$$;


ALTER FUNCTION sysinfo.operinfo_merge(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json) OWNER TO gm;

--
-- Name: FUNCTION operinfo_merge(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfo_merge(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_accounts character varying, p_tokentype smallint, p_tokeninterval integer, p_sysoperjson json)
 IS '合并员工
operatorid:员工编号
operatorname:员工姓名
tokentype:令牌类型1默认单人登录2多人登录
tokeninterval:令牌时长默认180分钟
sysoperjson:操作员所属系统{"systemid":系统id,}
返回：{"errorcode":0,"message":"执行成功！","info":{"id":id,"pass":密码}'';';


--
-- Name: operinfo_query(character varying, integer, integer, bigint, character varying, smallint, character varying, character varying, character varying, integer, integer, integer, text, character varying, timestamp without time zone, timestamp without time zone, smallint, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfo_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_isused integer, p_mycode integer, p_upcode integer, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_return json;v_check json;
begin
  v_check:=gm.check_login(p_token,126);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_rows is null then
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.operatorid,t1.operatorname,t1.sex,t1.phone,t1.accounts,t1.memo,t1.isused,t1.mycode,t1.upcode,t1.headimgurl,t1.nickname,t1.birthday::varchar,t1.tokentype,t1.tokeninterval,sysoper.sysoperjson,t1.createoperator,t2.operatorname createname,t1.createtime::varchar,t1.updateoperator ,t3.operatorname updatename,t1.updatetime::varchar,t1.deloperator,t4.operatorname delname,t1.deltime::varchar from sysinfo.operinfo t1 left join (select operatorid,array_to_json(array_agg(row_to_json(t))) sysoperjson from (select  t1.operatorid,t1.systemid,ts.systemname from sysinfo.sysoper t1 left join sysinfo.systeminfo ts on t1.systemid=ts.systemid )t group by t.operatorid) sysoper on t1.operatorid=sysoper.operatorid left join sysinfo.operinfo t2 on t1.createoperator=t2.operatorid left join sysinfo.operinfo t3 on t1.updateoperator=t3.operatorid left join sysinfo.operinfo t4 on t1.deloperator=t4.operatorid where (p_operatorid is null or p_operatorid=t1.operatorid) and (p_operatorname is null or position(p_operatorname in t1.operatorname )>0) and (p_sex is null or p_sex=t1.sex) and (p_phone is null or position(p_phone in t1.phone )>0) and (p_accounts is null or position(p_accounts in t1.accounts )>0) and (p_memo is null or position(p_memo in t1.memo )>0) and (p_isused is null or p_isused=t1.isused) and (p_mycode is null or p_mycode=t1.mycode) and (p_upcode is null or p_upcode=t1.upcode) and (p_headimgurl is null or position(p_headimgurl in t1.headimgurl )>0) and (p_nickname is null or position(p_nickname in t1.nickname )>0) and (p_beginbirthday is null or t1.birthday>=p_beginbirthday) and (p_endbirthday is null or t1.birthday<=p_endbirthday) and (p_tokentype is null or p_tokentype=t1.tokentype) and (p_tokeninterval is null or p_tokeninterval=t1.tokeninterval) order by t1.operatorid) t;
    v_c:=coalesce(json_array_length(v_return),0);
  else
    select count(*) into v_c from sysinfo.operinfo t1 where  (p_operatorid is null or p_operatorid=operatorid) and (p_operatorname is null or position(p_operatorname in t1.operatorname )>0) and (p_sex is null or p_sex=t1.sex) and (p_phone is null or position(p_phone in t1.phone )>0) and (p_accounts is null or position(p_accounts in t1.accounts )>0) and (p_memo is null or position(p_memo in t1.memo )>0) and (p_isused is null or p_isused=t1.isused) and (p_mycode is null or p_mycode=t1.mycode) and (p_upcode is null or p_upcode=t1.upcode) and (p_headimgurl is null or position(p_headimgurl in t1.headimgurl )>0) and (p_nickname is null or position(p_nickname in t1.nickname )>0) and (p_beginbirthday is null or t1.birthday>=p_beginbirthday) and (p_endbirthday is null or t1.birthday<=p_endbirthday) and (p_tokentype is null or p_tokentype=t1.tokentype) and (p_tokeninterval is null or p_tokeninterval=t1.tokeninterval);
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.operatorid,t1.operatorname,t1.sex,t1.phone,t1.accounts,t1.memo,t1.isused,t1.mycode,t1.upcode,t1.headimgurl,t1.nickname,t1.birthday::varchar,t1.tokentype,t1.tokeninterval,sysoper.sysoperjson,t1.createoperator,t2.operatorname createname,t1.createtime::varchar,t1.updateoperator ,t3.operatorname updatename,t1.updatetime::varchar,t1.deloperator,t4.operatorname delname,t1.deltime::varchar from sysinfo.operinfo t1 left join (select operatorid,array_to_json(array_agg(row_to_json(t))) sysoperjson from (select  t1.operatorid,t1.systemid,ts.systemname from sysinfo.sysoper t1 left join sysinfo.systeminfo ts on t1.systemid=ts.systemid )t group by t.operatorid) sysoper on t1.operatorid=sysoper.operatorid left join sysinfo.operinfo t2 on t1.createoperator=t2.operatorid left join sysinfo.operinfo t3 on t1.updateoperator=t3.operatorid left join sysinfo.operinfo t4 on t1.deloperator=t4.operatorid where (p_operatorid is null or p_operatorid=t1.operatorid) and (p_operatorname is null or position(p_operatorname in t1.operatorname )>0) and (p_sex is null or p_sex=t1.sex) and (p_phone is null or position(p_phone in t1.phone )>0) and (p_accounts is null or position(p_accounts in t1.accounts )>0) and (p_memo is null or position(p_memo in t1.memo )>0) and (p_isused is null or p_isused=t1.isused) and (p_mycode is null or p_mycode=t1.mycode) and (p_upcode is null or p_upcode=t1.upcode) and (p_headimgurl is null or position(p_headimgurl in t1.headimgurl )>0) and (p_nickname is null or position(p_nickname in t1.nickname )>0) and (p_beginbirthday is null or t1.birthday>=p_beginbirthday) and (p_endbirthday is null or t1.birthday<=p_endbirthday) and (p_tokentype is null or p_tokentype=t1.tokentype) and (p_tokeninterval is null or p_tokeninterval=t1.tokeninterval) order by t1.operatorid limit greatest(p_rows,1) offset greatest(least((p_page-1)*p_rows,(v_c/p_rows-1+abs(v_c % p_rows))*p_rows),0) ) t;
  end if;
  return gm.returnjson(0,json_build_object('total',v_c,'rows',v_return));
end;
$$;


ALTER FUNCTION sysinfo.operinfo_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_isused integer, p_mycode integer, p_upcode integer, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer) OWNER TO gm;

--
-- Name: FUNCTION operinfo_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_isused integer, p_mycode integer, p_upcode integer, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfo_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_isused integer, p_mycode integer, p_upcode integer, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer)
 IS '查询员工
operatorid:员工编号
operatorname:员工姓名
sex:性别
phone:电话
accounts:帐号
memo:备注
isused:是否使用
mycode:推广码
upcode:推广上级id
headimgurl:头像url
nickname:昵称
beginbirthday:生日
endbirthday:生日结束
tokentype:令牌类型1默认单人登录2多人登录
tokeninterval:令牌时长默认180分钟
返回:{"total":总记录数,rows":[{"operatorid":操作员id,"operatorname":操作员姓名,"operatorname":员工姓名,"sex":性别,"phone":电话,"accounts":帐号,"pass":密码,"memo":备注,"isused":使用,"mycode":推广码,"upcode":推广上级id,"headimgurl":头像url,"nickname":昵称,"birthday":生日,"tokentype":令牌类型1默认单人登录2多人登录,"tokeninterval":令牌时长默认180分钟,"sysoper":{"systemid":系统id,"systemname":系统名称}]}

';


--
-- Name: operinfo_undel(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfo_undel(p_token character varying, p_operatorid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,127);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.operinfo where operatorid=p_operatorid;
  if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！

  update sysinfo.operinfo set isused=1,deloperator=(v_check->'info'->>'operatorid')::integer,deltime=now() where operatorid=p_operatorid;
  return gm.returnjson(0); 
end;
$$;


ALTER FUNCTION sysinfo.operinfo_undel(p_token character varying, p_operatorid integer) OWNER TO gm;

--
-- Name: FUNCTION operinfo_undel(p_token character varying, p_operatorid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfo_undel(p_token character varying, p_operatorid integer)
 IS '恢复员工
operatorid:id';


--
-- Name: operinfoorg_add(character varying, bigint, character varying, smallint, character varying, character varying, character varying, character varying, text, character varying, timestamp without time zone, smallint, integer, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfoorg_add(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;v_pass varchar;v_mycode varchar;
begin
  v_check:=gm.check_login(p_token,144);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_operatorid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval('sysinfo.operinfo_operatorid_seq');
      select count(*) into v_c from sysinfo.operinfo where operatorid=v_id;
    end loop;
  else
    select count(*) into v_c from sysinfo.operinfo where operatorid=p_operatorid;
    if v_c>0 then return gm.returnjson(100011); end if;--操作员信息出错！
    v_id:=p_operatorid;
  end if;
	v_pass:=substring(md5(random()::varchar|| clock_timestamp()),1,8);
	v_c:=1;loop exit when (v_c>0);
  	v_mycode:=substring(md5(random()::varchar|| clock_timestamp()),1,8);
	  select count(*) into v_c from sysinfo.operinfo where mycode=v_mycode;
	end loop;	
  insert into sysinfo.sysoperorg( operatorid,sysorgid) select distinct v_id,sysorgid  from json_to_recordset(p_sysoperorgjson::json,true) as t(operatorid int4,sysorgid int4) ;
	insert into sysinfo.sysoper values(v_id,(v_check->'info'->>'systemid')::integer);
  insert into sysinfo.operinfo( operatorid,operatorname,sex,phone,accounts,memo,isused,pass,mycode,upcode,headimgurl,nickname,birthday,tokentype,tokeninterval,createoperator,createtime) values(v_id,p_operatorname,p_sex,p_phone,p_accounts,p_memo,1,v_pass,v_mycode,p_upcode,p_headimgurl,p_nickname,p_birthday,p_tokentype,p_tokeninterval ,(v_check->'info'->>'operatorid')::integer,now());
  return gm.returnjson(0,json_build_object('id',v_id,'pass',v_pass));
end; 
$$;


ALTER FUNCTION sysinfo.operinfoorg_add(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json) OWNER TO gm;

--
-- Name: FUNCTION operinfoorg_add(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfoorg_add(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json)
 IS '新增员工部门
operatorid:员工编号
operatorname:员工姓名
sex:性别
phone:电话
accounts:帐号
pass:密码
tokenkey:令牌
tokentime:令牌时间
memo:备注
mycode:推广码
upcode:推广上级id
headimgurl:头像url
nickname:昵称
birthday:生日
tokentype:令牌类型1默认单人登录2多人登录
tokeninterval:令牌时长默认180分钟
sysoperorgjson:操作员部门{"sysorgid":系统部门id,
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: operinfoorg_del(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfoorg_del(p_token character varying, p_operatorid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,144);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.operinfo t1 left join sysinfo.sysoper t2 on t1.operatorid=t2.operatorid where t1.operatorid=p_operatorid and t2.systemid=(v_check->'info'->>'systemid')::integer and isused=1;
  if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！
  delete from sysinfo.sysoperorg where operatorid=p_operatorid and sysorgid in (select sysorgid from sysinfo.sysorg where systemid=(v_check->'info'->>'systemid')::integer);
  update sysinfo.operinfo set isused=0,deloperator=(v_check->'info'->>'operatorid')::integer,deltime=now() where operatorid=p_operatorid;
  return gm.returnjson(0); 
end;
$$;


ALTER FUNCTION sysinfo.operinfoorg_del(p_token character varying, p_operatorid integer) OWNER TO gm;

--
-- Name: FUNCTION operinfoorg_del(p_token character varying, p_operatorid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfoorg_del(p_token character varying, p_operatorid integer)
 IS '删除员工部门
operatorid:id';


--
-- Name: operinfoorg_edit(character varying, bigint, character varying, smallint, character varying, character varying, character varying, character varying, text, character varying, timestamp without time zone, smallint, integer, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfoorg_edit(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,144);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  v_id:=p_operatorid;
  select count(*) into v_c from sysinfo.operinfo t1 left join sysinfo.sysoper t2 on t1.operatorid=t2.operatorid where t1.operatorid=p_operatorid and t2.systemid=(v_check->'info'->>'systemid')::integer and isused=1;
  if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！
  delete from sysinfo.sysoperorg where operatorid=p_operatorid and sysorgid in (select sysorgid from sysinfo.sysorg where systemid=(v_check->'info'->>'systemid')::integer);
  insert into sysinfo.sysoperorg( operatorid,sysorgid) select distinct v_id,sysorgid  from json_to_recordset(p_sysoperorgjson::json,true) as t(operatorid int4,sysorgid int4) where sysorgid in (select sysorgid from sysinfo.sysorg where systemid=systemid=(v_check->'info'->>'systemid')::integer);
  update sysinfo.operinfo set operatorname=p_operatorname,sex=p_sex,phone=p_phone,accounts=p_accounts,memo=p_memo,upcode=p_upcode,headimgurl=p_headimgurl,nickname=p_nickname,birthday=p_birthday,tokentype=p_tokentype,tokeninterval=p_tokeninterval ,updateoperator=(v_check->'info'->>'operatorid')::integer,updatetime=now() where operatorid=p_operatorid;
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.operinfoorg_edit(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json) OWNER TO gm;

--
-- Name: FUNCTION operinfoorg_edit(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfoorg_edit(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json)
 IS '修改员工部门
operatorid:员工编号
operatorname:员工姓名
sex:性别
phone:电话
accounts:帐号
pass:密码
tokenkey:令牌
tokentime:令牌时间
memo:备注
mycode:推广码
upcode:推广上级id
headimgurl:头像url
nickname:昵称
birthday:生日
tokentype:令牌类型1默认单人登录2多人登录
tokeninterval:令牌时长默认180分钟
sysoperorgjson:操作员部门{"sysorgid":系统部门id,
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: operinfoorg_merge(character varying, bigint, character varying, smallint, character varying, character varying, character varying, character varying, text, character varying, timestamp without time zone, smallint, integer, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfoorg_merge(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;v_pass varchar;v_mycode varchar;
begin
  v_check:=gm.check_login(p_token,144);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_operatorid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval('sysinfo.operinfo_operatorid_seq');
      select count(*) into v_c from sysinfo.operinfo where operatorid=v_id;
    end loop;
  else
    select count(*) into v_c from sysinfo.operinfo t1 left join sysinfo.sysoper t2 on t1.operatorid=t2.operatorid where t1.operatorid=p_operatorid and t2.systemid=(v_check->'info'->>'systemid')::integer and isused=1;
    if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！	
    v_id:=p_operatorid;
  end if;
	v_pass:=substring(md5(random()::varchar|| clock_timestamp()),1,8);
	v_c:=1;loop exit when (v_c>0);
    v_mycode:=substring(md5(random()::varchar|| clock_timestamp()),1,8);
	  select count(*) into v_c from sysinfo.operinfo where mycode=v_mycode;
	end loop;	
  delete from sysinfo.sysoperorg where operatorid=p_operatorid and sysorgid in (select sysorgid from sysinfo.sysorg where systemid=(v_check->'info'->>'systemid')::integer);
  insert into sysinfo.sysoperorg( operatorid,sysorgid) select distinct v_id,sysorgid  from json_to_recordset(p_sysoperorgjson::json,true) as t(operatorid int4,sysorgid int4) where sysorgid in (select sysorgid from sysinfo.sysorg where systemid=systemid=(v_check->'info'->>'systemid')::integer);
  with "te" as (update sysinfo.operinfo set operatorname=p_operatorname,sex=p_sex,phone=p_phone,accounts=p_accounts,memo=p_memo,upcode=p_upcode,headimgurl=p_headimgurl,nickname=p_nickname,birthday=p_birthday,tokentype=p_tokentype,tokeninterval=p_tokeninterval ,updateoperator=(v_check->'info'->>'operatorid')::integer,updatetime=now() where operatorid=v_id returning *)
  insert into sysinfo.operinfo ( operatorid,operatorname,sex,phone,accounts,pass,memo,isused,mycode,upcode,headimgurl,nickname,birthday,tokentype,tokeninterval,createoperator,createtime) select v_id,p_operatorname,p_sex,p_phone,p_accounts,v_pass,p_memo,1,v_mycode,p_upcode,p_headimgurl,p_nickname,p_birthday,p_tokentype,p_tokeninterval ,(v_check->'info'->>'operatorid')::integer,now() where (select count(*) from te) = 0;
  return gm.returnjson(0,json_build_object('id',v_id,'pass',v_pass));
end; 
$$;


ALTER FUNCTION sysinfo.operinfoorg_merge(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json) OWNER TO gm;

--
-- Name: FUNCTION operinfoorg_merge(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfoorg_merge(p_token character varying, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_birthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer, p_sysoperorgjson json)
 IS '合并员工部门
operatorid:员工编号
operatorname:员工姓名
sex:性别
phone:电话
accounts:帐号
pass:密码
tokenkey:令牌
tokentime:令牌时间
memo:备注
mycode:推广码
upcode:推广上级id
headimgurl:头像url
nickname:昵称
birthday:生日
tokentype:令牌类型1默认单人登录2多人登录
tokeninterval:令牌时长默认180分钟
sysoperorgjson:操作员部门{"sysorgid":系统部门id,
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: operinfoorg_query(character varying, integer, integer, bigint, character varying, smallint, character varying, character varying, character varying, integer, character varying, character varying, text, character varying, timestamp without time zone, timestamp without time zone, smallint, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfoorg_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_isused integer, p_mycode character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_return json;v_check json;
begin
  v_check:=gm.check_login(p_token,144);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_rows is null then
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.operatorid,t1.operatorname,t1.sex,t1.phone,t1.accounts,t1.memo,t1.isused,t1.mycode,t1.upcode,t1.headimgurl,t1.nickname,t1.birthday::varchar,t1.tokentype,t1.tokeninterval,t1.createoperator,tcreateoperator.operatorname createoperatorname,t1.createtime::varchar,t1.updateoperator,tupdateoperator.operatorname updateoperatorname,t1.updatetime::varchar,t1.deloperator,tdeloperator.operatorname deloperatorname,t1.deltime::varchar,sysoperorg.sysoperorgjson from sysinfo.operinfo t1 left join sysinfo.operinfo tcreateoperator on t1.createoperator=tcreateoperator.operatorid left join sysinfo.operinfo tupdateoperator on t1.updateoperator=tupdateoperator.operatorid left join sysinfo.operinfo tdeloperator on t1.deloperator=tdeloperator.operatorid left join (select operatorid,array_to_json(array_agg(row_to_json(t))) sysoperorgjson from (select  t1.operatorid,t1.sysorgid,t2.sysorgname from sysinfo.sysoperorg t1 left join sysinfo.sysorg t2 on t2.sysorgid=t1.sysorgid where systemid=(v_check->'info'->>'systemid')::integer order by t1.operatorid ) t group by t.operatorid) sysoperorg on t1.operatorid=sysoperorg.operatorid left join sysinfo.sysoper ts on ts.operatorid=t1.operatorid where  (p_operatorid is null or p_operatorid=t1.operatorid) and (p_operatorname is null or position(p_operatorname in t1.operatorname )>0) and (p_sex is null or p_sex=t1.sex) and (p_phone is null or position(p_phone in t1.phone )>0) and (p_accounts is null or position(p_accounts in t1.accounts )>0) and (p_memo is null or position(p_memo in t1.memo )>0) and (p_isused is null or p_isused=t1.isused) and (p_mycode is null or position(p_mycode in t1.mycode )>0) and (p_upcode is null or position(p_upcode in t1.upcode )>0) and (p_headimgurl is null or position(p_headimgurl in t1.headimgurl )>0) and (p_nickname is null or position(p_nickname in t1.nickname )>0) and (p_beginbirthday is null or t1.birthday>=p_beginbirthday) and (p_endbirthday is null or t1.birthday<=p_endbirthday) and (p_tokentype is null or p_tokentype=t1.tokentype) and (p_tokeninterval is null or p_tokeninterval=t1.tokeninterval) and systemid=(v_check->'info'->>'systemid')::integer order by t1.operatorid) t;
    v_c:=coalesce(json_array_length(v_return),0);
  else
    select count(*) into v_c from sysinfo.operinfo t1 left join sysinfo.sysoper ts on ts.operatorid=t1.operatorid where  (p_operatorid is null or p_operatorid=t1.operatorid) and (p_operatorname is null or position(p_operatorname in t1.operatorname )>0) and (p_sex is null or p_sex=t1.sex) and (p_phone is null or position(p_phone in t1.phone )>0) and (p_accounts is null or position(p_accounts in t1.accounts )>0) and (p_memo is null or position(p_memo in t1.memo )>0) and (p_isused is null or p_isused=t1.isused) and (p_mycode is null or position(p_mycode in t1.mycode )>0) and (p_upcode is null or position(p_upcode in t1.upcode )>0) and (p_headimgurl is null or position(p_headimgurl in t1.headimgurl )>0) and (p_nickname is null or position(p_nickname in t1.nickname )>0) and (p_beginbirthday is null or t1.birthday>=p_beginbirthday) and (p_endbirthday is null or t1.birthday<=p_endbirthday) and (p_tokentype is null or p_tokentype=t1.tokentype) and (p_tokeninterval is null or p_tokeninterval=t1.tokeninterval) and ts.systemid=(v_check->'info'->>'systemid')::integer;
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.operatorid,t1.operatorname,t1.sex,t1.phone,t1.accounts,t1.memo,t1.isused,t1.mycode,t1.upcode,t1.headimgurl,t1.nickname,t1.birthday::varchar,t1.tokentype,t1.tokeninterval,t1.createoperator,tcreateoperator.operatorname createoperatorname,t1.createtime::varchar,t1.updateoperator,tupdateoperator.operatorname updateoperatorname,t1.updatetime::varchar,t1.deloperator,tdeloperator.operatorname deloperatorname,t1.deltime::varchar,sysoperorg.sysoperorgjson from sysinfo.operinfo t1 left join sysinfo.operinfo tcreateoperator on t1.createoperator=tcreateoperator.operatorid left join sysinfo.operinfo tupdateoperator on t1.updateoperator=tupdateoperator.operatorid left join sysinfo.operinfo tdeloperator on t1.deloperator=tdeloperator.operatorid left join (select operatorid,array_to_json(array_agg(row_to_json(t))) sysoperorgjson from (select  t1.operatorid,t1.sysorgid,t2.sysorgname from sysinfo.sysoperorg t1 left join sysinfo.sysorg t2 on t2.sysorgid=t1.sysorgid) t group by t.operatorid) sysoperorg on t1.operatorid=sysoperorg.operatorid left join sysinfo.sysoper ts on ts.operatorid=t1.operatorid where  (p_operatorid is null or p_operatorid=t1.operatorid) and (p_operatorname is null or position(p_operatorname in t1.operatorname )>0) and (p_sex is null or p_sex=t1.sex) and (p_phone is null or position(p_phone in t1.phone )>0) and (p_accounts is null or position(p_accounts in t1.accounts )>0) and (p_memo is null or position(p_memo in t1.memo )>0) and (p_isused is null or p_isused=t1.isused) and (p_mycode is null or position(p_mycode in t1.mycode )>0) and (p_upcode is null or position(p_upcode in t1.upcode )>0) and (p_headimgurl is null or position(p_headimgurl in t1.headimgurl )>0) and (p_nickname is null or position(p_nickname in t1.nickname )>0) and (p_beginbirthday is null or t1.birthday>=p_beginbirthday) and (p_endbirthday is null or t1.birthday<=p_endbirthday) and (p_tokentype is null or p_tokentype=t1.tokentype) and (p_tokeninterval is null or p_tokeninterval=t1.tokeninterval) and ts.systemid=(v_check->'info'->>'systemid')::integer order by t1.operatorid limit greatest(p_rows,1) offset greatest(least((p_page-1)*p_rows,(v_c/p_rows-1+abs(v_c % p_rows))*p_rows),0) ) t;
  end if;
  return gm.returnjson(0,json_build_object('total',v_c,'rows',v_return));
end;
$$;


ALTER FUNCTION sysinfo.operinfoorg_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_isused integer, p_mycode character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer) OWNER TO gm;

--
-- Name: FUNCTION operinfoorg_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_isused integer, p_mycode character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfoorg_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_isused integer, p_mycode character varying, p_upcode character varying, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer)
 IS '查询员工部门
operatorid:员工编号
operatorname:员工姓名
sex:性别
phone:电话
accounts:帐号
pass:密码
tokenkey:令牌
begintokentime:令牌时间
endtokentime:令牌时间结束
memo:备注
isused:是否使用
mycode:推广码
upcode:推广上级id
headimgurl:头像url
nickname:昵称
beginbirthday:生日
endbirthday:生日结束
tokentype:令牌类型1默认单人登录2多人登录
tokeninterval:令牌时长默认180分钟
返回:{"total":总记录数,"rows":[{"operatorid":操作员id,"operatorname":操作员姓名,"operatorname":员工姓名,"sex":性别,"phone":电话,"accounts":帐号,"pass":密码,"tokenkey":令牌,"tokentime":令牌时间,"memo":备注,"isused":使用,"mycode":推广码,"upcode":推广上级id,"headimgurl":头像url,"nickname":昵称,"birthday":生日,"tokentype":令牌类型1默认单人登录2多人登录,"tokeninterval":令牌时长默认180分钟,"createoperator":操作员编号,"createoperatorname":创建人员,"updateoperator":操作员编号,"updateoperatorname":修改人员,"deloperator":操作员编号,"deloperatorname":删除人员}]}';


--
-- Name: operinfoorg_undel(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfoorg_undel(p_token character varying, p_operatorid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,145);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.operinfo t1 left join sysinfo.sysoper t2 on t1.operatorid=t2.operatorid where t1.operatorid=p_operatorid and t2.systemid=(v_check->'info'->>'systemid')::integer and isused=0;
  if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！

  update sysinfo.operinfo set isused=1,deloperator=(v_check->'info'->>'operatorid')::integer,deltime=now() where operatorid=p_operatorid;
  return gm.returnjson(0); 
end;
$$;


ALTER FUNCTION sysinfo.operinfoorg_undel(p_token character varying, p_operatorid integer) OWNER TO gm;

--
-- Name: FUNCTION operinfoorg_undel(p_token character varying, p_operatorid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfoorg_undel(p_token character varying, p_operatorid integer)
 IS '恢复员工部门
operatorid:id';


--
-- Name: operinfopermission_add(character varying, bigint, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfopermission_add(p_token character varying, p_operatorid bigint, p_operpermissionjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,138);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.operinfo t1 left join sysinfo.sysoper t2 on t1.operatorid=t2.operatorid where t1.operatorid=p_operatorid and isused=1 and systemid=(v_check->'info'->>'systemid')::integer;
  if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！
  insert into sysinfo.operpermission( operatorid,permissionid,permissiontype,ifpermission,permissionorder,params,sysactionid) select distinct p_operatorid,nextval('sysinfo.operpermission_permissionid_seq'),permissiontype,ifpermission,permissionorder,params,sysactionid  from json_to_recordset(p_operpermissionjson::json,true) as t(permissionid int4,permissiontype int2,ifpermission int2,permissionorder int4,params varchar,sysactionid int4)  where  (permissiontype=1 and sysactionid in (select sysactionid from sysinfo.sysaction where systemid=(v_check->'info'->>'systemid')::integer)) and (permissiontype=2 and sysactionid in (select roleinfoid from sysinfo.roleinfo where systemid=(v_check->'info'->>'systemid')::integer));
  return gm.returnjson(0,json_build_object('id',p_operatorid));
end; 
$$;


ALTER FUNCTION sysinfo.operinfopermission_add(p_token character varying, p_operatorid bigint, p_operpermissionjson json) OWNER TO gm;

--
-- Name: operinfopermission_del(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfopermission_del(p_token character varying, p_operatorid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,141);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.operinfo t1 left join sysinfo.sysoper t2 on t1.operatorid=t2.operatorid where t1.operatorid=p_operatorid and t1.isused=1 and t2.systemid=(v_check->'info'->>'systemid')::integer;
  if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！
  delete from sysinfo.operpermission where operatorid=p_operatorid and ((permissiontype=1 and sysactionid in (select sysactionid from sysinfo.sysaction where systemid=(v_check->'info'->>'systemid')::integer)) or (permissiontype=2 and sysactionid in (select roleinfoid from sysinfo.roleinfo where systemid=(v_check->'info'->>'systemid')::integer) ));
	update sysinfo.operinfo set isused=0 where operatorid=p_operatorid;
  return gm.returnjson(0); 
end;
$$;


ALTER FUNCTION sysinfo.operinfopermission_del(p_token character varying, p_operatorid integer) OWNER TO gm;

--
-- Name: FUNCTION operinfopermission_del(p_token character varying, p_operatorid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfopermission_del(p_token character varying, p_operatorid integer)
 IS '删除员工权限
operatorid:id';


--
-- Name: operinfopermission_edit(character varying, bigint, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfopermission_edit(p_token character varying, p_operatorid bigint, p_operpermissionjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,139);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.operinfo t1 left join sysinfo.sysoper t2 on t1.operatorid=t2.operatorid where t1.operatorid=p_operatorid and t1.isused=1 and t2.systemid=(v_check->'info'->>'systemid')::integer;
  if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！
  delete from sysinfo.operpermission where operatorid=p_operatorid and ((permissiontype=1 and sysactionid in (select sysactionid from sysinfo.sysaction where systemid=(v_check->'info'->>'systemid')::integer)) or (permissiontype=2 and sysactionid in (select roleinfoid from sysinfo.roleinfo where systemid=(v_check->'info'->>'systemid')::integer) ));
  insert into sysinfo.operpermission( operatorid,permissionid,permissiontype,ifpermission,permissionorder,params,sysactionid) select distinct p_operatorid,nextval('sysinfo.operpermission_permissionid_seq'),permissiontype,ifpermission,permissionorder,params,sysactionid  from json_to_recordset(p_operpermissionjson::json,true) as t(permissionid int4,permissiontype int2,ifpermission int2,permissionorder int4,params varchar,sysactionid int4)  where  (permissiontype=1 and sysactionid in (select sysactionid from sysinfo.sysaction where systemid=(v_check->'info'->>'systemid')::integer))  or (permissiontype=2 and sysactionid in (select roleinfoid from sysinfo.roleinfo where systemid=(v_check->'info'->>'systemid')::integer) );
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.operinfopermission_edit(p_token character varying, p_operatorid bigint, p_operpermissionjson json) OWNER TO gm;

--
-- Name: FUNCTION operinfopermission_edit(p_token character varying, p_operatorid bigint, p_operpermissionjson json) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfopermission_edit(p_token character varying, p_operatorid bigint, p_operpermissionjson json)
 IS '修改员工权限
operatorid:员工编号
operpermissionjson:员工权限{"permissiontype":权限类型1权限2角色,"ifpermission":允许,"permissionorder":权限级别,"params":参数,"sysactionid":权限编号,"permissionid":操作员权限编号,"systemid":系统id,}
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: operinfopermission_merge(character varying, bigint, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfopermission_merge(p_token character varying, p_operatorid bigint, p_operpermissionjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,140);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.operinfo t1 left join sysinfo.sysoper t2 on t1.operatorid=t2.operatorid where t1.operatorid=p_operatorid and t1.isused=1 and t2.systemid=(v_check->'info'->>'systemid')::integer;
  if v_c=0 then return gm.returnjson(100011); end if;--操作员信息出错！
  delete from sysinfo.operpermission where operatorid=p_operatorid and ((permissiontype=1 and sysactionid in (select sysactionid from sysinfo.sysaction where systemid=(v_check->'info'->>'systemid')::integer)) or (permissiontype=2 and sysactionid in (select roleinfoid from sysinfo.roleinfo where systemid=(v_check->'info'->>'systemid')::integer) ));
  insert into sysinfo.operpermission( operatorid,permissionid,permissiontype,ifpermission,permissionorder,params,sysactionid) select distinct p_operatorid,nextval('sysinfo.operpermission_permissionid_seq'),permissiontype,ifpermission,permissionorder,params,sysactionid  from json_to_recordset(p_operpermissionjson::json,true) as t(permissionid int4,permissiontype int2,ifpermission int2,permissionorder int4,params varchar,sysactionid int4)  where  (permissiontype=1 and sysactionid in (select sysactionid from sysinfo.sysaction where systemid=(v_check->'info'->>'systemid')::integer))  or (permissiontype=2 and sysactionid in (select roleinfoid from sysinfo.roleinfo where systemid=(v_check->'info'->>'systemid')::integer) );
  return gm.returnjson(0,json_build_object('id',p_operatorid));
end; 
$$;


ALTER FUNCTION sysinfo.operinfopermission_merge(p_token character varying, p_operatorid bigint, p_operpermissionjson json) OWNER TO gm;

--
-- Name: FUNCTION operinfopermission_merge(p_token character varying, p_operatorid bigint, p_operpermissionjson json) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfopermission_merge(p_token character varying, p_operatorid bigint, p_operpermissionjson json)
 IS '合并员工权限
operatorid:员工编号
operpermissionjson:员工权限{"permissiontype":权限类型1权限2角色,"ifpermission":允许,"permissionorder":权限级别,"params":参数,"sysactionid":权限编号,"permissionid":操作员权限编号,"systemid":系统id,}
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: operinfopermission_query(character varying, integer, integer, bigint, character varying, smallint, character varying, character varying, character varying, character varying, timestamp without time zone, timestamp without time zone, character varying, integer, integer, integer, text, character varying, timestamp without time zone, timestamp without time zone, smallint, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION operinfopermission_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_pass character varying, p_tokenkey character varying, p_begintokentime timestamp without time zone, p_endtokentime timestamp without time zone, p_memo character varying, p_isused integer, p_mycode integer, p_upcode integer, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_return json;v_check json;
begin
  v_check:=gm.check_login(p_token,143);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_rows is null then
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.operatorid,t1.operatorname,t1.isused,operpermission.operpermissionjson from sysinfo.operinfo t1 left join (select operatorid,array_to_json(array_agg(row_to_json(t))) operpermissionjson from (select  t1.operatorid,t1.permissiontype,t1.ifpermission,t1.permissionorder,t1.params,t1.sysactionid,t1.permissionid from sysinfo.operpermission t1)   t group by t.operatorid) operpermission on t1.operatorid=operpermission.operatorid where  t1.operatorid in (select operatorid from sysinfo.sysoper where systemid=(v_check->'info'->>'systemid')::integer) and (p_operatorid is null or p_operatorid=t1.operatorid)  order by t1.operatorid) t;
    v_c:=coalesce(json_array_length(v_return),0);
  else
    select count(*) into v_c from sysinfo.operinfo t1 where t1.operatorid in (select operatorid from sysinfo.sysoper where systemid=(v_check->'info'->>'systemid')::integer) and (p_operatorid is null or p_operatorid=operatorid) ;
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.operatorid,t1.operatorname,t1.isused,operpermission.operpermissionjson from sysinfo.operinfo t1 left join (select operatorid,array_to_json(array_agg(row_to_json(t))) operpermissionjson from (select  t1.operatorid,toper.operatorname,t1.permissiontype,t1.ifpermission,t1.permissionorder,t1.params,t1.sysactionid,t1.permissionid from sysinfo.operpermission t1 ) t group by t.operatorid) operpermission on t1.operatorid=operpermission.operatorid where t1.operatorid in (select operatorid from sysinfo.sysoper where systemid=(v_check->'info'->>'systemid')::integer) and (p_operatorid is null or p_operatorid=t1.operatorid)  order by t1.operatorid limit greatest(p_rows,1) offset greatest(least((p_page-1)*p_rows,(v_c/p_rows-1+abs(v_c % p_rows))*p_rows),0) ) t;
  end if;
  return gm.returnjson(0,json_build_object('total',v_c,'rows',v_return));
end;
$$;


ALTER FUNCTION sysinfo.operinfopermission_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_pass character varying, p_tokenkey character varying, p_begintokentime timestamp without time zone, p_endtokentime timestamp without time zone, p_memo character varying, p_isused integer, p_mycode integer, p_upcode integer, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer) OWNER TO gm;

--
-- Name: FUNCTION operinfopermission_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_pass character varying, p_tokenkey character varying, p_begintokentime timestamp without time zone, p_endtokentime timestamp without time zone, p_memo character varying, p_isused integer, p_mycode integer, p_upcode integer, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION operinfopermission_query(p_token character varying, p_rows integer, p_page integer, p_operatorid bigint, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_pass character varying, p_tokenkey character varying, p_begintokentime timestamp without time zone, p_endtokentime timestamp without time zone, p_memo character varying, p_isused integer, p_mycode integer, p_upcode integer, p_headimgurl text, p_nickname character varying, p_beginbirthday timestamp without time zone, p_endbirthday timestamp without time zone, p_tokentype smallint, p_tokeninterval integer)
 IS '查询员工
operatorid:员工编号
operatorname:员工姓名
sex:性别
phone:电话
accounts:帐号
pass:密码
tokenkey:令牌
begintokentime:令牌时间
endtokentime:令牌时间结束
memo:备注
isused:是否使用
mycode:推广码
upcode:推广上级id
headimgurl:头像url
nickname:昵称
beginbirthday:生日
endbirthday:生日结束
tokentype:令牌类型1默认单人登录2多人登录
tokeninterval:令牌时长默认180分钟
返回:{"operatorid":操作员id,"operatorname":操作员姓名,"operatorname":员工姓名,"sex":性别,"phone":电话,"accounts":帐号,"pass":密码,"tokenkey":令牌,"tokentime":令牌时间,"memo":备注,"isused":使用,"mycode":推广码,"upcode":推广上级id,"headimgurl":头像url,"nickname":昵称,"birthday":生日,"tokentype":令牌类型1默认单人登录2多人登录,"tokeninterval":令牌时长默认180分钟}';


--
-- Name: orgtype_add(character varying, integer, character varying, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION orgtype_add(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,120);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_orgtypeid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval('sysinfo.orgtype_orgtypeid_seq');
      select count(*) into v_c from sysinfo.orgtype where orgtypeid=v_id;
    end loop;
  else
    select count(*) into v_c from sysinfo.orgtype where orgtypeid=p_orgtypeid;
    if v_c>0 then return gm.returnjson(100020); end if;--部门类型信息出错！
    v_id:=p_orgtypeid;
  end if;
  insert into sysinfo.orgtype( isused,orgtypeid,orgtypename,description,systemid) values(1,v_id,p_orgtypename,p_description,(v_check->'info'->>'systemid')::integer );
  return gm.returnjson(0,json_build_object('id',v_id));
end; 
$$;


ALTER FUNCTION sysinfo.orgtype_add(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) OWNER TO gm;

--
-- Name: FUNCTION orgtype_add(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION orgtype_add(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying)
 IS '新增部门类型
orgtypeid:部门类型编号
orgtypename:部门类型名
description:说明
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: orgtype_del(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION orgtype_del(p_token character varying, p_orgtypeid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,120);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.orgtype where orgtypeid=p_orgtypeid and systemid=(v_check->'info'->>'systemid')::integer and isused=1;
  if v_c=0 then return gm.returnjson(100020); end if;--部门类型信息出错！
  update sysinfo.orgtype set isused=0 where orgtypeid=p_orgtypeid;
  return gm.returnjson(0); 
end;
$$;


ALTER FUNCTION sysinfo.orgtype_del(p_token character varying, p_orgtypeid integer) OWNER TO gm;

--
-- Name: FUNCTION orgtype_del(p_token character varying, p_orgtypeid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION orgtype_del(p_token character varying, p_orgtypeid integer)
 IS '删除部门类型
orgtypeid:id';


--
-- Name: orgtype_edit(character varying, integer, character varying, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION orgtype_edit(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,120);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  v_id:=p_orgtypeid;
  select count(*) into v_c from sysinfo.orgtype where orgtypeid=p_orgtypeid and systemid=(v_check->'info'->>'systemid')::integer and isused=1;
  if v_c=0 then return gm.returnjson(100020); end if;--部门类型信息出错！
  update sysinfo.orgtype set orgtypename=p_orgtypename,description=p_description,systemid=(v_check->'info'->>'systemid')::integer where orgtypeid=p_orgtypeid;
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.orgtype_edit(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) OWNER TO gm;

--
-- Name: FUNCTION orgtype_edit(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION orgtype_edit(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying)
 IS '修改部门类型
orgtypeid:部门类型编号
orgtypename:部门类型名
description:说明
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: orgtype_merge(character varying, integer, character varying, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION orgtype_merge(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,120);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_orgtypeid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval('sysinfo.orgtype_orgtypeid_seq');
      select count(*) into v_c from sysinfo.orgtype where orgtypeid=v_id;
    end loop;
  else
    v_id:=p_orgtypeid;
  end if;
  with "te" as (update sysinfo.orgtype set orgtypename=p_orgtypename,description=p_description,systemid=(v_check->'info'->>'systemid')::integer  where orgtypeid=v_id returning *)
  insert into sysinfo.orgtype ( isused,orgtypeid,orgtypename,description,systemid) select 1,v_id,p_orgtypename,p_description,(v_check->'info'->>'systemid')::integer  where (select count(*) from te) = 0;
  return gm.returnjson(0,json_build_object('id',v_id));
end; 
$$;


ALTER FUNCTION sysinfo.orgtype_merge(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) OWNER TO gm;

--
-- Name: FUNCTION orgtype_merge(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION orgtype_merge(p_token character varying, p_orgtypeid integer, p_orgtypename character varying, p_description character varying)
 IS '合并部门类型
orgtypeid:部门类型编号
orgtypename:部门类型名
description:说明
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: orgtype_query(character varying, integer, integer, integer, integer, character varying, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION orgtype_query(p_token character varying, p_rows integer, p_page integer, p_isused integer, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_return json;v_check json;
begin
  v_check:=gm.check_login(p_token,120);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_rows is null then
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.isused,t1.orgtypeid,t1.orgtypename,t1.description from sysinfo.orgtype t1 where  (p_isused is null or p_isused=t1.isused) and (p_orgtypeid is null or p_orgtypeid=t1.orgtypeid) and (p_orgtypename is null or position(p_orgtypename in t1.orgtypename )>0) and (p_description is null or position(p_description in t1.description )>0) and t1.systemid=(v_check->'info'->>'systemid')::integer order by t1.orgtypeid) t;
    v_c:=coalesce(json_array_length(v_return),0);
  else
    select count(*) into v_c from sysinfo.orgtype t1 where  (p_isused is null or p_isused=t1.isused) and (p_orgtypeid is null or p_orgtypeid=t1.orgtypeid) and (p_orgtypename is null or position(p_orgtypename in t1.orgtypename )>0) and (p_description is null or position(p_description in t1.description )>0) and t1.systemid=(v_check->'info'->>'systemid')::integer;
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.isused,t1.orgtypeid,t1.orgtypename,t1.description from sysinfo.orgtype t1 where  (p_isused is null or p_isused=t1.isused) and (p_orgtypeid is null or p_orgtypeid=t1.orgtypeid) and (p_orgtypename is null or position(p_orgtypename in t1.orgtypename )>0) and (p_description is null or position(p_description in t1.description )>0) and t1.systemid=(v_check->'info'->>'systemid')::integer order by t1.orgtypeid limit greatest(p_rows,1) offset greatest(least((p_page-1)*p_rows,(v_c/p_rows-1+abs(v_c % p_rows))*p_rows),0) ) t;
  end if;
  return gm.returnjson(0,json_build_object('total',v_c,'rows',v_return));
end;
$$;


ALTER FUNCTION sysinfo.orgtype_query(p_token character varying, p_rows integer, p_page integer, p_isused integer, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) OWNER TO gm;

--
-- Name: FUNCTION orgtype_query(p_token character varying, p_rows integer, p_page integer, p_isused integer, p_orgtypeid integer, p_orgtypename character varying, p_description character varying) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION orgtype_query(p_token character varying, p_rows integer, p_page integer, p_isused integer, p_orgtypeid integer, p_orgtypename character varying, p_description character varying)
 IS '查询部门类型
isused:是否使用
orgtypeid:部门类型编号
orgtypename:部门类型名
description:说明
返回:{"total":总记录数,"rows":[{"isused":显示,"orgtypeid":部门类型编号,"orgtypename":部门类型名,"description":说明}]}';


--
-- Name: orgtype_undel(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION orgtype_undel(p_token character varying, p_orgtypeid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,121);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.orgtype where orgtypeid=p_orgtypeid and systemid=(v_check->'info'->>'systemid')::integer and isused=0;
  if v_c=0 then return gm.returnjson(100020); end if;--部门类型信息出错！
  update sysinfo.orgtype set isused=1 where orgtypeid=p_orgtypeid;
  return gm.returnjson(0); 
end;
$$;


ALTER FUNCTION sysinfo.orgtype_undel(p_token character varying, p_orgtypeid integer) OWNER TO gm;

--
-- Name: FUNCTION orgtype_undel(p_token character varying, p_orgtypeid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION orgtype_undel(p_token character varying, p_orgtypeid integer)
 IS '恢复部门类型
orgtypeid:id';


--
-- Name: regaccount(character varying, character varying, smallint, character varying, character varying, character varying, integer, character varying, character varying, character varying, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION regaccount(p_code character varying, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_appid integer, p_nickname character varying, p_headimgurl character varying, p_system character varying, p_upcode character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c numeric;v_systemid int4;v_orgid int4;	v_id numeric;v_actionid varchar;v_pass varchar;v_return jsonb;v_mycode int;v_bool bool;v_unionid varchar;
BEGIN
	if p_system is null then 
	  v_systemid=100;
	else
	  select count(*) into v_c from sysinfo.systeminfo where loginname=p_system and isused=1;
		if v_c=1 then 
		  select systemid into v_systemid from sysinfo.systeminfo where loginname=p_system;
		else 
		  return gm.returnjson(100001); --帐号密码错误
		end if;
	end if;
  select isused into v_c from sysinfo.sysaction where actionid=171 and systemid=v_systemid;
	if v_c=0 then return gm.returnjson(100026);end if; --不能注册！
	if p_phone is null then 	  
		select count(*) into v_c from sysinfo.appparams where appid=p_appid and isused=1;
		if v_c=0 then return gm.returnjson(100026);end if; --不能注册！
		select accesstoken,tokentime+interval '2H'>now() into v_pass,v_bool from sysinfo.appparams where appid=p_appid and isused=1 and typeid=101;
		
		if v_pass is null then return gm.returnjson(100027);end if ;--注册码不正确！
		v_return:=gm.http_post('https://api.weixin.qq.com/wxa/business/getuserphonenumber?access_token='||v_pass||'&'::varchar,'{"code":"'||p_code||'"}','application/x-www-form-urlencoded');
		p_phone:=(v_return->>'phone_info')::json->>'purePhoneNumber';
	else		
  	select systemid into v_systemid from sms.sendcode where mobile=p_phone and code=p_code and expiretime>now() and actionid=136;
    if v_systemid is null then return gm.returnjson(100027);end if ;--注册码不正确！
	end if;
  select 'https://api.weixin.qq.com/sns/jscode2session?grant_type=authorization_code&'||params||'&js_code='||p_accounts into v_pass from sysinfo.appparams where appid=p_appid;
	v_return:=gm.http_get(v_pass);
	if not v_return?'openid' then 
	  return gm.returnjson(100028,v_return::jsonb);--手机码不正确！
	end if;
	v_pass=v_return->>'openid';
	if v_return?'unionid' then 
	  v_unionid:=v_return->>'unionid';
	else
	  v_unionid:=null;
	end if;
	select count(*) into v_c from sysinfo.operaccounts where accounts=v_pass and typeid=101;
	if v_c>0 then return gm.returnjson(100029);end if;--微信号已注册！
  select array_to_json(array_agg(row_to_json(t))) into v_return from (select isused,operatorid from sysinfo.operinfo where phone=p_phone) t;
  if jsonb_array_length(v_return)>0 then
	    v_return:=v_return->0;
			v_id:=(v_return->>'operatorid')::integer;
      if v_return->>'isused'='0' then 
		    update sysinfo.operinfo set isused=1 where operatorid=v_id;
		  end if;
      insert into "sysinfo"."operaccounts" ("operatorid", "accounts", "appid", "typeid", "isused", "unionid") VALUES (v_id, v_pass, p_appid, 101, 1,v_unionid);
			insert into sysinfo.sysoper(operatorid,systemid) select v_id,v_systemid from sysinfo.sysoper where not(operatorid=v_id and systemid=v_systemid);
		  return gm.returnjson(0,json_build_object('id',v_id));
	end if;
	p_accounts:=p_phone;	
	v_c:=1;loop exit when (v_c=0);
	  v_mycode=trunc(random()*90000000+10000000);
	  select count(*) into v_c from sysinfo.operinfo where mycode=v_mycode;
	end loop;
  v_c:=1;loop exit when (v_c=0);
    v_id :=nextval('sysinfo.operinfo_operatorid_seq');
    select count(*) into v_c from sysinfo.operinfo where operatorid=v_id;
  end loop;
  insert into "sysinfo"."operaccounts" ("operatorid", "accounts", "appid", "typeid", "isused", "unionid") VALUES (v_id, v_pass, p_appid, 101, 1,v_unionid);
  insert into sysinfo.operinfo( operatorid,operatorname,sex,phone,accounts,pass,memo,isused,mycode,upcode,nickname,headimgurl) values(v_id,p_operatorname,p_sex,p_phone,coalesce(p_accounts,p_phone),null,p_memo,1,v_mycode,p_upcode,p_nickname,p_headimgurl);
  insert into sysinfo.sysoper(operatorid,systemid) select v_id,v_systemid from sysinfo.sysoper where not(operatorid=v_id and systemid=v_systemid);
  return gm.returnjson(0,json_build_object('id',v_id));
	
END
$$;


ALTER FUNCTION sysinfo.regaccount(p_code character varying, p_operatorname character varying, p_sex smallint, p_phone character varying, p_accounts character varying, p_memo character varying, p_appid integer, p_nickname character varying, p_headimgurl character varying, p_system character varying, p_upcode character varying) OWNER TO gm;

--
-- Name: roleinfo_add(character varying, integer, character varying, character varying, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION roleinfo_add(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,132);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_roleinfoid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval('sysinfo.roleinfo_roleinfoid_seq');
      select count(*) into v_c from sysinfo.roleinfo where roleinfoid=v_id;
    end loop;
  else
    select count(*) into v_c from sysinfo.roleinfo where roleinfoid=p_roleinfoid;
    if v_c>0 then return gm.returnjson(100023); end if;--角色信息出错！
    v_id:=p_roleinfoid;
  end if;
  insert into sysinfo.rolepermission( roleinfoid,permissionid,permissiontype,ifpermission,permissionorder,params,sysactionid) select distinct v_id,nextval('sysinfo.rolepermission_permissionid_seq'),permissiontype,ifpermission,permissionorder,params,sysactionid  from json_to_recordset(p_rolepermissionjson::json,true) as t(permissionid int4,permissiontype int2,ifpermission int2,permissionorder int4,params varchar,sysactionid int4)  where  (permissiontype=1 and sysactionid in (select sysactionid from sysinfo.sysaction where systemid=(v_check->'info'->>'systemid')::integer)) or (permissiontype=2 and sysactionid in (select roleinfoid from sysinfo.roleinfo where systemid=(v_check->'info'->>'systemid')::integer));
  insert into sysinfo.roleinfo( roleinfoid,roleinfoname,description,isused,systemid) values(v_id,p_roleinfoname,p_description,1,(v_check->'info'->>'systemid')::integer );
  return gm.returnjson(0,json_build_object('id',v_id));
end; 
$$;


ALTER FUNCTION sysinfo.roleinfo_add(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json) OWNER TO gm;

--
-- Name: FUNCTION roleinfo_add(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION roleinfo_add(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json)
 IS '新增角色
roleinfoid:角色编号
roleinfoname:角色名
description:描述
rolepermissionjson:角色权限{"permissionid":角色权限编号,"permissiontype":权限类型,"ifpermission":允许,"permissionorder":权限级别,"params":参数,"sysactionid":权限编号,
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: roleinfo_del(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION roleinfo_del(p_token character varying, p_roleinfoid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,132);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.roleinfo where roleinfoid=p_roleinfoid and systemid=(v_check->'info'->>'systemid')::integer and isused=1;
  if v_c=0 then return gm.returnjson(100023); end if;--角色信息出错！
  delete from sysinfo.rolepermission where roleinfoid=p_roleinfoid;
  update sysinfo.roleinfo set isused=0 where roleinfoid=p_roleinfoid;
  return gm.returnjson(0); 
end;
$$;


ALTER FUNCTION sysinfo.roleinfo_del(p_token character varying, p_roleinfoid integer) OWNER TO gm;

--
-- Name: FUNCTION roleinfo_del(p_token character varying, p_roleinfoid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION roleinfo_del(p_token character varying, p_roleinfoid integer)
 IS '删除角色
roleinfoid:id';


--
-- Name: roleinfo_edit(character varying, integer, character varying, character varying, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION roleinfo_edit(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,132);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  v_id:=p_roleinfoid;
  select count(*) into v_c from sysinfo.roleinfo where roleinfoid=p_roleinfoid and systemid=(v_check->'info'->>'systemid')::integer and isused=1;
  if v_c=0 then return gm.returnjson(100023); end if;--角色信息出错！
	with recursive tree as 
(select sysactionid from json_to_recordset(p_rolepermissionjson,true) as t(permissionid int4,permissiontype int2,ifpermission int2,permissionorder int4,params varchar,sysactionid int4) where  permissiontype=2
union 
 select t.sysactionid from sysinfo.rolepermission t inner join tree on t.roleinfoid=tree.sysactionid where permissiontype=2 
)	select count(*) into v_c from tree where sysactionid=p_roleinfoid;
  if v_c>0 then return gm.returnjson(100017);end if;--不能循环定义！
  delete from sysinfo.rolepermission t1 where roleinfoid=p_roleinfoid and ((t1.permissiontype=1 and t1.sysactionid in (select sysactionid from sysinfo.sysaction where systemid=(v_check->'info'->>'systemid')::integer)) or (t1.permissiontype=2 and t1.sysactionid in (select roleinfoid from sysinfo.roleinfo where systemid=(v_check->'info'->>'systemid')::integer)));
  insert into sysinfo.rolepermission( roleinfoid,permissionid,permissiontype,ifpermission,permissionorder,params,sysactionid) select v_id,nextval('sysinfo.rolepermission_permissionid_seq'),permissiontype,ifpermission,permissionorder,params,sysactionid  from json_to_recordset(p_rolepermissionjson::json,true) as t(permissionid int4,permissiontype int2,ifpermission int2,permissionorder int4,params varchar,sysactionid int4) where (permissiontype=1 and sysactionid in (select sysactionid from sysinfo.sysaction where systemid=(v_check->'info'->>'systemid')::integer)) or (permissiontype=2 and sysactionid in (select roleinfoid from sysinfo.roleinfo where systemid=(v_check->'info'->>'systemid')::integer));
  update sysinfo.roleinfo set roleinfoname=p_roleinfoname,description=p_description,systemid=(v_check->'info'->>'systemid')::integer where roleinfoid=p_roleinfoid;
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.roleinfo_edit(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json) OWNER TO gm;

--
-- Name: FUNCTION roleinfo_edit(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION roleinfo_edit(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json)
 IS '修改角色
roleinfoid:角色编号
roleinfoname:角色名
description:描述
rolepermissionjson:角色权限{"permissionid":角色权限编号,"permissiontype":权限类型,"ifpermission":允许,"permissionorder":权限级别,"params":参数,"sysactionid":权限编号,
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: roleinfo_merge(character varying, integer, character varying, character varying, json); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION roleinfo_merge(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,132);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_roleinfoid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval('sysinfo.roleinfo_roleinfoid_seq');
      select count(*) into v_c from sysinfo.roleinfo where roleinfoid=v_id;
    end loop;
  else
    v_id:=p_roleinfoid;
  end if;
	with recursive tree as 
(select sysactionid from json_to_recordset(p_rolepermissionjson,true) as t(permissionid int4,permissiontype int2,ifpermission int2,permissionorder int4,params varchar,sysactionid int4) where  permissiontype=2
union 
 select t.sysactionid from sysinfo.rolepermission t inner join tree on t.roleinfoid=tree.sysactionid where permissiontype=2 
)	select count(*) into v_c from tree where sysactionid=v_id;
  if v_c>0 then return gm.returnjson(100017);end if;--不能循环定义！
  delete from sysinfo.rolepermission t1 where roleinfoid=p_roleinfoid and ((t1.permissiontype=1 and t1.sysactionid in (select sysactionid from sysinfo.sysaction where systemid=(v_check->'info'->>'systemid')::integer)) or (t1.permissiontype=2 and t1.sysactionid in (select roleinfoid from sysinfo.roleinfo where systemid=(v_check->'info'->>'systemid')::integer)));
  insert into sysinfo.rolepermission( roleinfoid,permissionid,permissiontype,ifpermission,permissionorder,params,sysactionid) select v_id,nextval('sysinfo.rolepermission_permissionid_seq'),permissiontype,ifpermission,permissionorder,params,sysactionid  from json_to_recordset(p_rolepermissionjson::json,true) as t(permissionid int4,permissiontype int2,ifpermission int2,permissionorder int4,params varchar,sysactionid int4) where (permissiontype=1 and sysactionid in (select sysactionid from sysinfo.sysaction where systemid=(v_check->'info'->>'systemid')::integer)) or (permissiontype=2 and sysactionid in (select roleinfoid from sysinfo.roleinfo where systemid=(v_check->'info'->>'systemid')::integer));
	with "te" as (update sysinfo.roleinfo set roleinfoname=p_roleinfoname,description=p_description,systemid=(v_check->'info'->>'systemid')::integer  where roleinfoid=v_id returning *)
  insert into sysinfo.roleinfo ( roleinfoid,roleinfoname,description,isused,systemid) select v_id,p_roleinfoname,p_description,1,(v_check->'info'->>'systemid')::integer  where (select count(*) from te) = 0;
  return gm.returnjson(0,json_build_object('id',v_id));
end; 
$$;


ALTER FUNCTION sysinfo.roleinfo_merge(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json) OWNER TO gm;

--
-- Name: FUNCTION roleinfo_merge(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION roleinfo_merge(p_token character varying, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_rolepermissionjson json)
 IS '合并角色
roleinfoid:角色编号
roleinfoname:角色名
description:描述
rolepermissionjson:角色权限{"permissionid":角色权限编号,"permissiontype":权限类型,"ifpermission":允许,"permissionorder":权限级别,"params":参数,"sysactionid":权限编号,
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: roleinfo_query(character varying, integer, integer, integer, character varying, character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION roleinfo_query(p_token character varying, p_rows integer, p_page integer, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_isused integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_return json;v_check json;
begin
  v_check:=gm.check_login(p_token,132);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_rows is null then
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.roleinfoid,t1.roleinfoname,t1.description,t1.isused,rolepermission.rolepermissionjson from sysinfo.roleinfo t1 left join (select roleinfoid,array_to_json(array_agg(row_to_json(t))) rolepermissionjson from (select  t1.roleinfoid,t1.permissionid,t1.permissiontype,t1.ifpermission,t1.permissionorder,t1.params,t1.sysactionid,case t1.permissiontype when 1 then t2.sysactionname else t3.roleinfoname end sysactionname from sysinfo.rolepermission t1  left join sysinfo.sysaction t2 on t2.sysactionid=t1.sysactionid left join sysinfo.roleinfo t3 on t3.roleinfoid=t1.sysactionid) t group by t.roleinfoid) rolepermission on t1.roleinfoid=rolepermission.roleinfoid where  (p_roleinfoid is null or p_roleinfoid=t1.roleinfoid) and (p_roleinfoname is null or position(p_roleinfoname in t1.roleinfoname )>0) and (p_description is null or position(p_description in t1.description )>0) and (p_isused is null or p_isused=t1.isused) and t1.systemid=(v_check->'info'->>'systemid')::integer order by t1.roleinfoid) t;
    v_c:=coalesce(json_array_length(v_return),0);
  else
    select count(*) into v_c from sysinfo.roleinfo t1 where  (p_roleinfoid is null or p_roleinfoid=t1.roleinfoid) and (p_roleinfoname is null or position(p_roleinfoname in t1.roleinfoname )>0) and (p_description is null or position(p_description in t1.description )>0) and (p_isused is null or p_isused=t1.isused) and t1.systemid=(v_check->'info'->>'systemid')::integer;
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.roleinfoid,t1.roleinfoname,t1.description,t1.isused,rolepermission.rolepermissionjson from sysinfo.roleinfo t1 left join (select roleinfoid,array_to_json(array_agg(row_to_json(t))) rolepermissionjson from (select  t1.roleinfoid,t1.permissionid,t1.permissiontype,t1.ifpermission,t1.permissionorder,t1.params,t1.sysactionid,case t1.permissiontype when 1 then t2.sysactionname else t3.roleinfoname end sysactionname from sysinfo.rolepermission t1  left join sysinfo.sysaction t2 on t2.sysactionid=t1.sysactionid left join sysinfo.roleinfo t3 on t3.roleinfoid=t1.sysactionid) t group by t.roleinfoid) rolepermission on t1.roleinfoid=rolepermission.roleinfoid where  (p_roleinfoid is null or p_roleinfoid=t1.roleinfoid) and (p_roleinfoname is null or position(p_roleinfoname in t1.roleinfoname )>0) and (p_description is null or position(p_description in t1.description )>0) and (p_isused is null or p_isused=t1.isused) and t1.systemid=(v_check->'info'->>'systemid')::integer order by t1.roleinfoid limit greatest(p_rows,1) offset greatest(least((p_page-1)*p_rows,(v_c/p_rows-1+abs(v_c % p_rows))*p_rows),0) ) t;
  end if;
  return gm.returnjson(0,json_build_object('total',v_c,'rows',v_return));
end;
$$;


ALTER FUNCTION sysinfo.roleinfo_query(p_token character varying, p_rows integer, p_page integer, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_isused integer) OWNER TO gm;

--
-- Name: FUNCTION roleinfo_query(p_token character varying, p_rows integer, p_page integer, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_isused integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION roleinfo_query(p_token character varying, p_rows integer, p_page integer, p_roleinfoid integer, p_roleinfoname character varying, p_description character varying, p_isused integer)
 IS '查询角色
roleinfoid:角色编号
roleinfoname:角色名
description:描述
isused:是否使用
返回:{"total":总记录数,"rows":[{"roleinfoid":角色编号,"roleinfoname":角色名,"description":描述,"isused":显示}]}';


--
-- Name: roleinfo_undel(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION roleinfo_undel(p_token character varying, p_roleinfoid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,133);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.roleinfo where roleinfoid=p_roleinfoid and systemid=(v_check->'info'->>'systemid')::integer and isused=0;
  if v_c=0 then return gm.returnjson(100023); end if;--角色信息出错！

  update sysinfo.roleinfo set isused=1 where roleinfoid=p_roleinfoid;
  return gm.returnjson(0); 
end;
$$;


ALTER FUNCTION sysinfo.roleinfo_undel(p_token character varying, p_roleinfoid integer) OWNER TO gm;

--
-- Name: FUNCTION roleinfo_undel(p_token character varying, p_roleinfoid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION roleinfo_undel(p_token character varying, p_roleinfoid integer)
 IS '恢复角色
roleinfoid:id';


--
-- Name: serverlog_query(character varying, integer, integer, bigint, inet, character varying, character varying, text, timestamp without time zone, timestamp without time zone, inet, text, bigint, text, text); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION serverlog_query(p_token character varying, p_rows integer, p_page integer, p_logid bigint, p_clientip inet, p_pckname character varying, p_funcname character varying, p_content text, p_beginlogtime timestamp without time zone, p_endlogtime timestamp without time zone, p_serverip inet, p_params text, p_operatorid bigint, p_res text, p_head text) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_return json;v_check json;
begin
  v_check:=gm.check_login(p_token,107);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_rows is null then
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.logid,t1.clientip,t1.pckname,t1.funcname,t1.content,t1.logtime::varchar,t1.serverip,t1.params,t1.operatorid,toperatorid.operatorname operatoridname,t1.res,t1.head from sysinfo.serverlog t1 left join sysinfo.operinfo toperatorid on t1.operatorid=toperatorid.operatorid where  (p_logid is null or p_logid=t1.logid) and (p_clientip is null or p_clientip=t1.clientip) and (p_pckname is null or position(p_pckname in t1.pckname )>0) and (p_funcname is null or position(p_funcname in t1.funcname )>0) and (p_content is null or position(p_content in t1.content )>0) and (p_beginlogtime is null or t1.logtime>=p_beginlogtime) and (p_endlogtime is null or t1.logtime<=p_endlogtime) and (p_serverip is null or p_serverip=t1.serverip) and (p_params is null or position(p_params in t1.params )>0) and (p_operatorid is null or p_operatorid=t1.operatorid) and (p_res is null or position(p_res in t1.res )>0) and (p_head is null or position(p_head in t1.head )>0) order by t1.logid) t;
    v_c:=coalesce(json_array_length(v_return),0);
  else
    select count(*) into v_c from sysinfo.serverlog t1 where  (p_logid is null or p_logid=t1.logid) and (p_clientip is null or p_clientip=t1.clientip) and (p_pckname is null or position(p_pckname in t1.pckname )>0) and (p_funcname is null or position(p_funcname in t1.funcname )>0) and (p_content is null or position(p_content in t1.content )>0) and (p_beginlogtime is null or t1.logtime>=p_beginlogtime) and (p_endlogtime is null or t1.logtime<=p_endlogtime) and (p_serverip is null or p_serverip=t1.serverip) and (p_params is null or position(p_params in t1.params )>0) and (p_operatorid is null or p_operatorid=t1.operatorid) and (p_res is null or position(p_res in t1.res )>0) and (p_head is null or position(p_head in t1.head )>0);
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.logid,t1.clientip,t1.pckname,t1.funcname,t1.content,t1.logtime::varchar,t1.serverip,t1.params,t1.operatorid,toperatorid.operatorname operatoridname,t1.res,t1.head from sysinfo.serverlog t1 left join sysinfo.operinfo toperatorid on t1.operatorid=toperatorid.operatorid where  (p_logid is null or p_logid=t1.logid) and (p_clientip is null or p_clientip=t1.clientip) and (p_pckname is null or position(p_pckname in t1.pckname )>0) and (p_funcname is null or position(p_funcname in t1.funcname )>0) and (p_content is null or position(p_content in t1.content )>0) and (p_beginlogtime is null or t1.logtime>=p_beginlogtime) and (p_endlogtime is null or t1.logtime<=p_endlogtime) and (p_serverip is null or p_serverip=t1.serverip) and (p_params is null or position(p_params in t1.params )>0) and (p_operatorid is null or p_operatorid=t1.operatorid) and (p_res is null or position(p_res in t1.res )>0) and (p_head is null or position(p_head in t1.head )>0) order by t1.logid limit greatest(p_rows,1) offset greatest(least((p_page-1)*p_rows,(v_c/p_rows-1+abs(v_c % p_rows))*p_rows),0) ) t;
  end if;
  return gm.returnjson(0,json_build_object('total',v_c,'rows',v_return));
end;
$$;


ALTER FUNCTION sysinfo.serverlog_query(p_token character varying, p_rows integer, p_page integer, p_logid bigint, p_clientip inet, p_pckname character varying, p_funcname character varying, p_content text, p_beginlogtime timestamp without time zone, p_endlogtime timestamp without time zone, p_serverip inet, p_params text, p_operatorid bigint, p_res text, p_head text) OWNER TO gm;

--
-- Name: FUNCTION serverlog_query(p_token character varying, p_rows integer, p_page integer, p_logid bigint, p_clientip inet, p_pckname character varying, p_funcname character varying, p_content text, p_beginlogtime timestamp without time zone, p_endlogtime timestamp without time zone, p_serverip inet, p_params text, p_operatorid bigint, p_res text, p_head text) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION serverlog_query(p_token character varying, p_rows integer, p_page integer, p_logid bigint, p_clientip inet, p_pckname character varying, p_funcname character varying, p_content text, p_beginlogtime timestamp without time zone, p_endlogtime timestamp without time zone, p_serverip inet, p_params text, p_operatorid bigint, p_res text, p_head text)
 IS '查询系统日志
logid:日志ID
clientip:客户IP
pckname:包名
funcname:功能名
content:内容
beginlogtime:时间
endlogtime:时间结束
serverip:服务器IP
params:参数
operatorid:操作员
res:返回
head:头
返回:{"total":总记录数,"rows":[{"logid":日志ID,"clientip":客户IP,"pckname":包名,"funcname":功能名,"content":内容,"logtime":时间,"serverip":服务器IP,"params":参数,"operatorid":操作员id,"operatorname":操作员姓名,"res":返回,"head":头}]}';


--
-- Name: sysaction_add(character varying, integer, character varying, integer, integer, character varying, integer, smallint); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysaction_add(p_token character varying, p_upid integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,108);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  if p_upid is not null then
    select count(*) into v_c from sysinfo.sysaction where sysactionid=p_upid and isused<>0;
    if v_c=0 then return gm.returnjson(100014);end if;--上级编号不存在
  end if;
  if p_sysactionid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id:=nextval(sysinfo.sysaction_sysactionid_seq);
      select count(*) into v_c from sysinfo.sysaction where sysactionid=v_id;
    end loop;
  else
    select count(*) into v_c from sysinfo.sysaction where sysactionid=p_sysactionid;
    if v_c>0 then return gm.returnjson(100013); end if;--系统权限信息出错！
    v_id:=p_sysactionid;
  end if;
  insert into sysinfo.sysaction( upid,isused,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(coalesce(p_upid,100),1,p_params,p_systemid,v_id,p_sysactionname,p_actionid,p_isdefault );
  return gm.returnjson(0,json_build_object('id',v_id));
end; 
$$;


ALTER FUNCTION sysinfo.sysaction_add(p_token character varying, p_upid integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint) OWNER TO gm;

--
-- Name: FUNCTION sysaction_add(p_token character varying, p_upid integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysaction_add(p_token character varying, p_upid integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint)
 IS '新增系统权限
upid:上级id
params:参数
systemid:系统编号
sysactionid:系统权限编号
sysactionname:权限名
actionid:权限编号
isdefault:是否默认
返回：{"errorcode":0,"message":"执行成功！","info":{"id":id} }';


--
-- Name: sysaction_del(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysaction_del(p_token character varying, p_sysactionid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c integer;v_check json;
begin
  v_check:=gm.check_login(p_token,111);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.sysaction where sysactionid=p_sysactionid;
  if v_c=0 then return gm.returnjson(100013); end if;--系统权限信息出错！
  select count(*) into v_c from sysinfo.sysaction where upid=p_sysactionid and isused<>0;
  if v_c>0 then return gm.returnjson(100016);end if;--有下级类型不能删除
  update sysinfo.sysaction set isused=0 where sysactionid=p_sysactionid;
  with recursive tree as
  ( select sysactionid,upid,1 as idlevel,sysactionid::varchar as idpath,t1.systemid from sysinfo.sysaction t1 where upid=0
  union
  select t1.sysactionid,t1.upid,t2.idlevel+1,t2.idpath||'.'||t1.sysactionid,t1.systemid from sysinfo.sysaction t1 inner join tree t2 on t2.sysactionid=t1.upid and t2.systemid=t1.systemid where isused<>0) 
  update sysinfo.sysaction t set idpath=t1.idpath,idlevel=t1.idlevel,idcount=coalesce(cc,0) from tree t1 left join (select upid,count(*) cc,systemid from sysinfo.sysaction where isused<>0 group by upid,systemid) t2 on t1.sysactionid=t2.upid
  where t.sysactionid=t1.sysactionid;
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.sysaction_del(p_token character varying, p_sysactionid integer) OWNER TO gm;

--
-- Name: FUNCTION sysaction_del(p_token character varying, p_sysactionid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysaction_del(p_token character varying, p_sysactionid integer)
 IS '删除系统权限
sysactionid:id';


--
-- Name: sysaction_edit(character varying, integer, character varying, integer, character varying, integer, integer, smallint); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysaction_edit(p_token character varying, p_upid integer, p_params character varying, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_systemid integer, p_isdefault smallint) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_idpath varchar;v_check json;
begin
  v_check:=gm.check_login(p_token,109);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.sysaction where sysactionid=p_sysactionid and isused<>0;
  if v_c=0 then return gm.returnjson(100013); end if;--系统权限信息出错！
	if p_actionid is not null then 
	  select count(*) into v_c from sysinfo.actions where actionid=p_actionid;
	  if v_c=0 then return gm.returnjson(100013); end if;--系统权限信息出错！
	end if;
	select count(*) into v_c from sysinfo.systeminfo where systemid=p_systemid;
  if v_c=0 then return gm.returnjson(100012);end if;--子系统信息出错！
  if p_upid is not null then
    select count(*) into v_c from sysinfo.sysaction where sysactionid=p_upid and isused<>0;
    if v_c<>1 then return gm.returnjson(100014);end if;--上级不存在
    select idpath into v_idpath from sysinfo.sysaction where sysactionid=p_upid and isused<>0;
    if position('.'||p_sysactionid||'.' in '.'||v_idpath||'.')>0 then return gm.returnjson(100017);end if;--上级机构不能循环定义
  end if;
	if p_isdefault<>0 then p_isdefault:=1;end if;
	update sysinfo.sysaction set upid=coalesce(p_upid,100),params=p_params,systemid=p_systemid,sysactionname=p_sysactionname,actionid=p_actionid,isdefault=p_isdefault  where sysactionid=p_sysactionid;
  with recursive tree as
  ( select sysactionid,upid,1 as idlevel,sysactionid::varchar as idpath,t1.systemid from sysinfo.sysaction t1 where upid=0
  union
  select t1.sysactionid,t1.upid,t2.idlevel+1,t2.idpath||'.'||t1.sysactionid,t1.systemid from sysinfo.sysaction t1 inner join tree t2 on t2.sysactionid=t1.upid and t2.systemid=t1.systemid where isused<>0) 
  update sysinfo.sysaction t set idpath=t1.idpath,idlevel=t1.idlevel,idcount=coalesce(cc,0) from tree t1 left join (select upid,count(*) cc,systemid from sysinfo.sysaction where isused<>0 group by upid,systemid) t2 on t1.sysactionid=t2.upid
  where t.sysactionid=t1.sysactionid;
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.sysaction_edit(p_token character varying, p_upid integer, p_params character varying, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_systemid integer, p_isdefault smallint) OWNER TO gm;

--
-- Name: FUNCTION sysaction_edit(p_token character varying, p_upid integer, p_params character varying, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_systemid integer, p_isdefault smallint) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysaction_edit(p_token character varying, p_upid integer, p_params character varying, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_systemid integer, p_isdefault smallint)
 IS '修改系统权限
params:参数
sysactionid:系统权限编号
sysactionname:权限名
actionid:权限编号
systemid:系统编号
isdeault:是否默认,默认是
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: sysaction_merge(character varying, integer, character varying, integer, integer, character varying, integer, smallint); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysaction_merge(p_token character varying, p_upid integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c integer;v_id integer;v_idpath varchar;v_check json;
begin
  v_check:=gm.check_login(p_token,110);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  if p_upid is not null then
    select count(*) into v_c from sysinfo.sysaction where sysactionid=p_upid and isused<>0;
    if v_c<>1 then return gm.returnjson(100014);end if;--上级不存在
    select idpath into v_idpath from sysinfo.sysaction where sysactionid=p_upid and isused<>0;
    if position('.'||p_sysactionid||'.' in '.'||v_idpath||'.')>0 then return gm.returnjson(100017);end if;--上级机构不能循环定义
  end if;
  if p_sysactionid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval(sysinfo.sysaction_sysactionid_seq);
      select count(*) into v_c from sysinfo.sysaction where sysactionid=v_id;
    end loop;
  else
    v_id:=p_sysactionid;
  end if;
  if position('.'||p_sysactionid||'.' in '.'||v_idpath||'.')>0 then return gm.returnjson(100033);end if;--上级机构不能循环定义
  with "te" as (update sysinfo.sysaction set upid=coalesce(p_upid,100),params=p_params,systemid=p_systemid,sysactionname=p_sysactionname,actionid=p_actionid,isdefault=p_isdefault  where sysactionid=p_sysactionid returning *)
  insert into sysinfo.sysaction ( upid,isused,params,systemid,sysactionid,sysactionname,actionid,isdefault) select coalesce(p_upid,100),1,p_params,p_systemid,v_id,p_sysactionname,p_actionid,p_isdefault  where (select count(*) from te) = 0;
  with recursive tree as
  ( select sysactionid,upid,1 as idlevel,sysactionid::varchar as idpath,t1.systemid from sysinfo.sysaction t1 where upid=0
  union
  select t1.sysactionid,t1.upid,t2.idlevel+1,t2.idpath||'.'||t1.sysactionid,t1.systemid from sysinfo.sysaction t1 inner join tree t2 on t2.sysactionid=t1.upid and t2.systemid=t1.systemid where isused<>0) 
  update sysinfo.sysaction t set idpath=t1.idpath,idlevel=t1.idlevel,idcount=coalesce(cc,0) from tree t1 left join (select upid,count(*) cc,systemid from sysinfo.sysaction where isused<>0 group by upid,systemid) t2 on t1.sysactionid=t2.upid
  where t.sysactionid=t1.sysactionid;
  return gm.returnjson(0,json_build_object('id',v_id));
end; 
$$;


ALTER FUNCTION sysinfo.sysaction_merge(p_token character varying, p_upid integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint) OWNER TO gm;

--
-- Name: FUNCTION sysaction_merge(p_token character varying, p_upid integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysaction_merge(p_token character varying, p_upid integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint)
 IS '合并系统权限
upid:上级id
params:参数
systemid:系统编号
sysactionid:系统权限编号
sysactionname:权限名
actionid:权限编号
isdefault:是否默认
返回：{"errorcode":0,"message":"执行成功！","info":{"id":id} }';


--
-- Name: sysaction_query(character varying, integer, integer, integer, character varying, integer, character varying, integer, integer, character varying, integer, smallint); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysaction_query(p_token character varying, p_rows integer, p_page integer, p_upid integer, p_idpath character varying, p_isused integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c integer;v_return json;v_check json;
begin
  v_check:=gm.check_login(p_token,113);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  if p_rows is null then
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.isused,t1.upid,t1.isused,t1.params,t1.systemid,ts.systemname,t1.sysactionid,t1.sysactionname,t1.actionid,t1.isdefault,tt.sysactionname upname from sysinfo.sysaction t1 left join sysinfo.sysaction tt on t1.upid=tt.sysactionid  left join sysinfo.systeminfo ts on t1.systemid=ts.systemid where (p_isused is null or t1.isused=p_isused) and (p_upid is null or p_upid=t1.upid) and (p_idpath is null or position(p_idpath in t1.idpath)>0)  and (p_isused is null or p_isused=t1.isused) and (p_params is null or position(p_params in t1.params )>0) and (p_systemid is null or t1.systemid=p_systemid) and (p_sysactionid is null or p_sysactionid=t1.sysactionid) and (p_sysactionname is null or position(p_sysactionname in t1.sysactionname )>0) and (p_actionid is null or p_actionid=t1.actionid) and (p_isdefault is null or p_isdefault=t1.isdefault) order by t1.sysactionid ) t;
    v_c:=coalesce(json_array_length(v_return),0);
  else
    select count(*) into v_c from sysinfo.sysaction t1 where (p_isused is null or t1.isused=p_isused) and (p_upid is null or p_upid=t1.upid) and (p_idpath is null or position(p_idpath in t1.idpath)>0)  and (p_isused is null or p_isused=t1.isused) and (p_params is null or position(p_params in t1.params )>0) and (p_systemid is null or t1.systemid=p_systemid) and (p_sysactionid is null or p_sysactionid=t1.sysactionid) and (p_sysactionname is null or position(p_sysactionname in t1.sysactionname )>0) and (p_actionid is null or p_actionid=t1.actionid) and (p_isdefault is null or p_isdefault=t1.isdefault);
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.isused,t1.upid,t1.isused,t1.params,t1.systemid,ts.systemname,t1.sysactionid,t1.sysactionname,t1.actionid,t1.isdefault,tt.sysactionname upname from sysinfo.sysaction t1 left join sysinfo.sysaction tt on t1.upid=tt.sysactionid  left join sysinfo.systeminfo ts on t1.systemid=ts.systemid where (p_isused is null or t1.isused=p_isused) and (p_upid is null or p_upid=t1.upid) and (p_idpath is null or position(p_idpath in t1.idpath)>0)  and (p_isused is null or p_isused=t1.isused) and (p_params is null or position(p_params in t1.params )>0) and (p_systemid is null or t1.systemid=p_systemid) and (p_sysactionid is null or p_sysactionid=t1.sysactionid) and (p_sysactionname is null or position(p_sysactionname in t1.sysactionname )>0) and (p_actionid is null or p_actionid=t1.actionid) and (p_isdefault is null or p_isdefault=t1.isdefault) order by t1.sysactionid limit greatest(p_rows,1) offset greatest(least((p_page-1)*p_rows,(v_c/p_rows-1+abs(v_c % p_rows))*p_rows),0) ) t;
  end if;
  return gm.returnjson(0,json_build_object('total',v_c,'rows',v_return));
end;
$$;


ALTER FUNCTION sysinfo.sysaction_query(p_token character varying, p_rows integer, p_page integer, p_upid integer, p_idpath character varying, p_isused integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint) OWNER TO gm;

--
-- Name: FUNCTION sysaction_query(p_token character varying, p_rows integer, p_page integer, p_upid integer, p_idpath character varying, p_isused integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysaction_query(p_token character varying, p_rows integer, p_page integer, p_upid integer, p_idpath character varying, p_isused integer, p_params character varying, p_systemid integer, p_sysactionid integer, p_sysactionname character varying, p_actionid integer, p_isdefault smallint)
 IS '查询系统权限
upid:上级id
idpath:包含节点
isused:是否使用
params:参数
systemid:系统编号
sysactionid:系统权限编号
sysactionname:权限名
actionid:权限编号
isdefault:是否默认
返回:{"total":总记录数,"rows":[{"upid":上级id,"isused":使用,"params":参数,"systemid":系统id,"systemname":系统名称,"sysactionid":系统权限编号,"sysactionname":权限名,"actionid":权限编号,"isdefault":是否默认}]}';


--
-- Name: sysaction_undel(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysaction_undel(p_token character varying, p_sysactionid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c integer;v_check json;
begin
  v_check:=gm.check_login(p_token,112);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  if p_sysactionid=100 then return gm.returnjson(100015);end if; --顶级
  select count(*) into v_c from sysinfo.sysaction where sysactionid=p_sysactionid;
  if v_c=0 then return gm.returnjson(100013); end if;--系统权限信息出错！
  select count(*) into v_c from sysinfo.sysaction where upid=p_sysactionid and isused<>0;
  if v_c>0 then return gm.returnjson(100016);end if;--有下级类型不能删除
  update sysinfo.sysaction set isused=1 where sysactionid=p_sysactionid;
  with recursive tree as
  ( select sysactionid,upid,1 as idlevel,sysactionid::varchar as idpath,t1.systemid from sysinfo.sysaction t1 where upid=0
  union
  select t1.sysactionid,t1.upid,t2.idlevel+1,t2.idpath||'.'||t1.sysactionid,t1.systemid from sysinfo.sysaction t1 inner join tree t2 on t2.sysactionid=t1.upid and t2.systemid=t1.systemid where isused<>0) 
  update sysinfo.sysaction t set idpath=t1.idpath,idlevel=t1.idlevel,idcount=coalesce(cc,0) from tree t1 left join (select upid,count(*) cc,systemid from sysinfo.sysaction where isused<>0 group by upid,systemid) t2 on t1.sysactionid=t2.upid
  where t.sysactionid=t1.sysactionid;
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.sysaction_undel(p_token character varying, p_sysactionid integer) OWNER TO gm;

--
-- Name: FUNCTION sysaction_undel(p_token character varying, p_sysactionid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysaction_undel(p_token character varying, p_sysactionid integer)
 IS '恢复系统权限
sysactionid:id';


--
-- Name: sysorg_add(character varying, integer, integer, character varying, character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysorg_add(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,114);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  if p_upid is not null then
    select count(*) into v_c from sysinfo.sysorg where sysorgid=p_upid and isused<>0;
    if v_c=0 then return gm.returnjson(100014);end if;--上级编号不存在
  end if;
  if p_sysorgid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id:=nextval(sysinfo.sysorg_sysorgid_seq);
      select count(*) into v_c from sysinfo.sysorg where sysorgid=v_id;
    end loop;
  else
    select count(*) into v_c from sysinfo.sysorg where sysorgid=p_sysorgid;
    if v_c>0 then return gm.returnjson(100018); end if;--部门信息出错！
    v_id:=p_sysorgid;
  end if;
  insert into sysinfo.sysorg( upid,isused,systemid,sysorgid,sysorgname,description,orgtype) values(coalesce(p_upid,100),1,(v_check->'info'->>'systemid')::integer,v_id,p_sysorgname,p_description,p_orgtype );
  return gm.returnjson(0,json_build_object('id',v_id));
end; 
$$;


ALTER FUNCTION sysinfo.sysorg_add(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) OWNER TO gm;

--
-- Name: FUNCTION sysorg_add(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysorg_add(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer)
 IS '新增部门
upid:上级id
sysorgid:部门id
sysorgname:部门名称
description:说明
orgtype:部门类型id
返回：{"errorcode":0,"message":"执行成功！","info":{"id":id} }';


--
-- Name: sysorg_del(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysorg_del(p_token character varying, p_sysorgid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c integer;v_check json;
begin
  v_check:=gm.check_login(p_token,117);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.sysorg where sysorgid=p_sysorgid;
  if v_c=0 then return gm.returnjson(100018); end if;--部门信息出错！
  select count(*) into v_c from sysinfo.sysorg where upid=p_sysorgid and isused<>0;
  if v_c>0 then return gm.returnjson(100016);end if;--有下级类型不能删除
  update sysinfo.sysorg set isused=0 where sysorgid=p_sysorgid;
  with recursive tree as
  ( select sysorgid,upid,1 as idlevel,sysorgid::varchar as idpath,t1.systemid from sysinfo.sysorg t1 where upid=0
  union
  select t1.sysorgid,t1.upid,t2.idlevel+1,t2.idpath||'.'||t1.sysorgid,t1.systemid from sysinfo.sysorg t1 inner join tree t2 on t2.sysorgid=t1.upid and t2.systemid=t1.systemid where isused<>0) 
  update sysinfo.sysorg t set idpath=t1.idpath,idlevel=t1.idlevel,idcount=coalesce(cc,0) from tree t1 left join (select upid,count(*) cc,systemid from sysinfo.sysorg where isused<>0 group by upid,systemid) t2 on t1.sysorgid=t2.upid
  where t.sysorgid=t1.sysorgid;
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.sysorg_del(p_token character varying, p_sysorgid integer) OWNER TO gm;

--
-- Name: FUNCTION sysorg_del(p_token character varying, p_sysorgid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysorg_del(p_token character varying, p_sysorgid integer)
 IS '删除部门
sysorgid:id';


--
-- Name: sysorg_edit(character varying, integer, integer, character varying, character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysorg_edit(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_idpath varchar;v_check json;
begin
  v_check:=gm.check_login(p_token,115);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.sysorg where sysorgid=p_sysorgid and isused<>0;
  if v_c=0 then return gm.returnjson(100018); end if;--部门信息出错！
  if p_upid is not null then
    select count(*) into v_c from sysinfo.sysorg where sysorgid=p_upid and isused<>0;
    if v_c<>1 then return gm.returnjson(100014);end if;--上级不存在
    select idpath into v_idpath from sysinfo.sysorg where sysorgid=p_upid and isused<>0;
    if position('.'||p_sysorgid||'.' in '.'||v_idpath||'.')>0 then return gm.returnjson(100017);end if;--上级机构不能循环定义
  end if;
  update sysinfo.sysorg set upid=coalesce(p_upid,100),systemid=(v_check->'info'->>'systemid')::integer,sysorgname=p_sysorgname,description=p_description,orgtype=p_orgtype  where sysorgid=p_sysorgid;
  with recursive tree as
  ( select sysorgid,upid,1 as idlevel,sysorgid::varchar as idpath,t1.systemid from sysinfo.sysorg t1 where upid=0
  union
  select t1.sysorgid,t1.upid,t2.idlevel+1,t2.idpath||'.'||t1.sysorgid,t1.systemid from sysinfo.sysorg t1 inner join tree t2 on t2.sysorgid=t1.upid and t2.systemid=t1.systemid where isused<>0) 
  update sysinfo.sysorg t set idpath=t1.idpath,idlevel=t1.idlevel,idcount=coalesce(cc,0) from tree t1 left join (select upid,count(*) cc,systemid from sysinfo.sysorg where isused<>0 group by upid,systemid) t2 on t1.sysorgid=t2.upid
  where t.sysorgid=t1.sysorgid;
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.sysorg_edit(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) OWNER TO gm;

--
-- Name: FUNCTION sysorg_edit(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysorg_edit(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer)
 IS '修改部门
upid:上级id
sysorgid:部门id
sysorgname:部门名称
description:说明
orgtype:部门类型id
返回：{"errorcode":0,"message":"执行成功！","info":{"id":id} }';


--
-- Name: sysorg_merge(character varying, integer, integer, character varying, character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysorg_merge(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c integer;v_id integer;v_idpath varchar;v_check json;
begin
  v_check:=gm.check_login(p_token,116);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  if p_upid is not null then
    select count(*) into v_c from sysinfo.sysorg where sysorgid=p_upid and isused<>0;
    if v_c<>1 then return gm.returnjson(100014);end if;--上级不存在
    select idpath into v_idpath from sysinfo.sysorg where sysorgid=p_upid and isused<>0;
    if position('.'||p_sysorgid||'.' in '.'||v_idpath||'.')>0 then return gm.returnjson(100017);end if;--上级机构不能循环定义
  end if;
  if p_sysorgid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval(sysinfo.sysorg_sysorgid_seq);
      select count(*) into v_c from sysinfo.sysorg where sysorgid=v_id;
    end loop;
  else
    v_id:=p_sysorgid;
  end if;
  if position('.'||p_sysorgid||'.' in '.'||v_idpath||'.')>0 then return gm.returnjson(100033);end if;--上级机构不能循环定义
  with "te" as (update sysinfo.sysorg set upid=coalesce(p_upid,100),systemid=(v_check->'info'->>'systemid')::integer,sysorgname=p_sysorgname,description=p_description,orgtype=p_orgtype  where sysorgid=p_sysorgid returning *)
  insert into sysinfo.sysorg ( upid,isused,systemid,sysorgid,sysorgname,description,orgtype) select coalesce(p_upid,100),1,(v_check->'info'->>'systemid')::integer,v_id,p_sysorgname,p_description,p_orgtype  where (select count(*) from te) = 0;
  with recursive tree as
  ( select sysorgid,upid,1 as idlevel,sysorgid::varchar as idpath,t1.systemid from sysinfo.sysorg t1 where upid=0
  union
  select t1.sysorgid,t1.upid,t2.idlevel+1,t2.idpath||'.'||t1.sysorgid,t1.systemid from sysinfo.sysorg t1 inner join tree t2 on t2.sysorgid=t1.upid and t2.systemid=t1.systemid where isused<>0) 
  update sysinfo.sysorg t set idpath=t1.idpath,idlevel=t1.idlevel,idcount=coalesce(cc,0) from tree t1 left join (select upid,count(*) cc,systemid from sysinfo.sysorg where isused<>0 group by upid,systemid) t2 on t1.sysorgid=t2.upid
  where t.sysorgid=t1.sysorgid;
  return gm.returnjson(0,json_build_object('id',v_id));
end; 
$$;


ALTER FUNCTION sysinfo.sysorg_merge(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) OWNER TO gm;

--
-- Name: FUNCTION sysorg_merge(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysorg_merge(p_token character varying, p_upid integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer)
 IS '合并部门
upid:上级id
sysorgid:部门id
sysorgname:部门名称
description:说明
orgtype:部门类型id
返回：{"errorcode":0,"message":"执行成功！","info":{"id":id} }';


--
-- Name: sysorg_query(character varying, integer, integer, integer, character varying, integer, integer, character varying, character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysorg_query(p_token character varying, p_rows integer, p_page integer, p_upid integer, p_idpath character varying, p_isused integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c integer;v_return json;v_check json;
begin
  v_check:=gm.check_login(p_token,119);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  if p_rows is null then
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.isused,t1.upid,t1.isused,t1.sysorgid,t1.sysorgname,t1.description,t1.orgtype,t2.orgtypename,tt.sysorgname upname from sysinfo.sysorg t1 left join sysinfo.sysorg tt on t1.upid=tt.sysorgid  left join sysinfo.orgtype t2 on t2.orgtypeid=t1.orgtype where (p_isused is null or t1.isused=p_isused) and (p_upid is null or p_upid=t1.upid) and (p_idpath is null or position(p_idpath in t1.idpath)>0)  and (p_isused is null or p_isused=t1.isused) and t1.systemid=(v_check->'info'->>'systemid')::integer and (p_sysorgid is null or p_sysorgid=t1.sysorgid) and (p_sysorgname is null or position(p_sysorgname in t1.sysorgname )>0) and (p_description is null or position(p_description in t1.description )>0) and (p_orgtype is null or p_orgtype=t1.orgtype) order by t1.sysorgid ) t;
    v_c:=coalesce(json_array_length(v_return),0);
  else
    select count(*) into v_c from sysinfo.sysorg t1 where (p_isused is null or t1.isused=p_isused) and (p_upid is null or p_upid=t1.upid) and (p_idpath is null or position(p_idpath in t1.idpath)>0)  and (p_isused is null or p_isused=t1.isused) and t1.systemid=(v_check->'info'->>'systemid')::integer and (p_sysorgid is null or p_sysorgid=t1.sysorgid) and (p_sysorgname is null or position(p_sysorgname in t1.sysorgname )>0) and (p_description is null or position(p_description in t1.description )>0) and (p_orgtype is null or p_orgtype=t1.orgtype);
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.isused,t1.upid,t1.isused,t1.sysorgid,t1.sysorgname,t1.description,t1.orgtype,t2.orgtypename,tt.sysorgname upname from sysinfo.sysorg t1 left join sysinfo.sysorg tt on t1.upid=tt.sysorgid  left join sysinfo.orgtype t2 on t2.orgtypeid=t1.orgtype where (p_isused is null or t1.isused=p_isused) and (p_upid is null or p_upid=t1.upid) and (p_idpath is null or position(p_idpath in t1.idpath)>0)  and (p_isused is null or p_isused=t1.isused) and t1.systemid=(v_check->'info'->>'systemid')::integer and (p_sysorgid is null or p_sysorgid=t1.sysorgid) and (p_sysorgname is null or position(p_sysorgname in t1.sysorgname )>0) and (p_description is null or position(p_description in t1.description )>0) and (p_orgtype is null or p_orgtype=t1.orgtype) order by t1.sysorgid limit greatest(p_rows,1) offset greatest(least((p_page-1)*p_rows,(v_c/p_rows-1+abs(v_c % p_rows))*p_rows),0) ) t;
  end if;
  return gm.returnjson(0,json_build_object('total',v_c,'rows',v_return));
end;
$$;


ALTER FUNCTION sysinfo.sysorg_query(p_token character varying, p_rows integer, p_page integer, p_upid integer, p_idpath character varying, p_isused integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) OWNER TO gm;

--
-- Name: FUNCTION sysorg_query(p_token character varying, p_rows integer, p_page integer, p_upid integer, p_idpath character varying, p_isused integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysorg_query(p_token character varying, p_rows integer, p_page integer, p_upid integer, p_idpath character varying, p_isused integer, p_sysorgid integer, p_sysorgname character varying, p_description character varying, p_orgtype integer)
 IS '查询部门
upid:上级id
idpath:包含节点
isused:是否使用
sysorgid:部门id
sysorgname:部门名称
description:说明
orgtype:部门类型id
返回:{"total":总记录数,"rows":[{"upid":上级id,"isused":显示,"sysorgid":部门id,"sysorgname":部门名称,"description":说明,"orgtype":部门类型id,"orgtypename":部门类型名}]}';


--
-- Name: sysorg_undel(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION sysorg_undel(p_token character varying, p_sysorgid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c integer;v_check json;
begin
  v_check:=gm.check_login(p_token,118);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  if p_sysorgid=100 then return gm.returnjson(100015);end if; --顶级
  select count(*) into v_c from sysinfo.sysorg where sysorgid=p_sysorgid;
  if v_c=0 then return gm.returnjson(100018); end if;--部门信息出错！
  select count(*) into v_c from sysinfo.sysorg where upid=p_sysorgid and isused<>0;
  if v_c>0 then return gm.returnjson(100016);end if;--有下级类型不能删除
  update sysinfo.sysorg set isused=1 where sysorgid=p_sysorgid;
  with recursive tree as
  ( select sysorgid,upid,1 as idlevel,sysorgid::varchar as idpath,t1.systemid from sysinfo.sysorg t1 where upid=0
  union
  select t1.sysorgid,t1.upid,t2.idlevel+1,t2.idpath||'.'||t1.sysorgid,t1.systemid from sysinfo.sysorg t1 inner join tree t2 on t2.sysorgid=t1.upid and t2.systemid=t1.systemid where isused<>0) 
  update sysinfo.sysorg t set idpath=t1.idpath,idlevel=t1.idlevel,idcount=coalesce(cc,0) from tree t1 left join (select upid,count(*) cc,systemid from sysinfo.sysorg where isused<>0 group by upid,systemid) t2 on t1.sysorgid=t2.upid
  where t.sysorgid=t1.sysorgid;
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.sysorg_undel(p_token character varying, p_sysorgid integer) OWNER TO gm;

--
-- Name: FUNCTION sysorg_undel(p_token character varying, p_sysorgid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION sysorg_undel(p_token character varying, p_sysorgid integer)
 IS '恢复部门
sysorgid:id';


--
-- Name: systeminfo_add(character varying, integer, character varying, smallint, character varying, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION systeminfo_add(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,101);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_prikey is null then return gm.returnjson(100012); end if;--子系统信息出错！
  if p_systemid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval('sysinfo.systeminfo_systemid_seq');
      select count(*) into v_c from sysinfo.systeminfo where systemid=v_id;
    end loop;
  else
    select count(*) into v_c from sysinfo.systeminfo where systemid=p_systemid;
    if v_c>0 then return gm.returnjson(100012); end if;--子系统信息出错！
    v_id:=p_systemid;
  end if;
  insert into sysinfo.systeminfo( systemid,systemname,isused,algorithm,prikey,loginname,createoperator,createtime) values(v_id,p_systemname,1,p_algorithm,p_prikey,p_loginname ,(v_check->'info'->>'operatorid')::integer,now());
  return gm.returnjson(0,json_build_object('id',v_id));
end; 
$$;


ALTER FUNCTION sysinfo.systeminfo_add(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying) OWNER TO gm;

--
-- Name: FUNCTION systeminfo_add(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION systeminfo_add(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying)
 IS '新增子系统
systemid:系统编号
systemname:系统名
algorithm:加密函数1aes128,2sm4
prikey:密钥
loginname:系统登录名
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: systeminfo_del(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION systeminfo_del(p_token character varying, p_systemid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,101);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.systeminfo where systemid=p_systemid;
  if v_c=0 then return gm.returnjson(100012); end if;--子系统信息出错！
  update sysinfo.systeminfo set isused=0,deloperator=(v_check->'info'->>'operatorid')::integer,deltime=now() where systemid=p_systemid;
  return gm.returnjson(0); 
end;
$$;


ALTER FUNCTION sysinfo.systeminfo_del(p_token character varying, p_systemid integer) OWNER TO gm;

--
-- Name: FUNCTION systeminfo_del(p_token character varying, p_systemid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION systeminfo_del(p_token character varying, p_systemid integer)
 IS '删除子系统
systemid:id';


--
-- Name: systeminfo_edit(character varying, integer, character varying, smallint, character varying, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION systeminfo_edit(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,101);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_prikey is null then return gm.returnjson(100012); end if;--子系统信息出错！
  v_id:=p_systemid;
  select count(*) into v_c from sysinfo.systeminfo where systemid=p_systemid;
  if v_c=0 then return gm.returnjson(100012); end if;--子系统信息出错！
  update sysinfo.systeminfo set systemname=p_systemname,algorithm=p_algorithm,prikey=p_prikey,loginname=p_loginname ,updateoperator=(v_check->'info'->>'operatorid')::integer,updatetime=now() where systemid=p_systemid;
  return gm.returnjson(0);
end;
$$;


ALTER FUNCTION sysinfo.systeminfo_edit(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying) OWNER TO gm;

--
-- Name: FUNCTION systeminfo_edit(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION systeminfo_edit(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying)
 IS '修改子系统
systemid:系统编号
systemname:系统名
algorithm:加密函数1aes128,2sm4
prikey:密钥
loginname:系统登录名
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: systeminfo_merge(character varying, integer, character varying, smallint, character varying, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION systeminfo_merge(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_id int;v_check json;
begin
  v_check:=gm.check_login(p_token,101);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_prikey is null then return gm.returnjson(100012); end if;--子系统信息出错！
  if p_systemid is null then 
    v_c:=1;loop exit when (v_c=0);
      v_id :=nextval('sysinfo.systeminfo_systemid_seq');
      select count(*) into v_c from sysinfo.systeminfo where systemid=v_id;
    end loop;
  else
    v_id:=p_systemid;
  end if;
  with "te" as (update sysinfo.systeminfo set systemname=p_systemname,algorithm=p_algorithm,prikey=p_prikey,loginname=p_loginname ,updateoperator=(v_check->'info'->>'operatorid')::integer,updatetime=now() where systemid=v_id returning *)
  insert into sysinfo.systeminfo ( systemid,systemname,isused,algorithm,prikey,loginname,createoperator,createtime) select v_id,p_systemname,1,p_algorithm,p_prikey,p_loginname ,(v_check->'info'->>'operatorid')::integer,now() where (select count(*) from te) = 0;
  return gm.returnjson(0,json_build_object('id',v_id));
end; 
$$;


ALTER FUNCTION sysinfo.systeminfo_merge(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying) OWNER TO gm;

--
-- Name: FUNCTION systeminfo_merge(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION systeminfo_merge(p_token character varying, p_systemid integer, p_systemname character varying, p_algorithm smallint, p_prikey character varying, p_loginname character varying)
 IS '合并子系统
systemid:系统编号
systemname:系统名
algorithm:加密函数1aes128,2sm4
prikey:密钥
loginname:系统登录名
返回：{"errorcode":0,"message":"执行成功！","info":id}';


--
-- Name: systeminfo_query(character varying, integer, integer, integer, character varying, integer, smallint, character varying, character varying); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION systeminfo_query(p_token character varying, p_rows integer, p_page integer, p_systemid integer, p_systemname character varying, p_isused integer, p_algorithm smallint, p_prikey character varying, p_loginname character varying) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_return json;v_check json;
begin
  v_check:=gm.check_login(p_token,101);
  if v_check->>'errorcode'<>'0' then return v_check; end if;

  if p_rows is null then
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.systemid,ts.systemname,t1.systemname,t1.isused,t1.algorithm,t1.prikey,t1.createoperator,tcreateoperator.operatorname createoperatorname,t1.createtime::varchar,t1.updateoperator,tupdateoperator.operatorname updateoperatorname,t1.updatetime::varchar,t1.deloperator,tdeloperator.operatorname deloperatorname,t1.deltime::varchar,t1.loginname from sysinfo.systeminfo t1 left join sysinfo.systeminfo ts on t1.systemid=ts.systemid left join sysinfo.operinfo tcreateoperator on t1.createoperator=tcreateoperator.operatorid left join sysinfo.operinfo tupdateoperator on t1.updateoperator=tupdateoperator.operatorid left join sysinfo.operinfo tdeloperator on t1.deloperator=tdeloperator.operatorid where  (p_systemid is null or t1.systemid=p_systemid) and (p_systemname is null or position(p_systemname in t1.systemname )>0) and (p_isused is null or p_isused=t1.isused) and (p_algorithm is null or p_algorithm=t1.algorithm) and (p_prikey is null or position(p_prikey in t1.prikey )>0) and (p_loginname is null or position(p_loginname in t1.loginname )>0) order by t1.systemid) t;
    v_c:=coalesce(json_array_length(v_return),0);
  else
    select count(*) into v_c from sysinfo.systeminfo t1 where  (p_systemid is null or t1.systemid=p_systemid) and (p_systemname is null or position(p_systemname in t1.systemname )>0) and (p_isused is null or p_isused=t1.isused) and (p_algorithm is null or p_algorithm=t1.algorithm) and (p_prikey is null or position(p_prikey in t1.prikey )>0) and (p_loginname is null or position(p_loginname in t1.loginname )>0);
    select array_to_json(array_agg(row_to_json(t))) into v_return from (select  t1.systemid,ts.systemname,t1.systemname,t1.isused,t1.algorithm,t1.prikey,t1.createoperator,tcreateoperator.operatorname createoperatorname,t1.createtime::varchar,t1.updateoperator,tupdateoperator.operatorname updateoperatorname,t1.updatetime::varchar,t1.deloperator,tdeloperator.operatorname deloperatorname,t1.deltime::varchar,t1.loginname from sysinfo.systeminfo t1 left join sysinfo.systeminfo ts on t1.systemid=ts.systemid left join sysinfo.operinfo tcreateoperator on t1.createoperator=tcreateoperator.operatorid left join sysinfo.operinfo tupdateoperator on t1.updateoperator=tupdateoperator.operatorid left join sysinfo.operinfo tdeloperator on t1.deloperator=tdeloperator.operatorid where  (p_systemid is null or t1.systemid=p_systemid) and (p_systemname is null or position(p_systemname in t1.systemname )>0) and (p_isused is null or p_isused=t1.isused) and (p_algorithm is null or p_algorithm=t1.algorithm) and (p_prikey is null or position(p_prikey in t1.prikey )>0) and (p_loginname is null or position(p_loginname in t1.loginname )>0) order by t1.systemid limit greatest(p_rows,1) offset greatest(least((p_page-1)*p_rows,(v_c/p_rows-1+abs(v_c % p_rows))*p_rows),0) ) t;
  end if;
  return gm.returnjson(0,json_build_object('total',v_c,'rows',v_return));
end;
$$;


ALTER FUNCTION sysinfo.systeminfo_query(p_token character varying, p_rows integer, p_page integer, p_systemid integer, p_systemname character varying, p_isused integer, p_algorithm smallint, p_prikey character varying, p_loginname character varying) OWNER TO gm;

--
-- Name: FUNCTION systeminfo_query(p_token character varying, p_rows integer, p_page integer, p_systemid integer, p_systemname character varying, p_isused integer, p_algorithm smallint, p_prikey character varying, p_loginname character varying) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION systeminfo_query(p_token character varying, p_rows integer, p_page integer, p_systemid integer, p_systemname character varying, p_isused integer, p_algorithm smallint, p_prikey character varying, p_loginname character varying)
 IS '查询子系统
systemid:系统编号
systemname:系统名
isused:是否使用
algorithm:加密函数1aes128,2sm4
prikey:密钥
loginname:系统登录名
返回:{"total":总记录数,"rows":[{"systemid":系统id,"systemname":系统名称,"systemname":系统名,"isused":使用,"algorithm":加密函数1aes128,2sm4,"prikey":密钥,"createoperator":操作员编号,"createoperatorname":创建人员,"updateoperator":操作员编号,"updateoperatorname":修改人员,"deloperator":操作员编号,"deloperatorname":删除人员,"loginname":系统登录名}]}';


--
-- Name: systeminfo_undel(character varying, integer); Type: FUNCTION; Schema: sysinfo; Owner: gm
--

CREATE FUNCTION systeminfo_undel(p_token character varying, p_systemid integer) RETURNS json
    LANGUAGE plpgsql NOT SHIPPABLE SECURITY DEFINER
 AS $$
declare v_c int;v_check json;
begin
  v_check:=gm.check_login(p_token,102);
  if v_check->>'errorcode'<>'0' then return v_check; end if;
  select count(*) into v_c from sysinfo.systeminfo where systemid=p_systemid;
  if v_c=0 then return gm.returnjson(100012); end if;--子系统信息出错！
  update sysinfo.systeminfo set isused=1,deloperator=(v_check->'info'->>'operatorid')::integer,deltime=now() where systemid=p_systemid;
  return gm.returnjson(0); 
end;
$$;


ALTER FUNCTION sysinfo.systeminfo_undel(p_token character varying, p_systemid integer) OWNER TO gm;

--
-- Name: FUNCTION systeminfo_undel(p_token character varying, p_systemid integer) ; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON FUNCTION systeminfo_undel(p_token character varying, p_systemid integer)
 IS '恢复子系统
systemid:id';


SET search_path = gm;

--
-- Name: nginx; Type: VIEW; Schema: gm; Owner: gm
--

CREATE VIEW nginx(params,func,proargnames,pronargs) AS
    SELECT string_agg(((('$'::text || (t.sort1)::text) || '::'::text) || (t.typname)::text), ','::text ORDER BY t.sort1) AS params, t.func, t.proargnames, t.pronargs FROM (SELECT row_number() OVER (PARTITION BY t_1.func ORDER BY t_1.sort) AS sort1, t3.typname, t_1.func, t_1.pronargs, t_1.proargnames FROM ((SELECT row_number() OVER () AS sort, t_2.func, t_2.pronargs, t_2.proargnames, t_2.proargtypes, t_2.aa FROM (SELECT ((((' "'::text || (t2.nspname)::text) || '"."'::text) || (t1.proname)::text) || '"'::text) AS func, t1.pronargs, (substr(((t1.proargnames)::character varying)::text, 2, (char_length(((t1.proargnames)::character varying)::text) - 2)) || ','::text) AS proargnames, t1.proargtypes, regexp_split_to_table(((t1.proargtypes)::character varying)::text, ' '::text) AS aa FROM (pg_proc t1 LEFT JOIN pg_namespace t2 ON ((t1.pronamespace = t2.oid))) WHERE (t2.nspname = 'sysinfo'::name)) t_2) t_1 LEFT JOIN pg_type t3 ON ((t_1.aa = ((t3.oid)::character varying)::text)))) t GROUP BY t.func, t.pronargs, t.proargnames ORDER BY (t.func)::bytea;


ALTER VIEW gm.nginx OWNER TO gm;

SET search_path = public;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: foreignkey; Type: TABLE; Schema: public; Owner: gm; Tablespace: 
--

CREATE TABLE foreignkey (
    foreignkeyid numeric(7,0),
    tablename character varying(255),
    fieldname character varying(255),
    foreigntable character varying(255),
    foreignfield character varying(255),
    foreigntitle character varying(255),
    foreignid character varying(255),
    errorcode numeric(7,0),
    errormessage character varying(255),
    "where" character varying(255),
    tabletitle character varying(255),
    istree numeric(4,0),
    schema character varying(255),
    foreignschema character varying(255)
)
WITH (orientation=row, compression=no);


ALTER TABLE public.foreignkey OWNER TO gm;

--
-- Name: COLUMN foreignkey.tablename; Type: COMMENT; Schema: public; Owner: gm
--

COMMENT ON COLUMN foreignkey.tablename IS '表名';


--
-- Name: COLUMN foreignkey.fieldname; Type: COMMENT; Schema: public; Owner: gm
--

COMMENT ON COLUMN foreignkey.fieldname IS '字段名';


--
-- Name: COLUMN foreignkey.foreigntable; Type: COMMENT; Schema: public; Owner: gm
--

COMMENT ON COLUMN foreignkey.foreigntable IS '外键表名';


--
-- Name: COLUMN foreignkey.foreignfield; Type: COMMENT; Schema: public; Owner: gm
--

COMMENT ON COLUMN foreignkey.foreignfield IS '外键显示字段';


--
-- Name: COLUMN foreignkey.foreigntitle; Type: COMMENT; Schema: public; Owner: gm
--

COMMENT ON COLUMN foreignkey.foreigntitle IS '外键表头';


--
-- Name: COLUMN foreignkey.foreignid; Type: COMMENT; Schema: public; Owner: gm
--

COMMENT ON COLUMN foreignkey.foreignid IS '外键连接字段';


SET search_path = sysinfo;

--
-- Name: actions; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE actions (
    isused smallint,
    actionid integer NOT NULL,
    actionname character varying(255),
    description character varying(255),
    params character varying(255),
    actionurl character varying(255),
    code character varying(255)
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.actions OWNER TO gm;

--
-- Name: TABLE actions; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE actions IS '权限名';


--
-- Name: COLUMN actions.isused; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN actions.isused IS '使用';


--
-- Name: COLUMN actions.actionid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN actions.actionid IS '权限编号';


--
-- Name: COLUMN actions.actionname; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN actions.actionname IS '权限名';


--
-- Name: COLUMN actions.description; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN actions.description IS '说明';


--
-- Name: COLUMN actions.params; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN actions.params IS '参数';


--
-- Name: COLUMN actions.actionurl; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN actions.actionurl IS '权限路径';


--
-- Name: COLUMN actions.code; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN actions.code IS '编码';


--
-- Name: appparams; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE appparams (
    appid integer NOT NULL,
    params character varying(255),
    accesstoken character varying(255),
    isused smallint,
    tokentime timestamp(6) without time zone,
    typeid integer
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.appparams OWNER TO gm;

--
-- Name: COLUMN appparams.appid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN appparams.appid IS 'appid';


--
-- Name: COLUMN appparams.params; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN appparams.params IS '参数';


--
-- Name: COLUMN appparams.accesstoken; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN appparams.accesstoken IS 'token';


--
-- Name: COLUMN appparams.isused; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN appparams.isused IS '是否使用';


--
-- Name: COLUMN appparams.tokentime; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN appparams.tokentime IS '生效时间';


--
-- Name: COLUMN appparams.typeid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN appparams.typeid IS '类型1:微信';


--
-- Name: errorcode; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE errorcode (
    message character varying(255),
    errorcode integer NOT NULL,
    primekey character varying(255),
    isused smallint,
    schema character varying(255)
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.errorcode OWNER TO gm;

--
-- Name: TABLE errorcode; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE errorcode IS '出错代码';


--
-- Name: COLUMN errorcode.message; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN errorcode.message IS '信息';


--
-- Name: COLUMN errorcode.errorcode; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN errorcode.errorcode IS '出错代码';


--
-- Name: COLUMN errorcode.primekey; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN errorcode.primekey IS '主键';


--
-- Name: COLUMN errorcode.isused; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN errorcode.isused IS '使用';


--
-- Name: COLUMN errorcode.schema; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN errorcode.schema IS '模式';


--
-- Name: funchtml; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE funchtml (
    htmlid integer NOT NULL,
    html1 text,
    html2 text
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.funchtml OWNER TO gm;

--
-- Name: loginlog; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE loginlog (
    logid bigint NOT NULL,
    logintime timestamp(6) without time zone,
    operatorno bigint,
    pass character varying(255),
    ip inet,
    accounts character varying(255),
    systemid smallint
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.loginlog OWNER TO gm;

--
-- Name: loginlog_logid_seq; Type: SEQUENCE; Schema: sysinfo; Owner: gm
--

CREATE  SEQUENCE loginlog_logid_seq
    START WITH 100
    INCREMENT BY 1
    MINVALUE 100
    NO MAXVALUE
    CACHE 1
    CYCLE;


ALTER SEQUENCE sysinfo.loginlog_logid_seq OWNER TO gm;

--
-- Name: operaccounts; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE operaccounts (
    operatorid integer,
    accounts character varying(255),
    appid integer,
    typeid integer,
    isused smallint,
    unionid character varying(255)
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.operaccounts OWNER TO gm;

--
-- Name: COLUMN operaccounts.operatorid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operaccounts.operatorid IS '操作员id';


--
-- Name: COLUMN operaccounts.accounts; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operaccounts.accounts IS '登录账号';


--
-- Name: COLUMN operaccounts.appid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operaccounts.appid IS 'appid';


--
-- Name: COLUMN operaccounts.typeid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operaccounts.typeid IS '101:微信';


--
-- Name: COLUMN operaccounts.isused; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operaccounts.isused IS '是否使用';


--
-- Name: COLUMN operaccounts.unionid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operaccounts.unionid IS '统一id';


--
-- Name: operinfo; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE operinfo (
    operatorid bigint NOT NULL,
    operatorname character varying(255),
    sex smallint,
    phone character varying(255),
    accounts character varying(255),
    pass character varying(255),
    tokenkey character varying(2000),
    tokentime timestamp(6) without time zone,
    memo character varying(255),
    isused smallint,
    mycode character varying(8),
    upcode character varying(8),
    headimgurl text,
    nickname character varying(255),
    birthday timestamp(6) without time zone,
    tokentype smallint DEFAULT 1,
    tokeninterval integer DEFAULT 180,
    createoperator integer,
    createtime timestamp(6) without time zone,
    updateoperator integer,
    updatetime timestamp(6) without time zone,
    deloperator integer,
    deltime timestamp(6) without time zone
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.operinfo OWNER TO gm;

--
-- Name: TABLE operinfo; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE operinfo IS '员工';


--
-- Name: COLUMN operinfo.operatorid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.operatorid IS '员工编号';


--
-- Name: COLUMN operinfo.operatorname; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.operatorname IS '员工姓名';


--
-- Name: COLUMN operinfo.sex; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.sex IS '性别';


--
-- Name: COLUMN operinfo.phone; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.phone IS '电话';


--
-- Name: COLUMN operinfo.accounts; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.accounts IS '帐号';


--
-- Name: COLUMN operinfo.pass; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.pass IS '密码';


--
-- Name: COLUMN operinfo.tokenkey; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.tokenkey IS '令牌';


--
-- Name: COLUMN operinfo.tokentime; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.tokentime IS '令牌时间';


--
-- Name: COLUMN operinfo.memo; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.memo IS '备注';


--
-- Name: COLUMN operinfo.isused; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.isused IS '使用';


--
-- Name: COLUMN operinfo.mycode; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.mycode IS '推广码';


--
-- Name: COLUMN operinfo.upcode; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.upcode IS '推广上级id';


--
-- Name: COLUMN operinfo.headimgurl; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.headimgurl IS '头像url';


--
-- Name: COLUMN operinfo.nickname; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.nickname IS '昵称';


--
-- Name: COLUMN operinfo.birthday; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.birthday IS '生日';


--
-- Name: COLUMN operinfo.tokentype; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.tokentype IS '令牌类型1默认单人登录2多人登录';


--
-- Name: COLUMN operinfo.tokeninterval; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.tokeninterval IS '令牌时长默认180分钟';


--
-- Name: COLUMN operinfo.createoperator; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.createoperator IS '创建人员';


--
-- Name: COLUMN operinfo.createtime; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.createtime IS '创建时间';


--
-- Name: COLUMN operinfo.updateoperator; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.updateoperator IS '修改人员';


--
-- Name: COLUMN operinfo.updatetime; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.updatetime IS '修改时间';


--
-- Name: COLUMN operinfo.deloperator; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.deloperator IS '删除人员';


--
-- Name: COLUMN operinfo.deltime; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operinfo.deltime IS '删除时间';


--
-- Name: operinfo_operatorid_seq; Type: SEQUENCE; Schema: sysinfo; Owner: gm
--

CREATE  SEQUENCE operinfo_operatorid_seq
    START WITH 100000
    INCREMENT BY 1
    MINVALUE 100000
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE sysinfo.operinfo_operatorid_seq OWNER TO gm;

--
-- Name: operpermission_permissionid_seq; Type: SEQUENCE; Schema: sysinfo; Owner: gm
--

CREATE  SEQUENCE operpermission_permissionid_seq
    START WITH 100
    INCREMENT BY 1
    MINVALUE 100
    NO MAXVALUE
    CACHE 1
    CYCLE;


ALTER SEQUENCE sysinfo.operpermission_permissionid_seq OWNER TO gm;

--
-- Name: operpermission; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE operpermission (
    operatorid bigint NOT NULL,
    permissiontype smallint NOT NULL,
    ifpermission smallint,
    permissionorder integer,
    params character varying(255),
    sysactionid integer NOT NULL,
    permissionid integer DEFAULT nextval('operpermission_permissionid_seq'::regclass) NOT NULL
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.operpermission OWNER TO gm;

--
-- Name: TABLE operpermission; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE operpermission IS '员工权限';


--
-- Name: COLUMN operpermission.operatorid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operpermission.operatorid IS '员工编号';


--
-- Name: COLUMN operpermission.permissiontype; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operpermission.permissiontype IS '权限类型1权限2角色';


--
-- Name: COLUMN operpermission.ifpermission; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operpermission.ifpermission IS '允许';


--
-- Name: COLUMN operpermission.permissionorder; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operpermission.permissionorder IS '权限级别';


--
-- Name: COLUMN operpermission.params; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operpermission.params IS '参数';


--
-- Name: COLUMN operpermission.sysactionid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operpermission.sysactionid IS '权限编号';


--
-- Name: COLUMN operpermission.permissionid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN operpermission.permissionid IS '操作员权限编号';


--
-- Name: orgtype; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE orgtype (
    isused smallint,
    orgtypeid integer NOT NULL,
    orgtypename character varying(255),
    description character varying(255),
    systemid integer
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.orgtype OWNER TO gm;

--
-- Name: TABLE orgtype; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE orgtype IS '部门类型';


--
-- Name: COLUMN orgtype.isused; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN orgtype.isused IS '显示';


--
-- Name: COLUMN orgtype.orgtypeid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN orgtype.orgtypeid IS '部门类型编号';


--
-- Name: COLUMN orgtype.orgtypename; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN orgtype.orgtypename IS '部门类型名';


--
-- Name: COLUMN orgtype.description; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN orgtype.description IS '说明';


--
-- Name: COLUMN orgtype.systemid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN orgtype.systemid IS '系统id';


--
-- Name: orgtype_orgtypeid_seq; Type: SEQUENCE; Schema: sysinfo; Owner: gm
--

CREATE  SEQUENCE orgtype_orgtypeid_seq
    START WITH 100
    INCREMENT BY 1
    MINVALUE 100
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE sysinfo.orgtype_orgtypeid_seq OWNER TO gm;

--
-- Name: roleinfo; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE roleinfo (
    roleinfoid integer NOT NULL,
    roleinfoname character varying(255),
    description character varying(255),
    isused smallint,
    systemid integer
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.roleinfo OWNER TO gm;

--
-- Name: TABLE roleinfo; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE roleinfo IS '角色';


--
-- Name: COLUMN roleinfo.roleinfoid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN roleinfo.roleinfoid IS '角色编号';


--
-- Name: COLUMN roleinfo.roleinfoname; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN roleinfo.roleinfoname IS '角色名';


--
-- Name: COLUMN roleinfo.description; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN roleinfo.description IS '描述';


--
-- Name: COLUMN roleinfo.isused; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN roleinfo.isused IS '显示';


--
-- Name: COLUMN roleinfo.systemid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN roleinfo.systemid IS '系统id';


--
-- Name: roleinfo_roleinfoid_seq; Type: SEQUENCE; Schema: sysinfo; Owner: gm
--

CREATE  SEQUENCE roleinfo_roleinfoid_seq
    START WITH 100
    INCREMENT BY 1
    MINVALUE 100
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE sysinfo.roleinfo_roleinfoid_seq OWNER TO gm;

--
-- Name: rolepermission; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE rolepermission (
    roleinfoid integer,
    permissionid integer NOT NULL,
    permissiontype smallint,
    ifpermission smallint,
    permissionorder integer,
    params character varying(255),
    sysactionid integer
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.rolepermission OWNER TO gm;

--
-- Name: TABLE rolepermission; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE rolepermission IS '角色权限';


--
-- Name: COLUMN rolepermission.roleinfoid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN rolepermission.roleinfoid IS '角色编号';


--
-- Name: COLUMN rolepermission.permissionid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN rolepermission.permissionid IS '角色权限编号';


--
-- Name: COLUMN rolepermission.permissiontype; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN rolepermission.permissiontype IS '权限类型';


--
-- Name: COLUMN rolepermission.ifpermission; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN rolepermission.ifpermission IS '允许';


--
-- Name: COLUMN rolepermission.permissionorder; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN rolepermission.permissionorder IS '权限级别';


--
-- Name: COLUMN rolepermission.params; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN rolepermission.params IS '参数';


--
-- Name: COLUMN rolepermission.sysactionid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN rolepermission.sysactionid IS '权限编号';


--
-- Name: rolepermission_permissionid_seq; Type: SEQUENCE; Schema: sysinfo; Owner: gm
--

CREATE  SEQUENCE rolepermission_permissionid_seq
    START WITH 100
    INCREMENT BY 1
    MINVALUE 100
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE sysinfo.rolepermission_permissionid_seq OWNER TO gm;

--
-- Name: serverlog_logid_seq; Type: SEQUENCE; Schema: sysinfo; Owner: conn
--

CREATE  SEQUENCE serverlog_logid_seq
    START WITH 100
    INCREMENT BY 1
    MINVALUE 100
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE sysinfo.serverlog_logid_seq OWNER TO conn;

--
-- Name: serverlog; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE serverlog (
    logid bigint DEFAULT nextval('serverlog_logid_seq'::regclass) NOT NULL,
    clientip inet,
    pckname character varying(255),
    funcname character varying(255),
    content text,
    logtime timestamp(6) without time zone,
    serverip inet,
    params text,
    operatorid bigint,
    res text,
    head text
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.serverlog OWNER TO gm;

--
-- Name: TABLE serverlog; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE serverlog IS '系统日志';


--
-- Name: COLUMN serverlog.logid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN serverlog.logid IS '日志ID';


--
-- Name: COLUMN serverlog.clientip; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN serverlog.clientip IS '客户IP';


--
-- Name: COLUMN serverlog.pckname; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN serverlog.pckname IS '包名';


--
-- Name: COLUMN serverlog.funcname; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN serverlog.funcname IS '功能名';


--
-- Name: COLUMN serverlog.content; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN serverlog.content IS '内容';


--
-- Name: COLUMN serverlog.logtime; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN serverlog.logtime IS '时间';


--
-- Name: COLUMN serverlog.serverip; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN serverlog.serverip IS '服务器IP';


--
-- Name: COLUMN serverlog.params; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN serverlog.params IS '参数';


--
-- Name: COLUMN serverlog.operatorid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN serverlog.operatorid IS '操作员';


--
-- Name: COLUMN serverlog.res; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN serverlog.res IS '返回';


--
-- Name: COLUMN serverlog.head; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN serverlog.head IS '头';


--
-- Name: sysaction; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE sysaction (
    isused smallint,
    idpath character varying(255),
    idlevel integer,
    idcount integer,
    upid integer,
    params character varying(255),
    systemid integer,
    sysactionid integer NOT NULL,
    sysactionname character varying(255),
    actionid integer,
    isdefault smallint
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.sysaction OWNER TO gm;

--
-- Name: TABLE sysaction; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE sysaction IS '系统权限';


--
-- Name: COLUMN sysaction.isused; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysaction.isused IS '使用';


--
-- Name: COLUMN sysaction.idpath; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysaction.idpath IS ' ';


--
-- Name: COLUMN sysaction.idlevel; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysaction.idlevel IS ' ';


--
-- Name: COLUMN sysaction.idcount; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysaction.idcount IS ' ';


--
-- Name: COLUMN sysaction.upid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysaction.upid IS '上级权限';


--
-- Name: COLUMN sysaction.params; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysaction.params IS '参数';


--
-- Name: COLUMN sysaction.systemid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysaction.systemid IS '系统编号';


--
-- Name: COLUMN sysaction.sysactionid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysaction.sysactionid IS '系统权限编号';


--
-- Name: COLUMN sysaction.sysactionname; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysaction.sysactionname IS '权限名';


--
-- Name: COLUMN sysaction.actionid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysaction.actionid IS '权限编号';


--
-- Name: COLUMN sysaction.isdefault; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysaction.isdefault IS '是否默认';


--
-- Name: sysaction_sysactionid_seq; Type: SEQUENCE; Schema: sysinfo; Owner: gm
--

CREATE  SEQUENCE sysaction_sysactionid_seq
    START WITH 100000000
    INCREMENT BY 1
    MINVALUE 100000000
    NO MAXVALUE
    CACHE 1
    CYCLE;


ALTER SEQUENCE sysinfo.sysaction_sysactionid_seq OWNER TO gm;

--
-- Name: sysoper; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE sysoper (
    operatorid integer NOT NULL,
    systemid integer NOT NULL
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.sysoper OWNER TO gm;

--
-- Name: TABLE sysoper; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE sysoper IS '操作员所属系统';


--
-- Name: COLUMN sysoper.operatorid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysoper.operatorid IS '操作员id';


--
-- Name: COLUMN sysoper.systemid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysoper.systemid IS '系统id';


--
-- Name: sysoperorg; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE sysoperorg (
    operatorid integer NOT NULL,
    sysorgid integer NOT NULL
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.sysoperorg OWNER TO gm;

--
-- Name: TABLE sysoperorg; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE sysoperorg IS '操作员部门';


--
-- Name: COLUMN sysoperorg.operatorid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysoperorg.operatorid IS '操作员id';


--
-- Name: COLUMN sysoperorg.sysorgid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysoperorg.sysorgid IS '系统部门id';


--
-- Name: sysoperorg_sysorgid_seq; Type: SEQUENCE; Schema: sysinfo; Owner: gm
--

CREATE  SEQUENCE sysoperorg_sysorgid_seq
    START WITH 100
    INCREMENT BY 1
    MINVALUE 100
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE sysinfo.sysoperorg_sysorgid_seq OWNER TO gm;

--
-- Name: sysorg; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE sysorg (
    isused smallint,
    idpath character varying(255),
    idlevel integer,
    idcount integer,
    upid integer,
    systemid integer,
    sysorgid integer NOT NULL,
    sysorgname character varying(255),
    description character varying(255),
    orgtype integer
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.sysorg OWNER TO gm;

--
-- Name: TABLE sysorg; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE sysorg IS '部门';


--
-- Name: COLUMN sysorg.isused; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysorg.isused IS '显示';


--
-- Name: COLUMN sysorg.upid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysorg.upid IS '上级部门';


--
-- Name: COLUMN sysorg.systemid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysorg.systemid IS '系统id';


--
-- Name: COLUMN sysorg.sysorgid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysorg.sysorgid IS '部门id';


--
-- Name: COLUMN sysorg.sysorgname; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysorg.sysorgname IS '部门名称';


--
-- Name: COLUMN sysorg.description; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysorg.description IS '说明';


--
-- Name: COLUMN sysorg.orgtype; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN sysorg.orgtype IS '部门类型id';


--
-- Name: sysorg_sysorgid_seq; Type: SEQUENCE; Schema: sysinfo; Owner: gm
--

CREATE  SEQUENCE sysorg_sysorgid_seq
    START WITH 100
    INCREMENT BY 1
    MINVALUE 100
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE sysinfo.sysorg_sysorgid_seq OWNER TO gm;

--
-- Name: systeminfo; Type: TABLE; Schema: sysinfo; Owner: gm; Tablespace: 
--

CREATE TABLE systeminfo (
    systemid integer NOT NULL,
    systemname character varying(255),
    isused smallint,
    algorithm smallint,
    prikey character varying(16) NOT NULL,
    createoperator integer,
    createtime timestamp(6) without time zone,
    updateoperator integer,
    updatetime timestamp(6) without time zone,
    deloperator integer,
    deltime timestamp(6) without time zone,
    loginname character varying(255)
)
WITH (orientation=row, compression=no);


ALTER TABLE sysinfo.systeminfo OWNER TO gm;

--
-- Name: TABLE systeminfo; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON TABLE systeminfo IS '子系统';


--
-- Name: COLUMN systeminfo.systemid; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.systemid IS '系统编号';


--
-- Name: COLUMN systeminfo.systemname; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.systemname IS '系统名';


--
-- Name: COLUMN systeminfo.isused; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.isused IS '使用';


--
-- Name: COLUMN systeminfo.algorithm; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.algorithm IS '加密函数1aes128,2sm4';


--
-- Name: COLUMN systeminfo.prikey; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.prikey IS '密钥';


--
-- Name: COLUMN systeminfo.createoperator; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.createoperator IS '创建人员';


--
-- Name: COLUMN systeminfo.createtime; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.createtime IS '创建时间';


--
-- Name: COLUMN systeminfo.updateoperator; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.updateoperator IS '修改人员';


--
-- Name: COLUMN systeminfo.updatetime; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.updatetime IS '修改时间';


--
-- Name: COLUMN systeminfo.deloperator; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.deloperator IS '删除人员';


--
-- Name: COLUMN systeminfo.deltime; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.deltime IS '删除时间';


--
-- Name: COLUMN systeminfo.loginname; Type: COMMENT; Schema: sysinfo; Owner: gm
--

COMMENT ON COLUMN systeminfo.loginname IS '系统登录名';


--
-- Name: systeminfo_systemid_seq; Type: SEQUENCE; Schema: sysinfo; Owner: gm
--

CREATE  SEQUENCE systeminfo_systemid_seq
    START WITH 100
    INCREMENT BY 1
    MINVALUE 100
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE sysinfo.systeminfo_systemid_seq OWNER TO gm;

--
-- Name: view_file; Type: VIEW; Schema: sysinfo; Owner: gm
--

CREATE VIEW view_file(filenum,dbid,spcid,phyrds,phywrts,phyblkrd,phyblkwrt,readtim,writetim,avgiotim,lstiotim,miniotim,maxiowtm,oid,relname,relnamespace,datname,spcname,nspname) AS
    SELECT t1.*, t2.oid, t2.relname, t2.relnamespace, t3.datname, t4.spcname, t5.nspname FROM ((((gs_file_stat t1 LEFT JOIN pg_class t2 ON ((t1.filenum = t2.relfilenode))) LEFT JOIN pg_database t3 ON ((t1.dbid = t3.oid))) LEFT JOIN pg_tablespace t4 ON ((t1.spcid = t4.oid))) LEFT JOIN pg_namespace t5 ON ((t2.relnamespace = t5.oid)));


ALTER VIEW sysinfo.view_file OWNER TO gm;

SET search_path = public;

--
--

COPY foreignkey (foreignkeyid, tablename, fieldname, foreigntable, foreignfield, foreigntitle, foreignid, errorcode, errormessage, "where", tabletitle, istree, schema, foreignschema) FROM stdin;
\.
;

SET search_path = sysinfo;

--
--

COPY actions (isused, actionid, actionname, description, params, actionurl, code) FROM stdin;
1	150	登录	\N	\N	sysinfo/login	\N
1	160	微信登录	\N	101	sysinfo/loginaccount	\N
1	161	注册	\N	\N	sysinfo/reg	\N
1	171	微信注册	\N	101	sysinfo/regmicrochat	\N
1	128	合并员工所属系统	\N	\N	sysinfo/operinfo_merge	\N
1	129	删除员工所属系统	\N	\N	sysinfo/operinfo_del	\N
1	130	恢复员工所属系统	\N	\N	sysinfo/operinfo_undel	\N
1	131	查询员工所属系统	\N	\N	sysinfo/operinfo_query	\N
1	114	新增部门	\N	\N	sysinfo/sysorg_add	\N
1	146	合并员工部门	\N	\N	sysinfo/operinfoorg_merge	\N
1	147	删除员工部门	\N	\N	sysinfo/operinfoorg_del	\N
1	101	新增子系统	\N	Gao@12345	sysinfo/systeminfo_add	\N
1	102	修改子系统	\N	\N	sysinfo/systeminfo_edit	\N
1	103	合并子系统	\N	\N	sysinfo/systeminfo_merge	\N
1	104	删除子系统	\N	\N	sysinfo/systeminfo_del	\N
1	105	恢复子系统	\N	\N	sysinfo/systeminfo_undel	\N
1	106	查询子系统	\N	\N	sysinfo/systeminfo_query	\N
1	148	恢复员工部门	\N	\N	sysinfo/operinfoorg_undel	\N
1	149	查询员工部门	\N	\N	sysinfo/operinfo_query	\N
1	138	新增员工权限	\N	\N	sysinfo/operinfopermission_add	\N
1	139	修改员工权限	\N	\N	sysinfo/operinfopermission_edit	\N
1	140	合并员工权限	\N	\N	sysinfo/operinfopermission_merge	\N
1	141	删除员工权限	\N	\N	sysinfo/operinfopermission_del	\N
1	142	恢复员工权限	\N	\N	sysinfo/operinfopermission_undel	\N
1	143	查询员工权限	\N	\N	sysinfo/operinfo_query	\N
1	115	修改部门	\N	\N	sysinfo/sysorg_edit	\N
1	116	合并部门	\N	\N	sysinfo/sysorg_merge	\N
1	132	新增角色	\N	\N	sysinfo/roleinfo_add	\N
1	133	修改角色	\N	\N	sysinfo/roleinfo_edit	\N
1	134	合并角色	\N	\N	sysinfo/roleinfo_merge	\N
1	135	删除角色	\N	\N	sysinfo/roleinfo_del	\N
1	136	恢复角色	\N	\N	sysinfo/roleinfo_undel	\N
1	137	查询角色	\N	\N	sysinfo/roleinfo_query	\N
1	145	修改员工部门	\N	\N	sysinfo/operinfoorg_edit	\N
1	144	新增员工部门	\N	\N	sysinfo/operinfoorg_add	\N
1	117	删除部门	\N	\N	sysinfo/sysorg_del	\N
1	118	恢复部门	\N	\N	sysinfo/sysorg_undel	\N
1	119	查询部门	\N	\N	sysinfo/sysorg_query	\N
1	107	查询系统日志	\N	\N	sysinfo/serverlog_query	\N
1	180	查询权限名	\N	\N	sysinfo/actions_query	\N
1	126	新增员工所属系统	\N	\N	sysinfo/operinfo_add	\N
1	127	修改员工所属系统	\N	\N	sysinfo/operinfo_edit	\N
1	181	查询出错代码	\N	\N	sysinfo/errorcode_query	\N
1	120	新增部门类型	\N	\N	sysinfo/orgtype_add	\N
1	121	修改部门类型	\N	\N	sysinfo/orgtype_edit	\N
1	122	合并部门类型	\N	\N	sysinfo/orgtype_merge	\N
1	123	删除部门类型	\N	\N	sysinfo/orgtype_del	\N
1	124	恢复部门类型	\N	\N	sysinfo/orgtype_undel	\N
1	125	查询部门类型	\N	\N	sysinfo/orgtype_query	\N
1	108	新增系统权限	\N	\N	sysinfo/sysaction_add	\N
1	109	修改系统权限	\N	\N	sysinfo/sysaction_edit	\N
1	110	合并系统权限	\N	\N	sysinfo/sysaction_merge	\N
1	111	删除系统权限	\N	\N	sysinfo/sysaction_del	\N
1	112	恢复系统权限	\N	\N	sysinfo/sysaction_undel	\N
1	113	查询系统权限	\N	\N	sysinfo/sysaction_query	\N
\.
;

--
--

COPY errorcode (message, errorcode, primekey, isused, schema) FROM stdin;
操作员信息出错！	100011	operatorid	1	sysinfo.operinfo
权限信息出错！	100013	sysactionid	1	sysinfo.sysaction
上级不存在！	100014	\N	1	\N
顶级不能删除！	100015	\N	1	\N
执行成功！	0	\N	1	\N
有下级不能删除！	100016	\N	1	\N
员工权限信息出错！	100025	permissionid	1	sysinfo.operpermission
部门信息出错！	100018	sysorgid	1	sysinfo.sysorg
部门类型信息出错！	100020	orgtypeid	1	sysinfo.orgtype
不能注册！	100026	\N	\N	\N
帐号密码错误	100001	\N	1	\N
注册码不正确！	100027	\N	\N	\N
登录错误超过5次，帐号锁定10分钟！	100002	\N	1	\N
登录错误超过10次，帐号锁定3小时！	100003	\N	1	\N
手机码不正确！	100028	\N	\N	\N
小程序已注册！	100029	\N	\N	\N
非法登录！	100005	\N	1	\N
登录已失效！	100006	\N	1	\N
账号不能重复！	100022	\N	\N	\N
角色信息出错！	100023	roleinfoid	1	sysinfo.roleinfo
无此权限	100008	\N	1	\N
帐号不能为空	100009	\N	1	\N
密码不能为空！	100010	\N	1	\N
操作员部门信息出错！	100019	sysorgid	1	sysinfo.sysoperorg
角色权限信息出错！	100024	permissionid	1	sysinfo.rolepermission
子系统信息出错！	100012	systemid	1	sysinfo.systeminfo
操作员所属系统信息出错！	100021	systemid	1	sysinfo.sysoper
不能循环定义！	100017	\N	1	\N
系统日志信息出错！	100030	logid	1	sysinfo.serverlog
权限名信息出错！	100031	actionid	1	sysinfo.actions
出错代码信息出错！	100032	errorcode	1	sysinfo.errorcode
\.
;

--
--

COPY funchtml (htmlid, html1, html2) FROM stdin;
100	<!DOCTYPE html>\r\n<html lang="en">\r\n  <head>\r\n    <meta charset="UTF-8" />\r\n    <meta http-equiv="X-UA-Compatible" content="IE=edge" />\r\n    <meta name="viewport" content="width=device-width, initial-scale=1.0" />\r\n    <title>接口文档</title>\r\n    <style>\r\n      * {\r\n        margin: 0;\r\n        padding: 0;\r\n      }\r\n\r\n      html,\r\n      body {\r\n        width: 100%;\r\n        height: 100%;\r\n      }\r\n      ul li {\r\n        cursor: pointer;\r\n        list-style-type: none;\r\n      }\r\n\r\n      ul li:hover {\r\n        cursor: pointer;\r\n      }\r\n      .content {\r\n        width: 100%;\r\n        height: 100%;\r\n      }\r\n      .title {\r\n        width: 100%;\r\n        height: 70px;\r\n        line-height: 70px;\r\n        display: flex;\r\n        align-items: center;\r\n      }\r\n      .btn{\r\n        width: 200px;\r\n        padding-left: 20px;\r\n        box-sizing: border-box;\r\n      }\r\n\r\n      .line {\r\n        height: 42px;\r\n        border-right: 2px solid #263238;\r\n      }\r\n      .title_r {\r\n        flex: 1;\r\n        text-align: center;\r\n      }\r\n\r\n      .main {\r\n        width: 100%;\r\n        height: calc(100% - 70px);\r\n        display: flex;\r\n      }\r\n      #port {\r\n        width: 18%;\r\n        height: 100%;\r\n      }\r\n\r\n      #viewport {\r\n        box-sizing: border-box;\r\n        flex: 1;\r\n        height: 100%;\r\n        background-color: #abb1b7;\r\n        padding: 10px 40px 40px 40px;\r\n        color: #fff;\r\n      }\r\n      .nav {\r\n        width: 100%;\r\n        height: 100%;\r\n        background: #263238;\r\n        transition: all 0.3s;\r\n        overflow: auto;\r\n      }\r\n      .nav a {\r\n        display: block;\r\n        overflow: hidden;\r\n        padding-left: 20px;\r\n        line-height: 46px;\r\n        max-height: 46px;\r\n        color: #abb1b7;\r\n        transition: all 0.3s;\r\n      }\r\n      .nav a span {\r\n        margin-left: 30px;\r\n      }\r\n      .nav-item {\r\n        position: relative;\r\n      }\r\n      .nav-item.nav-show {\r\n        border-bottom: none;\r\n      }\r\n      .nav-item ul {\r\n        display: none;\r\n        background: rgba(0, 0, 0, 0.1);\r\n      }\r\n      .nav-item ul span {\r\n        display: block;\r\n        margin-left: 50px;\r\n      }\r\n      .nav-item.nav-show ul {\r\n        display: block;\r\n      }\r\n      .nav-item > a:before {\r\n        content: "";\r\n        position: absolute;\r\n        left: 0px;\r\n        width: 2px;\r\n        height: 46px;\r\n        background: #34a0ce;\r\n        opacity: 0;\r\n        transition: all 0.3s;\r\n      }\r\n      .nav .nav-icon {\r\n        font-size: 20px;\r\n        position: absolute;\r\n        margin-left: -1px;\r\n      }\r\n      /* 此处修改导航图标 可自定义iconfont 替换*/\r\n      .icon_1::after {\r\n        content: "\\e62b";\r\n      }\r\n      .icon_2::after {\r\n        content: "\\e669";\r\n      }\r\n      .icon_3::after {\r\n        content: "\\e61d";\r\n      }\r\n      /*---------------------*/\r\n      .nav-more {\r\n        float: right;\r\n        margin-right: 20px;\r\n        font-size: 12px;\r\n        transition: transform 0.3s;\r\n      }\r\n      /* 此处为导航右侧箭头 */\r\n      .nav-more::after {\r\n        width: 15px;\r\n        height: 15px;\r\n        margin-left: 9px;\r\n        border: 1px solid red;\r\n        transform: rotate(-45deg);\r\n        border-top-color: transparent;\r\n        border-left-color: transparent;\r\n      }\r\n      /*---------------------*/\r\n      .nav-show .nav-more {\r\n        transform: rotate(90deg);\r\n      }\r\n      .nav-show,\r\n      .nav-item > a:hover {\r\n        color: #fff;\r\n        background: rgba(0, 0, 0, 0.1);\r\n      }\r\n      .nav-show > a:before,\r\n      .nav-item > a:hover:before {\r\n        opacity: 1;\r\n      }\r\n      .nav-item li:hover a {\r\n        color: #fff;\r\n        background: rgba(0, 0, 0, 0.1);\r\n      }\r\n      .json_box {\r\n        width: calc(100% - 0px);\r\n        height: 100%;\r\n        word-break: break-all;\r\n        background-color: #fbfbfb;\r\n        color: #263238;\r\n        border-radius: 20px;\r\n        padding: 15px;\r\n        box-sizing: border-box;\r\n        margin-top: 10px;\r\n        overflow: auto;\r\n      }\r\n      .drap_line {\r\n        width: 4px;\r\n        height: 100%;\r\n        background-color: #263238;\r\n        cursor: e-resize;\r\n      }\r\n      \r\n    </style>\r\n  </head>\r\n  <body>\r\n    <!-- src="https://cdn.bootcss.com/jquery/3.2.1/jquery.min.js" -->\r\n    <!-- ! jQuery v3.2.1 | (c) JS Foundation and other contributors | jquery.org/license  -->\r\n    <script type="text/javascript">\r\n      !(function (a, b) {\r\n        "use strict";\r\n        "object" == typeof module && "object" == typeof module.exports\r\n          ? (module.exports = a.document\r\n              ? b(a, !0)\r\n              : function (a) {\r\n                  if (!a.document)\r\n                    throw new Error("jQuery requires a window with a document");\r\n                  return b(a);\r\n                })\r\n          : b(a);\r\n      })("undefined" != typeof window ? window : this, function (a, b) {\r\n        "use strict";\r\n        var c = [],\r\n          d = a.document,\r\n          e = Object.getPrototypeOf,\r\n          f = c.slice,\r\n          g = c.concat,\r\n          h = c.push,\r\n          i = c.indexOf,\r\n          j = {},\r\n          k = j.toString,\r\n          l = j.hasOwnProperty,\r\n          m = l.toString,\r\n          n = m.call(Object),\r\n          o = {};\r\n        function p(a, b) {\r\n          b = b || d;\r\n          var c = b.createElement("script");\r\n          (c.text = a), b.head.appendChild(c).parentNode.removeChild(c);\r\n        }\r\n        var q = "3.2.1",\r\n          r = function (a, b) {\r\n            return new r.fn.init(a, b);\r\n          },\r\n          s = /^[\\s\\uFEFF\\xA0]+|[\\s\\uFEFF\\xA0]+$/g,\r\n          t = /^-ms-/,\r\n          u = /-([a-z])/g,\r\n          v = function (a, b) {\r\n            return b.toUpperCase();\r\n          };\r\n        (r.fn = r.prototype =\r\n          {\r\n            jquery: q,\r\n            constructor: r,\r\n            length: 0,\r\n            toArray: function () {\r\n              return f.call(this);\r\n            },\r\n            get: function (a) {\r\n              return null == a\r\n                ? f.call(this)\r\n                : a < 0\r\n                ? this[a + this.length]\r\n                : this[a];\r\n            },\r\n            pushStack: function (a) {\r\n              var b = r.merge(this.constructor(), a);\r\n              return (b.prevObject = this), b;\r\n            },\r\n            each: function (a) {\r\n              return r.each(this, a);\r\n            },\r\n            map: function (a) {\r\n              return this.pushStack(\r\n                r.map(this, function (b, c) {\r\n                  return a.call(b, c, b);\r\n                })\r\n              );\r\n            },\r\n            slice: function () {\r\n              return this.pushStack(f.apply(this, arguments));\r\n            },\r\n            first: function () {\r\n              return this.eq(0);\r\n            },\r\n            last: function () {\r\n              return this.eq(-1);\r\n            },\r\n            eq: function (a) {\r\n              var b = this.length,\r\n                c = +a + (a < 0 ? b : 0);\r\n              return this.pushStack(c >= 0 && c < b ? [this[c]] : []);\r\n            },\r\n            end: function () {\r\n              return this.prevObject || this.constructor();\r\n            },\r\n            push: h,\r\n            sort: c.sort,\r\n            splice: c.splice,\r\n          }),\r\n          (r.extend = r.fn.extend =\r\n            function () {\r\n              var a,\r\n                b,\r\n                c,\r\n                d,\r\n                e,\r\n                f,\r\n                g = arguments[0] || {},\r\n                h = 1,\r\n                i = arguments.length,\r\n                j = !1;\r\n              for (\r\n                "boolean" == typeof g &&\r\n                  ((j = g), (g = arguments[h] || {}), h++),\r\n                  "object" == typeof g || r.isFunction(g) || (g = {}),\r\n                  h === i && ((g = this), h--);\r\n                h < i;\r\n                h++\r\n              )\r\n                if (null != (a = arguments[h]))\r\n                  for (b in a)\r\n                    (c = g[b]),\r\n                      (d = a[b]),\r\n                      g !== d &&\r\n                        (j &&\r\n                        d &&\r\n                        (r.isPlainObject(d) || (e = Array.isArray(d)))\r\n                          ? (e\r\n                              ? ((e = !1), (f = c && Array.isArray(c) ? c : []))\r\n                              : (f = c && r.isPlainObject(c) ? c : {}),\r\n                            (g[b] = r.extend(j, f, d)))\r\n                          : void 0 !== d && (g[b] = d));\r\n              return g;\r\n            }),\r\n          r.extend({\r\n            expando: "jQuery" + (q + Math.random()).replace(/\\D/g, ""),\r\n            isReady: !0,\r\n            error: function (a) {\r\n              throw new Error(a);\r\n            },\r\n            noop: function () {},\r\n            isFunction: function (a) {\r\n              return "function" === r.type(a);\r\n            },\r\n            isWindow: function (a) {\r\n              return null != a && a === a.window;\r\n            },\r\n            isNumeric: function (a) {\r\n              var b = r.type(a);\r\n              return (\r\n                ("number" === b || "string" === b) && !isNaN(a - parseFloat(a))\r\n              );\r\n            },\r\n            isPlainObject: function (a) {\r\n              var b, c;\r\n              return (\r\n                !(!a || "[object Object]" !== k.call(a)) &&\r\n                (!(b = e(a)) ||\r\n                  ((c = l.call(b, "constructor") && b.constructor),\r\n                  "function" == typeof c && m.call(c) === n))\r\n              );\r\n            },\r\n            isEmptyObject: function (a) {\r\n              var b;\r\n              for (b in a) return !1;\r\n              return !0;\r\n            },\r\n            type: function (a) {\r\n              return null == a\r\n                ? a + ""\r\n                : "object" == typeof a || "function" == typeof a\r\n                ? j[k.call(a)] || "object"\r\n                : typeof a;\r\n            },\r\n            globalEval: function (a) {\r\n              p(a);\r\n            },\r\n            camelCase: function (a) {\r\n              return a.replace(t, "ms-").replace(u, v);\r\n            },\r\n            each: function (a, b) {\r\n              var c,\r\n                d = 0;\r\n              if (w(a)) {\r\n                for (c = a.length; d < c; d++)\r\n                  if (b.call(a[d], d, a[d]) === !1) break;\r\n              } else for (d in a) if (b.call(a[d], d, a[d]) === !1) break;\r\n              return a;\r\n            },\r\n            trim: function (a) {\r\n              return null == a ? "" : (a + "").replace(s, "");\r\n            },\r\n            makeArray: function (a, b) {\r\n              var c = b || [];\r\n              return (\r\n                null != a &&\r\n                  (w(Object(a))\r\n                    ? r.merge(c, "string" == typeof a ? [a] : a)\r\n                    : h.call(c, a)),\r\n                c\r\n              );\r\n            },\r\n            inArray: function (a, b, c) {\r\n              return null == b ? -1 : i.call(b, a, c);\r\n            },\r\n            merge: function (a, b) {\r\n              for (var c = +b.length, d = 0, e = a.length; d < c; d++)\r\n                a[e++] = b[d];\r\n              return (a.length = e), a;\r\n            },\r\n            grep: function (a, b, c) {\r\n              for (var d, e = [], f = 0, g = a.length, h = !c; f < g; f++)\r\n                (d = !b(a[f], f)), d !== h && e.push(a[f]);\r\n              return e;\r\n            },\r\n            map: function (a, b, c) {\r\n              var d,\r\n                e,\r\n                f = 0,\r\n                h = [];\r\n              if (w(a))\r\n                for (d = a.length; f < d; f++)\r\n                  (e = b(a[f], f, c)), null != e && h.push(e);\r\n              else for (f in a) (e = b(a[f], f, c)), null != e && h.push(e);\r\n              return g.apply([], h);\r\n            },\r\n            guid: 1,\r\n            proxy: function (a, b) {\r\n              var c, d, e;\r\n              if (\r\n                ("string" == typeof b && ((c = a[b]), (b = a), (a = c)),\r\n                r.isFunction(a))\r\n              )\r\n                return (\r\n                  (d = f.call(arguments, 2)),\r\n                  (e = function () {\r\n                    return a.apply(b || this, d.concat(f.call(arguments)));\r\n                  }),\r\n                  (e.guid = a.guid = a.guid || r.guid++),\r\n                  e\r\n                );\r\n            },\r\n            now: Date.now,\r\n            support: o,\r\n          }),\r\n          "function" == typeof Symbol &&\r\n            (r.fn[Symbol.iterator] = c[Symbol.iterator]),\r\n          r.each(\r\n            "Boolean Number String Function Array Date RegExp Object Error Symbol".split(\r\n              " "\r\n            ),\r\n            function (a, b) {\r\n              j["[object " + b + "]"] = b.toLowerCase();\r\n            }\r\n          );\r\n        function w(a) {\r\n          var b = !!a && "length" in a && a.length,\r\n            c = r.type(a);\r\n          return (\r\n            "function" !== c &&\r\n            !r.isWindow(a) &&\r\n            ("array" === c ||\r\n              0 === b ||\r\n              ("number" == typeof b && b > 0 && b - 1 in a))\r\n          );\r\n        }\r\n        var x = (function (a) {\r\n          var b,\r\n            c,\r\n            d,\r\n            e,\r\n            f,\r\n            g,\r\n            h,\r\n            i,\r\n            j,\r\n            k,\r\n            l,\r\n            m,\r\n            n,\r\n            o,\r\n            p,\r\n            q,\r\n            r,\r\n            s,\r\n            t,\r\n            u = "sizzle" + 1 * new Date(),\r\n            v = a.document,\r\n            w = 0,\r\n            x = 0,\r\n            y = ha(),\r\n            z = ha(),\r\n            A = ha(),\r\n            B = function (a, b) {\r\n              return a === b && (l = !0), 0;\r\n            },\r\n            C = {}.hasOwnProperty,\r\n            D = [],\r\n            E = D.pop,\r\n            F = D.push,\r\n            G = D.push,\r\n            H = D.slice,\r\n            I = function (a, b) {\r\n              for (var c = 0, d = a.length; c < d; c++)\r\n                if (a[c] === b) return c;\r\n              return -1;\r\n            },\r\n            J =\r\n              "checked|selected|async|autofocus|autoplay|controls|defer|disabled|hidden|ismap|loop|multiple|open|readonly|required|scoped",\r\n            K = "[\\\\x20\\\\t\\\\r\\\\n\\\\f]",\r\n            L = "(?:\\\\\\\\.|[\\\\w-]|[^\\0-\\\\xa0])+",\r\n            M =\r\n              "\\\\[" +\r\n              K +\r\n              "*(" +\r\n              L +\r\n              ")(?:" +\r\n              K +\r\n              "*([*^$|!~]?=)" +\r\n              K +\r\n              "*(?:'((?:\\\\\\\\.|[^\\\\\\\\'])*)'|\\"((?:\\\\\\\\.|[^\\\\\\\\\\"])*)\\"|(" +\r\n              L +\r\n              "))|)" +\r\n              K +\r\n              "*\\\\]",\r\n            N =\r\n              ":(" +\r\n              L +\r\n              ")(?:\\\\((('((?:\\\\\\\\.|[^\\\\\\\\'])*)'|\\"((?:\\\\\\\\.|[^\\\\\\\\\\"])*)\\")|((?:\\\\\\\\.|[^\\\\\\\\()[\\\\]]|" +\r\n              M +\r\n              ")*)|.*)\\\\)|)",\r\n            O = new RegExp(K + "+", "g"),\r\n            P = new RegExp(\r\n              "^" + K + "+|((?:^|[^\\\\\\\\])(?:\\\\\\\\.)*)" + K + "+$",\r\n              "g"\r\n            ),\r\n            Q = new RegExp("^" + K + "*," + K + "*"),\r\n            R = new RegExp("^" + K + "*([>+~]|" + K + ")" + K + "*"),\r\n            S = new RegExp("=" + K + "*([^\\\\]'\\"]*?)" + K + "*\\\\]", "g"),\r\n            T = new RegExp(N),\r\n            U = new RegExp("^" + L + "$"),\r\n            V = {\r\n              ID: new RegExp("^#(" + L + ")"),\r\n              CLASS: new RegExp("^\\\\.(" + L + ")"),\r\n              TAG: new RegExp("^(" + L + "|[*])"),\r\n              ATTR: new RegExp("^" + M),\r\n              PSEUDO: new RegExp("^" + N),\r\n              CHILD: new RegExp(\r\n                "^:(only|first|last|nth|nth-last)-(child|of-type)(?:\\\\(" +\r\n                  K +\r\n                  "*(even|odd|(([+-]|)(\\\\d*)n|)" +\r\n                  K +\r\n                  "*(?:([+-]|)" +\r\n                  K +\r\n                  "*(\\\\d+)|))" +\r\n                  K +\r\n                  "*\\\\)|)",\r\n                "i"\r\n              ),\r\n              bool: new RegExp("^(?:" + J + ")$", "i"),\r\n              needsContext: new RegExp(\r\n                "^" +\r\n                  K +\r\n                  "*[>+~]|:(even|odd|eq|gt|lt|nth|first|last)(?:\\\\(" +\r\n                  K +\r\n                  "*((?:-\\\\d)?\\\\d*)" +\r\n                  K +\r\n                  "*\\\\)|)(?=[^-]|$)",\r\n                "i"\r\n              ),\r\n            },\r\n            W = /^(?:input|select|textarea|button)$/i,\r\n            X = /^h\\d$/i,\r\n            Y = /^[^{]+\\{\\s*\\[native \\w/,\r\n            Z = /^(?:#([\\w-]+)|(\\w+)|\\.([\\w-]+))$/,\r\n            $ = /[+~]/,\r\n            _ = new RegExp("\\\\\\\\([\\\\da-f]{1,6}" + K + "?|(" + K + ")|.)", "ig"),\r\n            aa = function (a, b, c) {\r\n              var d = "0x" + b - 65536;\r\n              return d !== d || c\r\n                ? b\r\n                : d < 0\r\n                ? String.fromCharCode(d + 65536)\r\n                : String.fromCharCode((d >> 10) | 55296, (1023 & d) | 56320);\r\n            },\r\n            ba = /([\\0-\\x1f\\x7f]|^-?\\d)|^-$|[^\\0-\\x1f\\x7f-\\uFFFF\\w-]/g,\r\n            ca = function (a, b) {\r\n              return b\r\n                ? "\\0" === a\r\n                  ? "\\ufffd"\r\n                  : a.slice(0, -1) +\r\n                    "\\\\" +\r\n                    a.charCodeAt(a.length - 1).toString(16) +\r\n                    " "\r\n                : "\\\\" + a;\r\n            },\r\n            da = function () {\r\n              m();\r\n            },\r\n            ea = ta(\r\n              function (a) {\r\n                return a.disabled === !0 && ("form" in a || "label" in a);\r\n              },\r\n              { dir: "parentNode", next: "legend" }\r\n            );\r\n          try {\r\n            G.apply((D = H.call(v.childNodes)), v.childNodes),\r\n              D[v.childNodes.length].nodeType;\r\n          } catch (fa) {\r\n            G = {\r\n              apply: D.length\r\n                ? function (a, b) {\r\n                    F.apply(a, H.call(b));\r\n                  }\r\n                : function (a, b) {\r\n                    var c = a.length,\r\n                      d = 0;\r\n                    while ((a[c++] = b[d++]));\r\n                    a.length = c - 1;\r\n                  },\r\n            };\r\n          }\r\n          function ga(a, b, d, e) {\r\n            var f,\r\n              h,\r\n              j,\r\n              k,\r\n              l,\r\n              o,\r\n              r,\r\n              s = b && b.ownerDocument,\r\n              w = b ? b.nodeType : 9;\r\n            if (\r\n              ((d = d || []),\r\n              "string" != typeof a || !a || (1 !== w && 9 !== w && 11 !== w))\r\n            )\r\n              return d;\r\n            if (\r\n              !e &&\r\n              ((b ? b.ownerDocument || b : v) !== n && m(b), (b = b || n), p)\r\n            ) {\r\n              if (11 !== w && (l = Z.exec(a)))\r\n                if ((f = l[1])) {\r\n                  if (9 === w) {\r\n                    if (!(j = b.getElementById(f))) return d;\r\n                    if (j.id === f) return d.push(j), d;\r\n                  } else if (\r\n                    s &&\r\n                    (j = s.getElementById(f)) &&\r\n                    t(b, j) &&\r\n                    j.id === f\r\n                  )\r\n                    return d.push(j), d;\r\n                } else {\r\n                  if (l[2]) return G.apply(d, b.getElementsByTagName(a)), d;\r\n                  if (\r\n                    (f = l[3]) &&\r\n                    c.getElementsByClassName &&\r\n                    b.getElementsByClassName\r\n                  )\r\n                    return G.apply(d, b.getElementsByClassName(f)), d;\r\n                }\r\n              if (c.qsa && !A[a + " "] && (!q || !q.test(a))) {\r\n                if (1 !== w) (s = b), (r = a);\r\n                else if ("object" !== b.nodeName.toLowerCase()) {\r\n                  (k = b.getAttribute("id"))\r\n                    ? (k = k.replace(ba, ca))\r\n                    : b.setAttribute("id", (k = u)),\r\n                    (o = g(a)),\r\n                    (h = o.length);\r\n                  while (h--) o[h] = "#" + k + " " + sa(o[h]);\r\n                  (r = o.join(",")), (s = ($.test(a) && qa(b.parentNode)) || b);\r\n                }\r\n                if (r)\r\n                  try {\r\n                    return G.apply(d, s.querySelectorAll(r)), d;\r\n                  } catch (x) {\r\n                  } finally {\r\n                    k === u && b.removeAttribute("id");\r\n                  }\r\n              }\r\n            }\r\n            return i(a.replace(P, "$1"), b, d, e);\r\n          }\r\n          function ha() {\r\n            var a = [];\r\n            function b(c, e) {\r\n              return (\r\n                a.push(c + " ") > d.cacheLength && delete b[a.shift()],\r\n                (b[c + " "] = e)\r\n              );\r\n            }\r\n            return b;\r\n          }\r\n          function ia(a) {\r\n            return (a[u] = !0), a;\r\n          }\r\n          function ja(a) {\r\n            var b = n.createElement("fieldset");\r\n            try {\r\n              return !!a(b);\r\n            } catch (c) {\r\n              return !1;\r\n            } finally {\r\n              b.parentNode && b.parentNode.removeChild(b), (b = null);\r\n            }\r\n          }\r\n          function ka(a, b) {\r\n            var c = a.split("|"),\r\n              e = c.length;\r\n            while (e--) d.attrHandle[c[e]] = b;\r\n          }\r\n          function la(a, b) {\r\n            var c = b && a,\r\n              d =\r\n                c &&\r\n                1 === a.nodeType &&\r\n                1 === b.nodeType &&\r\n                a.sourceIndex - b.sourceIndex;\r\n            if (d) return d;\r\n            if (c) while ((c = c.nextSibling)) if (c === b) return -1;\r\n            return a ? 1 : -1;\r\n          }\r\n          function ma(a) {\r\n            return function (b) {\r\n              var c = b.nodeName.toLowerCase();\r\n              return "input" === c && b.type === a;\r\n            };\r\n          }\r\n          function na(a) {\r\n            return function (b) {\r\n              var c = b.nodeName.toLowerCase();\r\n              return ("input" === c || "button" === c) && b.type === a;\r\n            };\r\n          }\r\n          function oa(a) {\r\n            return function (b) {\r\n              return "form" in b\r\n                ? b.parentNode && b.disabled === !1\r\n                  ? "label" in b\r\n                    ? "label" in b.parentNode\r\n                      ? b.parentNode.disabled === a\r\n                      : b.disabled === a\r\n                    : b.isDisabled === a || (b.isDisabled !== !a && ea(b) === a)\r\n                  : b.disabled === a\r\n                : "label" in b && b.disabled === a;\r\n            };\r\n          }\r\n          function pa(a) {\r\n            return ia(function (b) {\r\n              return (\r\n                (b = +b),\r\n                ia(function (c, d) {\r\n                  var e,\r\n                    f = a([], c.length, b),\r\n                    g = f.length;\r\n                  while (g--) c[(e = f[g])] && (c[e] = !(d[e] = c[e]));\r\n                })\r\n              );\r\n            });\r\n          }\r\n          function qa(a) {\r\n            return a && "undefined" != typeof a.getElementsByTagName && a;\r\n          }\r\n          (c = ga.support = {}),\r\n            (f = ga.isXML =\r\n              function (a) {\r\n                var b = a && (a.ownerDocument || a).documentElement;\r\n                return !!b && "HTML" !== b.nodeName;\r\n              }),\r\n            (m = ga.setDocument =\r\n              function (a) {\r\n                var b,\r\n                  e,\r\n                  g = a ? a.ownerDocument || a : v;\r\n                return g !== n && 9 === g.nodeType && g.documentElement\r\n                  ? ((n = g),\r\n                    (o = n.documentElement),\r\n                    (p = !f(n)),\r\n                    v !== n &&\r\n                      (e = n.defaultView) &&\r\n                      e.top !== e &&\r\n                      (e.addEventListener\r\n                        ? e.addEventListener("unload", da, !1)\r\n                        : e.attachEvent && e.attachEvent("onunload", da)),\r\n                    (c.attributes = ja(function (a) {\r\n                      return (a.className = "i"), !a.getAttribute("className");\r\n                    })),\r\n                    (c.getElementsByTagName = ja(function (a) {\r\n                      return (\r\n                        a.appendChild(n.createComment("")),\r\n                        !a.getElementsByTagName("*").length\r\n                      );\r\n                    })),\r\n                    (c.getElementsByClassName = Y.test(\r\n                      n.getElementsByClassName\r\n                    )),\r\n                    (c.getById = ja(function (a) {\r\n                      return (\r\n                        (o.appendChild(a).id = u),\r\n                        !n.getElementsByName || !n.getElementsByName(u).length\r\n                      );\r\n                    })),\r\n                    c.getById\r\n                      ? ((d.filter.ID = function (a) {\r\n                          var b = a.replace(_, aa);\r\n                          return function (a) {\r\n                            return a.getAttribute("id") === b;\r\n                          };\r\n                        }),\r\n                        (d.find.ID = function (a, b) {\r\n                          if ("undefined" != typeof b.getElementById && p) {\r\n                            var c = b.getElementById(a);\r\n                            return c ? [c] : [];\r\n                          }\r\n                        }))\r\n                      : ((d.filter.ID = function (a) {\r\n                          var b = a.replace(_, aa);\r\n                          return function (a) {\r\n                            var c =\r\n                              "undefined" != typeof a.getAttributeNode &&\r\n                              a.getAttributeNode("id");\r\n                            return c && c.value === b;\r\n                          };\r\n                        }),\r\n                        (d.find.ID = function (a, b) {\r\n                          if ("undefined" != typeof b.getElementById && p) {\r\n                            var c,\r\n                              d,\r\n                              e,\r\n                              f = b.getElementById(a);\r\n                            if (f) {\r\n                              if (\r\n                                ((c = f.getAttributeNode("id")),\r\n                                c && c.value === a)\r\n                              )\r\n                                return [f];\r\n                              (e = b.getElementsByName(a)), (d = 0);\r\n                              while ((f = e[d++]))\r\n                                if (\r\n                                  ((c = f.getAttributeNode("id")),\r\n                                  c && c.value === a)\r\n                                )\r\n                                  return [f];\r\n                            }\r\n                            return [];\r\n                          }\r\n                        })),\r\n                    (d.find.TAG = c.getElementsByTagName\r\n                      ? function (a, b) {\r\n                          return "undefined" != typeof b.getElementsByTagName\r\n                            ? b.getElementsByTagName(a)\r\n                            : c.qsa\r\n                            ? b.querySelectorAll(a)\r\n                            : void 0;\r\n                        }\r\n                      : function (a, b) {\r\n                          var c,\r\n                            d = [],\r\n                            e = 0,\r\n                            f = b.getElementsByTagName(a);\r\n                          if ("*" === a) {\r\n                            while ((c = f[e++])) 1 === c.nodeType && d.push(c);\r\n                            return d;\r\n                          }\r\n                          return f;\r\n                        }),\r\n                    (d.find.CLASS =\r\n                      c.getElementsByClassName &&\r\n                      function (a, b) {\r\n                        if ("undefined" != typeof b.getElementsByClassName && p)\r\n                          return b.getElementsByClassName(a);\r\n                      }),\r\n                    (r = []),\r\n                    (q = []),\r\n                    (c.qsa = Y.test(n.querySelectorAll)) &&\r\n                      (ja(function (a) {\r\n                        (o.appendChild(a).innerHTML =\r\n                          "<a id='" +\r\n                          u +\r\n                          "'></a><select id='" +\r\n                          u +\r\n                          "-\\r\\\\' msallowcapture=''><option selected=''></option></select>"),\r\n                          a.querySelectorAll("[msallowcapture^='']").length &&\r\n                            q.push("[*^$]=" + K + "*(?:''|\\"\\")"),\r\n                          a.querySelectorAll("[selected]").length ||\r\n                            q.push("\\\\[" + K + "*(?:value|" + J + ")"),\r\n                          a.querySelectorAll("[id~=" + u + "-]").length ||\r\n                            q.push("~="),\r\n                          a.querySelectorAll(":checked").length ||\r\n                            q.push(":checked"),\r\n                          a.querySelectorAll("a#" + u + "+*").length ||\r\n                            q.push(".#.+[+~]");\r\n                      }),\r\n                      ja(function (a) {\r\n                        a.innerHTML =\r\n                          "<a href='' disabled='disabled'></a><select disabled='disabled'><option/></select>";\r\n                        var b = n.createElement("input");\r\n                        b.setAttribute("type", "hidden"),\r\n                          a.appendChild(b).setAttribute("name", "D"),\r\n                          a.querySelectorAll("[name=d]").length &&\r\n                            q.push("name" + K + "*[*^$|!~]?="),\r\n                          2 !== a.querySelectorAll(":enabled").length &&\r\n                            q.push(":enabled", ":disabled"),\r\n                          (o.appendChild(a).disabled = !0),\r\n                          2 !== a.querySelectorAll(":disabled").length &&\r\n                            q.push(":enabled", ":disabled"),\r\n                          a.querySelectorAll("*,:x"),\r\n                          q.push(",.*:");\r\n                      })),\r\n                    (c.matchesSelector = Y.test(\r\n                      (s =\r\n                        o.matches ||\r\n                        o.webkitMatchesSelector ||\r\n                        o.mozMatchesSelector ||\r\n                        o.oMatchesSelector ||\r\n                        o.msMatchesSelector)\r\n                    )) &&\r\n                      ja(function (a) {\r\n                        (c.disconnectedMatch = s.call(a, "*")),\r\n                          s.call(a, "[s!='']:x"),\r\n                          r.push("!=", N);\r\n                      }),\r\n                    (q = q.length && new RegExp(q.join("|"))),\r\n                    (r = r.length && new RegExp(r.join("|"))),\r\n                    (b = Y.test(o.compareDocumentPosition)),\r\n                    (t =\r\n                      b || Y.test(o.contains)\r\n                        ? function (a, b) {\r\n                            var c = 9 === a.nodeType ? a.documentElement : a,\r\n                              d = b && b.parentNode;\r\n                            return (\r\n                              a === d ||\r\n                              !(\r\n                                !d ||\r\n                                1 !== d.nodeType ||\r\n                                !(c.contains\r\n                                  ? c.contains(d)\r\n                                  : a.compareDocumentPosition &&\r\n                                    16 & a.compareDocumentPosition(d))\r\n                              )\r\n                            );\r\n                          }\r\n                        : function (a, b) {\r\n                            if (b)\r\n                              while ((b = b.parentNode)) if (b === a) return !0;\r\n                            return !1;\r\n                          }),\r\n                    (B = b\r\n                      ? function (a, b) {\r\n                          if (a === b) return (l = !0), 0;\r\n                          var d =\r\n                            !a.compareDocumentPosition -\r\n                            !b.compareDocumentPosition;\r\n                          return d\r\n                            ? d\r\n                            : ((d =\r\n                                (a.ownerDocument || a) ===\r\n                                (b.ownerDocument || b)\r\n                                  ? a.compareDocumentPosition(b)\r\n                                  : 1),\r\n                              1 & d ||\r\n                              (!c.sortDetached &&\r\n                                b.compareDocumentPosition(a) === d)\r\n                                ? a === n || (a.ownerDocument === v && t(v, a))\r\n                                  ? -1\r\n                                  : b === n ||\r\n                                    (b.ownerDocument === v && t(v, b))\r\n                                  ? 1\r\n                                  : k\r\n                                  ? I(k, a) - I(k, b)\r\n                                  : 0\r\n                                : 4 & d\r\n                                ? -1\r\n                                : 1);\r\n                        }\r\n                      : function (a, b) {\r\n                          if (a === b) return (l = !0), 0;\r\n                          var c,\r\n                            d = 0,\r\n                            e = a.parentNode,\r\n                            f = b.parentNode,\r\n                            g = [a],\r\n                            h = [b];\r\n                          if (!e || !f)\r\n                            return a === n\r\n                              ? -1\r\n                              : b === n\r\n                              ? 1\r\n                              : e\r\n                              ? -1\r\n                              : f\r\n                              ? 1\r\n                              : k\r\n                              ? I(k, a) - I(k, b)\r\n                              : 0;\r\n                          if (e === f) return la(a, b);\r\n                          c = a;\r\n                          while ((c = c.parentNode)) g.unshift(c);\r\n                          c = b;\r\n                          while ((c = c.parentNode)) h.unshift(c);\r\n                          while (g[d] === h[d]) d++;\r\n                          return d\r\n                            ? la(g[d], h[d])\r\n                            : g[d] === v\r\n                            ? -1\r\n                            : h[d] === v\r\n                            ? 1\r\n                            : 0;\r\n                        }),\r\n                    n)\r\n                  : n;\r\n              }),\r\n            (ga.matches = function (a, b) {\r\n              return ga(a, null, null, b);\r\n            }),\r\n            (ga.matchesSelector = function (a, b) {\r\n              if (\r\n                ((a.ownerDocument || a) !== n && m(a),\r\n                (b = b.replace(S, "='$1']")),\r\n                c.matchesSelector &&\r\n                  p &&\r\n                  !A[b + " "] &&\r\n                  (!r || !r.test(b)) &&\r\n                  (!q || !q.test(b)))\r\n              )\r\n                try {\r\n                  var d = s.call(a, b);\r\n                  if (\r\n                    d ||\r\n                    c.disconnectedMatch ||\r\n                    (a.document && 11 !== a.document.nodeType)\r\n                  )\r\n                    return d;\r\n                } catch (e) {}\r\n              return ga(b, n, null, [a]).length > 0;\r\n            }),\r\n            (ga.contains = function (a, b) {\r\n              return (a.ownerDocument || a) !== n && m(a), t(a, b);\r\n            }),\r\n            (ga.attr = function (a, b) {\r\n              (a.ownerDocument || a) !== n && m(a);\r\n              var e = d.attrHandle[b.toLowerCase()],\r\n                f =\r\n                  e && C.call(d.attrHandle, b.toLowerCase())\r\n                    ? e(a, b, !p)\r\n                    : void 0;\r\n              return void 0 !== f\r\n                ? f\r\n                : c.attributes || !p\r\n                ? a.getAttribute(b)\r\n                : (f = a.getAttributeNode(b)) && f.specified\r\n                ? f.value\r\n                : null;\r\n            }),\r\n            (ga.escape = function (a) {\r\n              return (a + "").replace(ba, ca);\r\n            }),\r\n            (ga.error = function (a) {\r\n              throw new Error("Syntax error, unrecognized expression: " + a);\r\n            }),\r\n            (ga.uniqueSort = function (a) {\r\n              var b,\r\n                d = [],\r\n                e = 0,\r\n                f = 0;\r\n              if (\r\n                ((l = !c.detectDuplicates),\r\n                (k = !c.sortStable && a.slice(0)),\r\n                a.sort(B),\r\n                l)\r\n              ) {\r\n                while ((b = a[f++])) b === a[f] && (e = d.push(f));\r\n                while (e--) a.splice(d[e], 1);\r\n              }\r\n              return (k = null), a;\r\n            }),\r\n            (e = ga.getText =\r\n              function (a) {\r\n                var b,\r\n                  c = "",\r\n                  d = 0,\r\n                  f = a.nodeType;\r\n                if (f) {\r\n                  if (1 === f || 9 === f || 11 === f) {\r\n                    if ("string" == typeof a.textContent) return a.textContent;\r\n                    for (a = a.firstChild; a; a = a.nextSibling) c += e(a);\r\n                  } else if (3 === f || 4 === f) return a.nodeValue;\r\n                } else while ((b = a[d++])) c += e(b);\r\n                return c;\r\n              }),\r\n            (d = ga.selectors =\r\n              {\r\n                cacheLength: 50,\r\n                createPseudo: ia,\r\n                match: V,\r\n                attrHandle: {},\r\n                find: {},\r\n                relative: {\r\n                  ">": { dir: "parentNode", first: !0 },\r\n                  " ": { dir: "parentNode" },\r\n                  "+": { dir: "previousSibling", first: !0 },\r\n                  "~": { dir: "previousSibling" },\r\n                },\r\n                preFilter: {\r\n                  ATTR: function (a) {\r\n                    return (\r\n                      (a[1] = a[1].replace(_, aa)),\r\n                      (a[3] = (a[3] || a[4] || a[5] || "").replace(_, aa)),\r\n                      "~=" === a[2] && (a[3] = " " + a[3] + " "),\r\n                      a.slice(0, 4)\r\n                    );\r\n                  },\r\n                  CHILD: function (a) {\r\n                    return (\r\n                      (a[1] = a[1].toLowerCase()),\r\n                      "nth" === a[1].slice(0, 3)\r\n                        ? (a[3] || ga.error(a[0]),\r\n                          (a[4] = +(a[4]\r\n                            ? a[5] + (a[6] || 1)\r\n                            : 2 * ("even" === a[3] || "odd" === a[3]))),\r\n                          (a[5] = +(a[7] + a[8] || "odd" === a[3])))\r\n                        : a[3] && ga.error(a[0]),\r\n                      a\r\n                    );\r\n                  },\r\n                  PSEUDO: function (a) {\r\n                    var b,\r\n                      c = !a[6] && a[2];\r\n                    return V.CHILD.test(a[0])\r\n                      ? null\r\n                      : (a[3]\r\n                          ? (a[2] = a[4] || a[5] || "")\r\n                          : c &&\r\n                            T.test(c) &&\r\n                            (b = g(c, !0)) &&\r\n                            (b = c.indexOf(")", c.length - b) - c.length) &&\r\n                            ((a[0] = a[0].slice(0, b)), (a[2] = c.slice(0, b))),\r\n                        a.slice(0, 3));\r\n                  },\r\n                },\r\n                filter: {\r\n                  TAG: function (a) {\r\n                    var b = a.replace(_, aa).toLowerCase();\r\n                    return "*" === a\r\n                      ? function () {\r\n                          return !0;\r\n                        }\r\n                      : function (a) {\r\n                          return a.nodeName && a.nodeName.toLowerCase() === b;\r\n                        };\r\n                  },\r\n                  CLASS: function (a) {\r\n                    var b = y[a + " "];\r\n                    return (\r\n                      b ||\r\n                      ((b = new RegExp(\r\n                        "(^|" + K + ")" + a + "(" + K + "|$)"\r\n                      )) &&\r\n                        y(a, function (a) {\r\n                          return b.test(\r\n                            ("string" == typeof a.className && a.className) ||\r\n                              ("undefined" != typeof a.getAttribute &&\r\n                                a.getAttribute("class")) ||\r\n                              ""\r\n                          );\r\n                        }))\r\n                    );\r\n                  },\r\n                  ATTR: function (a, b, c) {\r\n                    return function (d) {\r\n                      var e = ga.attr(d, a);\r\n                      return null == e\r\n                        ? "!=" === b\r\n                        : !b ||\r\n                            ((e += ""),\r\n                            "=" === b\r\n                              ? e === c\r\n                              : "!=" === b\r\n                              ? e !== c\r\n                              : "^=" === b\r\n                              ? c && 0 === e.indexOf(c)\r\n                              : "*=" === b\r\n                              ? c && e.indexOf(c) > -1\r\n                              : "$=" === b\r\n                              ? c && e.slice(-c.length) === c\r\n                              : "~=" === b\r\n                              ? (" " + e.replace(O, " ") + " ").indexOf(c) > -1\r\n                              : "|=" === b &&\r\n                                (e === c ||\r\n                                  e.slice(0, c.length + 1) === c + "-"));\r\n                    };\r\n                  },\r\n                  CHILD: function (a, b, c, d, e) {\r\n                    var f = "nth" !== a.slice(0, 3),\r\n                      g = "last" !== a.slice(-4),\r\n                      h = "of-type" === b;\r\n                    return 1 === d && 0 === e\r\n                      ? function (a) {\r\n                          return !!a.parentNode;\r\n                        }\r\n                      : function (b, c, i) {\r\n                          var j,\r\n                            k,\r\n                            l,\r\n                            m,\r\n                            n,\r\n                            o,\r\n                            p = f !== g ? "nextSibling" : "previousSibling",\r\n                            q = b.parentNode,\r\n                            r = h && b.nodeName.toLowerCase(),\r\n                            s = !i && !h,\r\n                            t = !1;\r\n                          if (q) {\r\n                            if (f) {\r\n                              while (p) {\r\n                                m = b;\r\n                                while ((m = m[p]))\r\n                                  if (\r\n                                    h\r\n                                      ? m.nodeName.toLowerCase() === r\r\n                                      : 1 === m.nodeType\r\n                                  )\r\n                                    return !1;\r\n                                o = p = "only" === a && !o && "nextSibling";\r\n                              }\r\n                              return !0;\r\n                            }\r\n                            if (\r\n                              ((o = [g ? q.firstChild : q.lastChild]), g && s)\r\n                            ) {\r\n                              (m = q),\r\n                                (l = m[u] || (m[u] = {})),\r\n                                (k = l[m.uniqueID] || (l[m.uniqueID] = {})),\r\n                                (j = k[a] || []),\r\n                                (n = j[0] === w && j[1]),\r\n                                (t = n && j[2]),\r\n                                (m = n && q.childNodes[n]);\r\n                              while (\r\n                                (m =\r\n                                  (++n && m && m[p]) || (t = n = 0) || o.pop())\r\n                              )\r\n                                if (1 === m.nodeType && ++t && m === b) {\r\n                                  k[a] = [w, n, t];\r\n                                  break;\r\n                                }\r\n                            } else if (\r\n                              (s &&\r\n                                ((m = b),\r\n                                (l = m[u] || (m[u] = {})),\r\n                                (k = l[m.uniqueID] || (l[m.uniqueID] = {})),\r\n                                (j = k[a] || []),\r\n                                (n = j[0] === w && j[1]),\r\n                                (t = n)),\r\n                              t === !1)\r\n                            )\r\n                              while (\r\n                                (m =\r\n                                  (++n && m && m[p]) || (t = n = 0) || o.pop())\r\n                              )\r\n                                if (\r\n                                  (h\r\n                                    ? m.nodeName.toLowerCase() === r\r\n                                    : 1 === m.nodeType) &&\r\n                                  ++t &&\r\n                                  (s &&\r\n                                    ((l = m[u] || (m[u] = {})),\r\n                                    (k = l[m.uniqueID] || (l[m.uniqueID] = {})),\r\n                                    (k[a] = [w, t])),\r\n                                  m === b)\r\n                                )\r\n                                  break;\r\n                            return (\r\n                              (t -= e), t === d || (t % d === 0 && t / d >= 0)\r\n                            );\r\n                          }\r\n                        };\r\n                  },\r\n                  PSEUDO: function (a, b) {\r\n                    var c,\r\n                      e =\r\n                        d.pseudos[a] ||\r\n                        d.setFilters[a.toLowerCase()] ||\r\n                        ga.error("unsupported pseudo: " + a);\r\n                    return e[u]\r\n                      ? e(b)\r\n                      : e.length > 1\r\n                      ? ((c = [a, a, "", b]),\r\n                        d.setFilters.hasOwnProperty(a.toLowerCase())\r\n                          ? ia(function (a, c) {\r\n                              var d,\r\n                                f = e(a, b),\r\n                                g = f.length;\r\n                              while (g--)\r\n                                (d = I(a, f[g])), (a[d] = !(c[d] = f[g]));\r\n                            })\r\n                          : function (a) {\r\n                              return e(a, 0, c);\r\n                            })\r\n                      : e;\r\n                  },\r\n                },\r\n                pseudos: {\r\n                  not: ia(function (a) {\r\n                    var b = [],\r\n                      c = [],\r\n                      d = h(a.replace(P, "$1"));\r\n                    return d[u]\r\n                      ? ia(function (a, b, c, e) {\r\n                          var f,\r\n                            g = d(a, null, e, []),\r\n                            h = a.length;\r\n                          while (h--) (f = g[h]) && (a[h] = !(b[h] = f));\r\n                        })\r\n                      : function (a, e, f) {\r\n                          return (\r\n                            (b[0] = a),\r\n                            d(b, null, f, c),\r\n                            (b[0] = null),\r\n                            !c.pop()\r\n                          );\r\n                        };\r\n                  }),\r\n                  has: ia(function (a) {\r\n                    return function (b) {\r\n                      return ga(a, b).length > 0;\r\n                    };\r\n                  }),\r\n                  contains: ia(function (a) {\r\n                    return (\r\n                      (a = a.replace(_, aa)),\r\n                      function (b) {\r\n                        return (\r\n                          (b.textContent || b.innerText || e(b)).indexOf(a) > -1\r\n                        );\r\n                      }\r\n                    );\r\n                  }),\r\n                  lang: ia(function (a) {\r\n                    return (\r\n                      U.test(a || "") || ga.error("unsupported lang: " + a),\r\n                      (a = a.replace(_, aa).toLowerCase()),\r\n                      function (b) {\r\n                        var c;\r\n                        do\r\n                          if (\r\n                            (c = p\r\n                              ? b.lang\r\n                              : b.getAttribute("xml:lang") ||\r\n                                b.getAttribute("lang"))\r\n                          )\r\n                            return (\r\n                              (c = c.toLowerCase()),\r\n                              c === a || 0 === c.indexOf(a + "-")\r\n                            );\r\n                        while ((b = b.parentNode) && 1 === b.nodeType);\r\n                        return !1;\r\n                      }\r\n                    );\r\n                  }),\r\n                  target: function (b) {\r\n                    var c = a.location && a.location.hash;\r\n                    return c && c.slice(1) === b.id;\r\n                  },\r\n                  root: function (a) {\r\n                    return a === o;\r\n                  },\r\n                  focus: function (a) {\r\n                    return (\r\n                      a === n.activeElement &&\r\n                      (!n.hasFocus || n.hasFocus()) &&\r\n                      !!(a.type || a.href || ~a.tabIndex)\r\n                    );\r\n                  },\r\n                  enabled: oa(!1),\r\n                  disabled: oa(!0),\r\n                  checked: function (a) {\r\n                    var b = a.nodeName.toLowerCase();\r\n                    return (\r\n                      ("input" === b && !!a.checked) ||\r\n                      ("option" === b && !!a.selected)\r\n                    );\r\n                  },\r\n                  selected: function (a) {\r\n                    return (\r\n                      a.parentNode && a.parentNode.selectedIndex,\r\n                      a.selected === !0\r\n                    );\r\n                  },\r\n                  empty: function (a) {\r\n                    for (a = a.firstChild; a; a = a.nextSibling)\r\n                      if (a.nodeType < 6) return !1;\r\n                    return !0;\r\n                  },\r\n                  parent: function (a) {\r\n                    return !d.pseudos.empty(a);\r\n                  },\r\n                  header: function (a) {\r\n                    return X.test(a.nodeName);\r\n                  },\r\n                  input: function (a) {\r\n                    return W.test(a.nodeName);\r\n                  },\r\n                  button: function (a) {\r\n                    var b = a.nodeName.toLowerCase();\r\n                    return (\r\n                      ("input" === b && "button" === a.type) || "button" === b\r\n                    );\r\n                  },\r\n                  text: function (a) {\r\n                    var b;\r\n                    return (\r\n                      "input" === a.nodeName.toLowerCase() &&\r\n                      "text" === a.type &&\r\n                      (null == (b = a.getAttribute("type")) ||\r\n                        "text" === b.toLowerCase())\r\n                    );\r\n                  },\r\n                  first: pa(function () {\r\n                    return [0];\r\n                  }),\r\n                  last: pa(function (a, b) {\r\n                    return [b - 1];\r\n                  }),\r\n                  eq: pa(function (a, b, c) {\r\n                    return [c < 0 ? c + b : c];\r\n                  }),\r\n                  even: pa(function (a, b) {\r\n                    for (var c = 0; c < b; c += 2) a.push(c);\r\n                    return a;\r\n                  }),\r\n                  odd: pa(function (a, b) {\r\n                    for (var c = 1; c < b; c += 2) a.push(c);\r\n                    return a;\r\n                  }),\r\n                  lt: pa(function (a, b, c) {\r\n                    for (var d = c < 0 ? c + b : c; --d >= 0; ) a.push(d);\r\n                    return a;\r\n                  }),\r\n                  gt: pa(function (a, b, c) {\r\n                    for (var d = c < 0 ? c + b : c; ++d < b; ) a.push(d);\r\n                    return a;\r\n                  }),\r\n                },\r\n              }),\r\n            (d.pseudos.nth = d.pseudos.eq);\r\n          for (b in {\r\n            radio: !0,\r\n            checkbox: !0,\r\n            file: !0,\r\n            password: !0,\r\n            image: !0,\r\n          })\r\n            d.pseudos[b] = ma(b);\r\n          for (b in { submit: !0, reset: !0 }) d.pseudos[b] = na(b);\r\n          function ra() {}\r\n          (ra.prototype = d.filters = d.pseudos),\r\n            (d.setFilters = new ra()),\r\n            (g = ga.tokenize =\r\n              function (a, b) {\r\n                var c,\r\n                  e,\r\n                  f,\r\n                  g,\r\n                  h,\r\n                  i,\r\n                  j,\r\n                  k = z[a + " "];\r\n                if (k) return b ? 0 : k.slice(0);\r\n                (h = a), (i = []), (j = d.preFilter);\r\n                while (h) {\r\n                  (c && !(e = Q.exec(h))) ||\r\n                    (e && (h = h.slice(e[0].length) || h), i.push((f = []))),\r\n                    (c = !1),\r\n                    (e = R.exec(h)) &&\r\n                      ((c = e.shift()),\r\n                      f.push({ value: c, type: e[0].replace(P, " ") }),\r\n                      (h = h.slice(c.length)));\r\n                  for (g in d.filter)\r\n                    !(e = V[g].exec(h)) ||\r\n                      (j[g] && !(e = j[g](e))) ||\r\n                      ((c = e.shift()),\r\n                      f.push({ value: c, type: g, matches: e }),\r\n                      (h = h.slice(c.length)));\r\n                  if (!c) break;\r\n                }\r\n                return b ? h.length : h ? ga.error(a) : z(a, i).slice(0);\r\n              });\r\n          function sa(a) {\r\n            for (var b = 0, c = a.length, d = ""; b < c; b++) d += a[b].value;\r\n            return d;\r\n          }\r\n          function ta(a, b, c) {\r\n            var d = b.dir,\r\n              e = b.next,\r\n              f = e || d,\r\n              g = c && "parentNode" === f,\r\n              h = x++;\r\n            return b.first\r\n              ? function (b, c, e) {\r\n                  while ((b = b[d]))\r\n                    if (1 === b.nodeType || g) return a(b, c, e);\r\n                  return !1;\r\n                }\r\n              : function (b, c, i) {\r\n                  var j,\r\n                    k,\r\n                    l,\r\n                    m = [w, h];\r\n                  if (i) {\r\n                    while ((b = b[d]))\r\n                      if ((1 === b.nodeType || g) && a(b, c, i)) return !0;\r\n                  } else\r\n                    while ((b = b[d]))\r\n                      if (1 === b.nodeType || g)\r\n                        if (\r\n                          ((l = b[u] || (b[u] = {})),\r\n                          (k = l[b.uniqueID] || (l[b.uniqueID] = {})),\r\n                          e && e === b.nodeName.toLowerCase())\r\n                        )\r\n                          b = b[d] || b;\r\n                        else {\r\n                          if ((j = k[f]) && j[0] === w && j[1] === h)\r\n                            return (m[2] = j[2]);\r\n                          if (((k[f] = m), (m[2] = a(b, c, i)))) return !0;\r\n                        }\r\n                  return !1;\r\n                };\r\n          }\r\n          function ua(a) {\r\n            return a.length > 1\r\n              ? function (b, c, d) {\r\n                  var e = a.length;\r\n                  while (e--) if (!a[e](b, c, d)) return !1;\r\n                  return !0;\r\n                }\r\n              : a[0];\r\n          }\r\n          function va(a, b, c) {\r\n            for (var d = 0, e = b.length; d < e; d++) ga(a, b[d], c);\r\n            return c;\r\n          }\r\n          function wa(a, b, c, d, e) {\r\n            for (var f, g = [], h = 0, i = a.length, j = null != b; h < i; h++)\r\n              (f = a[h]) && ((c && !c(f, d, e)) || (g.push(f), j && b.push(h)));\r\n            return g;\r\n          }\r\n          function xa(a, b, c, d, e, f) {\r\n            return (\r\n              d && !d[u] && (d = xa(d)),\r\n              e && !e[u] && (e = xa(e, f)),\r\n              ia(function (f, g, h, i) {\r\n                var j,\r\n                  k,\r\n                  l,\r\n                  m = [],\r\n                  n = [],\r\n                  o = g.length,\r\n                  p = f || va(b || "*", h.nodeType ? [h] : h, []),\r\n                  q = !a || (!f && b) ? p : wa(p, m, a, h, i),\r\n                  r = c ? (e || (f ? a : o || d) ? [] : g) : q;\r\n                if ((c && c(q, r, h, i), d)) {\r\n                  (j = wa(r, n)), d(j, [], h, i), (k = j.length);\r\n                  while (k--) (l = j[k]) && (r[n[k]] = !(q[n[k]] = l));\r\n                }\r\n                if (f) {\r\n                  if (e || a) {\r\n                    if (e) {\r\n                      (j = []), (k = r.length);\r\n                      while (k--) (l = r[k]) && j.push((q[k] = l));\r\n                      e(null, (r = []), j, i);\r\n                    }\r\n                    k = r.length;\r\n                    while (k--)\r\n                      (l = r[k]) &&\r\n                        (j = e ? I(f, l) : m[k]) > -1 &&\r\n                        (f[j] = !(g[j] = l));\r\n                  }\r\n                } else (r = wa(r === g ? r.splice(o, r.length) : r)), e ? e(null, g, r, i) : G.apply(g, r);\r\n              })\r\n            );\r\n          }\r\n          function ya(a) {\r\n            for (\r\n              var b,\r\n                c,\r\n                e,\r\n                f = a.length,\r\n                g = d.relative[a[0].type],\r\n                h = g || d.relative[" "],\r\n                i = g ? 1 : 0,\r\n                k = ta(\r\n                  function (a) {\r\n                    return a === b;\r\n                  },\r\n                  h,\r\n                  !0\r\n                ),\r\n                l = ta(\r\n                  function (a) {\r\n                    return I(b, a) > -1;\r\n                  },\r\n                  h,\r\n                  !0\r\n                ),\r\n                m = [\r\n                  function (a, c, d) {\r\n                    var e =\r\n                      (!g && (d || c !== j)) ||\r\n                      ((b = c).nodeType ? k(a, c, d) : l(a, c, d));\r\n                    return (b = null), e;\r\n                  },\r\n                ];\r\n              i < f;\r\n              i++\r\n            )\r\n              if ((c = d.relative[a[i].type])) m = [ta(ua(m), c)];\r\n              else {\r\n                if (\r\n                  ((c = d.filter[a[i].type].apply(null, a[i].matches)), c[u])\r\n                ) {\r\n                  for (e = ++i; e < f; e++) if (d.relative[a[e].type]) break;\r\n                  return xa(\r\n                    i > 1 && ua(m),\r\n                    i > 1 &&\r\n                      sa(\r\n                        a\r\n                          .slice(0, i - 1)\r\n                          .concat({ value: " " === a[i - 2].type ? "*" : "" })\r\n                      ).replace(P, "$1"),\r\n                    c,\r\n                    i < e && ya(a.slice(i, e)),\r\n                    e < f && ya((a = a.slice(e))),\r\n                    e < f && sa(a)\r\n                  );\r\n                }\r\n                m.push(c);\r\n              }\r\n            return ua(m);\r\n          }\r\n          function za(a, b) {\r\n            var c = b.length > 0,\r\n              e = a.length > 0,\r\n              f = function (f, g, h, i, k) {\r\n                var l,\r\n                  o,\r\n                  q,\r\n                  r = 0,\r\n                  s = "0",\r\n                  t = f && [],\r\n                  u = [],\r\n                  v = j,\r\n                  x = f || (e && d.find.TAG("*", k)),\r\n                  y = (w += null == v ? 1 : Math.random() || 0.1),\r\n                  z = x.length;\r\n                for (\r\n                  k && (j = g === n || g || k);\r\n                  s !== z && null != (l = x[s]);\r\n                  s++\r\n                ) {\r\n                  if (e && l) {\r\n                    (o = 0), g || l.ownerDocument === n || (m(l), (h = !p));\r\n                    while ((q = a[o++]))\r\n                      if (q(l, g || n, h)) {\r\n                        i.push(l);\r\n                        break;\r\n                      }\r\n                    k && (w = y);\r\n                  }\r\n                  c && ((l = !q && l) && r--, f && t.push(l));\r\n                }\r\n                if (((r += s), c && s !== r)) {\r\n                  o = 0;\r\n                  while ((q = b[o++])) q(t, u, g, h);\r\n                  if (f) {\r\n                    if (r > 0) while (s--) t[s] || u[s] || (u[s] = E.call(i));\r\n                    u = wa(u);\r\n                  }\r\n                  G.apply(i, u),\r\n                    k &&\r\n                      !f &&\r\n                      u.length > 0 &&\r\n                      r + b.length > 1 &&\r\n                      ga.uniqueSort(i);\r\n                }\r\n                return k && ((w = y), (j = v)), t;\r\n              };\r\n            return c ? ia(f) : f;\r\n          }\r\n          return (\r\n            (h = ga.compile =\r\n              function (a, b) {\r\n                var c,\r\n                  d = [],\r\n                  e = [],\r\n                  f = A[a + " "];\r\n                if (!f) {\r\n                  b || (b = g(a)), (c = b.length);\r\n                  while (c--) (f = ya(b[c])), f[u] ? d.push(f) : e.push(f);\r\n                  (f = A(a, za(e, d))), (f.selector = a);\r\n                }\r\n                return f;\r\n              }),\r\n            (i = ga.select =\r\n              function (a, b, c, e) {\r\n                var f,\r\n                  i,\r\n                  j,\r\n                  k,\r\n                  l,\r\n                  m = "function" == typeof a && a,\r\n                  n = !e && g((a = m.selector || a));\r\n                if (((c = c || []), 1 === n.length)) {\r\n                  if (\r\n                    ((i = n[0] = n[0].slice(0)),\r\n                    i.length > 2 &&\r\n                      "ID" === (j = i[0]).type &&\r\n                      9 === b.nodeType &&\r\n                      p &&\r\n                      d.relative[i[1].type])\r\n                  ) {\r\n                    if (\r\n                      ((b = (d.find.ID(j.matches[0].replace(_, aa), b) ||\r\n                        [])[0]),\r\n                      !b)\r\n                    )\r\n                      return c;\r\n                    m && (b = b.parentNode),\r\n                      (a = a.slice(i.shift().value.length));\r\n                  }\r\n                  f = V.needsContext.test(a) ? 0 : i.length;\r\n                  while (f--) {\r\n                    if (((j = i[f]), d.relative[(k = j.type)])) break;\r\n                    if (\r\n                      (l = d.find[k]) &&\r\n                      (e = l(\r\n                        j.matches[0].replace(_, aa),\r\n                        ($.test(i[0].type) && qa(b.parentNode)) || b\r\n                      ))\r\n                    ) {\r\n                      if ((i.splice(f, 1), (a = e.length && sa(i)), !a))\r\n                        return G.apply(c, e), c;\r\n                      break;\r\n                    }\r\n                  }\r\n                }\r\n                return (\r\n                  (m || h(a, n))(\r\n                    e,\r\n                    b,\r\n                    !p,\r\n                    c,\r\n                    !b || ($.test(a) && qa(b.parentNode)) || b\r\n                  ),\r\n                  c\r\n                );\r\n              }),\r\n            (c.sortStable = u.split("").sort(B).join("") === u),\r\n            (c.detectDuplicates = !!l),\r\n            m(),\r\n            (c.sortDetached = ja(function (a) {\r\n              return 1 & a.compareDocumentPosition(n.createElement("fieldset"));\r\n            })),\r\n            ja(function (a) {\r\n              return (\r\n                (a.innerHTML = "<a href='#'></a>"),\r\n                "#" === a.firstChild.getAttribute("href")\r\n              );\r\n            }) ||\r\n              ka("type|href|height|width", function (a, b, c) {\r\n                if (!c)\r\n                  return a.getAttribute(b, "type" === b.toLowerCase() ? 1 : 2);\r\n              }),\r\n            (c.attributes &&\r\n              ja(function (a) {\r\n                return (\r\n                  (a.innerHTML = "<input/>"),\r\n                  a.firstChild.setAttribute("value", ""),\r\n                  "" === a.firstChild.getAttribute("value")\r\n                );\r\n              })) ||\r\n              ka("value", function (a, b, c) {\r\n                if (!c && "input" === a.nodeName.toLowerCase())\r\n                  return a.defaultValue;\r\n              }),\r\n            ja(function (a) {\r\n              return null == a.getAttribute("disabled");\r\n            }) ||\r\n              ka(J, function (a, b, c) {\r\n                var d;\r\n                if (!c)\r\n                  return a[b] === !0\r\n                    ? b.toLowerCase()\r\n                    : (d = a.getAttributeNode(b)) && d.specified\r\n                    ? d.value\r\n                    : null;\r\n              }),\r\n            ga\r\n          );\r\n        })(a);\r\n        (r.find = x),\r\n          (r.expr = x.selectors),\r\n          (r.expr[":"] = r.expr.pseudos),\r\n          (r.uniqueSort = r.unique = x.uniqueSort),\r\n          (r.text = x.getText),\r\n          (r.isXMLDoc = x.isXML),\r\n          (r.contains = x.contains),\r\n          (r.escapeSelector = x.escape);\r\n        var y = function (a, b, c) {\r\n            var d = [],\r\n              e = void 0 !== c;\r\n            while ((a = a[b]) && 9 !== a.nodeType)\r\n              if (1 === a.nodeType) {\r\n                if (e && r(a).is(c)) break;\r\n                d.push(a);\r\n              }\r\n            return d;\r\n          },\r\n          z = function (a, b) {\r\n            for (var c = []; a; a = a.nextSibling)\r\n              1 === a.nodeType && a !== b && c.push(a);\r\n            return c;\r\n          },\r\n          A = r.expr.match.needsContext;\r\n        function B(a, b) {\r\n          return a.nodeName && a.nodeName.toLowerCase() === b.toLowerCase();\r\n        }\r\n        var C =\r\n            /^<([a-z][^\\/\\0>:\\x20\\t\\r\\n\\f]*)[\\x20\\t\\r\\n\\f]*\\/?>(?:<\\/\\1>|)$/i,\r\n          D = /^.[^:#\\[\\.,]*$/;\r\n        function E(a, b, c) {\r\n          return r.isFunction(b)\r\n            ? r.grep(a, function (a, d) {\r\n                return !!b.call(a, d, a) !== c;\r\n              })\r\n            : b.nodeType\r\n            ? r.grep(a, function (a) {\r\n                return (a === b) !== c;\r\n              })\r\n            : "string" != typeof b\r\n            ? r.grep(a, function (a) {\r\n                return i.call(b, a) > -1 !== c;\r\n              })\r\n            : D.test(b)\r\n            ? r.filter(b, a, c)\r\n            : ((b = r.filter(b, a)),\r\n              r.grep(a, function (a) {\r\n                return i.call(b, a) > -1 !== c && 1 === a.nodeType;\r\n              }));\r\n        }\r\n        (r.filter = function (a, b, c) {\r\n          var d = b[0];\r\n          return (\r\n            c && (a = ":not(" + a + ")"),\r\n            1 === b.length && 1 === d.nodeType\r\n              ? r.find.matchesSelector(d, a)\r\n                ? [d]\r\n                : []\r\n              : r.find.matches(\r\n                  a,\r\n                  r.grep(b, function (a) {\r\n                    return 1 === a.nodeType;\r\n                  })\r\n                )\r\n          );\r\n        }),\r\n          r.fn.extend({\r\n            find: function (a) {\r\n              var b,\r\n                c,\r\n                d = this.length,\r\n                e = this;\r\n              if ("string" != typeof a)\r\n                return this.pushStack(\r\n                  r(a).filter(function () {\r\n                    for (b = 0; b < d; b++)\r\n                      if (r.contains(e[b], this)) return !0;\r\n                  })\r\n                );\r\n              for (c = this.pushStack([]), b = 0; b < d; b++)\r\n                r.find(a, e[b], c);\r\n              return d > 1 ? r.uniqueSort(c) : c;\r\n            },\r\n            filter: function (a) {\r\n              return this.pushStack(E(this, a || [], !1));\r\n            },\r\n            not: function (a) {\r\n              return this.pushStack(E(this, a || [], !0));\r\n            },\r\n            is: function (a) {\r\n              return !!E(\r\n                this,\r\n                "string" == typeof a && A.test(a) ? r(a) : a || [],\r\n                !1\r\n              ).length;\r\n            },\r\n          });\r\n        var F,\r\n          G = /^(?:\\s*(<[\\w\\W]+>)[^>]*|#([\\w-]+))$/,\r\n          H = (r.fn.init = function (a, b, c) {\r\n            var e, f;\r\n            if (!a) return this;\r\n            if (((c = c || F), "string" == typeof a)) {\r\n              if (\r\n                ((e =\r\n                  "<" === a[0] && ">" === a[a.length - 1] && a.length >= 3\r\n                    ? [null, a, null]\r\n                    : G.exec(a)),\r\n                !e || (!e[1] && b))\r\n              )\r\n                return !b || b.jquery\r\n                  ? (b || c).find(a)\r\n                  : this.constructor(b).find(a);\r\n              if (e[1]) {\r\n                if (\r\n                  ((b = b instanceof r ? b[0] : b),\r\n                  r.merge(\r\n                    this,\r\n                    r.parseHTML(\r\n                      e[1],\r\n                      b && b.nodeType ? b.ownerDocument || b : d,\r\n                      !0\r\n                    )\r\n                  ),\r\n                  C.test(e[1]) && r.isPlainObject(b))\r\n                )\r\n                  for (e in b)\r\n                    r.isFunction(this[e]) ? this[e](b[e]) : this.attr(e, b[e]);\r\n                return this;\r\n              }\r\n              return (\r\n                (f = d.getElementById(e[2])),\r\n                f && ((this[0] = f), (this.length = 1)),\r\n                this\r\n              );\r\n            }\r\n            return a.nodeType\r\n              ? ((this[0] = a), (this.length = 1), this)\r\n              : r.isFunction(a)\r\n              ? void 0 !== c.ready\r\n                ? c.ready(a)\r\n                : a(r)\r\n              : r.makeArray(a, this);\r\n          });\r\n        (H.prototype = r.fn), (F = r(d));\r\n        var I = /^(?:parents|prev(?:Until|All))/,\r\n          J = { children: !0, contents: !0, next: !0, prev: !0 };\r\n        r.fn.extend({\r\n          has: function (a) {\r\n            var b = r(a, this),\r\n              c = b.length;\r\n            return this.filter(function () {\r\n              for (var a = 0; a < c; a++) if (r.contains(this, b[a])) return !0;\r\n            });\r\n          },\r\n          closest: function (a, b) {\r\n            var c,\r\n              d = 0,\r\n              e = this.length,\r\n              f = [],\r\n              g = "string" != typeof a && r(a);\r\n            if (!A.test(a))\r\n              for (; d < e; d++)\r\n                for (c = this[d]; c && c !== b; c = c.parentNode)\r\n                  if (\r\n                    c.nodeType < 11 &&\r\n                    (g\r\n                      ? g.index(c) > -1\r\n                      : 1 === c.nodeType && r.find.matchesSelector(c, a))\r\n                  ) {\r\n                    f.push(c);\r\n                    break;\r\n                  }\r\n            return this.pushStack(f.length > 1 ? r.uniqueSort(f) : f);\r\n          },\r\n          index: function (a) {\r\n            return a\r\n              ? "string" == typeof a\r\n                ? i.call(r(a), this[0])\r\n                : i.call(this, a.jquery ? a[0] : a)\r\n              : this[0] && this[0].parentNode\r\n              ? this.first().prevAll().length\r\n              : -1;\r\n          },\r\n          add: function (a, b) {\r\n            return this.pushStack(r.uniqueSort(r.merge(this.get(), r(a, b))));\r\n          },\r\n          addBack: function (a) {\r\n            return this.add(\r\n              null == a ? this.prevObject : this.prevObject.filter(a)\r\n            );\r\n          },\r\n        });\r\n        function K(a, b) {\r\n          while ((a = a[b]) && 1 !== a.nodeType);\r\n          return a;\r\n        }\r\n        r.each(\r\n          {\r\n            parent: function (a) {\r\n              var b = a.parentNode;\r\n              return b && 11 !== b.nodeType ? b : null;\r\n            },\r\n            parents: function (a) {\r\n              return y(a, "parentNode");\r\n            },\r\n            parentsUntil: function (a, b, c) {\r\n              return y(a, "parentNode", c);\r\n            },\r\n            next: function (a) {\r\n              return K(a, "nextSibling");\r\n            },\r\n            prev: function (a) {\r\n              return K(a, "previousSibling");\r\n            },\r\n            nextAll: function (a) {\r\n              return y(a, "nextSibling");\r\n            },\r\n            prevAll: function (a) {\r\n              return y(a, "previousSibling");\r\n            },\r\n            nextUntil: function (a, b, c) {\r\n              return y(a, "nextSibling", c);\r\n            },\r\n            prevUntil: function (a, b, c) {\r\n              return y(a, "previousSibling", c);\r\n            },\r\n            siblings: function (a) {\r\n              return z((a.parentNode || {}).firstChild, a);\r\n            },\r\n            children: function (a) {\r\n              return z(a.firstChild);\r\n            },\r\n            contents: function (a) {\r\n              return B(a, "iframe")\r\n                ? a.contentDocument\r\n                : (B(a, "template") && (a = a.content || a),\r\n                  r.merge([], a.childNodes));\r\n            },\r\n          },\r\n          function (a, b) {\r\n            r.fn[a] = function (c, d) {\r\n              var e = r.map(this, b, c);\r\n              return (\r\n                "Until" !== a.slice(-5) && (d = c),\r\n                d && "string" == typeof d && (e = r.filter(d, e)),\r\n                this.length > 1 &&\r\n                  (J[a] || r.uniqueSort(e), I.test(a) && e.reverse()),\r\n                this.pushStack(e)\r\n              );\r\n            };\r\n          }\r\n        );\r\n        var L = /[^\\x20\\t\\r\\n\\f]+/g;\r\n        function M(a) {\r\n          var b = {};\r\n          return (\r\n            r.each(a.match(L) || [], function (a, c) {\r\n              b[c] = !0;\r\n            }),\r\n            b\r\n          );\r\n        }\r\n        r.Callbacks = function (a) {\r\n          a = "string" == typeof a ? M(a) : r.extend({}, a);\r\n          var b,\r\n            c,\r\n            d,\r\n            e,\r\n            f = [],\r\n            g = [],\r\n            h = -1,\r\n            i = function () {\r\n              for (e = e || a.once, d = b = !0; g.length; h = -1) {\r\n                c = g.shift();\r\n                while (++h < f.length)\r\n                  f[h].apply(c[0], c[1]) === !1 &&\r\n                    a.stopOnFalse &&\r\n                    ((h = f.length), (c = !1));\r\n              }\r\n              a.memory || (c = !1), (b = !1), e && (f = c ? [] : "");\r\n            },\r\n            j = {\r\n              add: function () {\r\n                return (\r\n                  f &&\r\n                    (c && !b && ((h = f.length - 1), g.push(c)),\r\n                    (function d(b) {\r\n                      r.each(b, function (b, c) {\r\n                        r.isFunction(c)\r\n                          ? (a.unique && j.has(c)) || f.push(c)\r\n                          : c && c.length && "string" !== r.type(c) && d(c);\r\n                      });\r\n                    })(arguments),\r\n                    c && !b && i()),\r\n                  this\r\n                );\r\n              },\r\n              remove: function () {\r\n                return (\r\n                  r.each(arguments, function (a, b) {\r\n                    var c;\r\n                    while ((c = r.inArray(b, f, c)) > -1)\r\n                      f.splice(c, 1), c <= h && h--;\r\n                  }),\r\n                  this\r\n                );\r\n              },\r\n              has: function (a) {\r\n                return a ? r.inArray(a, f) > -1 : f.length > 0;\r\n              },\r\n              empty: function () {\r\n                return f && (f = []), this;\r\n              },\r\n              disable: function () {\r\n                return (e = g = []), (f = c = ""), this;\r\n              },\r\n              disabled: function () {\r\n                return !f;\r\n              },\r\n              lock: function () {\r\n                return (e = g = []), c || b || (f = c = ""), this;\r\n              },\r\n              locked: function () {\r\n                return !!e;\r\n              },\r\n              fireWith: function (a, c) {\r\n                return (\r\n                  e ||\r\n                    ((c = c || []),\r\n                    (c = [a, c.slice ? c.slice() : c]),\r\n                    g.push(c),\r\n                    b || i()),\r\n                  this\r\n                );\r\n              },\r\n              fire: function () {\r\n                return j.fireWith(this, arguments), this;\r\n              },\r\n              fired: function () {\r\n                return !!d;\r\n              },\r\n            };\r\n          return j;\r\n        };\r\n        function N(a) {\r\n          return a;\r\n        }\r\n        function O(a) {\r\n          throw a;\r\n        }\r\n        function P(a, b, c, d) {\r\n          var e;\r\n          try {\r\n            a && r.isFunction((e = a.promise))\r\n              ? e.call(a).done(b).fail(c)\r\n              : a && r.isFunction((e = a.then))\r\n              ? e.call(a, b, c)\r\n              : b.apply(void 0, [a].slice(d));\r\n          } catch (a) {\r\n            c.apply(void 0, [a]);\r\n          }\r\n        }\r\n        r.extend({\r\n          Deferred: function (b) {\r\n            var c = [\r\n                [\r\n                  "notify",\r\n                  "progress",\r\n                  r.Callbacks("memory"),\r\n                  r.Callbacks("memory"),\r\n                  2,\r\n                ],\r\n                [\r\n                  "resolve",\r\n                  "done",\r\n                  r.Callbacks("once memory"),\r\n                  r.Callbacks("once memory"),\r\n                  0,\r\n                  "resolved",\r\n                ],\r\n                [\r\n                  "reject",\r\n                  "fail",\r\n                  r.Callbacks("once memory"),\r\n                  r.Callbacks("once memory"),\r\n                  1,\r\n                  "rejected",\r\n                ],\r\n              ],\r\n              d = "pending",\r\n              e = {\r\n                state: function () {\r\n                  return d;\r\n                },\r\n                always: function () {\r\n                  return f.done(arguments).fail(arguments), this;\r\n                },\r\n                catch: function (a) {\r\n                  return e.then(null, a);\r\n                },\r\n                pipe: function () {\r\n                  var a = arguments;\r\n                  return r\r\n                    .Deferred(function (b) {\r\n                      r.each(c, function (c, d) {\r\n                        var e = r.isFunction(a[d[4]]) && a[d[4]];\r\n                        f[d[1]](function () {\r\n                          var a = e && e.apply(this, arguments);\r\n                          a && r.isFunction(a.promise)\r\n                            ? a\r\n                                .promise()\r\n                                .progress(b.notify)\r\n                                .done(b.resolve)\r\n                                .fail(b.reject)\r\n                            : b[d[0] + "With"](this, e ? [a] : arguments);\r\n                        });\r\n                      }),\r\n                        (a = null);\r\n                    })\r\n                    .promise();\r\n                },\r\n                then: function (b, d, e) {\r\n                  var f = 0;\r\n                  function g(b, c, d, e) {\r\n                    return function () {\r\n                      var h = this,\r\n                        i = arguments,\r\n                        j = function () {\r\n                          var a, j;\r\n                          if (!(b < f)) {\r\n                            if (((a = d.apply(h, i)), a === c.promise()))\r\n                              throw new TypeError("Thenable self-resolution");\r\n                            (j =\r\n                              a &&\r\n                              ("object" == typeof a ||\r\n                                "function" == typeof a) &&\r\n                              a.then),\r\n                              r.isFunction(j)\r\n                                ? e\r\n                                  ? j.call(a, g(f, c, N, e), g(f, c, O, e))\r\n                                  : (f++,\r\n                                    j.call(\r\n                                      a,\r\n                                      g(f, c, N, e),\r\n                                      g(f, c, O, e),\r\n                                      g(f, c, N, c.notifyWith)\r\n                                    ))\r\n                                : (d !== N && ((h = void 0), (i = [a])),\r\n                                  (e || c.resolveWith)(h, i));\r\n                          }\r\n                        },\r\n                        k = e\r\n                          ? j\r\n                          : function () {\r\n                              try {\r\n                                j();\r\n                              } catch (a) {\r\n                                r.Deferred.exceptionHook &&\r\n                                  r.Deferred.exceptionHook(a, k.stackTrace),\r\n                                  b + 1 >= f &&\r\n                                    (d !== O && ((h = void 0), (i = [a])),\r\n                                    c.rejectWith(h, i));\r\n                              }\r\n                            };\r\n                      b\r\n                        ? k()\r\n                        : (r.Deferred.getStackHook &&\r\n                            (k.stackTrace = r.Deferred.getStackHook()),\r\n                          a.setTimeout(k));\r\n                    };\r\n                  }\r\n                  return r\r\n                    .Deferred(function (a) {\r\n                      c[0][3].add(\r\n                        g(0, a, r.isFunction(e) ? e : N, a.notifyWith)\r\n                      ),\r\n                        c[1][3].add(g(0, a, r.isFunction(b) ? b : N)),\r\n                        c[2][3].add(g(0, a, r.isFunction(d) ? d : O));\r\n                    })\r\n                    .promise();\r\n                },\r\n                promise: function (a) {\r\n                  return null != a ? r.extend(a, e) : e;\r\n                },\r\n              },\r\n              f = {};\r\n            return (\r\n              r.each(c, function (a, b) {\r\n                var g = b[2],\r\n                  h = b[5];\r\n                (e[b[1]] = g.add),\r\n                  h &&\r\n                    g.add(\r\n                      function () {\r\n                        d = h;\r\n                      },\r\n                      c[3 - a][2].disable,\r\n                      c[0][2].lock\r\n                    ),\r\n                  g.add(b[3].fire),\r\n                  (f[b[0]] = function () {\r\n                    return (\r\n                      f[b[0] + "With"](this === f ? void 0 : this, arguments),\r\n                      this\r\n                    );\r\n                  }),\r\n                  (f[b[0] + "With"] = g.fireWith);\r\n              }),\r\n              e.promise(f),\r\n              b && b.call(f, f),\r\n              f\r\n            );\r\n          },\r\n          when: function (a) {\r\n            var b = arguments.length,\r\n              c = b,\r\n              d = Array(c),\r\n              e = f.call(arguments),\r\n              g = r.Deferred(),\r\n              h = function (a) {\r\n                return function (c) {\r\n                  (d[a] = this),\r\n                    (e[a] = arguments.length > 1 ? f.call(arguments) : c),\r\n                    --b || g.resolveWith(d, e);\r\n                };\r\n              };\r\n            if (\r\n              b <= 1 &&\r\n              (P(a, g.done(h(c)).resolve, g.reject, !b),\r\n              "pending" === g.state() || r.isFunction(e[c] && e[c].then))\r\n            )\r\n              return g.then();\r\n            while (c--) P(e[c], h(c), g.reject);\r\n            return g.promise();\r\n          },\r\n        });\r\n        var Q = /^(Eval|Internal|Range|Reference|Syntax|Type|URI)Error$/;\r\n        (r.Deferred.exceptionHook = function (b, c) {\r\n          a.console &&\r\n            a.console.warn &&\r\n            b &&\r\n            Q.test(b.name) &&\r\n            a.console.warn(\r\n              "jQuery.Deferred exception: " + b.message,\r\n              b.stack,\r\n              c\r\n            );\r\n        }),\r\n          (r.readyException = function (b) {\r\n            a.setTimeout(function () {\r\n              throw b;\r\n            });\r\n          });\r\n        var R = r.Deferred();\r\n        (r.fn.ready = function (a) {\r\n          return (\r\n            R.then(a)["catch"](function (a) {\r\n              r.readyException(a);\r\n            }),\r\n            this\r\n          );\r\n        }),\r\n          r.extend({\r\n            isReady: !1,\r\n            readyWait: 1,\r\n            ready: function (a) {\r\n              (a === !0 ? --r.readyWait : r.isReady) ||\r\n                ((r.isReady = !0),\r\n                (a !== !0 && --r.readyWait > 0) || R.resolveWith(d, [r]));\r\n            },\r\n          }),\r\n          (r.ready.then = R.then);\r\n        function S() {\r\n          d.removeEventListener("DOMContentLoaded", S),\r\n            a.removeEventListener("load", S),\r\n            r.ready();\r\n        }\r\n        "complete" === d.readyState ||\r\n        ("loading" !== d.readyState && !d.documentElement.doScroll)\r\n          ? a.setTimeout(r.ready)\r\n          : (d.addEventListener("DOMContentLoaded", S),\r\n            a.addEventListener("load", S));\r\n        var T = function (a, b, c, d, e, f, g) {\r\n            var h = 0,\r\n              i = a.length,\r\n              j = null == c;\r\n            if ("object" === r.type(c)) {\r\n              e = !0;\r\n              for (h in c) T(a, b, h, c[h], !0, f, g);\r\n            } else if (\r\n              void 0 !== d &&\r\n              ((e = !0),\r\n              r.isFunction(d) || (g = !0),\r\n              j &&\r\n                (g\r\n                  ? (b.call(a, d), (b = null))\r\n                  : ((j = b),\r\n                    (b = function (a, b, c) {\r\n                      return j.call(r(a), c);\r\n                    }))),\r\n              b)\r\n            )\r\n              for (; h < i; h++)\r\n                b(a[h], c, g ? d : d.call(a[h], h, b(a[h], c)));\r\n            return e ? a : j ? b.call(a) : i ? b(a[0], c) : f;\r\n          },\r\n          U = function (a) {\r\n            return 1 === a.nodeType || 9 === a.nodeType || !+a.nodeType;\r\n          };\r\n        function V() {\r\n          this.expando = r.expando + V.uid++;\r\n        }\r\n        (V.uid = 1),\r\n          (V.prototype = {\r\n            cache: function (a) {\r\n              var b = a[this.expando];\r\n              return (\r\n                b ||\r\n                  ((b = {}),\r\n                  U(a) &&\r\n                    (a.nodeType\r\n                      ? (a[this.expando] = b)\r\n                      : Object.defineProperty(a, this.expando, {\r\n                          value: b,\r\n                          configurable: !0,\r\n                        }))),\r\n                b\r\n              );\r\n            },\r\n            set: function (a, b, c) {\r\n              var d,\r\n                e = this.cache(a);\r\n              if ("string" == typeof b) e[r.camelCase(b)] = c;\r\n              else for (d in b) e[r.camelCase(d)] = b[d];\r\n              return e;\r\n            },\r\n            get: function (a, b) {\r\n              return void 0 === b\r\n                ? this.cache(a)\r\n                : a[this.expando] && a[this.expando][r.camelCase(b)];\r\n            },\r\n            access: function (a, b, c) {\r\n              return void 0 === b || (b && "string" == typeof b && void 0 === c)\r\n                ? this.get(a, b)\r\n                : (this.set(a, b, c), void 0 !== c ? c : b);\r\n            },\r\n            remove: function (a, b) {\r\n              var c,\r\n                d = a[this.expando];\r\n              if (void 0 !== d) {\r\n                if (void 0 !== b) {\r\n                  Array.isArray(b)\r\n                    ? (b = b.map(r.camelCase))\r\n                    : ((b = r.camelCase(b)),\r\n                      (b = b in d ? [b] : b.match(L) || [])),\r\n                    (c = b.length);\r\n                  while (c--) delete d[b[c]];\r\n                }\r\n                (void 0 === b || r.isEmptyObject(d)) &&\r\n                  (a.nodeType\r\n                    ? (a[this.expando] = void 0)\r\n                    : delete a[this.expando]);\r\n              }\r\n            },\r\n            hasData: function (a) {\r\n              var b = a[this.expando];\r\n              return void 0 !== b && !r.isEmptyObject(b);\r\n            },\r\n          });\r\n        var W = new V(),\r\n          X = new V(),\r\n          Y = /^(?:\\{[\\w\\W]*\\}|\\[[\\w\\W]*\\])$/,\r\n          Z = /[A-Z]/g;\r\n        function $(a) {\r\n          return (\r\n            "true" === a ||\r\n            ("false" !== a &&\r\n              ("null" === a\r\n                ? null\r\n                : a === +a + ""\r\n                ? +a\r\n                : Y.test(a)\r\n                ? JSON.parse(a)\r\n                : a))\r\n          );\r\n        }\r\n        function _(a, b, c) {\r\n          var d;\r\n          if (void 0 === c && 1 === a.nodeType)\r\n            if (\r\n              ((d = "data-" + b.replace(Z, "-$&").toLowerCase()),\r\n              (c = a.getAttribute(d)),\r\n              "string" == typeof c)\r\n            ) {\r\n              try {\r\n                c = $(c);\r\n              } catch (e) {}\r\n              X.set(a, b, c);\r\n            } else c = void 0;\r\n          return c;\r\n        }\r\n        r.extend({\r\n          hasData: function (a) {\r\n            return X.hasData(a) || W.hasData(a);\r\n          },\r\n          data: function (a, b, c) {\r\n            return X.access(a, b, c);\r\n          },\r\n          removeData: function (a, b) {\r\n            X.remove(a, b);\r\n          },\r\n          _data: function (a, b, c) {\r\n            return W.access(a, b, c);\r\n          },\r\n          _removeData: function (a, b) {\r\n            W.remove(a, b);\r\n          },\r\n        }),\r\n          r.fn.extend({\r\n            data: function (a, b) {\r\n              var c,\r\n                d,\r\n                e,\r\n                f = this[0],\r\n                g = f && f.attributes;\r\n              if (void 0 === a) {\r\n                if (\r\n                  this.length &&\r\n                  ((e = X.get(f)),\r\n                  1 === f.nodeType && !W.get(f, "hasDataAttrs"))\r\n                ) {\r\n                  c = g.length;\r\n                  while (c--)\r\n                    g[c] &&\r\n                      ((d = g[c].name),\r\n                      0 === d.indexOf("data-") &&\r\n                        ((d = r.camelCase(d.slice(5))), _(f, d, e[d])));\r\n                  W.set(f, "hasDataAttrs", !0);\r\n                }\r\n                return e;\r\n              }\r\n              return "object" == typeof a\r\n                ? this.each(function () {\r\n                    X.set(this, a);\r\n                  })\r\n                : T(\r\n                    this,\r\n                    function (b) {\r\n                      var c;\r\n                      if (f && void 0 === b) {\r\n                        if (((c = X.get(f, a)), void 0 !== c)) return c;\r\n                        if (((c = _(f, a)), void 0 !== c)) return c;\r\n                      } else\r\n                        this.each(function () {\r\n                          X.set(this, a, b);\r\n                        });\r\n                    },\r\n                    null,\r\n                    b,\r\n                    arguments.length > 1,\r\n                    null,\r\n                    !0\r\n                  );\r\n            },\r\n            removeData: function (a) {\r\n              return this.each(function () {\r\n                X.remove(this, a);\r\n              });\r\n            },\r\n          }),\r\n          r.extend({\r\n            queue: function (a, b, c) {\r\n              var d;\r\n              if (a)\r\n                return (\r\n                  (b = (b || "fx") + "queue"),\r\n                  (d = W.get(a, b)),\r\n                  c &&\r\n                    (!d || Array.isArray(c)\r\n                      ? (d = W.access(a, b, r.makeArray(c)))\r\n                      : d.push(c)),\r\n                  d || []\r\n                );\r\n            },\r\n            dequeue: function (a, b) {\r\n              b = b || "fx";\r\n              var c = r.queue(a, b),\r\n                d = c.length,\r\n                e = c.shift(),\r\n                f = r._queueHooks(a, b),\r\n                g = function () {\r\n                  r.dequeue(a, b);\r\n                };\r\n              "inprogress" === e && ((e = c.shift()), d--),\r\n                e &&\r\n                  ("fx" === b && c.unshift("inprogress"),\r\n                  delete f.stop,\r\n                  e.call(a, g, f)),\r\n                !d && f && f.empty.fire();\r\n            },\r\n            _queueHooks: function (a, b) {\r\n              var c = b + "queueHooks";\r\n              return (\r\n                W.get(a, c) ||\r\n                W.access(a, c, {\r\n                  empty: r.Callbacks("once memory").add(function () {\r\n                    W.remove(a, [b + "queue", c]);\r\n                  }),\r\n                })\r\n              );\r\n            },\r\n          }),\r\n          r.fn.extend({\r\n            queue: function (a, b) {\r\n              var c = 2;\r\n              return (\r\n                "string" != typeof a && ((b = a), (a = "fx"), c--),\r\n                arguments.length < c\r\n                  ? r.queue(this[0], a)\r\n                  : void 0 === b\r\n                  ? this\r\n                  : this.each(function () {\r\n                      var c = r.queue(this, a, b);\r\n                      r._queueHooks(this, a),\r\n                        "fx" === a &&\r\n                          "inprogress" !== c[0] &&\r\n                          r.dequeue(this, a);\r\n                    })\r\n              );\r\n            },\r\n            dequeue: function (a) {\r\n              return this.each(function () {\r\n                r.dequeue(this, a);\r\n              });\r\n            },\r\n            clearQueue: function (a) {\r\n              return this.queue(a || "fx", []);\r\n            },\r\n            promise: function (a, b) {\r\n              var c,\r\n                d = 1,\r\n                e = r.Deferred(),\r\n                f = this,\r\n                g = this.length,\r\n                h = function () {\r\n                  --d || e.resolveWith(f, [f]);\r\n                };\r\n              "string" != typeof a && ((b = a), (a = void 0)), (a = a || "fx");\r\n              while (g--)\r\n                (c = W.get(f[g], a + "queueHooks")),\r\n                  c && c.empty && (d++, c.empty.add(h));\r\n              return h(), e.promise(b);\r\n            },\r\n          });\r\n        var aa = /[+-]?(?:\\d*\\.|)\\d+(?:[eE][+-]?\\d+|)/.source,\r\n          ba = new RegExp("^(?:([+-])=|)(" + aa + ")([a-z%]*)$", "i"),\r\n          ca = ["Top", "Right", "Bottom", "Left"],\r\n          da = function (a, b) {\r\n            return (\r\n              (a = b || a),\r\n              "none" === a.style.display ||\r\n                ("" === a.style.display &&\r\n                  r.contains(a.ownerDocument, a) &&\r\n                  "none" === r.css(a, "display"))\r\n            );\r\n          },\r\n          ea = function (a, b, c, d) {\r\n            var e,\r\n              f,\r\n              g = {};\r\n            for (f in b) (g[f] = a.style[f]), (a.style[f] = b[f]);\r\n            e = c.apply(a, d || []);\r\n            for (f in b) a.style[f] = g[f];\r\n            return e;\r\n          };\r\n        function fa(a, b, c, d) {\r\n          var e,\r\n            f = 1,\r\n            g = 20,\r\n            h = d\r\n              ? function () {\r\n                  return d.cur();\r\n                }\r\n              : function () {\r\n                  return r.css(a, b, "");\r\n                },\r\n            i = h(),\r\n            j = (c && c[3]) || (r.cssNumber[b] ? "" : "px"),\r\n            k = (r.cssNumber[b] || ("px" !== j && +i)) && ba.exec(r.css(a, b));\r\n          if (k && k[3] !== j) {\r\n            (j = j || k[3]), (c = c || []), (k = +i || 1);\r\n            do (f = f || ".5"), (k /= f), r.style(a, b, k + j);\r\n            while (f !== (f = h() / i) && 1 !== f && --g);\r\n          }\r\n          return (\r\n            c &&\r\n              ((k = +k || +i || 0),\r\n              (e = c[1] ? k + (c[1] + 1) * c[2] : +c[2]),\r\n              d && ((d.unit = j), (d.start = k), (d.end = e))),\r\n            e\r\n          );\r\n        }\r\n        var ga = {};\r\n        function ha(a) {\r\n          var b,\r\n            c = a.ownerDocument,\r\n            d = a.nodeName,\r\n            e = ga[d];\r\n          return e\r\n            ? e\r\n            : ((b = c.body.appendChild(c.createElement(d))),\r\n              (e = r.css(b, "display")),\r\n              b.parentNode.removeChild(b),\r\n              "none" === e && (e = "block"),\r\n              (ga[d] = e),\r\n              e);\r\n        }\r\n        function ia(a, b) {\r\n          for (var c, d, e = [], f = 0, g = a.length; f < g; f++)\r\n            (d = a[f]),\r\n              d.style &&\r\n                ((c = d.style.display),\r\n                b\r\n                  ? ("none" === c &&\r\n                      ((e[f] = W.get(d, "display") || null),\r\n                      e[f] || (d.style.display = "")),\r\n                    "" === d.style.display && da(d) && (e[f] = ha(d)))\r\n                  : "none" !== c && ((e[f] = "none"), W.set(d, "display", c)));\r\n          for (f = 0; f < g; f++) null != e[f] && (a[f].style.display = e[f]);\r\n          return a;\r\n        }\r\n        r.fn.extend({\r\n          show: function () {\r\n            return ia(this, !0);\r\n          },\r\n          hide: function () {\r\n            return ia(this);\r\n          },\r\n          toggle: function (a) {\r\n            return "boolean" == typeof a\r\n              ? a\r\n                ? this.show()\r\n                : this.hide()\r\n              : this.each(function () {\r\n                  da(this) ? r(this).show() : r(this).hide();\r\n                });\r\n          },\r\n        });\r\n        var ja = /^(?:checkbox|radio)$/i,\r\n          ka = /<([a-z][^\\/\\0>\\x20\\t\\r\\n\\f]+)/i,\r\n          la = /^$|\\/(?:java|ecma)script/i,\r\n          ma = {\r\n            option: [1, "<select multiple='multiple'>", "</select>"],\r\n            thead: [1, "<table>", "</table>"],\r\n            col: [2, "<table><colgroup>", "</colgroup></table>"],\r\n            tr: [2, "<table><tbody>", "</tbody></table>"],\r\n            td: [3, "<table><tbody><tr>", "</tr></tbody></table>"],\r\n            _default: [0, "", ""],\r\n          };\r\n        (ma.optgroup = ma.option),\r\n          (ma.tbody = ma.tfoot = ma.colgroup = ma.caption = ma.thead),\r\n          (ma.th = ma.td);\r\n        function na(a, b) {\r\n          var c;\r\n          return (\r\n            (c =\r\n              "undefined" != typeof a.getElementsByTagName\r\n                ? a.getElementsByTagName(b || "*")\r\n                : "undefined" != typeof a.querySelectorAll\r\n                ? a.querySelectorAll(b || "*")\r\n                : []),\r\n            void 0 === b || (b && B(a, b)) ? r.merge([a], c) : c\r\n          );\r\n        }\r\n        function oa(a, b) {\r\n          for (var c = 0, d = a.length; c < d; c++)\r\n            W.set(a[c], "globalEval", !b || W.get(b[c], "globalEval"));\r\n        }\r\n        var pa = /<|&#?\\w+;/;\r\n        function qa(a, b, c, d, e) {\r\n          for (\r\n            var f,\r\n              g,\r\n              h,\r\n              i,\r\n              j,\r\n              k,\r\n              l = b.createDocumentFragment(),\r\n              m = [],\r\n              n = 0,\r\n              o = a.length;\r\n            n < o;\r\n            n++\r\n          )\r\n            if (((f = a[n]), f || 0 === f))\r\n              if ("object" === r.type(f)) r.merge(m, f.nodeType ? [f] : f);\r\n              else if (pa.test(f)) {\r\n                (g = g || l.appendChild(b.createElement("div"))),\r\n                  (h = (ka.exec(f) || ["", ""])[1].toLowerCase()),\r\n                  (i = ma[h] || ma._default),\r\n                  (g.innerHTML = i[1] + r.htmlPrefilter(f) + i[2]),\r\n                  (k = i[0]);\r\n                while (k--) g = g.lastChild;\r\n                r.merge(m, g.childNodes),\r\n                  (g = l.firstChild),\r\n                  (g.textContent = "");\r\n              } else m.push(b.createTextNode(f));\r\n          (l.textContent = ""), (n = 0);\r\n          while ((f = m[n++]))\r\n            if (d && r.inArray(f, d) > -1) e && e.push(f);\r\n            else if (\r\n              ((j = r.contains(f.ownerDocument, f)),\r\n              (g = na(l.appendChild(f), "script")),\r\n              j && oa(g),\r\n              c)\r\n            ) {\r\n              k = 0;\r\n              while ((f = g[k++])) la.test(f.type || "") && c.push(f);\r\n            }\r\n          return l;\r\n        }\r\n        !(function () {\r\n          var a = d.createDocumentFragment(),\r\n            b = a.appendChild(d.createElement("div")),\r\n            c = d.createElement("input");\r\n          c.setAttribute("type", "radio"),\r\n            c.setAttribute("checked", "checked"),\r\n            c.setAttribute("name", "t"),\r\n            b.appendChild(c),\r\n            (o.checkClone = b.cloneNode(!0).cloneNode(!0).lastChild.checked),\r\n            (b.innerHTML = "<textarea>x</textarea>"),\r\n            (o.noCloneChecked = !!b.cloneNode(!0).lastChild.defaultValue);\r\n        })();\r\n        var ra = d.documentElement,\r\n          sa = /^key/,\r\n          ta = /^(?:mouse|pointer|contextmenu|drag|drop)|click/,\r\n          ua = /^([^.]*)(?:\\.(.+)|)/;\r\n        function va() {\r\n          return !0;\r\n        }\r\n        function wa() {\r\n          return !1;\r\n        }\r\n        function xa() {\r\n          try {\r\n            return d.activeElement;\r\n          } catch (a) {}\r\n        }\r\n        function ya(a, b, c, d, e, f) {\r\n          var g, h;\r\n          if ("object" == typeof b) {\r\n            "string" != typeof c && ((d = d || c), (c = void 0));\r\n            for (h in b) ya(a, h, c, d, b[h], f);\r\n            return a;\r\n          }\r\n          if (\r\n            (null == d && null == e\r\n              ? ((e = c), (d = c = void 0))\r\n              : null == e &&\r\n                ("string" == typeof c\r\n                  ? ((e = d), (d = void 0))\r\n                  : ((e = d), (d = c), (c = void 0))),\r\n            e === !1)\r\n          )\r\n            e = wa;\r\n          else if (!e) return a;\r\n          return (\r\n            1 === f &&\r\n              ((g = e),\r\n              (e = function (a) {\r\n                return r().off(a), g.apply(this, arguments);\r\n              }),\r\n              (e.guid = g.guid || (g.guid = r.guid++))),\r\n            a.each(function () {\r\n              r.event.add(this, b, e, d, c);\r\n            })\r\n          );\r\n        }\r\n        (r.event = {\r\n          global: {},\r\n          add: function (a, b, c, d, e) {\r\n            var f,\r\n              g,\r\n              h,\r\n              i,\r\n              j,\r\n              k,\r\n              l,\r\n              m,\r\n              n,\r\n              o,\r\n              p,\r\n              q = W.get(a);\r\n            if (q) {\r\n              c.handler && ((f = c), (c = f.handler), (e = f.selector)),\r\n                e && r.find.matchesSelector(ra, e),\r\n                c.guid || (c.guid = r.guid++),\r\n                (i = q.events) || (i = q.events = {}),\r\n                (g = q.handle) ||\r\n                  (g = q.handle =\r\n                    function (b) {\r\n                      return "undefined" != typeof r &&\r\n                        r.event.triggered !== b.type\r\n                        ? r.event.dispatch.apply(a, arguments)\r\n                        : void 0;\r\n                    }),\r\n                (b = (b || "").match(L) || [""]),\r\n                (j = b.length);\r\n              while (j--)\r\n                (h = ua.exec(b[j]) || []),\r\n                  (n = p = h[1]),\r\n                  (o = (h[2] || "").split(".").sort()),\r\n                  n &&\r\n                    ((l = r.event.special[n] || {}),\r\n                    (n = (e ? l.delegateType : l.bindType) || n),\r\n                    (l = r.event.special[n] || {}),\r\n                    (k = r.extend(\r\n                      {\r\n                        type: n,\r\n                        origType: p,\r\n                        data: d,\r\n                        handler: c,\r\n                        guid: c.guid,\r\n                        selector: e,\r\n                        needsContext: e && r.expr.match.needsContext.test(e),\r\n                        namespace: o.join("."),\r\n                      },\r\n                      f\r\n                    )),\r\n                    (m = i[n]) ||\r\n                      ((m = i[n] = []),\r\n                      (m.delegateCount = 0),\r\n                      (l.setup && l.setup.call(a, d, o, g) !== !1) ||\r\n                        (a.addEventListener && a.addEventListener(n, g))),\r\n                    l.add &&\r\n                      (l.add.call(a, k),\r\n                      k.handler.guid || (k.handler.guid = c.guid)),\r\n                    e ? m.splice(m.delegateCount++, 0, k) : m.push(k),\r\n                    (r.event.global[n] = !0));\r\n            }\r\n          },\r\n          remove: function (a, b, c, d, e) {\r\n            var f,\r\n              g,\r\n              h,\r\n              i,\r\n              j,\r\n              k,\r\n              l,\r\n              m,\r\n              n,\r\n              o,\r\n              p,\r\n              q = W.hasData(a) && W.get(a);\r\n            if (q && (i = q.events)) {\r\n              (b = (b || "").match(L) || [""]), (j = b.length);\r\n              while (j--)\r\n                if (\r\n                  ((h = ua.exec(b[j]) || []),\r\n                  (n = p = h[1]),\r\n                  (o = (h[2] || "").split(".").sort()),\r\n                  n)\r\n                ) {\r\n                  (l = r.event.special[n] || {}),\r\n                    (n = (d ? l.delegateType : l.bindType) || n),\r\n                    (m = i[n] || []),\r\n                    (h =\r\n                      h[2] &&\r\n                      new RegExp(\r\n                        "(^|\\\\.)" + o.join("\\\\.(?:.*\\\\.|)") + "(\\\\.|$)"\r\n                      )),\r\n                    (g = f = m.length);\r\n                  while (f--)\r\n                    (k = m[f]),\r\n                      (!e && p !== k.origType) ||\r\n                        (c && c.guid !== k.guid) ||\r\n                        (h && !h.test(k.namespace)) ||\r\n                        (d &&\r\n                          d !== k.selector &&\r\n                          ("**" !== d || !k.selector)) ||\r\n                        (m.splice(f, 1),\r\n                        k.selector && m.delegateCount--,\r\n                        l.remove && l.remove.call(a, k));\r\n                  g &&\r\n                    !m.length &&\r\n                    ((l.teardown && l.teardown.call(a, o, q.handle) !== !1) ||\r\n                      r.removeEvent(a, n, q.handle),\r\n                    delete i[n]);\r\n                } else for (n in i) r.event.remove(a, n + b[j], c, d, !0);\r\n              r.isEmptyObject(i) && W.remove(a, "handle events");\r\n            }\r\n          },\r\n          dispatch: function (a) {\r\n            var b = r.event.fix(a),\r\n              c,\r\n              d,\r\n              e,\r\n              f,\r\n              g,\r\n              h,\r\n              i = new Array(arguments.length),\r\n              j = (W.get(this, "events") || {})[b.type] || [],\r\n              k = r.event.special[b.type] || {};\r\n            for (i[0] = b, c = 1; c < arguments.length; c++)\r\n              i[c] = arguments[c];\r\n            if (\r\n              ((b.delegateTarget = this),\r\n              !k.preDispatch || k.preDispatch.call(this, b) !== !1)\r\n            ) {\r\n              (h = r.event.handlers.call(this, b, j)), (c = 0);\r\n              while ((f = h[c++]) && !b.isPropagationStopped()) {\r\n                (b.currentTarget = f.elem), (d = 0);\r\n                while (\r\n                  (g = f.handlers[d++]) &&\r\n                  !b.isImmediatePropagationStopped()\r\n                )\r\n                  (b.rnamespace && !b.rnamespace.test(g.namespace)) ||\r\n                    ((b.handleObj = g),\r\n                    (b.data = g.data),\r\n                    (e = (\r\n                      (r.event.special[g.origType] || {}).handle || g.handler\r\n                    ).apply(f.elem, i)),\r\n                    void 0 !== e &&\r\n                      (b.result = e) === !1 &&\r\n                      (b.preventDefault(), b.stopPropagation()));\r\n              }\r\n              return k.postDispatch && k.postDispatch.call(this, b), b.result;\r\n            }\r\n          },\r\n          handlers: function (a, b) {\r\n            var c,\r\n              d,\r\n              e,\r\n              f,\r\n              g,\r\n              h = [],\r\n              i = b.delegateCount,\r\n              j = a.target;\r\n            if (i && j.nodeType && !("click" === a.type && a.button >= 1))\r\n              for (; j !== this; j = j.parentNode || this)\r\n                if (\r\n                  1 === j.nodeType &&\r\n                  ("click" !== a.type || j.disabled !== !0)\r\n                ) {\r\n                  for (f = [], g = {}, c = 0; c < i; c++)\r\n                    (d = b[c]),\r\n                      (e = d.selector + " "),\r\n                      void 0 === g[e] &&\r\n                        (g[e] = d.needsContext\r\n                          ? r(e, this).index(j) > -1\r\n                          : r.find(e, this, null, [j]).length),\r\n                      g[e] && f.push(d);\r\n                  f.length && h.push({ elem: j, handlers: f });\r\n                }\r\n            return (\r\n              (j = this),\r\n              i < b.length && h.push({ elem: j, handlers: b.slice(i) }),\r\n              h\r\n            );\r\n          },\r\n          addProp: function (a, b) {\r\n            Object.defineProperty(r.Event.prototype, a, {\r\n              enumerable: !0,\r\n              configurable: !0,\r\n              get: r.isFunction(b)\r\n                ? function () {\r\n                    if (this.originalEvent) return b(this.originalEvent);\r\n                  }\r\n                : function () {\r\n                    if (this.originalEvent) return this.originalEvent[a];\r\n                  },\r\n              set: function (b) {\r\n                Object.defineProperty(this, a, {\r\n                  enumerable: !0,\r\n                  configurable: !0,\r\n                  writable: !0,\r\n                  value: b,\r\n                });\r\n              },\r\n            });\r\n          },\r\n          fix: function (a) {\r\n            return a[r.expando] ? a : new r.Event(a);\r\n          },\r\n          special: {\r\n            load: { noBubble: !0 },\r\n            focus: {\r\n              trigger: function () {\r\n                if (this !== xa() && this.focus) return this.focus(), !1;\r\n              },\r\n              delegateType: "focusin",\r\n            },\r\n            blur: {\r\n              trigger: function () {\r\n                if (this === xa() && this.blur) return this.blur(), !1;\r\n              },\r\n              delegateType: "focusout",\r\n            },\r\n            click: {\r\n              trigger: function () {\r\n                if ("checkbox" === this.type && this.click && B(this, "input"))\r\n                  return this.click(), !1;\r\n              },\r\n              _default: function (a) {\r\n                return B(a.target, "a");\r\n              },\r\n            },\r\n            beforeunload: {\r\n              postDispatch: function (a) {\r\n                void 0 !== a.result &&\r\n                  a.originalEvent &&\r\n                  (a.originalEvent.returnValue = a.result);\r\n              },\r\n            },\r\n          },\r\n        }),\r\n          (r.removeEvent = function (a, b, c) {\r\n            a.removeEventListener && a.removeEventListener(b, c);\r\n          }),\r\n          (r.Event = function (a, b) {\r\n            return this instanceof r.Event\r\n              ? (a && a.type\r\n                  ? ((this.originalEvent = a),\r\n                    (this.type = a.type),\r\n                    (this.isDefaultPrevented =\r\n                      a.defaultPrevented ||\r\n                      (void 0 === a.defaultPrevented && a.returnValue === !1)\r\n                        ? va\r\n                        : wa),\r\n                    (this.target =\r\n                      a.target && 3 === a.target.nodeType\r\n                        ? a.target.parentNode\r\n                        : a.target),\r\n                    (this.currentTarget = a.currentTarget),\r\n                    (this.relatedTarget = a.relatedTarget))\r\n                  : (this.type = a),\r\n                b && r.extend(this, b),\r\n                (this.timeStamp = (a && a.timeStamp) || r.now()),\r\n                void (this[r.expando] = !0))\r\n              : new r.Event(a, b);\r\n          }),\r\n          (r.Event.prototype = {\r\n            constructor: r.Event,\r\n            isDefaultPrevented: wa,\r\n            isPropagationStopped: wa,\r\n            isImmediatePropagationStopped: wa,\r\n            isSimulated: !1,\r\n            preventDefault: function () {\r\n              var a = this.originalEvent;\r\n              (this.isDefaultPrevented = va),\r\n                a && !this.isSimulated && a.preventDefault();\r\n            },\r\n            stopPropagation: function () {\r\n              var a = this.originalEvent;\r\n              (this.isPropagationStopped = va),\r\n                a && !this.isSimulated && a.stopPropagation();\r\n            },\r\n            stopImmediatePropagation: function () {\r\n              var a = this.originalEvent;\r\n              (this.isImmediatePropagationStopped = va),\r\n                a && !this.isSimulated && a.stopImmediatePropagation(),\r\n                this.stopPropagation();\r\n            },\r\n          }),\r\n          r.each(\r\n            {\r\n              altKey: !0,\r\n              bubbles: !0,\r\n              cancelable: !0,\r\n              changedTouches: !0,\r\n              ctrlKey: !0,\r\n              detail: !0,\r\n              eventPhase: !0,\r\n              metaKey: !0,\r\n              pageX: !0,\r\n              pageY: !0,\r\n              shiftKey: !0,\r\n              view: !0,\r\n              char: !0,\r\n              charCode: !0,\r\n              key: !0,\r\n              keyCode: !0,\r\n              button: !0,\r\n              buttons: !0,\r\n              clientX: !0,\r\n              clientY: !0,\r\n              offsetX: !0,\r\n              offsetY: !0,\r\n              pointerId: !0,\r\n              pointerType: !0,\r\n              screenX: !0,\r\n              screenY: !0,\r\n              targetTouches: !0,\r\n              toElement: !0,\r\n              touches: !0,\r\n              which: function (a) {\r\n                var b = a.button;\r\n                return null == a.which && sa.test(a.type)\r\n                  ? null != a.charCode\r\n                    ? a.charCode\r\n                    : a.keyCode\r\n                  : !a.which && void 0 !== b && ta.test(a.type)\r\n                  ? 1 & b\r\n                    ? 1\r\n                    : 2 & b\r\n                    ? 3\r\n                    : 4 & b\r\n                    ? 2\r\n                    : 0\r\n                  : a.which;\r\n              },\r\n            },\r\n            r.event.addProp\r\n          ),\r\n          r.each(\r\n            {\r\n              mouseenter: "mouseover",\r\n              mouseleave: "mouseout",\r\n              pointerenter: "pointerover",\r\n              pointerleave: "pointerout",\r\n            },\r\n            function (a, b) {\r\n              r.event.special[a] = {\r\n                delegateType: b,\r\n                bindType: b,\r\n                handle: function (a) {\r\n                  var c,\r\n                    d = this,\r\n                    e = a.relatedTarget,\r\n                    f = a.handleObj;\r\n                  return (\r\n                    (e && (e === d || r.contains(d, e))) ||\r\n                      ((a.type = f.origType),\r\n                      (c = f.handler.apply(this, arguments)),\r\n                      (a.type = b)),\r\n                    c\r\n                  );\r\n                },\r\n              };\r\n            }\r\n          ),\r\n          r.fn.extend({\r\n            on: function (a, b, c, d) {\r\n              return ya(this, a, b, c, d);\r\n            },\r\n            one: function (a, b, c, d) {\r\n              return ya(this, a, b, c, d, 1);\r\n            },\r\n            off: function (a, b, c) {\r\n              var d, e;\r\n              if (a && a.preventDefault && a.handleObj)\r\n                return (\r\n                  (d = a.handleObj),\r\n                  r(a.delegateTarget).off(\r\n                    d.namespace ? d.origType + "." + d.namespace : d.origType,\r\n                    d.selector,\r\n                    d.handler\r\n                  ),\r\n                  this\r\n                );\r\n              if ("object" == typeof a) {\r\n                for (e in a) this.off(e, b, a[e]);\r\n                return this;\r\n              }\r\n              return (\r\n                (b !== !1 && "function" != typeof b) || ((c = b), (b = void 0)),\r\n                c === !1 && (c = wa),\r\n                this.each(function () {\r\n                  r.event.remove(this, a, c, b);\r\n                })\r\n              );\r\n            },\r\n          });\r\n        var za =\r\n            /<(?!area|br|col|embed|hr|img|input|link|meta|param)(([a-z][^\\/\\0>\\x20\\t\\r\\n\\f]*)[^>]*)\\/>/gi,\r\n          Aa = /<script|<style|<link/i,\r\n          Ba = /checked\\s*(?:[^=]|=\\s*.checked.)/i,\r\n          Ca = /^true\\/(.*)/,\r\n          Da = /^\\s*<!(?:\\[CDATA\\[|--)|(?:\\]\\]|--)>\\s*$/g;\r\n        function Ea(a, b) {\r\n          return B(a, "table") && B(11 !== b.nodeType ? b : b.firstChild, "tr")\r\n            ? r(">tbody", a)[0] || a\r\n            : a;\r\n        }\r\n        function Fa(a) {\r\n          return (a.type = (null !== a.getAttribute("type")) + "/" + a.type), a;\r\n        }\r\n        function Ga(a) {\r\n          var b = Ca.exec(a.type);\r\n          return b ? (a.type = b[1]) : a.removeAttribute("type"), a;\r\n        }\r\n        function Ha(a, b) {\r\n          var c, d, e, f, g, h, i, j;\r\n          if (1 === b.nodeType) {\r\n            if (\r\n              W.hasData(a) &&\r\n              ((f = W.access(a)), (g = W.set(b, f)), (j = f.events))\r\n            ) {\r\n              delete g.handle, (g.events = {});\r\n              for (e in j)\r\n                for (c = 0, d = j[e].length; c < d; c++)\r\n                  r.event.add(b, e, j[e][c]);\r\n            }\r\n            X.hasData(a) &&\r\n              ((h = X.access(a)), (i = r.extend({}, h)), X.set(b, i));\r\n          }\r\n        }\r\n        function Ia(a, b) {\r\n          var c = b.nodeName.toLowerCase();\r\n          "input" === c && ja.test(a.type)\r\n            ? (b.checked = a.checked)\r\n            : ("input" !== c && "textarea" !== c) ||\r\n              (b.defaultValue = a.defaultValue);\r\n        }\r\n        function Ja(a, b, c, d) {\r\n          b = g.apply([], b);\r\n          var e,\r\n            f,\r\n            h,\r\n            i,\r\n            j,\r\n            k,\r\n            l = 0,\r\n            m = a.length,\r\n            n = m - 1,\r\n            q = b[0],\r\n            s = r.isFunction(q);\r\n          if (\r\n            s ||\r\n            (m > 1 && "string" == typeof q && !o.checkClone && Ba.test(q))\r\n          )\r\n            return a.each(function (e) {\r\n              var f = a.eq(e);\r\n              s && (b[0] = q.call(this, e, f.html())), Ja(f, b, c, d);\r\n            });\r\n          if (\r\n            m &&\r\n            ((e = qa(b, a[0].ownerDocument, !1, a, d)),\r\n            (f = e.firstChild),\r\n            1 === e.childNodes.length && (e = f),\r\n            f || d)\r\n          ) {\r\n            for (h = r.map(na(e, "script"), Fa), i = h.length; l < m; l++)\r\n              (j = e),\r\n                l !== n &&\r\n                  ((j = r.clone(j, !0, !0)), i && r.merge(h, na(j, "script"))),\r\n                c.call(a[l], j, l);\r\n            if (i)\r\n              for (\r\n                k = h[h.length - 1].ownerDocument, r.map(h, Ga), l = 0;\r\n                l < i;\r\n                l++\r\n              )\r\n                (j = h[l]),\r\n                  la.test(j.type || "") &&\r\n                    !W.access(j, "globalEval") &&\r\n                    r.contains(k, j) &&\r\n                    (j.src\r\n                      ? r._evalUrl && r._evalUrl(j.src)\r\n                      : p(j.textContent.replace(Da, ""), k));\r\n          }\r\n          return a;\r\n        }\r\n        function Ka(a, b, c) {\r\n          for (\r\n            var d, e = b ? r.filter(b, a) : a, f = 0;\r\n            null != (d = e[f]);\r\n            f++\r\n          )\r\n            c || 1 !== d.nodeType || r.cleanData(na(d)),\r\n              d.parentNode &&\r\n                (c && r.contains(d.ownerDocument, d) && oa(na(d, "script")),\r\n                d.parentNode.removeChild(d));\r\n          return a;\r\n        }\r\n        r.extend({\r\n          htmlPrefilter: function (a) {\r\n            return a.replace(za, "<$1></$2>");\r\n          },\r\n          clone: function (a, b, c) {\r\n            var d,\r\n              e,\r\n              f,\r\n              g,\r\n              h = a.cloneNode(!0),\r\n              i = r.contains(a.ownerDocument, a);\r\n            if (\r\n              !(\r\n                o.noCloneChecked ||\r\n                (1 !== a.nodeType && 11 !== a.nodeType) ||\r\n                r.isXMLDoc(a)\r\n              )\r\n            )\r\n              for (g = na(h), f = na(a), d = 0, e = f.length; d < e; d++)\r\n                Ia(f[d], g[d]);\r\n            if (b)\r\n              if (c)\r\n                for (\r\n                  f = f || na(a), g = g || na(h), d = 0, e = f.length;\r\n                  d < e;\r\n                  d++\r\n                )\r\n                  Ha(f[d], g[d]);\r\n              else Ha(a, h);\r\n            return (\r\n              (g = na(h, "script")),\r\n              g.length > 0 && oa(g, !i && na(a, "script")),\r\n              h\r\n            );\r\n          },\r\n          cleanData: function (a) {\r\n            for (\r\n              var b, c, d, e = r.event.special, f = 0;\r\n              void 0 !== (c = a[f]);\r\n              f++\r\n            )\r\n              if (U(c)) {\r\n                if ((b = c[W.expando])) {\r\n                  if (b.events)\r\n                    for (d in b.events)\r\n                      e[d]\r\n                        ? r.event.remove(c, d)\r\n                        : r.removeEvent(c, d, b.handle);\r\n                  c[W.expando] = void 0;\r\n                }\r\n                c[X.expando] && (c[X.expando] = void 0);\r\n              }\r\n          },\r\n        }),\r\n          r.fn.extend({\r\n            detach: function (a) {\r\n              return Ka(this, a, !0);\r\n            },\r\n            remove: function (a) {\r\n              return Ka(this, a);\r\n            },\r\n            text: function (a) {\r\n              return T(\r\n                this,\r\n                function (a) {\r\n                  return void 0 === a\r\n                    ? r.text(this)\r\n                    : this.empty().each(function () {\r\n                        (1 !== this.nodeType &&\r\n                          11 !== this.nodeType &&\r\n                          9 !== this.nodeType) ||\r\n                          (this.textContent = a);\r\n                      });\r\n                },\r\n                null,\r\n                a,\r\n                arguments.length\r\n              );\r\n            },\r\n            append: function () {\r\n              return Ja(this, arguments, function (a) {\r\n                if (\r\n                  1 === this.nodeType ||\r\n                  11 === this.nodeType ||\r\n                  9 === this.nodeType\r\n                ) {\r\n                  var b = Ea(this, a);\r\n                  b.appendChild(a);\r\n                }\r\n              });\r\n            },\r\n            prepend: function () {\r\n              return Ja(this, arguments, function (a) {\r\n                if (\r\n                  1 === this.nodeType ||\r\n                  11 === this.nodeType ||\r\n                  9 === this.nodeType\r\n                ) {\r\n                  var b = Ea(this, a);\r\n                  b.insertBefore(a, b.firstChild);\r\n                }\r\n              });\r\n            },\r\n            before: function () {\r\n              return Ja(this, arguments, function (a) {\r\n                this.parentNode && this.parentNode.insertBefore(a, this);\r\n              });\r\n            },\r\n            after: function () {\r\n              return Ja(this, arguments, function (a) {\r\n                this.parentNode &&\r\n                  this.parentNode.insertBefore(a, this.nextSibling);\r\n              });\r\n            },\r\n            empty: function () {\r\n              for (var a, b = 0; null != (a = this[b]); b++)\r\n                1 === a.nodeType &&\r\n                  (r.cleanData(na(a, !1)), (a.textContent = ""));\r\n              return this;\r\n            },\r\n            clone: function (a, b) {\r\n              return (\r\n                (a = null != a && a),\r\n                (b = null == b ? a : b),\r\n                this.map(function () {\r\n                  return r.clone(this, a, b);\r\n                })\r\n              );\r\n            },\r\n            html: function (a) {\r\n              return T(\r\n                this,\r\n                function (a) {\r\n                  var b = this[0] || {},\r\n                    c = 0,\r\n                    d = this.length;\r\n                  if (void 0 === a && 1 === b.nodeType) return b.innerHTML;\r\n                  if (\r\n                    "string" == typeof a &&\r\n                    !Aa.test(a) &&\r\n                    !ma[(ka.exec(a) || ["", ""])[1].toLowerCase()]\r\n                  ) {\r\n                    a = r.htmlPrefilter(a);\r\n                    try {\r\n                      for (; c < d; c++)\r\n                        (b = this[c] || {}),\r\n                          1 === b.nodeType &&\r\n                            (r.cleanData(na(b, !1)), (b.innerHTML = a));\r\n                      b = 0;\r\n                    } catch (e) {}\r\n                  }\r\n                  b && this.empty().append(a);\r\n                },\r\n                null,\r\n                a,\r\n                arguments.length\r\n              );\r\n            },\r\n            replaceWith: function () {\r\n              var a = [];\r\n              return Ja(\r\n                this,\r\n                arguments,\r\n                function (b) {\r\n                  var c = this.parentNode;\r\n                  r.inArray(this, a) < 0 &&\r\n                    (r.cleanData(na(this)), c && c.replaceChild(b, this));\r\n                },\r\n                a\r\n              );\r\n            },\r\n          }),\r\n          r.each(\r\n            {\r\n              appendTo: "append",\r\n              prependTo: "prepend",\r\n              insertBefore: "before",\r\n              insertAfter: "after",\r\n              replaceAll: "replaceWith",\r\n            },\r\n            function (a, b) {\r\n              r.fn[a] = function (a) {\r\n                for (\r\n                  var c, d = [], e = r(a), f = e.length - 1, g = 0;\r\n                  g <= f;\r\n                  g++\r\n                )\r\n                  (c = g === f ? this : this.clone(!0)),\r\n                    r(e[g])[b](c),\r\n                    h.apply(d, c.get());\r\n                return this.pushStack(d);\r\n              };\r\n            }\r\n          );\r\n        var La = /^margin/,\r\n          Ma = new RegExp("^(" + aa + ")(?!px)[a-z%]+$", "i"),\r\n          Na = function (b) {\r\n            var c = b.ownerDocument.defaultView;\r\n            return (c && c.opener) || (c = a), c.getComputedStyle(b);\r\n          };\r\n        !(function () {\r\n          function b() {\r\n            if (i) {\r\n              (i.style.cssText =\r\n                "box-sizing:border-box;position:relative;display:block;margin:auto;border:1px;padding:1px;top:1%;width:50%"),\r\n                (i.innerHTML = ""),\r\n                ra.appendChild(h);\r\n              var b = a.getComputedStyle(i);\r\n              (c = "1%" !== b.top),\r\n                (g = "2px" === b.marginLeft),\r\n                (e = "4px" === b.width),\r\n                (i.style.marginRight = "50%"),\r\n                (f = "4px" === b.marginRight),\r\n                ra.removeChild(h),\r\n                (i = null);\r\n            }\r\n          }\r\n          var c,\r\n            e,\r\n            f,\r\n            g,\r\n            h = d.createElement("div"),\r\n            i = d.createElement("div");\r\n          i.style &&\r\n            ((i.style.backgroundClip = "content-box"),\r\n            (i.cloneNode(!0).style.backgroundClip = ""),\r\n            (o.clearCloneStyle = "content-box" === i.style.backgroundClip),\r\n            (h.style.cssText =\r\n              "border:0;width:8px;height:0;top:0;left:-9999px;padding:0;margin-top:1px;position:absolute"),\r\n            h.appendChild(i),\r\n            r.extend(o, {\r\n              pixelPosition: function () {\r\n                return b(), c;\r\n              },\r\n              boxSizingReliable: function () {\r\n                return b(), e;\r\n              },\r\n              pixelMarginRight: function () {\r\n                return b(), f;\r\n              },\r\n              reliableMarginLeft: function () {\r\n                return b(), g;\r\n              },\r\n            }));\r\n        })();\r\n        function Oa(a, b, c) {\r\n          var d,\r\n            e,\r\n            f,\r\n            g,\r\n            h = a.style;\r\n          return (\r\n            (c = c || Na(a)),\r\n            c &&\r\n              ((g = c.getPropertyValue(b) || c[b]),\r\n              "" !== g || r.contains(a.ownerDocument, a) || (g = r.style(a, b)),\r\n              !o.pixelMarginRight() &&\r\n                Ma.test(g) &&\r\n                La.test(b) &&\r\n                ((d = h.width),\r\n                (e = h.minWidth),\r\n                (f = h.maxWidth),\r\n                (h.minWidth = h.maxWidth = h.width = g),\r\n                (g = c.width),\r\n                (h.width = d),\r\n                (h.minWidth = e),\r\n                (h.maxWidth = f))),\r\n            void 0 !== g ? g + "" : g\r\n          );\r\n        }\r\n        function Pa(a, b) {\r\n          return {\r\n            get: function () {\r\n              return a()\r\n                ? void delete this.get\r\n                : (this.get = b).apply(this, arguments);\r\n            },\r\n          };\r\n        }\r\n        var Qa = /^(none|table(?!-c[ea]).+)/,\r\n          Ra = /^--/,\r\n          Sa = { position: "absolute", visibility: "hidden", display: "block" },\r\n          Ta = { letterSpacing: "0", fontWeight: "400" },\r\n          Ua = ["Webkit", "Moz", "ms"],\r\n          Va = d.createElement("div").style;\r\n        function Wa(a) {\r\n          if (a in Va) return a;\r\n          var b = a[0].toUpperCase() + a.slice(1),\r\n            c = Ua.length;\r\n          while (c--) if (((a = Ua[c] + b), a in Va)) return a;\r\n        }\r\n        function Xa(a) {\r\n          var b = r.cssProps[a];\r\n          return b || (b = r.cssProps[a] = Wa(a) || a), b;\r\n        }\r\n        function Ya(a, b, c) {\r\n          var d = ba.exec(b);\r\n          return d ? Math.max(0, d[2] - (c || 0)) + (d[3] || "px") : b;\r\n        }\r\n        function Za(a, b, c, d, e) {\r\n          var f,\r\n            g = 0;\r\n          for (\r\n            f = c === (d ? "border" : "content") ? 4 : "width" === b ? 1 : 0;\r\n            f < 4;\r\n            f += 2\r\n          )\r\n            "margin" === c && (g += r.css(a, c + ca[f], !0, e)),\r\n              d\r\n                ? ("content" === c && (g -= r.css(a, "padding" + ca[f], !0, e)),\r\n                  "margin" !== c &&\r\n                    (g -= r.css(a, "border" + ca[f] + "Width", !0, e)))\r\n                : ((g += r.css(a, "padding" + ca[f], !0, e)),\r\n                  "padding" !== c &&\r\n                    (g += r.css(a, "border" + ca[f] + "Width", !0, e)));\r\n          return g;\r\n        }\r\n        function $a(a, b, c) {\r\n          var d,\r\n            e = Na(a),\r\n            f = Oa(a, b, e),\r\n            g = "border-box" === r.css(a, "boxSizing", !1, e);\r\n          return Ma.test(f)\r\n            ? f\r\n            : ((d = g && (o.boxSizingReliable() || f === a.style[b])),\r\n              "auto" === f &&\r\n                (f = a["offset" + b[0].toUpperCase() + b.slice(1)]),\r\n              (f = parseFloat(f) || 0),\r\n              f + Za(a, b, c || (g ? "border" : "content"), d, e) + "px");\r\n        }\r\n        r.extend({\r\n          cssHooks: {\r\n            opacity: {\r\n              get: function (a, b) {\r\n                if (b) {\r\n                  var c = Oa(a, "opacity");\r\n                  return "" === c ? "1" : c;\r\n                }\r\n              },\r\n            },\r\n          },\r\n          cssNumber: {\r\n            animationIterationCount: !0,\r\n            columnCount: !0,\r\n            fillOpacity: !0,\r\n            flexGrow: !0,\r\n            flexShrink: !0,\r\n            fontWeight: !0,\r\n            lineHeight: !0,\r\n            opacity: !0,\r\n            order: !0,\r\n            orphans: !0,\r\n            widows: !0,\r\n            zIndex: !0,\r\n            zoom: !0,\r\n          },\r\n          cssProps: { float: "cssFloat" },\r\n          style: function (a, b, c, d) {\r\n            if (a && 3 !== a.nodeType && 8 !== a.nodeType && a.style) {\r\n              var e,\r\n                f,\r\n                g,\r\n                h = r.camelCase(b),\r\n                i = Ra.test(b),\r\n                j = a.style;\r\n              return (\r\n                i || (b = Xa(h)),\r\n                (g = r.cssHooks[b] || r.cssHooks[h]),\r\n                void 0 === c\r\n                  ? g && "get" in g && void 0 !== (e = g.get(a, !1, d))\r\n                    ? e\r\n                    : j[b]\r\n                  : ((f = typeof c),\r\n                    "string" === f &&\r\n                      (e = ba.exec(c)) &&\r\n                      e[1] &&\r\n                      ((c = fa(a, b, e)), (f = "number")),\r\n                    null != c &&\r\n                      c === c &&\r\n                      ("number" === f &&\r\n                        (c += (e && e[3]) || (r.cssNumber[h] ? "" : "px")),\r\n                      o.clearCloneStyle ||\r\n                        "" !== c ||\r\n                        0 !== b.indexOf("background") ||\r\n                        (j[b] = "inherit"),\r\n                      (g && "set" in g && void 0 === (c = g.set(a, c, d))) ||\r\n                        (i ? j.setProperty(b, c) : (j[b] = c))),\r\n                    void 0)\r\n              );\r\n            }\r\n          },\r\n          css: function (a, b, c, d) {\r\n            var e,\r\n              f,\r\n              g,\r\n              h = r.camelCase(b),\r\n              i = Ra.test(b);\r\n            return (\r\n              i || (b = Xa(h)),\r\n              (g = r.cssHooks[b] || r.cssHooks[h]),\r\n              g && "get" in g && (e = g.get(a, !0, c)),\r\n              void 0 === e && (e = Oa(a, b, d)),\r\n              "normal" === e && b in Ta && (e = Ta[b]),\r\n              "" === c || c\r\n                ? ((f = parseFloat(e)), c === !0 || isFinite(f) ? f || 0 : e)\r\n                : e\r\n            );\r\n          },\r\n        }),\r\n          r.each(["height", "width"], function (a, b) {\r\n            r.cssHooks[b] = {\r\n              get: function (a, c, d) {\r\n                if (c)\r\n                  return !Qa.test(r.css(a, "display")) ||\r\n                    (a.getClientRects().length &&\r\n                      a.getBoundingClientRect().width)\r\n                    ? $a(a, b, d)\r\n                    : ea(a, Sa, function () {\r\n                        return $a(a, b, d);\r\n                      });\r\n              },\r\n              set: function (a, c, d) {\r\n                var e,\r\n                  f = d && Na(a),\r\n                  g =\r\n                    d &&\r\n                    Za(\r\n                      a,\r\n                      b,\r\n                      d,\r\n                      "border-box" === r.css(a, "boxSizing", !1, f),\r\n                      f\r\n                    );\r\n                return (\r\n                  g &&\r\n                    (e = ba.exec(c)) &&\r\n                    "px" !== (e[3] || "px") &&\r\n                    ((a.style[b] = c), (c = r.css(a, b))),\r\n                  Ya(a, c, g)\r\n                );\r\n              },\r\n            };\r\n          }),\r\n          (r.cssHooks.marginLeft = Pa(o.reliableMarginLeft, function (a, b) {\r\n            if (b)\r\n              return (\r\n                (parseFloat(Oa(a, "marginLeft")) ||\r\n                  a.getBoundingClientRect().left -\r\n                    ea(a, { marginLeft: 0 }, function () {\r\n                      return a.getBoundingClientRect().left;\r\n                    })) + "px"\r\n              );\r\n          })),\r\n          r.each({ margin: "", padding: "", border: "Width" }, function (a, b) {\r\n            (r.cssHooks[a + b] = {\r\n              expand: function (c) {\r\n                for (\r\n                  var d = 0,\r\n                    e = {},\r\n                    f = "string" == typeof c ? c.split(" ") : [c];\r\n                  d < 4;\r\n                  d++\r\n                )\r\n                  e[a + ca[d] + b] = f[d] || f[d - 2] || f[0];\r\n                return e;\r\n              },\r\n            }),\r\n              La.test(a) || (r.cssHooks[a + b].set = Ya);\r\n          }),\r\n          r.fn.extend({\r\n            css: function (a, b) {\r\n              return T(\r\n                this,\r\n                function (a, b, c) {\r\n                  var d,\r\n                    e,\r\n                    f = {},\r\n                    g = 0;\r\n                  if (Array.isArray(b)) {\r\n                    for (d = Na(a), e = b.length; g < e; g++)\r\n                      f[b[g]] = r.css(a, b[g], !1, d);\r\n                    return f;\r\n                  }\r\n                  return void 0 !== c ? r.style(a, b, c) : r.css(a, b);\r\n                },\r\n                a,\r\n                b,\r\n                arguments.length > 1\r\n              );\r\n            },\r\n          });\r\n        function _a(a, b, c, d, e) {\r\n          return new _a.prototype.init(a, b, c, d, e);\r\n        }\r\n        (r.Tween = _a),\r\n          (_a.prototype = {\r\n            constructor: _a,\r\n            init: function (a, b, c, d, e, f) {\r\n              (this.elem = a),\r\n                (this.prop = c),\r\n                (this.easing = e || r.easing._default),\r\n                (this.options = b),\r\n                (this.start = this.now = this.cur()),\r\n                (this.end = d),\r\n                (this.unit = f || (r.cssNumber[c] ? "" : "px"));\r\n            },\r\n            cur: function () {\r\n              var a = _a.propHooks[this.prop];\r\n              return a && a.get ? a.get(this) : _a.propHooks._default.get(this);\r\n            },\r\n            run: function (a) {\r\n              var b,\r\n                c = _a.propHooks[this.prop];\r\n              return (\r\n                this.options.duration\r\n                  ? (this.pos = b =\r\n                      r.easing[this.easing](\r\n                        a,\r\n                        this.options.duration * a,\r\n                        0,\r\n                        1,\r\n                        this.options.duration\r\n                      ))\r\n                  : (this.pos = b = a),\r\n                (this.now = (this.end - this.start) * b + this.start),\r\n                this.options.step &&\r\n                  this.options.step.call(this.elem, this.now, this),\r\n                c && c.set ? c.set(this) : _a.propHooks._default.set(this),\r\n                this\r\n              );\r\n            },\r\n          }),\r\n          (_a.prototype.init.prototype = _a.prototype),\r\n          (_a.propHooks = {\r\n            _default: {\r\n              get: function (a) {\r\n                var b;\r\n                return 1 !== a.elem.nodeType ||\r\n                  (null != a.elem[a.prop] && null == a.elem.style[a.prop])\r\n                  ? a.elem[a.prop]\r\n                  : ((b = r.css(a.elem, a.prop, "")),\r\n                    b && "auto" !== b ? b : 0);\r\n              },\r\n              set: function (a) {\r\n                r.fx.step[a.prop]\r\n                  ? r.fx.step[a.prop](a)\r\n                  : 1 !== a.elem.nodeType ||\r\n                    (null == a.elem.style[r.cssProps[a.prop]] &&\r\n                      !r.cssHooks[a.prop])\r\n                  ? (a.elem[a.prop] = a.now)\r\n                  : r.style(a.elem, a.prop, a.now + a.unit);\r\n              },\r\n            },\r\n          }),\r\n          (_a.propHooks.scrollTop = _a.propHooks.scrollLeft =\r\n            {\r\n              set: function (a) {\r\n                a.elem.nodeType &&\r\n                  a.elem.parentNode &&\r\n                  (a.elem[a.prop] = a.now);\r\n              },\r\n            }),\r\n          (r.easing = {\r\n            linear: function (a) {\r\n              return a;\r\n            },\r\n            swing: function (a) {\r\n              return 0.5 - Math.cos(a * Math.PI) / 2;\r\n            },\r\n            _default: "swing",\r\n          }),\r\n          (r.fx = _a.prototype.init),\r\n          (r.fx.step = {});\r\n        var ab,\r\n          bb,\r\n          cb = /^(?:toggle|show|hide)$/,\r\n          db = /queueHooks$/;\r\n        function eb() {\r\n          bb &&\r\n            (d.hidden === !1 && a.requestAnimationFrame\r\n              ? a.requestAnimationFrame(eb)\r\n              : a.setTimeout(eb, r.fx.interval),\r\n            r.fx.tick());\r\n        }\r\n        function fb() {\r\n          return (\r\n            a.setTimeout(function () {\r\n              ab = void 0;\r\n            }),\r\n            (ab = r.now())\r\n          );\r\n        }\r\n        function gb(a, b) {\r\n          var c,\r\n            d = 0,\r\n            e = { height: a };\r\n          for (b = b ? 1 : 0; d < 4; d += 2 - b)\r\n            (c = ca[d]), (e["margin" + c] = e["padding" + c] = a);\r\n          return b && (e.opacity = e.width = a), e;\r\n        }\r\n        function hb(a, b, c) {\r\n          for (\r\n            var d,\r\n              e = (kb.tweeners[b] || []).concat(kb.tweeners["*"]),\r\n              f = 0,\r\n              g = e.length;\r\n            f < g;\r\n            f++\r\n          )\r\n            if ((d = e[f].call(c, b, a))) return d;\r\n        }\r\n        function ib(a, b, c) {\r\n          var d,\r\n            e,\r\n            f,\r\n            g,\r\n            h,\r\n            i,\r\n            j,\r\n            k,\r\n            l = "width" in b || "height" in b,\r\n            m = this,\r\n            n = {},\r\n            o = a.style,\r\n            p = a.nodeType && da(a),\r\n            q = W.get(a, "fxshow");\r\n          c.queue ||\r\n            ((g = r._queueHooks(a, "fx")),\r\n            null == g.unqueued &&\r\n              ((g.unqueued = 0),\r\n              (h = g.empty.fire),\r\n              (g.empty.fire = function () {\r\n                g.unqueued || h();\r\n              })),\r\n            g.unqueued++,\r\n            m.always(function () {\r\n              m.always(function () {\r\n                g.unqueued--, r.queue(a, "fx").length || g.empty.fire();\r\n              });\r\n            }));\r\n          for (d in b)\r\n            if (((e = b[d]), cb.test(e))) {\r\n              if (\r\n                (delete b[d],\r\n                (f = f || "toggle" === e),\r\n                e === (p ? "hide" : "show"))\r\n              ) {\r\n                if ("show" !== e || !q || void 0 === q[d]) continue;\r\n                p = !0;\r\n              }\r\n              n[d] = (q && q[d]) || r.style(a, d);\r\n            }\r\n          if (((i = !r.isEmptyObject(b)), i || !r.isEmptyObject(n))) {\r\n            l &&\r\n              1 === a.nodeType &&\r\n              ((c.overflow = [o.overflow, o.overflowX, o.overflowY]),\r\n              (j = q && q.display),\r\n              null == j && (j = W.get(a, "display")),\r\n              (k = r.css(a, "display")),\r\n              "none" === k &&\r\n                (j\r\n                  ? (k = j)\r\n                  : (ia([a], !0),\r\n                    (j = a.style.display || j),\r\n                    (k = r.css(a, "display")),\r\n                    ia([a]))),\r\n              ("inline" === k || ("inline-block" === k && null != j)) &&\r\n                "none" === r.css(a, "float") &&\r\n                (i ||\r\n                  (m.done(function () {\r\n                    o.display = j;\r\n                  }),\r\n                  null == j && ((k = o.display), (j = "none" === k ? "" : k))),\r\n                (o.display = "inline-block"))),\r\n              c.overflow &&\r\n                ((o.overflow = "hidden"),\r\n                m.always(function () {\r\n                  (o.overflow = c.overflow[0]),\r\n                    (o.overflowX = c.overflow[1]),\r\n                    (o.overflowY = c.overflow[2]);\r\n                })),\r\n              (i = !1);\r\n            for (d in n)\r\n              i ||\r\n                (q\r\n                  ? "hidden" in q && (p = q.hidden)\r\n                  : (q = W.access(a, "fxshow", { display: j })),\r\n                f && (q.hidden = !p),\r\n                p && ia([a], !0),\r\n                m.done(function () {\r\n                  p || ia([a]), W.remove(a, "fxshow");\r\n                  for (d in n) r.style(a, d, n[d]);\r\n                })),\r\n                (i = hb(p ? q[d] : 0, d, m)),\r\n                d in q ||\r\n                  ((q[d] = i.start), p && ((i.end = i.start), (i.start = 0)));\r\n          }\r\n        }\r\n        function jb(a, b) {\r\n          var c, d, e, f, g;\r\n          for (c in a)\r\n            if (\r\n              ((d = r.camelCase(c)),\r\n              (e = b[d]),\r\n              (f = a[c]),\r\n              Array.isArray(f) && ((e = f[1]), (f = a[c] = f[0])),\r\n              c !== d && ((a[d] = f), delete a[c]),\r\n              (g = r.cssHooks[d]),\r\n              g && "expand" in g)\r\n            ) {\r\n              (f = g.expand(f)), delete a[d];\r\n              for (c in f) c in a || ((a[c] = f[c]), (b[c] = e));\r\n            } else b[d] = e;\r\n        }\r\n        function kb(a, b, c) {\r\n          var d,\r\n            e,\r\n            f = 0,\r\n            g = kb.prefilters.length,\r\n            h = r.Deferred().always(function () {\r\n              delete i.elem;\r\n            }),\r\n            i = function () {\r\n              if (e) return !1;\r\n              for (\r\n                var b = ab || fb(),\r\n                  c = Math.max(0, j.startTime + j.duration - b),\r\n                  d = c / j.duration || 0,\r\n                  f = 1 - d,\r\n                  g = 0,\r\n                  i = j.tweens.length;\r\n                g < i;\r\n                g++\r\n              )\r\n                j.tweens[g].run(f);\r\n              return (\r\n                h.notifyWith(a, [j, f, c]),\r\n                f < 1 && i\r\n                  ? c\r\n                  : (i || h.notifyWith(a, [j, 1, 0]), h.resolveWith(a, [j]), !1)\r\n              );\r\n            },\r\n            j = h.promise({\r\n              elem: a,\r\n              props: r.extend({}, b),\r\n              opts: r.extend(\r\n                !0,\r\n                { specialEasing: {}, easing: r.easing._default },\r\n                c\r\n              ),\r\n              originalProperties: b,\r\n              originalOptions: c,\r\n              startTime: ab || fb(),\r\n              duration: c.duration,\r\n              tweens: [],\r\n              createTween: function (b, c) {\r\n                var d = r.Tween(\r\n                  a,\r\n                  j.opts,\r\n                  b,\r\n                  c,\r\n                  j.opts.specialEasing[b] || j.opts.easing\r\n                );\r\n                return j.tweens.push(d), d;\r\n              },\r\n              stop: function (b) {\r\n                var c = 0,\r\n                  d = b ? j.tweens.length : 0;\r\n                if (e) return this;\r\n                for (e = !0; c < d; c++) j.tweens[c].run(1);\r\n                return (\r\n                  b\r\n                    ? (h.notifyWith(a, [j, 1, 0]), h.resolveWith(a, [j, b]))\r\n                    : h.rejectWith(a, [j, b]),\r\n                  this\r\n                );\r\n              },\r\n            }),\r\n            k = j.props;\r\n          for (jb(k, j.opts.specialEasing); f < g; f++)\r\n            if ((d = kb.prefilters[f].call(j, a, k, j.opts)))\r\n              return (\r\n                r.isFunction(d.stop) &&\r\n                  (r._queueHooks(j.elem, j.opts.queue).stop = r.proxy(\r\n                    d.stop,\r\n                    d\r\n                  )),\r\n                d\r\n              );\r\n          return (\r\n            r.map(k, hb, j),\r\n            r.isFunction(j.opts.start) && j.opts.start.call(a, j),\r\n            j\r\n              .progress(j.opts.progress)\r\n              .done(j.opts.done, j.opts.complete)\r\n              .fail(j.opts.fail)\r\n              .always(j.opts.always),\r\n            r.fx.timer(r.extend(i, { elem: a, anim: j, queue: j.opts.queue })),\r\n            j\r\n          );\r\n        }\r\n        (r.Animation = r.extend(kb, {\r\n          tweeners: {\r\n            "*": [\r\n              function (a, b) {\r\n                var c = this.createTween(a, b);\r\n                return fa(c.elem, a, ba.exec(b), c), c;\r\n              },\r\n            ],\r\n          },\r\n          tweener: function (a, b) {\r\n            r.isFunction(a) ? ((b = a), (a = ["*"])) : (a = a.match(L));\r\n            for (var c, d = 0, e = a.length; d < e; d++)\r\n              (c = a[d]),\r\n                (kb.tweeners[c] = kb.tweeners[c] || []),\r\n                kb.tweeners[c].unshift(b);\r\n          },\r\n          prefilters: [ib],\r\n          prefilter: function (a, b) {\r\n            b ? kb.prefilters.unshift(a) : kb.prefilters.push(a);\r\n          },\r\n        })),\r\n          (r.speed = function (a, b, c) {\r\n            var d =\r\n              a && "object" == typeof a\r\n                ? r.extend({}, a)\r\n                : {\r\n                    complete: c || (!c && b) || (r.isFunction(a) && a),\r\n                    duration: a,\r\n                    easing: (c && b) || (b && !r.isFunction(b) && b),\r\n                  };\r\n            return (\r\n              r.fx.off\r\n                ? (d.duration = 0)\r\n                : "number" != typeof d.duration &&\r\n                  (d.duration in r.fx.speeds\r\n                    ? (d.duration = r.fx.speeds[d.duration])\r\n                    : (d.duration = r.fx.speeds._default)),\r\n              (null != d.queue && d.queue !== !0) || (d.queue = "fx"),\r\n              (d.old = d.complete),\r\n              (d.complete = function () {\r\n                r.isFunction(d.old) && d.old.call(this),\r\n                  d.queue && r.dequeue(this, d.queue);\r\n              }),\r\n              d\r\n            );\r\n          }),\r\n          r.fn.extend({\r\n            fadeTo: function (a, b, c, d) {\r\n              return this.filter(da)\r\n                .css("opacity", 0)\r\n                .show()\r\n                .end()\r\n                .animate({ opacity: b }, a, c, d);\r\n            },\r\n            animate: function (a, b, c, d) {\r\n              var e = r.isEmptyObject(a),\r\n                f = r.speed(b, c, d),\r\n                g = function () {\r\n                  var b = kb(this, r.extend({}, a), f);\r\n                  (e || W.get(this, "finish")) && b.stop(!0);\r\n                };\r\n              return (\r\n                (g.finish = g),\r\n                e || f.queue === !1 ? this.each(g) : this.queue(f.queue, g)\r\n              );\r\n            },\r\n            stop: function (a, b, c) {\r\n              var d = function (a) {\r\n                var b = a.stop;\r\n                delete a.stop, b(c);\r\n              };\r\n              return (\r\n                "string" != typeof a && ((c = b), (b = a), (a = void 0)),\r\n                b && a !== !1 && this.queue(a || "fx", []),\r\n                this.each(function () {\r\n                  var b = !0,\r\n                    e = null != a && a + "queueHooks",\r\n                    f = r.timers,\r\n                    g = W.get(this);\r\n                  if (e) g[e] && g[e].stop && d(g[e]);\r\n                  else for (e in g) g[e] && g[e].stop && db.test(e) && d(g[e]);\r\n                  for (e = f.length; e--; )\r\n                    f[e].elem !== this ||\r\n                      (null != a && f[e].queue !== a) ||\r\n                      (f[e].anim.stop(c), (b = !1), f.splice(e, 1));\r\n                  (!b && c) || r.dequeue(this, a);\r\n                })\r\n              );\r\n            },\r\n            finish: function (a) {\r\n              return (\r\n                a !== !1 && (a = a || "fx"),\r\n                this.each(function () {\r\n                  var b,\r\n                    c = W.get(this),\r\n                    d = c[a + "queue"],\r\n                    e = c[a + "queueHooks"],\r\n                    f = r.timers,\r\n                    g = d ? d.length : 0;\r\n                  for (\r\n                    c.finish = !0,\r\n                      r.queue(this, a, []),\r\n                      e && e.stop && e.stop.call(this, !0),\r\n                      b = f.length;\r\n                    b--;\r\n\r\n                  )\r\n                    f[b].elem === this &&\r\n                      f[b].queue === a &&\r\n                      (f[b].anim.stop(!0), f.splice(b, 1));\r\n                  for (b = 0; b < g; b++)\r\n                    d[b] && d[b].finish && d[b].finish.call(this);\r\n                  delete c.finish;\r\n                })\r\n              );\r\n            },\r\n          }),\r\n          r.each(["toggle", "show", "hide"], function (a, b) {\r\n            var c = r.fn[b];\r\n            r.fn[b] = function (a, d, e) {\r\n              return null == a || "boolean" == typeof a\r\n                ? c.apply(this, arguments)\r\n                : this.animate(gb(b, !0), a, d, e);\r\n            };\r\n          }),\r\n          r.each(\r\n            {\r\n              slideDown: gb("show"),\r\n              slideUp: gb("hide"),\r\n              slideToggle: gb("toggle"),\r\n              fadeIn: { opacity: "show" },\r\n              fadeOut: { opacity: "hide" },\r\n              fadeToggle: { opacity: "toggle" },\r\n            },\r\n            function (a, b) {\r\n              r.fn[a] = function (a, c, d) {\r\n                return this.animate(b, a, c, d);\r\n              };\r\n            }\r\n          ),\r\n          (r.timers = []),\r\n          (r.fx.tick = function () {\r\n            var a,\r\n              b = 0,\r\n              c = r.timers;\r\n            for (ab = r.now(); b < c.length; b++)\r\n              (a = c[b]), a() || c[b] !== a || c.splice(b--, 1);\r\n            c.length || r.fx.stop(), (ab = void 0);\r\n          }),\r\n          (r.fx.timer = function (a) {\r\n            r.timers.push(a), r.fx.start();\r\n          }),\r\n          (r.fx.interval = 13),\r\n          (r.fx.start = function () {\r\n            bb || ((bb = !0), eb());\r\n          }),\r\n          (r.fx.stop = function () {\r\n            bb = null;\r\n          }),\r\n          (r.fx.speeds = { slow: 600, fast: 200, _default: 400 }),\r\n          (r.fn.delay = function (b, c) {\r\n            return (\r\n              (b = r.fx ? r.fx.speeds[b] || b : b),\r\n              (c = c || "fx"),\r\n              this.queue(c, function (c, d) {\r\n                var e = a.setTimeout(c, b);\r\n                d.stop = function () {\r\n                  a.clearTimeout(e);\r\n                };\r\n              })\r\n            );\r\n          }),\r\n          (function () {\r\n            var a = d.createElement("input"),\r\n              b = d.createElement("select"),\r\n              c = b.appendChild(d.createElement("option"));\r\n            (a.type = "checkbox"),\r\n              (o.checkOn = "" !== a.value),\r\n              (o.optSelected = c.selected),\r\n              (a = d.createElement("input")),\r\n              (a.value = "t"),\r\n              (a.type = "radio"),\r\n              (o.radioValue = "t" === a.value);\r\n          })();\r\n        var lb,\r\n          mb = r.expr.attrHandle;\r\n        r.fn.extend({\r\n          attr: function (a, b) {\r\n            return T(this, r.attr, a, b, arguments.length > 1);\r\n          },\r\n          removeAttr: function (a) {\r\n            return this.each(function () {\r\n              r.removeAttr(this, a);\r\n            });\r\n          },\r\n        }),\r\n          r.extend({\r\n            attr: function (a, b, c) {\r\n              var d,\r\n                e,\r\n                f = a.nodeType;\r\n              if (3 !== f && 8 !== f && 2 !== f)\r\n                return "undefined" == typeof a.getAttribute\r\n                  ? r.prop(a, b, c)\r\n                  : ((1 === f && r.isXMLDoc(a)) ||\r\n                      (e =\r\n                        r.attrHooks[b.toLowerCase()] ||\r\n                        (r.expr.match.bool.test(b) ? lb : void 0)),\r\n                    void 0 !== c\r\n                      ? null === c\r\n                        ? void r.removeAttr(a, b)\r\n                        : e && "set" in e && void 0 !== (d = e.set(a, c, b))\r\n                        ? d\r\n                        : (a.setAttribute(b, c + ""), c)\r\n                      : e && "get" in e && null !== (d = e.get(a, b))\r\n                      ? d\r\n                      : ((d = r.find.attr(a, b)), null == d ? void 0 : d));\r\n            },\r\n            attrHooks: {\r\n              type: {\r\n                set: function (a, b) {\r\n                  if (!o.radioValue && "radio" === b && B(a, "input")) {\r\n                    var c = a.value;\r\n                    return a.setAttribute("type", b), c && (a.value = c), b;\r\n                  }\r\n                },\r\n              },\r\n            },\r\n            removeAttr: function (a, b) {\r\n              var c,\r\n                d = 0,\r\n                e = b && b.match(L);\r\n              if (e && 1 === a.nodeType)\r\n                while ((c = e[d++])) a.removeAttribute(c);\r\n            },\r\n          }),\r\n          (lb = {\r\n            set: function (a, b, c) {\r\n              return b === !1 ? r.removeAttr(a, c) : a.setAttribute(c, c), c;\r\n            },\r\n          }),\r\n          r.each(r.expr.match.bool.source.match(/\\w+/g), function (a, b) {\r\n            var c = mb[b] || r.find.attr;\r\n            mb[b] = function (a, b, d) {\r\n              var e,\r\n                f,\r\n                g = b.toLowerCase();\r\n              return (\r\n                d ||\r\n                  ((f = mb[g]),\r\n                  (mb[g] = e),\r\n                  (e = null != c(a, b, d) ? g : null),\r\n                  (mb[g] = f)),\r\n                e\r\n              );\r\n            };\r\n          });\r\n        var nb = /^(?:input|select|textarea|button)$/i,\r\n          ob = /^(?:a|area)$/i;\r\n        r.fn.extend({\r\n          prop: function (a, b) {\r\n            return T(this, r.prop, a, b, arguments.length > 1);\r\n          },\r\n          removeProp: function (a) {\r\n            return this.each(function () {\r\n              delete this[r.propFix[a] || a];\r\n            });\r\n          },\r\n        }),\r\n          r.extend({\r\n            prop: function (a, b, c) {\r\n              var d,\r\n                e,\r\n                f = a.nodeType;\r\n              if (3 !== f && 8 !== f && 2 !== f)\r\n                return (\r\n                  (1 === f && r.isXMLDoc(a)) ||\r\n                    ((b = r.propFix[b] || b), (e = r.propHooks[b])),\r\n                  void 0 !== c\r\n                    ? e && "set" in e && void 0 !== (d = e.set(a, c, b))\r\n                      ? d\r\n                      : (a[b] = c)\r\n                    : e && "get" in e && null !== (d = e.get(a, b))\r\n                    ? d\r\n                    : a[b]\r\n                );\r\n            },\r\n            propHooks: {\r\n              tabIndex: {\r\n                get: function (a) {\r\n                  var b = r.find.attr(a, "tabindex");\r\n                  return b\r\n                    ? parseInt(b, 10)\r\n                    : nb.test(a.nodeName) || (ob.test(a.nodeName) && a.href)\r\n                    ? 0\r\n                    : -1;\r\n                },\r\n              },\r\n            },\r\n            propFix: { for: "htmlFor", class: "className" },\r\n          }),\r\n          o.optSelected ||\r\n            (r.propHooks.selected = {\r\n              get: function (a) {\r\n                var b = a.parentNode;\r\n                return b && b.parentNode && b.parentNode.selectedIndex, null;\r\n              },\r\n              set: function (a) {\r\n                var b = a.parentNode;\r\n                b &&\r\n                  (b.selectedIndex, b.parentNode && b.parentNode.selectedIndex);\r\n              },\r\n            }),\r\n          r.each(\r\n            [\r\n              "tabIndex",\r\n              "readOnly",\r\n              "maxLength",\r\n              "cellSpacing",\r\n              "cellPadding",\r\n              "rowSpan",\r\n              "colSpan",\r\n              "useMap",\r\n              "frameBorder",\r\n              "contentEditable",\r\n            ],\r\n            function () {\r\n              r.propFix[this.toLowerCase()] = this;\r\n            }\r\n          );\r\n        function pb(a) {\r\n          var b = a.match(L) || [];\r\n          return b.join(" ");\r\n        }\r\n        function qb(a) {\r\n          return (a.getAttribute && a.getAttribute("class")) || "";\r\n        }\r\n        r.fn.extend({\r\n          addClass: function (a) {\r\n            var b,\r\n              c,\r\n              d,\r\n              e,\r\n              f,\r\n              g,\r\n              h,\r\n              i = 0;\r\n            if (r.isFunction(a))\r\n              return this.each(function (b) {\r\n                r(this).addClass(a.call(this, b, qb(this)));\r\n              });\r\n            if ("string" == typeof a && a) {\r\n              b = a.match(L) || [];\r\n              while ((c = this[i++]))\r\n                if (\r\n                  ((e = qb(c)), (d = 1 === c.nodeType && " " + pb(e) + " "))\r\n                ) {\r\n                  g = 0;\r\n                  while ((f = b[g++]))\r\n                    d.indexOf(" " + f + " ") < 0 && (d += f + " ");\r\n                  (h = pb(d)), e !== h && c.setAttribute("class", h);\r\n                }\r\n            }\r\n            return this;\r\n          },\r\n          removeClass: function (a) {\r\n            var b,\r\n              c,\r\n              d,\r\n              e,\r\n              f,\r\n              g,\r\n              h,\r\n              i = 0;\r\n            if (r.isFunction(a))\r\n              return this.each(function (b) {\r\n                r(this).removeClass(a.call(this, b, qb(this)));\r\n              });\r\n            if (!arguments.length) return this.attr("class", "");\r\n            if ("string" == typeof a && a) {\r\n              b = a.match(L) || [];\r\n              while ((c = this[i++]))\r\n                if (\r\n                  ((e = qb(c)), (d = 1 === c.nodeType && " " + pb(e) + " "))\r\n                ) {\r\n                  g = 0;\r\n                  while ((f = b[g++]))\r\n                    while (d.indexOf(" " + f + " ") > -1)\r\n                      d = d.replace(" " + f + " ", " ");\r\n                  (h = pb(d)), e !== h && c.setAttribute("class", h);\r\n                }\r\n            }\r\n            return this;\r\n          },\r\n          toggleClass: function (a, b) {\r\n            var c = typeof a;\r\n            return "boolean" == typeof b && "string" === c\r\n              ? b\r\n                ? this.addClass(a)\r\n                : this.removeClass(a)\r\n              : r.isFunction(a)\r\n              ? this.each(function (c) {\r\n                  r(this).toggleClass(a.call(this, c, qb(this), b), b);\r\n                })\r\n              : this.each(function () {\r\n                  var b, d, e, f;\r\n                  if ("string" === c) {\r\n                    (d = 0), (e = r(this)), (f = a.match(L) || []);\r\n                    while ((b = f[d++]))\r\n                      e.hasClass(b) ? e.removeClass(b) : e.addClass(b);\r\n                  } else (void 0 !== a && "boolean" !== c) || ((b = qb(this)), b && W.set(this, "__className__", b), this.setAttribute && this.setAttribute("class", b || a === !1 ? "" : W.get(this, "__className__") || ""));\r\n                });\r\n          },\r\n          hasClass: function (a) {\r\n            var b,\r\n              c,\r\n              d = 0;\r\n            b = " " + a + " ";\r\n            while ((c = this[d++]))\r\n              if (1 === c.nodeType && (" " + pb(qb(c)) + " ").indexOf(b) > -1)\r\n                return !0;\r\n            return !1;\r\n          },\r\n        });\r\n        var rb = /\\r/g;\r\n        r.fn.extend({\r\n          val: function (a) {\r\n            var b,\r\n              c,\r\n              d,\r\n              e = this[0];\r\n            {\r\n              if (arguments.length)\r\n                return (\r\n                  (d = r.isFunction(a)),\r\n                  this.each(function (c) {\r\n                    var e;\r\n                    1 === this.nodeType &&\r\n                      ((e = d ? a.call(this, c, r(this).val()) : a),\r\n                      null == e\r\n                        ? (e = "")\r\n                        : "number" == typeof e\r\n                        ? (e += "")\r\n                        : Array.isArray(e) &&\r\n                          (e = r.map(e, function (a) {\r\n                            return null == a ? "" : a + "";\r\n                          })),\r\n                      (b =\r\n                        r.valHooks[this.type] ||\r\n                        r.valHooks[this.nodeName.toLowerCase()]),\r\n                      (b && "set" in b && void 0 !== b.set(this, e, "value")) ||\r\n                        (this.value = e));\r\n                  })\r\n                );\r\n              if (e)\r\n                return (\r\n                  (b =\r\n                    r.valHooks[e.type] || r.valHooks[e.nodeName.toLowerCase()]),\r\n                  b && "get" in b && void 0 !== (c = b.get(e, "value"))\r\n                    ? c\r\n                    : ((c = e.value),\r\n                      "string" == typeof c\r\n                        ? c.replace(rb, "")\r\n                        : null == c\r\n                        ? ""\r\n                        : c)\r\n                );\r\n            }\r\n          },\r\n        }),\r\n          r.extend({\r\n            valHooks: {\r\n              option: {\r\n                get: function (a) {\r\n                  var b = r.find.attr(a, "value");\r\n                  return null != b ? b : pb(r.text(a));\r\n                },\r\n              },\r\n              select: {\r\n                get: function (a) {\r\n                  var b,\r\n                    c,\r\n                    d,\r\n                    e = a.options,\r\n                    f = a.selectedIndex,\r\n                    g = "select-one" === a.type,\r\n                    h = g ? null : [],\r\n                    i = g ? f + 1 : e.length;\r\n                  for (d = f < 0 ? i : g ? f : 0; d < i; d++)\r\n                    if (\r\n                      ((c = e[d]),\r\n                      (c.selected || d === f) &&\r\n                        !c.disabled &&\r\n                        (!c.parentNode.disabled ||\r\n                          !B(c.parentNode, "optgroup")))\r\n                    ) {\r\n                      if (((b = r(c).val()), g)) return b;\r\n                      h.push(b);\r\n                    }\r\n                  return h;\r\n                },\r\n                set: function (a, b) {\r\n                  var c,\r\n                    d,\r\n                    e = a.options,\r\n                    f = r.makeArray(b),\r\n                    g = e.length;\r\n                  while (g--)\r\n                    (d = e[g]),\r\n                      (d.selected =\r\n                        r.inArray(r.valHooks.option.get(d), f) > -1) &&\r\n                        (c = !0);\r\n                  return c || (a.selectedIndex = -1), f;\r\n                },\r\n              },\r\n            },\r\n          }),\r\n          r.each(["radio", "checkbox"], function () {\r\n            (r.valHooks[this] = {\r\n              set: function (a, b) {\r\n                if (Array.isArray(b))\r\n                  return (a.checked = r.inArray(r(a).val(), b) > -1);\r\n              },\r\n            }),\r\n              o.checkOn ||\r\n                (r.valHooks[this].get = function (a) {\r\n                  return null === a.getAttribute("value") ? "on" : a.value;\r\n                });\r\n          });\r\n        var sb = /^(?:focusinfocus|focusoutblur)$/;\r\n        r.extend(r.event, {\r\n          trigger: function (b, c, e, f) {\r\n            var g,\r\n              h,\r\n              i,\r\n              j,\r\n              k,\r\n              m,\r\n              n,\r\n              o = [e || d],\r\n              p = l.call(b, "type") ? b.type : b,\r\n              q = l.call(b, "namespace") ? b.namespace.split(".") : [];\r\n            if (\r\n              ((h = i = e = e || d),\r\n              3 !== e.nodeType &&\r\n                8 !== e.nodeType &&\r\n                !sb.test(p + r.event.triggered) &&\r\n                (p.indexOf(".") > -1 &&\r\n                  ((q = p.split(".")), (p = q.shift()), q.sort()),\r\n                (k = p.indexOf(":") < 0 && "on" + p),\r\n                (b = b[r.expando]\r\n                  ? b\r\n                  : new r.Event(p, "object" == typeof b && b)),\r\n                (b.isTrigger = f ? 2 : 3),\r\n                (b.namespace = q.join(".")),\r\n                (b.rnamespace = b.namespace\r\n                  ? new RegExp("(^|\\\\.)" + q.join("\\\\.(?:.*\\\\.|)") + "(\\\\.|$)")\r\n                  : null),\r\n                (b.result = void 0),\r\n                b.target || (b.target = e),\r\n                (c = null == c ? [b] : r.makeArray(c, [b])),\r\n                (n = r.event.special[p] || {}),\r\n                f || !n.trigger || n.trigger.apply(e, c) !== !1))\r\n            ) {\r\n              if (!f && !n.noBubble && !r.isWindow(e)) {\r\n                for (\r\n                  j = n.delegateType || p, sb.test(j + p) || (h = h.parentNode);\r\n                  h;\r\n                  h = h.parentNode\r\n                )\r\n                  o.push(h), (i = h);\r\n                i === (e.ownerDocument || d) &&\r\n                  o.push(i.defaultView || i.parentWindow || a);\r\n              }\r\n              g = 0;\r\n              while ((h = o[g++]) && !b.isPropagationStopped())\r\n                (b.type = g > 1 ? j : n.bindType || p),\r\n                  (m =\r\n                    (W.get(h, "events") || {})[b.type] && W.get(h, "handle")),\r\n                  m && m.apply(h, c),\r\n                  (m = k && h[k]),\r\n                  m &&\r\n                    m.apply &&\r\n                    U(h) &&\r\n                    ((b.result = m.apply(h, c)),\r\n                    b.result === !1 && b.preventDefault());\r\n              return (\r\n                (b.type = p),\r\n                f ||\r\n                  b.isDefaultPrevented() ||\r\n                  (n._default && n._default.apply(o.pop(), c) !== !1) ||\r\n                  !U(e) ||\r\n                  (k &&\r\n                    r.isFunction(e[p]) &&\r\n                    !r.isWindow(e) &&\r\n                    ((i = e[k]),\r\n                    i && (e[k] = null),\r\n                    (r.event.triggered = p),\r\n                    e[p](),\r\n                    (r.event.triggered = void 0),\r\n                    i && (e[k] = i))),\r\n                b.result\r\n              );\r\n            }\r\n          },\r\n          simulate: function (a, b, c) {\r\n            var d = r.extend(new r.Event(), c, { type: a, isSimulated: !0 });\r\n            r.event.trigger(d, null, b);\r\n          },\r\n        }),\r\n          r.fn.extend({\r\n            trigger: function (a, b) {\r\n              return this.each(function () {\r\n                r.event.trigger(a, b, this);\r\n              });\r\n            },\r\n            triggerHandler: function (a, b) {\r\n              var c = this[0];\r\n              if (c) return r.event.trigger(a, b, c, !0);\r\n            },\r\n          }),\r\n          r.each(\r\n            "blur focus focusin focusout resize scroll click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup contextmenu".split(\r\n              " "\r\n            ),\r\n            function (a, b) {\r\n              r.fn[b] = function (a, c) {\r\n                return arguments.length > 0\r\n                  ? this.on(b, null, a, c)\r\n                  : this.trigger(b);\r\n              };\r\n            }\r\n          ),\r\n          r.fn.extend({\r\n            hover: function (a, b) {\r\n              return this.mouseenter(a).mouseleave(b || a);\r\n            },\r\n          }),\r\n          (o.focusin = "onfocusin" in a),\r\n          o.focusin ||\r\n            r.each({ focus: "focusin", blur: "focusout" }, function (a, b) {\r\n              var c = function (a) {\r\n                r.event.simulate(b, a.target, r.event.fix(a));\r\n              };\r\n              r.event.special[b] = {\r\n                setup: function () {\r\n                  var d = this.ownerDocument || this,\r\n                    e = W.access(d, b);\r\n                  e || d.addEventListener(a, c, !0),\r\n                    W.access(d, b, (e || 0) + 1);\r\n                },\r\n                teardown: function () {\r\n                  var d = this.ownerDocument || this,\r\n                    e = W.access(d, b) - 1;\r\n                  e\r\n                    ? W.access(d, b, e)\r\n                    : (d.removeEventListener(a, c, !0), W.remove(d, b));\r\n                },\r\n              };\r\n            });\r\n        var tb = a.location,\r\n          ub = r.now(),\r\n          vb = /\\?/;\r\n        r.parseXML = function (b) {\r\n          var c;\r\n          if (!b || "string" != typeof b) return null;\r\n          try {\r\n            c = new a.DOMParser().parseFromString(b, "text/xml");\r\n          } catch (d) {\r\n            c = void 0;\r\n          }\r\n          return (\r\n            (c && !c.getElementsByTagName("parsererror").length) ||\r\n              r.error("Invalid XML: " + b),\r\n            c\r\n          );\r\n        };\r\n        var wb = /\\[\\]$/,\r\n          xb = /\\r?\\n/g,\r\n          yb = /^(?:submit|button|image|reset|file)$/i,\r\n          zb = /^(?:input|select|textarea|keygen)/i;\r\n        function Ab(a, b, c, d) {\r\n          var e;\r\n          if (Array.isArray(b))\r\n            r.each(b, function (b, e) {\r\n              c || wb.test(a)\r\n                ? d(a, e)\r\n                : Ab(\r\n                    a +\r\n                      "[" +\r\n                      ("object" == typeof e && null != e ? b : "") +\r\n                      "]",\r\n                    e,\r\n                    c,\r\n                    d\r\n                  );\r\n            });\r\n          else if (c || "object" !== r.type(b)) d(a, b);\r\n          else for (e in b) Ab(a + "[" + e + "]", b[e], c, d);\r\n        }\r\n        (r.param = function (a, b) {\r\n          var c,\r\n            d = [],\r\n            e = function (a, b) {\r\n              var c = r.isFunction(b) ? b() : b;\r\n              d[d.length] =\r\n                encodeURIComponent(a) +\r\n                "=" +\r\n                encodeURIComponent(null == c ? "" : c);\r\n            };\r\n          if (Array.isArray(a) || (a.jquery && !r.isPlainObject(a)))\r\n            r.each(a, function () {\r\n              e(this.name, this.value);\r\n            });\r\n          else for (c in a) Ab(c, a[c], b, e);\r\n          return d.join("&");\r\n        }),\r\n          r.fn.extend({\r\n            serialize: function () {\r\n              return r.param(this.serializeArray());\r\n            },\r\n            serializeArray: function () {\r\n              return this.map(function () {\r\n                var a = r.prop(this, "elements");\r\n                return a ? r.makeArray(a) : this;\r\n              })\r\n                .filter(function () {\r\n                  var a = this.type;\r\n                  return (\r\n                    this.name &&\r\n                    !r(this).is(":disabled") &&\r\n                    zb.test(this.nodeName) &&\r\n                    !yb.test(a) &&\r\n                    (this.checked || !ja.test(a))\r\n                  );\r\n                })\r\n                .map(function (a, b) {\r\n                  var c = r(this).val();\r\n                  return null == c\r\n                    ? null\r\n                    : Array.isArray(c)\r\n                    ? r.map(c, function (a) {\r\n                        return { name: b.name, value: a.replace(xb, "\\r\\n") };\r\n                      })\r\n                    : { name: b.name, value: c.replace(xb, "\\r\\n") };\r\n                })\r\n                .get();\r\n            },\r\n          });\r\n        var Bb = /%20/g,\r\n          Cb = /#.*$/,\r\n          Db = /([?&])_=[^&]*/,\r\n          Eb = /^(.*?):[ \\t]*([^\\r\\n]*)$/gm,\r\n          Fb = /^(?:about|app|app-storage|.+-extension|file|res|widget):$/,\r\n          Gb = /^(?:GET|HEAD)$/,\r\n          Hb = /^\\/\\//,\r\n          Ib = {},\r\n          Jb = {},\r\n          Kb = "*/".concat("*"),\r\n          Lb = d.createElement("a");\r\n        Lb.href = tb.href;\r\n        function Mb(a) {\r\n          return function (b, c) {\r\n            "string" != typeof b && ((c = b), (b = "*"));\r\n            var d,\r\n              e = 0,\r\n              f = b.toLowerCase().match(L) || [];\r\n            if (r.isFunction(c))\r\n              while ((d = f[e++]))\r\n                "+" === d[0]\r\n                  ? ((d = d.slice(1) || "*"), (a[d] = a[d] || []).unshift(c))\r\n                  : (a[d] = a[d] || []).push(c);\r\n          };\r\n        }\r\n        function Nb(a, b, c, d) {\r\n          var e = {},\r\n            f = a === Jb;\r\n          function g(h) {\r\n            var i;\r\n            return (\r\n              (e[h] = !0),\r\n              r.each(a[h] || [], function (a, h) {\r\n                var j = h(b, c, d);\r\n                return "string" != typeof j || f || e[j]\r\n                  ? f\r\n                    ? !(i = j)\r\n                    : void 0\r\n                  : (b.dataTypes.unshift(j), g(j), !1);\r\n              }),\r\n              i\r\n            );\r\n          }\r\n          return g(b.dataTypes[0]) || (!e["*"] && g("*"));\r\n        }\r\n        function Ob(a, b) {\r\n          var c,\r\n            d,\r\n            e = r.ajaxSettings.flatOptions || {};\r\n          for (c in b)\r\n            void 0 !== b[c] && ((e[c] ? a : d || (d = {}))[c] = b[c]);\r\n          return d && r.extend(!0, a, d), a;\r\n        }\r\n        function Pb(a, b, c) {\r\n          var d,\r\n            e,\r\n            f,\r\n            g,\r\n            h = a.contents,\r\n            i = a.dataTypes;\r\n          while ("*" === i[0])\r\n            i.shift(),\r\n              void 0 === d &&\r\n                (d = a.mimeType || b.getResponseHeader("Content-Type"));\r\n          if (d)\r\n            for (e in h)\r\n              if (h[e] && h[e].test(d)) {\r\n                i.unshift(e);\r\n                break;\r\n              }\r\n          if (i[0] in c) f = i[0];\r\n          else {\r\n            for (e in c) {\r\n              if (!i[0] || a.converters[e + " " + i[0]]) {\r\n                f = e;\r\n                break;\r\n              }\r\n              g || (g = e);\r\n            }\r\n            f = f || g;\r\n          }\r\n          if (f) return f !== i[0] && i.unshift(f), c[f];\r\n        }\r\n        function Qb(a, b, c, d) {\r\n          var e,\r\n            f,\r\n            g,\r\n            h,\r\n            i,\r\n            j = {},\r\n            k = a.dataTypes.slice();\r\n          if (k[1])\r\n            for (g in a.converters) j[g.toLowerCase()] = a.converters[g];\r\n          f = k.shift();\r\n          while (f)\r\n            if (\r\n              (a.responseFields[f] && (c[a.responseFields[f]] = b),\r\n              !i && d && a.dataFilter && (b = a.dataFilter(b, a.dataType)),\r\n              (i = f),\r\n              (f = k.shift()))\r\n            )\r\n              if ("*" === f) f = i;\r\n              else if ("*" !== i && i !== f) {\r\n                if (((g = j[i + " " + f] || j["* " + f]), !g))\r\n                  for (e in j)\r\n                    if (\r\n                      ((h = e.split(" ")),\r\n                      h[1] === f && (g = j[i + " " + h[0]] || j["* " + h[0]]))\r\n                    ) {\r\n                      g === !0\r\n                        ? (g = j[e])\r\n                        : j[e] !== !0 && ((f = h[0]), k.unshift(h[1]));\r\n                      break;\r\n                    }\r\n                if (g !== !0)\r\n                  if (g && a["throws"]) b = g(b);\r\n                  else\r\n                    try {\r\n                      b = g(b);\r\n                    } catch (l) {\r\n                      return {\r\n                        state: "parsererror",\r\n                        error: g ? l : "No conversion from " + i + " to " + f,\r\n                      };\r\n                    }\r\n              }\r\n          return { state: "success", data: b };\r\n        }\r\n        r.extend({\r\n          active: 0,\r\n          lastModified: {},\r\n          etag: {},\r\n          ajaxSettings: {\r\n            url: tb.href,\r\n            type: "GET",\r\n            isLocal: Fb.test(tb.protocol),\r\n            global: !0,\r\n            processData: !0,\r\n            async: !0,\r\n            contentType: "application/x-www-form-urlencoded; charset=UTF-8",\r\n            accepts: {\r\n              "*": Kb,\r\n              text: "text/plain",\r\n              html: "text/html",\r\n              xml: "application/xml, text/xml",\r\n              json: "application/json, text/javascript",\r\n            },\r\n            contents: { xml: /\\bxml\\b/, html: /\\bhtml/, json: /\\bjson\\b/ },\r\n            responseFields: {\r\n              xml: "responseXML",\r\n              text: "responseText",\r\n              json: "responseJSON",\r\n            },\r\n            converters: {\r\n              "* text": String,\r\n              "text html": !0,\r\n              "text json": JSON.parse,\r\n              "text xml": r.parseXML,\r\n            },\r\n            flatOptions: { url: !0, context: !0 },\r\n          },\r\n          ajaxSetup: function (a, b) {\r\n            return b ? Ob(Ob(a, r.ajaxSettings), b) : Ob(r.ajaxSettings, a);\r\n          },\r\n          ajaxPrefilter: Mb(Ib),\r\n          ajaxTransport: Mb(Jb),\r\n          ajax: function (b, c) {\r\n            "object" == typeof b && ((c = b), (b = void 0)), (c = c || {});\r\n            var e,\r\n              f,\r\n              g,\r\n              h,\r\n              i,\r\n              j,\r\n              k,\r\n              l,\r\n              m,\r\n              n,\r\n              o = r.ajaxSetup({}, c),\r\n              p = o.context || o,\r\n              q = o.context && (p.nodeType || p.jquery) ? r(p) : r.event,\r\n              s = r.Deferred(),\r\n              t = r.Callbacks("once memory"),\r\n              u = o.statusCode || {},\r\n              v = {},\r\n              w = {},\r\n              x = "canceled",\r\n              y = {\r\n                readyState: 0,\r\n                getResponseHeader: function (a) {\r\n                  var b;\r\n                  if (k) {\r\n                    if (!h) {\r\n                      h = {};\r\n                      while ((b = Eb.exec(g))) h[b[1].toLowerCase()] = b[2];\r\n                    }\r\n                    b = h[a.toLowerCase()];\r\n                  }\r\n                  return null == b ? null : b;\r\n                },\r\n                getAllResponseHeaders: function () {\r\n                  return k ? g : null;\r\n                },\r\n                setRequestHeader: function (a, b) {\r\n                  return (\r\n                    null == k &&\r\n                      ((a = w[a.toLowerCase()] = w[a.toLowerCase()] || a),\r\n                      (v[a] = b)),\r\n                    this\r\n                  );\r\n                },\r\n                overrideMimeType: function (a) {\r\n                  return null == k && (o.mimeType = a), this;\r\n                },\r\n                statusCode: function (a) {\r\n                  var b;\r\n                  if (a)\r\n                    if (k) y.always(a[y.status]);\r\n                    else for (b in a) u[b] = [u[b], a[b]];\r\n                  return this;\r\n                },\r\n                abort: function (a) {\r\n                  var b = a || x;\r\n                  return e && e.abort(b), A(0, b), this;\r\n                },\r\n              };\r\n            if (\r\n              (s.promise(y),\r\n              (o.url = ((b || o.url || tb.href) + "").replace(\r\n                Hb,\r\n                tb.protocol + "//"\r\n              )),\r\n              (o.type = c.method || c.type || o.method || o.type),\r\n              (o.dataTypes = (o.dataType || "*").toLowerCase().match(L) || [\r\n                "",\r\n              ]),\r\n              null == o.crossDomain)\r\n            ) {\r\n              j = d.createElement("a");\r\n              try {\r\n                (j.href = o.url),\r\n                  (j.href = j.href),\r\n                  (o.crossDomain =\r\n                    Lb.protocol + "//" + Lb.host != j.protocol + "//" + j.host);\r\n              } catch (z) {\r\n                o.crossDomain = !0;\r\n              }\r\n            }\r\n            if (\r\n              (o.data &&\r\n                o.processData &&\r\n                "string" != typeof o.data &&\r\n                (o.data = r.param(o.data, o.traditional)),\r\n              Nb(Ib, o, c, y),\r\n              k)\r\n            )\r\n              return y;\r\n            (l = r.event && o.global),\r\n              l && 0 === r.active++ && r.event.trigger("ajaxStart"),\r\n              (o.type = o.type.toUpperCase()),\r\n              (o.hasContent = !Gb.test(o.type)),\r\n              (f = o.url.replace(Cb, "")),\r\n              o.hasContent\r\n                ? o.data &&\r\n                  o.processData &&\r\n                  0 ===\r\n                    (o.contentType || "").indexOf(\r\n                      "application/x-www-form-urlencoded"\r\n                    ) &&\r\n                  (o.data = o.data.replace(Bb, "+"))\r\n                : ((n = o.url.slice(f.length)),\r\n                  o.data &&\r\n                    ((f += (vb.test(f) ? "&" : "?") + o.data), delete o.data),\r\n                  o.cache === !1 &&\r\n                    ((f = f.replace(Db, "$1")),\r\n                    (n = (vb.test(f) ? "&" : "?") + "_=" + ub++ + n)),\r\n                  (o.url = f + n)),\r\n              o.ifModified &&\r\n                (r.lastModified[f] &&\r\n                  y.setRequestHeader("If-Modified-Since", r.lastModified[f]),\r\n                r.etag[f] && y.setRequestHeader("If-None-Match", r.etag[f])),\r\n              ((o.data && o.hasContent && o.contentType !== !1) ||\r\n                c.contentType) &&\r\n                y.setRequestHeader("Content-Type", o.contentType),\r\n              y.setRequestHeader(\r\n                "Accept",\r\n                o.dataTypes[0] && o.accepts[o.dataTypes[0]]\r\n                  ? o.accepts[o.dataTypes[0]] +\r\n                      ("*" !== o.dataTypes[0] ? ", " + Kb + "; q=0.01" : "")\r\n                  : o.accepts["*"]\r\n              );\r\n            for (m in o.headers) y.setRequestHeader(m, o.headers[m]);\r\n            if (o.beforeSend && (o.beforeSend.call(p, y, o) === !1 || k))\r\n              return y.abort();\r\n            if (\r\n              ((x = "abort"),\r\n              t.add(o.complete),\r\n              y.done(o.success),\r\n              y.fail(o.error),\r\n              (e = Nb(Jb, o, c, y)))\r\n            ) {\r\n              if (((y.readyState = 1), l && q.trigger("ajaxSend", [y, o]), k))\r\n                return y;\r\n              o.async &&\r\n                o.timeout > 0 &&\r\n                (i = a.setTimeout(function () {\r\n                  y.abort("timeout");\r\n                }, o.timeout));\r\n              try {\r\n                (k = !1), e.send(v, A);\r\n              } catch (z) {\r\n                if (k) throw z;\r\n                A(-1, z);\r\n              }\r\n            } else A(-1, "No Transport");\r\n            function A(b, c, d, h) {\r\n              var j,\r\n                m,\r\n                n,\r\n                v,\r\n                w,\r\n                x = c;\r\n              k ||\r\n                ((k = !0),\r\n                i && a.clearTimeout(i),\r\n                (e = void 0),\r\n                (g = h || ""),\r\n                (y.readyState = b > 0 ? 4 : 0),\r\n                (j = (b >= 200 && b < 300) || 304 === b),\r\n                d && (v = Pb(o, y, d)),\r\n                (v = Qb(o, v, y, j)),\r\n                j\r\n                  ? (o.ifModified &&\r\n                      ((w = y.getResponseHeader("Last-Modified")),\r\n                      w && (r.lastModified[f] = w),\r\n                      (w = y.getResponseHeader("etag")),\r\n                      w && (r.etag[f] = w)),\r\n                    204 === b || "HEAD" === o.type\r\n                      ? (x = "nocontent")\r\n                      : 304 === b\r\n                      ? (x = "notmodified")\r\n                      : ((x = v.state), (m = v.data), (n = v.error), (j = !n)))\r\n                  : ((n = x), (!b && x) || ((x = "error"), b < 0 && (b = 0))),\r\n                (y.status = b),\r\n                (y.statusText = (c || x) + ""),\r\n                j ? s.resolveWith(p, [m, x, y]) : s.rejectWith(p, [y, x, n]),\r\n                y.statusCode(u),\r\n                (u = void 0),\r\n                l &&\r\n                  q.trigger(j ? "ajaxSuccess" : "ajaxError", [y, o, j ? m : n]),\r\n                t.fireWith(p, [y, x]),\r\n                l &&\r\n                  (q.trigger("ajaxComplete", [y, o]),\r\n                  --r.active || r.event.trigger("ajaxStop")));\r\n            }\r\n            return y;\r\n          },\r\n          getJSON: function (a, b, c) {\r\n            return r.get(a, b, c, "json");\r\n          },\r\n          getScript: function (a, b) {\r\n            return r.get(a, void 0, b, "script");\r\n          },\r\n        }),\r\n          r.each(["get", "post"], function (a, b) {\r\n            r[b] = function (a, c, d, e) {\r\n              return (\r\n                r.isFunction(c) && ((e = e || d), (d = c), (c = void 0)),\r\n                r.ajax(\r\n                  r.extend(\r\n                    { url: a, type: b, dataType: e, data: c, success: d },\r\n                    r.isPlainObject(a) && a\r\n                  )\r\n                )\r\n              );\r\n            };\r\n          }),\r\n          (r._evalUrl = function (a) {\r\n            return r.ajax({\r\n              url: a,\r\n              type: "GET",\r\n              dataType: "script",\r\n              cache: !0,\r\n              async: !1,\r\n              global: !1,\r\n              throws: !0,\r\n            });\r\n          }),\r\n          r.fn.extend({\r\n            wrapAll: function (a) {\r\n              var b;\r\n              return (\r\n                this[0] &&\r\n                  (r.isFunction(a) && (a = a.call(this[0])),\r\n                  (b = r(a, this[0].ownerDocument).eq(0).clone(!0)),\r\n                  this[0].parentNode && b.insertBefore(this[0]),\r\n                  b\r\n                    .map(function () {\r\n                      var a = this;\r\n                      while (a.firstElementChild) a = a.firstElementChild;\r\n                      return a;\r\n                    })\r\n                    .append(this)),\r\n                this\r\n              );\r\n            },\r\n            wrapInner: function (a) {\r\n              return r.isFunction(a)\r\n                ? this.each(function (b) {\r\n                    r(this).wrapInner(a.call(this, b));\r\n                  })\r\n                : this.each(function () {\r\n                    var b = r(this),\r\n                      c = b.contents();\r\n                    c.length ? c.wrapAll(a) : b.append(a);\r\n                  });\r\n            },\r\n            wrap: function (a) {\r\n              var b = r.isFunction(a);\r\n              return this.each(function (c) {\r\n                r(this).wrapAll(b ? a.call(this, c) : a);\r\n              });\r\n            },\r\n            unwrap: function (a) {\r\n              return (\r\n                this.parent(a)\r\n                  .not("body")\r\n                  .each(function () {\r\n                    r(this).replaceWith(this.childNodes);\r\n                  }),\r\n                this\r\n              );\r\n            },\r\n          }),\r\n          (r.expr.pseudos.hidden = function (a) {\r\n            return !r.expr.pseudos.visible(a);\r\n          }),\r\n          (r.expr.pseudos.visible = function (a) {\r\n            return !!(\r\n              a.offsetWidth ||\r\n              a.offsetHeight ||\r\n              a.getClientRects().length\r\n            );\r\n          }),\r\n          (r.ajaxSettings.xhr = function () {\r\n            try {\r\n              return new a.XMLHttpRequest();\r\n            } catch (b) {}\r\n          });\r\n        var Rb = { 0: 200, 1223: 204 },\r\n          Sb = r.ajaxSettings.xhr();\r\n        (o.cors = !!Sb && "withCredentials" in Sb),\r\n          (o.ajax = Sb = !!Sb),\r\n          r.ajaxTransport(function (b) {\r\n            var c, d;\r\n            if (o.cors || (Sb && !b.crossDomain))\r\n              return {\r\n                send: function (e, f) {\r\n                  var g,\r\n                    h = b.xhr();\r\n                  if (\r\n                    (h.open(b.type, b.url, b.async, b.username, b.password),\r\n                    b.xhrFields)\r\n                  )\r\n                    for (g in b.xhrFields) h[g] = b.xhrFields[g];\r\n                  b.mimeType &&\r\n                    h.overrideMimeType &&\r\n                    h.overrideMimeType(b.mimeType),\r\n                    b.crossDomain ||\r\n                      e["X-Requested-With"] ||\r\n                      (e["X-Requested-With"] = "XMLHttpRequest");\r\n                  for (g in e) h.setRequestHeader(g, e[g]);\r\n                  (c = function (a) {\r\n                    return function () {\r\n                      c &&\r\n                        ((c =\r\n                          d =\r\n                          h.onload =\r\n                          h.onerror =\r\n                          h.onabort =\r\n                          h.onreadystatechange =\r\n                            null),\r\n                        "abort" === a\r\n                          ? h.abort()\r\n                          : "error" === a\r\n                          ? "number" != typeof h.status\r\n                            ? f(0, "error")\r\n                            : f(h.status, h.statusText)\r\n                          : f(\r\n                              Rb[h.status] || h.status,\r\n                              h.statusText,\r\n                              "text" !== (h.responseType || "text") ||\r\n                                "string" != typeof h.responseText\r\n                                ? { binary: h.response }\r\n                                : { text: h.responseText },\r\n                              h.getAllResponseHeaders()\r\n                            ));\r\n                    };\r\n                  }),\r\n                    (h.onload = c()),\r\n                    (d = h.onerror = c("error")),\r\n                    void 0 !== h.onabort\r\n                      ? (h.onabort = d)\r\n                      : (h.onreadystatechange = function () {\r\n                          4 === h.readyState &&\r\n                            a.setTimeout(function () {\r\n                              c && d();\r\n                            });\r\n                        }),\r\n                    (c = c("abort"));\r\n                  try {\r\n                    h.send((b.hasContent && b.data) || null);\r\n                  } catch (i) {\r\n                    if (c) throw i;\r\n                  }\r\n                },\r\n                abort: function () {\r\n                  c && c();\r\n                },\r\n              };\r\n          }),\r\n          r.ajaxPrefilter(function (a) {\r\n            a.crossDomain && (a.contents.script = !1);\r\n          }),\r\n          r.ajaxSetup({\r\n            accepts: {\r\n              script:\r\n                "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript",\r\n            },\r\n            contents: { script: /\\b(?:java|ecma)script\\b/ },\r\n            converters: {\r\n              "text script": function (a) {\r\n                return r.globalEval(a), a;\r\n              },\r\n            },\r\n          }),\r\n          r.ajaxPrefilter("script", function (a) {\r\n            void 0 === a.cache && (a.cache = !1),\r\n              a.crossDomain && (a.type = "GET");\r\n          }),\r\n          r.ajaxTransport("script", function (a) {\r\n            if (a.crossDomain) {\r\n              var b, c;\r\n              return {\r\n                send: function (e, f) {\r\n                  (b = r("<script>")\r\n                    .prop({ charset: a.scriptCharset, src: a.url })\r\n                    .on(\r\n                      "load error",\r\n                      (c = function (a) {\r\n                        b.remove(),\r\n                          (c = null),\r\n                          a && f("error" === a.type ? 404 : 200, a.type);\r\n                      })\r\n                    )),\r\n                    d.head.appendChild(b[0]);\r\n                },\r\n                abort: function () {\r\n                  c && c();\r\n                },\r\n              };\r\n            }\r\n          });\r\n        var Tb = [],\r\n          Ub = /(=)\\?(?=&|$)|\\?\\?/;\r\n        r.ajaxSetup({\r\n          jsonp: "callback",\r\n          jsonpCallback: function () {\r\n            var a = Tb.pop() || r.expando + "_" + ub++;\r\n            return (this[a] = !0), a;\r\n          },\r\n        }),\r\n          r.ajaxPrefilter("json jsonp", function (b, c, d) {\r\n            var e,\r\n              f,\r\n              g,\r\n              h =\r\n                b.jsonp !== !1 &&\r\n                (Ub.test(b.url)\r\n                  ? "url"\r\n                  : "string" == typeof b.data &&\r\n                    0 ===\r\n                      (b.contentType || "").indexOf(\r\n                        "application/x-www-form-urlencoded"\r\n                      ) &&\r\n                    Ub.test(b.data) &&\r\n                    "data");\r\n            if (h || "jsonp" === b.dataTypes[0])\r\n              return (\r\n                (e = b.jsonpCallback =\r\n                  r.isFunction(b.jsonpCallback)\r\n                    ? b.jsonpCallback()\r\n                    : b.jsonpCallback),\r\n                h\r\n                  ? (b[h] = b[h].replace(Ub, "$1" + e))\r\n                  : b.jsonp !== !1 &&\r\n                    (b.url += (vb.test(b.url) ? "&" : "?") + b.jsonp + "=" + e),\r\n                (b.converters["script json"] = function () {\r\n                  return g || r.error(e + " was not called"), g[0];\r\n                }),\r\n                (b.dataTypes[0] = "json"),\r\n                (f = a[e]),\r\n                (a[e] = function () {\r\n                  g = arguments;\r\n                }),\r\n                d.always(function () {\r\n                  void 0 === f ? r(a).removeProp(e) : (a[e] = f),\r\n                    b[e] && ((b.jsonpCallback = c.jsonpCallback), Tb.push(e)),\r\n                    g && r.isFunction(f) && f(g[0]),\r\n                    (g = f = void 0);\r\n                }),\r\n                "script"\r\n              );\r\n          }),\r\n          (o.createHTMLDocument = (function () {\r\n            var a = d.implementation.createHTMLDocument("").body;\r\n            return (\r\n              (a.innerHTML = "<form></form><form></form>"),\r\n              2 === a.childNodes.length\r\n            );\r\n          })()),\r\n          (r.parseHTML = function (a, b, c) {\r\n            if ("string" != typeof a) return [];\r\n            "boolean" == typeof b && ((c = b), (b = !1));\r\n            var e, f, g;\r\n            return (\r\n              b ||\r\n                (o.createHTMLDocument\r\n                  ? ((b = d.implementation.createHTMLDocument("")),\r\n                    (e = b.createElement("base")),\r\n                    (e.href = d.location.href),\r\n                    b.head.appendChild(e))\r\n                  : (b = d)),\r\n              (f = C.exec(a)),\r\n              (g = !c && []),\r\n              f\r\n                ? [b.createElement(f[1])]\r\n                : ((f = qa([a], b, g)),\r\n                  g && g.length && r(g).remove(),\r\n                  r.merge([], f.childNodes))\r\n            );\r\n          }),\r\n          (r.fn.load = function (a, b, c) {\r\n            var d,\r\n              e,\r\n              f,\r\n              g = this,\r\n              h = a.indexOf(" ");\r\n            return (\r\n              h > -1 && ((d = pb(a.slice(h))), (a = a.slice(0, h))),\r\n              r.isFunction(b)\r\n                ? ((c = b), (b = void 0))\r\n                : b && "object" == typeof b && (e = "POST"),\r\n              g.length > 0 &&\r\n                r\r\n                  .ajax({ url: a, type: e || "GET", dataType: "html", data: b })\r\n                  .done(function (a) {\r\n                    (f = arguments),\r\n                      g.html(d ? r("<div>").append(r.parseHTML(a)).find(d) : a);\r\n                  })\r\n                  .always(\r\n                    c &&\r\n                      function (a, b) {\r\n                        g.each(function () {\r\n                          c.apply(this, f || [a.responseText, b, a]);\r\n                        });\r\n                      }\r\n                  ),\r\n              this\r\n            );\r\n          }),\r\n          r.each(\r\n            [\r\n              "ajaxStart",\r\n              "ajaxStop",\r\n              "ajaxComplete",\r\n              "ajaxError",\r\n              "ajaxSuccess",\r\n              "ajaxSend",\r\n            ],\r\n            function (a, b) {\r\n              r.fn[b] = function (a) {\r\n                return this.on(b, a);\r\n              };\r\n            }\r\n          ),\r\n          (r.expr.pseudos.animated = function (a) {\r\n            return r.grep(r.timers, function (b) {\r\n              return a === b.elem;\r\n            }).length;\r\n          }),\r\n          (r.offset = {\r\n            setOffset: function (a, b, c) {\r\n              var d,\r\n                e,\r\n                f,\r\n                g,\r\n                h,\r\n                i,\r\n                j,\r\n                k = r.css(a, "position"),\r\n                l = r(a),\r\n                m = {};\r\n              "static" === k && (a.style.position = "relative"),\r\n                (h = l.offset()),\r\n                (f = r.css(a, "top")),\r\n                (i = r.css(a, "left")),\r\n                (j =\r\n                  ("absolute" === k || "fixed" === k) &&\r\n                  (f + i).indexOf("auto") > -1),\r\n                j\r\n                  ? ((d = l.position()), (g = d.top), (e = d.left))\r\n                  : ((g = parseFloat(f) || 0), (e = parseFloat(i) || 0)),\r\n                r.isFunction(b) && (b = b.call(a, c, r.extend({}, h))),\r\n                null != b.top && (m.top = b.top - h.top + g),\r\n                null != b.left && (m.left = b.left - h.left + e),\r\n                "using" in b ? b.using.call(a, m) : l.css(m);\r\n            },\r\n          }),\r\n          r.fn.extend({\r\n            offset: function (a) {\r\n              if (arguments.length)\r\n                return void 0 === a\r\n                  ? this\r\n                  : this.each(function (b) {\r\n                      r.offset.setOffset(this, a, b);\r\n                    });\r\n              var b,\r\n                c,\r\n                d,\r\n                e,\r\n                f = this[0];\r\n              if (f)\r\n                return f.getClientRects().length\r\n                  ? ((d = f.getBoundingClientRect()),\r\n                    (b = f.ownerDocument),\r\n                    (c = b.documentElement),\r\n                    (e = b.defaultView),\r\n                    {\r\n                      top: d.top + e.pageYOffset - c.clientTop,\r\n                      left: d.left + e.pageXOffset - c.clientLeft,\r\n                    })\r\n                  : { top: 0, left: 0 };\r\n            },\r\n            position: function () {\r\n              if (this[0]) {\r\n                var a,\r\n                  b,\r\n                  c = this[0],\r\n                  d = { top: 0, left: 0 };\r\n                return (\r\n                  "fixed" === r.css(c, "position")\r\n                    ? (b = c.getBoundingClientRect())\r\n                    : ((a = this.offsetParent()),\r\n                      (b = this.offset()),\r\n                      B(a[0], "html") || (d = a.offset()),\r\n                      (d = {\r\n                        top: d.top + r.css(a[0], "borderTopWidth", !0),\r\n                        left: d.left + r.css(a[0], "borderLeftWidth", !0),\r\n                      })),\r\n                  {\r\n                    top: b.top - d.top - r.css(c, "marginTop", !0),\r\n                    left: b.left - d.left - r.css(c, "marginLeft", !0),\r\n                  }\r\n                );\r\n              }\r\n            },\r\n            offsetParent: function () {\r\n              return this.map(function () {\r\n                var a = this.offsetParent;\r\n                while (a && "static" === r.css(a, "position"))\r\n                  a = a.offsetParent;\r\n                return a || ra;\r\n              });\r\n            },\r\n          }),\r\n          r.each(\r\n            { scrollLeft: "pageXOffset", scrollTop: "pageYOffset" },\r\n            function (a, b) {\r\n              var c = "pageYOffset" === b;\r\n              r.fn[a] = function (d) {\r\n                return T(\r\n                  this,\r\n                  function (a, d, e) {\r\n                    var f;\r\n                    return (\r\n                      r.isWindow(a)\r\n                        ? (f = a)\r\n                        : 9 === a.nodeType && (f = a.defaultView),\r\n                      void 0 === e\r\n                        ? f\r\n                          ? f[b]\r\n                          : a[d]\r\n                        : void (f\r\n                            ? f.scrollTo(\r\n                                c ? f.pageXOffset : e,\r\n                                c ? e : f.pageYOffset\r\n                              )\r\n                            : (a[d] = e))\r\n                    );\r\n                  },\r\n                  a,\r\n                  d,\r\n                  arguments.length\r\n                );\r\n              };\r\n            }\r\n          ),\r\n          r.each(["top", "left"], function (a, b) {\r\n            r.cssHooks[b] = Pa(o.pixelPosition, function (a, c) {\r\n              if (c)\r\n                return (\r\n                  (c = Oa(a, b)), Ma.test(c) ? r(a).position()[b] + "px" : c\r\n                );\r\n            });\r\n          }),\r\n          r.each({ Height: "height", Width: "width" }, function (a, b) {\r\n            r.each(\r\n              { padding: "inner" + a, content: b, "": "outer" + a },\r\n              function (c, d) {\r\n                r.fn[d] = function (e, f) {\r\n                  var g = arguments.length && (c || "boolean" != typeof e),\r\n                    h = c || (e === !0 || f === !0 ? "margin" : "border");\r\n                  return T(\r\n                    this,\r\n                    function (b, c, e) {\r\n                      var f;\r\n                      return r.isWindow(b)\r\n                        ? 0 === d.indexOf("outer")\r\n                          ? b["inner" + a]\r\n                          : b.document.documentElement["client" + a]\r\n                        : 9 === b.nodeType\r\n                        ? ((f = b.documentElement),\r\n                          Math.max(\r\n                            b.body["scroll" + a],\r\n                            f["scroll" + a],\r\n                            b.body["offset" + a],\r\n                            f["offset" + a],\r\n                            f["client" + a]\r\n                          ))\r\n                        : void 0 === e\r\n                        ? r.css(b, c, h)\r\n                        : r.style(b, c, e, h);\r\n                    },\r\n                    b,\r\n                    g ? e : void 0,\r\n                    g\r\n                  );\r\n                };\r\n              }\r\n            );\r\n          }),\r\n          r.fn.extend({\r\n            bind: function (a, b, c) {\r\n              return this.on(a, null, b, c);\r\n            },\r\n            unbind: function (a, b) {\r\n              return this.off(a, null, b);\r\n            },\r\n            delegate: function (a, b, c, d) {\r\n              return this.on(b, a, c, d);\r\n            },\r\n            undelegate: function (a, b, c) {\r\n              return 1 === arguments.length\r\n                ? this.off(a, "**")\r\n                : this.off(b, a || "**", c);\r\n            },\r\n          }),\r\n          (r.holdReady = function (a) {\r\n            a ? r.readyWait++ : r.ready(!0);\r\n          }),\r\n          (r.isArray = Array.isArray),\r\n          (r.parseJSON = JSON.parse),\r\n          (r.nodeName = B),\r\n          "function" == typeof define &&\r\n            define.amd &&\r\n            define("jquery", [], function () {\r\n              return r;\r\n            });\r\n        var Vb = a.jQuery,\r\n          Wb = a.$;\r\n        return (\r\n          (r.noConflict = function (b) {\r\n            return (\r\n              a.$ === r && (a.$ = Wb), b && a.jQuery === r && (a.jQuery = Vb), r\r\n            );\r\n          }),\r\n          b || (a.jQuery = a.$ = r),\r\n          r\r\n        );\r\n      });\r\n    </script>\r\n    <div class="content">\r\n      <div class="title">\r\n        <div class="btn">\r\n        <button class="title_l" id="showAll">显示全部文档</button>\r\n        </div>\r\n        <div class="line"></div>\r\n        <div class="title_r">\r\n          <h1>nginxdb接口帮助</h1>\r\n        </div>\r\n      </div>\r\n\r\n      <div class="main">\r\n        <div id="port">\r\n          <ul class="nav"></ul>\r\n        </div>\r\n        <div id="drapLine" class="drap_line"></div>\r\n        <div id="viewport">\r\n          <div id="nav">全部文档</div>\r\n          <div id="jsonBox" class="json_box">\r\n            <div>device / barcode_edit</div>\r\n            <div>barcode:条码，为空则返回当前生产状态，为新条码则生成新订单</div><br>\r\n            <div>device / brand_add</div>\r\n            <div>null</div>\r\n          </div>\r\n        </div>\r\n      </div>\r\n    </div>\r\n\r\n    <script>\r\n      $(function () {\r\n        let jsonData =	;\r\n\r\n\r\n\r\n        let htmlTxt = "";\r\n        let jsonHTMl = [];\r\n        let jsonAlltext="";\r\n        let jsonTextArr=[];\r\n\r\n        getHTML(jsonData);\r\n        function getHTML(jsonData) {\r\n          let jsonObj = [];\r\n          jsonData.forEach((v, i) => {\r\n            getT(v.c)\r\n            jsonAlltext+=`\r\n            <div style="color: red;">${v.a} / ${v.b}</div>\r\n            <div>${t}</div><br>\r\n            `\r\n\r\n            jsonObj.push({ name: v.a, item: [] });\r\n          });\r\n          \r\n          function uniqueFunc(arr, uniId) {\r\n            const res = new Map();\r\n            return arr.filter(\r\n              (item) => !res.has(item[uniId]) && res.set(item[uniId], 1)\r\n            );\r\n          }\r\n\r\n          function getT(c){\r\n          t = JSON.stringify(c)\r\n                  .replaceAll("\\\\r\\\\n", "<br>")\r\n                  .replaceAll('\\\\"', '"')\r\n                  .replaceAll("\\\\t", "&nbsp&nbsp&nbsp&nbsp")\r\n                  .replaceAll(" ", "&nbsp");\r\n                if (t.length > 4) t = t.substring(1, t.length - 1);\r\n                return t;\r\n          }\r\n\r\n          let newArr = uniqueFunc(jsonObj, "name");\r\n          for (let i = 0; i < newArr.length; i++) {\r\n            jsonHTMl.push([]);\r\n          }\r\n\r\n          jsonData.forEach((v, i) => {\r\n            newArr.forEach((j, n) => {\r\n              if (v.a == j.name) {\r\n                newArr[n].item.push(v.b);\r\n                getT(v.c);\r\n                jsonHTMl[n].push(t);\r\n              }\r\n            });\r\n            \r\n          });\r\n\r\n          for (const key in newArr) {\r\n            let html=""\r\n            newArr[key].item.forEach((v,i)=>{\r\n            let text=jsonHTMl[key][i]\r\n            html+=`\r\n            <div style="color: red;">${ newArr[key].name} / ${v}</div>\r\n            <div>${text}</div><br>\r\n            `\r\n            })\r\n            jsonTextArr.push(html)\r\n          }\r\n         \r\n          htmlTxt = "";\r\n          newArr.forEach((v, n) => {\r\n            htmlTxt += `\r\n            <li class="nav-item">\r\n            <a href="javascript:;"\r\n              ><i class="nav-icon"></i><span>${v.name}</span><i class="nav-more"></i\r\n            ></a>\r\n            <ul>`;\r\n            v.item.forEach((j, i) => {\r\n              if (v.item.length - 1 != i) {\r\n                htmlTxt += ` \r\n              <li one=${n} two=${i}>\r\n                <a href="javascript:;" ><span>${v.item[i]}</span></a>\r\n              </li>`;\r\n              } else {\r\n                htmlTxt += `\r\n              <li one=${n} two=${i}>\r\n                <a href="javascript:;"><span>${v.item[i]}</span></a>\r\n              </li>\r\n            </ul>\r\n            </li>`;\r\n              }\r\n            });\r\n          });\r\n          return htmlTxt;\r\n        }\r\n\r\n        $(".nav").html(htmlTxt);\r\n        // nav收缩展开\r\n        $(".nav-item>a").on("click", function () {\r\n          $("#nav").text($(this).text())\r\n          $("#jsonBox").html(jsonTextArr[$(this).parent().index()]);\r\n          if (!$(".nav").hasClass("nav-mini")) {\r\n            if ($(this).next().css("display") == "none") {\r\n              $(".nav-item").children("ul").slideUp(300);\r\n              $(this).next("ul").slideDown(300);\r\n              $(this)\r\n                .parent("li")\r\n                .addClass("nav-show")\r\n                .siblings("li")\r\n                .removeClass("nav-show");\r\n            } else {\r\n              //收缩已展开\r\n              $(this).next("ul").slideUp(300);\r\n              $(".nav-item.nav-show").removeClass("nav-show");\r\n            }\r\n          }\r\n        });\r\n\r\n        $(".nav-item").on("click", "ul>li", function () {\r\n          $("#nav").text(\r\n            `${$(this).parents(".nav-item").children("a").text()} / ${$(\r\n              this\r\n            ).text()}`\r\n          );\r\n          let one = $(this).attr("one");\r\n          let two = $(this).attr("two");\r\n          $("#jsonBox").html(jsonHTMl[one][two]);\r\n        });\r\n\r\n        //设置最大/最小宽度\r\n        var max_width = "400",\r\n          min_width = "200";\r\n        var drapLine = $("#drapLine")[0],\r\n          left = $("#port")[0],\r\n          right = $("#viewport")[0];\r\n        var mouse_x = 0;\r\n\r\n        function mouseMove(e) {\r\n          var e = e || window.event;\r\n          var left_width = e.clientX - mouse_x;\r\n          left_width = left_width < min_width ? min_width : left_width;\r\n          left_width = left_width > max_width ? max_width : left_width;\r\n          console.log(left_width);\r\n          left.style.width = left_width + "px";\r\n        }\r\n\r\n        function mouseUp() {\r\n          document.onmousemove = null;\r\n          document.onmouseup = null;\r\n          //localStorage设置\r\n          localStorage.setItem("sliderWidth", left.style.width);\r\n        }\r\n\r\n        var history_width = localStorage.getItem("sliderWidth");\r\n        if (history_width) {\r\n          left.style.width = history_width;\r\n        }\r\n\r\n        drapLine.onmousedown = function (e) {\r\n          var e = e || window.event;\r\n          //阻止默认事件\r\n          e.preventDefault();\r\n          mouse_x = e.clientX - left.offsetWidth;\r\n          document.onmousemove = mouseMove;\r\n          document.onmouseup = mouseUp;\r\n        };\r\n\r\n        $("#jsonBox").html(jsonAlltext);\r\n        $("#showAll").on("click",  function () {\r\n          $("#nav").text("全部文档")\r\n          $("#jsonBox").html(jsonAlltext); \r\n        });\r\n      });\r\n    </script>\r\n  </body>\r\n</html>\r\n
\.
;

--
-- Name: loginlog_logid_seq; Type: SEQUENCE SET; Schema: sysinfo; Owner: gm
--

SELECT pg_catalog.setval('loginlog_logid_seq', 134, true);


--
--

COPY operaccounts (operatorid, accounts, appid, typeid, isused, unionid) FROM stdin;
100000	oa-Uv5dfZ4rr-zaTtU8deSSwSKoI	100	101	1	oLhaDwdn5I7uW2sSrYWIaSfQy1s4
104	oWVMb6Ej1FGqQLmued5ZYOlxvrP8	100	101	1	\N
\.
;

--
--

COPY operinfo (operatorid, operatorname, sex, phone, accounts, pass, tokenkey, tokentime, memo, isused, mycode, upcode, headimgurl, nickname, birthday, tokentype, tokeninterval, createoperator, createtime, updateoperator, updatetime, deloperator, deltime) FROM stdin;
100001	test	\N	\N	test	a5cdb68a	\N	\N	\N	1	\N	\N	\N	\N	\N	1	180	100000	2024-01-10 04:11:39.800757	\N	\N	\N	\N
100000	系统管理员	\N	\N	admin	123456	Iewjqk3BQ+rXznbeAidxjodxdIfuRZPLz0MkzNpXWZIe+qjLF9qgjzTv/c07ZJk6HUQ4xYCNySCqpEJvEG7jDH35X51lYJ0/n3690THiXJubv2xsMY4tTzt8NWRdpu+QN8FExuG7s4zASVKRkBwTaJU/H0O26ULhKgAjP8u48gIeQb0ojgAhzsW9KdhdTfc8T2wHa6Joecw6bv35WP5IrZopip4R2Vfwm3JrvrUx0fNkBdmbVJp23akP7iYnZuw851QrWd4Mz3TfztHWCilXEWeDHnvi4NJogn1zIpa0a8JzyLItuSpLvjdeAgU+lqF1wpqUfNG0+qxrkBkyt2dY5zcGFrLN+rC4afrlroMcmj03azGBJ9EKZu/xZOyJsAFkzCE5+Q==	2024-01-13 02:09:40.561856	\N	1	\N	\N	\N	\N	\N	1	180	\N	\N	\N	\N	\N	\N
104	微信	\N	13006324400	13006324400	\N	\N	2023-08-22 01:09:57.352746	\N	1	88965760	\N	https://thirdwx.qlogo.cn/mmopen/vi_32/POgEwh4mIHO4nibH0KlMECNjjGxQUq24ZEaGT4poC6icRiccVGKSyXwibcPq4BWmiaIGuG1icwxaQX6grC9VemZoJ8rg/132	微信用户	\N	1	180	\N	\N	100000	2024-01-10 04:13:27.167142	\N	\N
\.
;

--
-- Name: operinfo_operatorid_seq; Type: SEQUENCE SET; Schema: sysinfo; Owner: gm
--

SELECT pg_catalog.setval('operinfo_operatorid_seq', 100001, true);


--
--

COPY operpermission (operatorid, permissiontype, ifpermission, permissionorder, params, sysactionid, permissionid) FROM stdin;
100000	1	\N	\N	\N	100	100
\.
;

--
-- Name: operpermission_permissionid_seq; Type: SEQUENCE SET; Schema: sysinfo; Owner: gm
--

SELECT pg_catalog.setval('operpermission_permissionid_seq', 100, false);


--
--

COPY orgtype (isused, orgtypeid, orgtypename, description, systemid) FROM stdin;
1	100	部门	\N	100
\.
;

--
-- Name: orgtype_orgtypeid_seq; Type: SEQUENCE SET; Schema: sysinfo; Owner: gm
--

SELECT pg_catalog.setval('orgtype_orgtypeid_seq', 100, false);


--
--

COPY roleinfo (roleinfoid, roleinfoname, description, isused, systemid) FROM stdin;
100	权限管理员	\N	1	100
101	测试	\N	1	100
102	测试1	\N	1	100
\.
;

--
-- Name: roleinfo_roleinfoid_seq; Type: SEQUENCE SET; Schema: sysinfo; Owner: gm
--

SELECT pg_catalog.setval('roleinfo_roleinfoid_seq', 102, true);


--
--

COPY rolepermission (roleinfoid, permissionid, permissiontype, ifpermission, permissionorder, params, sysactionid) FROM stdin;
100	104	1	\N	\N	\N	100
100	105	1	\N	\N	\N	138
100	106	1	\N	\N	\N	102
100	107	2	\N	\N	\N	101
101	108	1	\N	\N	\N	144
101	109	1	\N	\N	\N	100
102	110	1	\N	\N	\N	100
\.
;

--
-- Name: rolepermission_permissionid_seq; Type: SEQUENCE SET; Schema: sysinfo; Owner: gm
--

SELECT pg_catalog.setval('rolepermission_permissionid_seq', 110, true);


--
-- Name: serverlog_logid_seq; Type: SEQUENCE SET; Schema: sysinfo; Owner: conn
--

SELECT pg_catalog.setval('serverlog_logid_seq', 100, false);


--
--

COPY sysaction (isused, idpath, idlevel, idcount, upid, params, systemid, sysactionid, sysactionname, actionid, isdefault) FROM stdin;
1	100.9108.180	3	0	9108	\N	100	180	查询权限名	180	\N
1	100.9109.181	3	0	9109	\N	100	181	查询出错代码	181	\N
1	100.9002.9102.115	4	0	9102	\N	100	115	修改部门	115	\N
1	100.9002.9101.122	4	0	9101	\N	100	122	合并部门类型	122	\N
1	100.9002.9101.123	4	0	9101	\N	100	123	删除部门类型	123	\N
1	100.9002.9101.124	4	0	9101	\N	100	124	恢复部门类型	124	\N
1	100.9002.9101.125	4	0	9101	\N	100	125	查询部门类型	125	\N
1	100.9001.9104.128	4	0	9104	\N	100	128	合并员工所属系统	128	\N
1	100.9001.9104.129	4	0	9104	\N	100	129	删除员工所属系统	129	\N
1	100.9108	2	1	100	\N	100	9108	权限名	\N	\N
1	100.107	2	0	100	\N	100	107	查询系统日志	107	\N
1	100.9001.9104.130	4	0	9104	\N	100	130	恢复员工所属系统	130	\N
1	100.9001.9104.131	4	0	9104	\N	100	131	查询员工所属系统	131	\N
1	100.150	2	0	100	\N	100	150	登录	150	\N
1	100.9001.9100	3	6	9001	\N	100	9100	系统权限	\N	\N
1	100.9002.9102.118	4	0	9102	\N	100	118	恢复部门	118	\N
1	100.9002.9107.142	4	0	9107	\N	100	142	恢复员工权限	142	\N
1	100.9002.9107.143	4	0	9107	\N	100	143	查询员工权限	143	\N
1	100.9002.9105.132	4	0	9105	\N	100	132	新增角色	132	\N
1	100.9001.9100.111	4	0	9100	\N	100	111	删除系统权限	111	\N
1	100.9001.9100.112	4	0	9100	\N	100	112	恢复系统权限	112	\N
1	100.9109	2	1	100	\N	100	9109	出错代码	\N	\N
1	100.9002.9107.139	4	0	9107	\N	100	139	修改员工权限	139	\N
1	100.9002.9107.140	4	0	9107	\N	100	140	合并员工权限	140	\N
1	100.9002.9107.141	4	0	9107	\N	100	141	删除员工权限	141	\N
1	100.9103.103	3	0	9103	\N	100	103	合并子系统	103	\N
1	100.9103.104	3	0	9103	\N	100	104	删除子系统	104	\N
1	100.171	2	0	100	101	100	171	微信注册	171	\N
1	100.9002.9101.120	4	0	9101	\N	100	120	新增部门类型	120	\N
1	100.9002.9101.121	4	0	9101	\N	100	121	修改部门类型	121	\N
1	100.160	2	0	100	101	100	160	微信登录	160	\N
1	100.9001.9100.109	4	0	9100	\N	100	109	修改系统权限	109	\N
1	100.9001.9100.110	4	0	9100	\N	100	110	合并系统权限	110	\N
1	100.9001.9104.126	4	0	9104	\N	100	126	新增员工所属系统	126	\N
1	100.9001.9104.127	4	0	9104	\N	100	127	修改员工所属系统	127	\N
1	100	1	10	0	\N	100	100	系统	\N	\N
1	100.9001	2	2	100	\N	100	9001	系统管理	\N	\N
1	100.9002	2	5	100	\N	100	9002	本系统管理	\N	\N
1	100.9103	2	6	100	\N	100	9103	系统日志	\N	\N
1	100.9001.9100.113	4	0	9100	\N	100	113	查询系统权限	113	\N
1	100.9103.105	3	0	9103	\N	100	105	恢复子系统	105	\N
1	100.9103.106	3	0	9103	\N	100	106	查询子系统	106	\N
1	100.9002.9105	3	6	9002	\N	100	9105	角色	\N	\N
1	100.9002.9106	3	6	9002	\N	100	9106	员工部门	\N	\N
1	100.9002.9101	3	6	9002	\N	100	9101	部门类型	\N	\N
1	100.9002.9102.114	4	0	9102	\N	100	114	新增部门	114	\N
1	100.9002.9102	3	6	9002	\N	100	9102	部门	\N	\N
1	100.9001.9104	3	6	9001	\N	100	9104	员工所属系统	\N	\N
1	100.9002.9107	3	6	9002	\N	100	9107	员工权限	\N	\N
1	100.9002.9106.144	4	0	9106	\N	100	144	新增员工部门	144	\N
1	100.9002.9106.148	4	0	9106	\N	100	148	恢复员工部门	148	\N
1	100.9002.9106.149	4	0	9106	\N	100	149	查询员工部门	149	\N
1	100.9103.101	3	0	9103	\N	100	101	新增子系统	101	\N
1	100.161	2	0	100	\N	100	161	注册	161	\N
1	100.9002.9102.116	4	0	9102	\N	100	116	合并部门	116	\N
1	100.9002.9102.117	4	0	9102	\N	100	117	删除部门	117	\N
1	100.9002.9105.133	4	0	9105	\N	100	133	修改角色	133	\N
1	100.9002.9105.137	4	0	9105	\N	100	137	查询角色	137	\N
1	100.9002.9102.119	4	0	9102	\N	100	119	查询部门	119	\N
1	100.9002.9105.134	4	0	9105	\N	100	134	合并角色	134	\N
1	100.9002.9105.135	4	0	9105	\N	100	135	删除角色	135	\N
1	100.9002.9105.136	4	0	9105	\N	100	136	恢复角色	136	\N
1	100.9103.102	3	0	9103	\N	100	102	修改子系统	102	\N
1	100.9001.9100.108	4	0	9100	\N	100	108	新增系统权限	108	\N
1	100.9002.9107.138	4	0	9107	\N	100	138	新增员工权限	138	\N
1	100.9002.9106.146	4	0	9106	\N	100	146	合并员工部门	146	\N
1	100.9002.9106.145	4	0	9106	\N	100	145	修改员工部门	145	\N
1	100.9002.9106.147	4	0	9106	\N	100	147	删除员工部门	147	\N
\.
;

--
-- Name: sysaction_sysactionid_seq; Type: SEQUENCE SET; Schema: sysinfo; Owner: gm
--

SELECT pg_catalog.setval('sysaction_sysactionid_seq', 100000000, false);


--
--

COPY sysoper (operatorid, systemid) FROM stdin;
100000	99
100000	100
100001	100
100001	99
104	99
\.
;

--
--

COPY sysoperorg (operatorid, sysorgid) FROM stdin;
100000	100
100000	101
\.
;

--
-- Name: sysoperorg_sysorgid_seq; Type: SEQUENCE SET; Schema: sysinfo; Owner: gm
--

SELECT pg_catalog.setval('sysoperorg_sysorgid_seq', 100, false);


--
--

COPY sysorg (isused, idpath, idlevel, idcount, upid, systemid, sysorgid, sysorgname, description, orgtype) FROM stdin;
1	\N	\N	\N	100	100	100	公司	\N	100
1	\N	\N	\N	100	100	101	销售部	\N	\N
\.
;

--
-- Name: sysorg_sysorgid_seq; Type: SEQUENCE SET; Schema: sysinfo; Owner: gm
--

SELECT pg_catalog.setval('sysorg_sysorgid_seq', 100, false);


--
--

COPY systeminfo (systemid, systemname, isused, algorithm, prikey, createoperator, createtime, updateoperator, updatetime, deloperator, deltime, loginname) FROM stdin;
100	总系统	1	1	Gao@12345	\N	\N	100000	2024-01-06 07:19:48.56056	100000	2024-01-06 07:18:23.729135	100
\.
;

--
-- Name: systeminfo_systemid_seq; Type: SEQUENCE SET; Schema: sysinfo; Owner: gm
--

SELECT pg_catalog.setval('systeminfo_systemid_seq', 100, false);


--
-- Name: actions_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE actions
    ADD CONSTRAINT actions_pkey PRIMARY KEY  (actionid);


--
-- Name: appparams_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE appparams
    ADD CONSTRAINT appparams_pkey PRIMARY KEY  (appid);


--
-- Name: employeepermission_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE operpermission
    ADD CONSTRAINT employeepermission_pkey PRIMARY KEY  (permissionid);


--
-- Name: errorcode_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE errorcode
    ADD CONSTRAINT errorcode_pkey PRIMARY KEY  (errorcode);


--
-- Name: funchtml_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE funchtml
    ADD CONSTRAINT funchtml_pkey PRIMARY KEY  (htmlid);


--
-- Name: loginlog_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE loginlog
    ADD CONSTRAINT loginlog_pkey PRIMARY KEY  (logid);


--
-- Name: operinfo_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE operinfo
    ADD CONSTRAINT operinfo_pkey PRIMARY KEY  (operatorid);


--
-- Name: orgtype_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE orgtype
    ADD CONSTRAINT orgtype_pkey PRIMARY KEY  (orgtypeid);


--
-- Name: roleinfo_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE roleinfo
    ADD CONSTRAINT roleinfo_pkey PRIMARY KEY  (roleinfoid);


--
-- Name: rolepermission_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE rolepermission
    ADD CONSTRAINT rolepermission_pkey PRIMARY KEY  (permissionid);


--
-- Name: serverlog_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE serverlog
    ADD CONSTRAINT serverlog_pkey PRIMARY KEY  (logid);


--
-- Name: sysaction_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE sysaction
    ADD CONSTRAINT sysaction_pkey PRIMARY KEY  (sysactionid);


--
-- Name: sysoper_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE sysoper
    ADD CONSTRAINT sysoper_pkey PRIMARY KEY  (operatorid, systemid);


--
-- Name: sysoperorg_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE sysoperorg
    ADD CONSTRAINT sysoperorg_pkey PRIMARY KEY  (operatorid, sysorgid);


--
-- Name: sysorg_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE sysorg
    ADD CONSTRAINT sysorg_pkey PRIMARY KEY  (sysorgid);


--
-- Name: systeminfo_pkey; Type: CONSTRAINT; Schema: sysinfo; Owner: gm; Tablespace: 
--

ALTER TABLE systeminfo
    ADD CONSTRAINT systeminfo_pkey PRIMARY KEY  (systemid);


--
-- Name: gm; Type: ACL; Schema: -; Owner: gm
--

REVOKE ALL ON SCHEMA gm FROM PUBLIC;
REVOKE ALL ON SCHEMA gm FROM gm;
GRANT CREATE,USAGE ON SCHEMA gm TO gm;
GRANT USAGE ON SCHEMA gm TO conn;


--
-- Name: public; Type: ACL; Schema: -; Owner: opengauss
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM opengauss;
GRANT CREATE,USAGE ON SCHEMA public TO opengauss;
GRANT USAGE ON SCHEMA public TO PUBLIC;


--
-- Name: sysinfo; Type: ACL; Schema: -; Owner: gm
--

REVOKE ALL ON SCHEMA sysinfo FROM PUBLIC;
REVOKE ALL ON SCHEMA sysinfo FROM gm;
GRANT CREATE,USAGE ON SCHEMA sysinfo TO gm;
GRANT USAGE ON SCHEMA sysinfo TO conn;


SET search_path = gm;

--
-- Name: nginx; Type: ACL; Schema: gm; Owner: gm
--

REVOKE ALL ON TABLE nginx FROM PUBLIC;
REVOKE ALL ON TABLE nginx FROM gm;
GRANT SELECT,INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,UPDATE ON TABLE nginx TO gm;
GRANT SELECT ON TABLE nginx TO conn;


--
--

INSERT INTO sysinfo.appparams (appid, params, accesstoken, isused, tokentime, typeid) VALUES (100, 'appid=xxx&secret=xxx', 'xxx', 1, '2023-08-23 17:08:57.622318', 101);INSERT INTO sysinfo.operinfo (operatorid, operatorname, sex, phone, accounts, pass, memo, isused, mycode, upcode, headimgurl, nickname, birthday, tokentype, tokeninterval ) VALUES (100000, '系统管理员', NULL, NULL, 'admin', '123456',  NULL, 1, NULL, NULL, NULL, NULL, NULL, 1, 180);INSERT INTO sysinfo.operpermission (operatorid, permissiontype, ifpermission, permissionorder, params, sysactionid, permissionid, systemid) VALUES (100000, 1, NULL, NULL, NULL, 100, 100, 100);INSERT INTO sysinfo.orgtype (isused, orgtypeid, orgtypename, description, systemid) VALUES (1, 100, '部门', NULL, 100);INSERT INTO sysinfo.sysoper (operatorid, systemid) VALUES (100000, 100);INSERT INTO sysinfo.sysoperorg (operatorid, sysorgid) VALUES (100000, 100);INSERT INTO sysinfo.sysorg (isused, idpath, idlevel, idcount, upid, systemid, sysorgid, sysorgname, description, orgtype) VALUES (1, NULL, NULL, NULL, NULL, 100, 100, NULL, NULL, NULL);INSERT INTO sysinfo.systeminfo (systemid, systemname, isused, adminid, algorithm, prikey, loginname) VALUES (100, '维护系统', 1, 100000, 1, 'Gao@12345', NULL);insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,150,'登录',null,null,'sysinfo/login',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,160,'微信登录',null,'101','sysinfo/loginaccount',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,161,'注册',null,null,'sysinfo/reg',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,171,'微信注册',null,'101','sysinfo/regmicrochat',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,128,'合并员工所属系统',null,null,'sysinfo/operinfo_merge',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,129,'删除员工所属系统',null,null,'sysinfo/operinfo_del',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,130,'恢复员工所属系统',null,null,'sysinfo/operinfo_undel',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,131,'查询员工所属系统',null,null,'sysinfo/operinfo_query',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,114,'新增部门',null,null,'sysinfo/sysorg_add',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,146,'合并员工部门',null,null,'sysinfo/operinfoorg_merge',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,147,'删除员工部门',null,null,'sysinfo/operinfoorg_del',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,101,'新增子系统',null,'Gao@12345','sysinfo/systeminfo_add',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,102,'修改子系统',null,null,'sysinfo/systeminfo_edit',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,103,'合并子系统',null,null,'sysinfo/systeminfo_merge',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,104,'删除子系统',null,null,'sysinfo/systeminfo_del',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,105,'恢复子系统',null,null,'sysinfo/systeminfo_undel',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,106,'查询子系统',null,null,'sysinfo/systeminfo_query',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,148,'恢复员工部门',null,null,'sysinfo/operinfoorg_undel',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,149,'查询员工部门',null,null,'sysinfo/operinfo_query',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,138,'新增员工权限',null,null,'sysinfo/operinfopermission_add',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,139,'修改员工权限',null,null,'sysinfo/operinfopermission_edit',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,140,'合并员工权限',null,null,'sysinfo/operinfopermission_merge',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,141,'删除员工权限',null,null,'sysinfo/operinfopermission_del',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,142,'恢复员工权限',null,null,'sysinfo/operinfopermission_undel',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,143,'查询员工权限',null,null,'sysinfo/operinfo_query',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,115,'修改部门',null,null,'sysinfo/sysorg_edit',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,116,'合并部门',null,null,'sysinfo/sysorg_merge',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,132,'新增角色',null,null,'sysinfo/roleinfo_add',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,133,'修改角色',null,null,'sysinfo/roleinfo_edit',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,134,'合并角色',null,null,'sysinfo/roleinfo_merge',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,135,'删除角色',null,null,'sysinfo/roleinfo_del',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,136,'恢复角色',null,null,'sysinfo/roleinfo_undel',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,137,'查询角色',null,null,'sysinfo/roleinfo_query',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,145,'修改员工部门',null,null,'sysinfo/operinfoorg_edit',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,144,'新增员工部门',null,null,'sysinfo/operinfoorg_add',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,117,'删除部门',null,null,'sysinfo/sysorg_del',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,118,'恢复部门',null,null,'sysinfo/sysorg_undel',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,119,'查询部门',null,null,'sysinfo/sysorg_query',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,107,'查询系统日志',null,null,'sysinfo/serverlog_query',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,180,'查询权限名',null,null,'sysinfo/actions_query',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,126,'新增员工所属系统',null,null,'sysinfo/operinfo_add',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,127,'修改员工所属系统',null,null,'sysinfo/operinfo_edit',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,181,'查询出错代码',null,null,'sysinfo/errorcode_query',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,120,'新增部门类型',null,null,'sysinfo/orgtype_add',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,121,'修改部门类型',null,null,'sysinfo/orgtype_edit',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,122,'合并部门类型',null,null,'sysinfo/orgtype_merge',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,123,'删除部门类型',null,null,'sysinfo/orgtype_del',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,124,'恢复部门类型',null,null,'sysinfo/orgtype_undel',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,125,'查询部门类型',null,null,'sysinfo/orgtype_query',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,108,'新增系统权限',null,null,'sysinfo/sysaction_add',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,109,'修改系统权限',null,null,'sysinfo/sysaction_edit',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,110,'合并系统权限',null,null,'sysinfo/sysaction_merge',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,111,'删除系统权限',null,null,'sysinfo/sysaction_del',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,112,'恢复系统权限',null,null,'sysinfo/sysaction_undel',null);
insert into sysinfo.actions(isused,actionid,actionname,description,params,actionurl,code) values(1,113,'查询系统权限',null,null,'sysinfo/sysaction_query',null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9108.180',3,0,9108,null,100,180,'查询权限名',180,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9109.181',3,0,9109,null,100,181,'查询出错代码',181,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9102.115',4,0,9102,null,100,115,'修改部门',115,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9101.122',4,0,9101,null,100,122,'合并部门类型',122,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9101.123',4,0,9101,null,100,123,'删除部门类型',123,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9101.124',4,0,9101,null,100,124,'恢复部门类型',124,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9101.125',4,0,9101,null,100,125,'查询部门类型',125,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9104.128',4,0,9104,null,100,128,'合并员工所属系统',128,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9104.129',4,0,9104,null,100,129,'删除员工所属系统',129,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9108',2,1,100,null,100,9108,'权限名',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.107',2,0,100,null,100,107,'查询系统日志',107,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9104.130',4,0,9104,null,100,130,'恢复员工所属系统',130,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9104.131',4,0,9104,null,100,131,'查询员工所属系统',131,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.150',2,0,100,null,100,150,'登录',150,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9100',3,6,9001,null,100,9100,'系统权限',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9102.118',4,0,9102,null,100,118,'恢复部门',118,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9107.142',4,0,9107,null,100,142,'恢复员工权限',142,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9107.143',4,0,9107,null,100,143,'查询员工权限',143,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9105.132',4,0,9105,null,100,132,'新增角色',132,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9100.111',4,0,9100,null,100,111,'删除系统权限',111,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9100.112',4,0,9100,null,100,112,'恢复系统权限',112,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9109',2,1,100,null,100,9109,'出错代码',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9107.139',4,0,9107,null,100,139,'修改员工权限',139,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9107.140',4,0,9107,null,100,140,'合并员工权限',140,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9107.141',4,0,9107,null,100,141,'删除员工权限',141,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9103.103',3,0,9103,null,100,103,'合并子系统',103,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9103.104',3,0,9103,null,100,104,'删除子系统',104,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.171',2,0,100,'101',100,171,'微信注册',171,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9101.120',4,0,9101,null,100,120,'新增部门类型',120,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9101.121',4,0,9101,null,100,121,'修改部门类型',121,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.160',2,0,100,'101',100,160,'微信登录',160,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9100.109',4,0,9100,null,100,109,'修改系统权限',109,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9100.110',4,0,9100,null,100,110,'合并系统权限',110,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9104.126',4,0,9104,null,100,126,'新增员工所属系统',126,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9104.127',4,0,9104,null,100,127,'修改员工所属系统',127,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100',1,10,0,null,100,100,'系统',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001',2,2,100,null,100,9001,'系统管理',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002',2,5,100,null,100,9002,'本系统管理',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9103',2,6,100,null,100,9103,'系统日志',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9100.113',4,0,9100,null,100,113,'查询系统权限',113,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9103.105',3,0,9103,null,100,105,'恢复子系统',105,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9103.106',3,0,9103,null,100,106,'查询子系统',106,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9105',3,6,9002,null,100,9105,'角色',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9106',3,6,9002,null,100,9106,'员工部门',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9101',3,6,9002,null,100,9101,'部门类型',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9102.114',4,0,9102,null,100,114,'新增部门',114,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9102',3,6,9002,null,100,9102,'部门',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9104',3,6,9001,null,100,9104,'员工所属系统',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9107',3,6,9002,null,100,9107,'员工权限',null,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9106.144',4,0,9106,null,100,144,'新增员工部门',144,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9106.148',4,0,9106,null,100,148,'恢复员工部门',148,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9106.149',4,0,9106,null,100,149,'查询员工部门',149,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9103.101',3,0,9103,null,100,101,'新增子系统',101,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.161',2,0,100,null,100,161,'注册',161,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9102.116',4,0,9102,null,100,116,'合并部门',116,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9102.117',4,0,9102,null,100,117,'删除部门',117,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9105.133',4,0,9105,null,100,133,'修改角色',133,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9105.137',4,0,9105,null,100,137,'查询角色',137,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9102.119',4,0,9102,null,100,119,'查询部门',119,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9105.134',4,0,9105,null,100,134,'合并角色',134,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9105.135',4,0,9105,null,100,135,'删除角色',135,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9105.136',4,0,9105,null,100,136,'恢复角色',136,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9103.102',3,0,9103,null,100,102,'修改子系统',102,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9001.9100.108',4,0,9100,null,100,108,'新增系统权限',108,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9107.138',4,0,9107,null,100,138,'新增员工权限',138,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9106.146',4,0,9106,null,100,146,'合并员工部门',146,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9106.145',4,0,9106,null,100,145,'修改员工部门',145,null);
insert into sysinfo.sysaction(isused,idpath,idlevel,idcount,upid,params,systemid,sysactionid,sysactionname,actionid,isdefault) values(1,'100.9002.9106.147',4,0,9106,null,100,147,'删除员工部门',147,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('操作员信息出错！',100011,'operatorid',1,'sysinfo.operinfo');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('权限信息出错！',100013,'sysactionid',1,'sysinfo.sysaction');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('上级不存在！',100014,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('顶级不能删除！',100015,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('执行成功！',0,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('有下级不能删除！',100016,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('员工权限信息出错！',100025,'permissionid',1,'sysinfo.operpermission');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('部门信息出错！',100018,'sysorgid',1,'sysinfo.sysorg');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('部门类型信息出错！',100020,'orgtypeid',1,'sysinfo.orgtype');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('不能注册！',100026,null,null,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('帐号密码错误',100001,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('注册码不正确！',100027,null,null,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('登录错误超过5次，帐号锁定10分钟！',100002,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('登录错误超过10次，帐号锁定3小时！',100003,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('手机码不正确！',100028,null,null,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('小程序已注册！',100029,null,null,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('非法登录！',100005,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('登录已失效！',100006,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('账号不能重复！',100022,null,null,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('角色信息出错！',100023,'roleinfoid',1,'sysinfo.roleinfo');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('无此权限',100008,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('帐号不能为空',100009,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('密码不能为空！',100010,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('操作员部门信息出错！',100019,'sysorgid',1,'sysinfo.sysoperorg');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('角色权限信息出错！',100024,'permissionid',1,'sysinfo.rolepermission');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('子系统信息出错！',100012,'systemid',1,'sysinfo.systeminfo');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('操作员所属系统信息出错！',100021,'systemid',1,'sysinfo.sysoper');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('不能循环定义！',100017,null,1,null);
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('系统日志信息出错！',100030,'logid',1,'sysinfo.serverlog');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('权限名信息出错！',100031,'actionid',1,'sysinfo.actions');
insert into sysinfo.errorcode(message,errorcode,primekey,isused,schema) values('出错代码信息出错！',100032,'errorcode',1,'sysinfo.errorcode');
insert into sysinfo.funchtml(htmlid,html1,html2) values(100,'<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>接口文档</title>
    <style>
      * {
        margin: 0;
        padding: 0;
      }

      html,
      body {
        width: 100%;
        height: 100%;
      }
      ul li {
        cursor: pointer;
        list-style-type: none;
      }

      ul li:hover {
        cursor: pointer;
      }
      .content {
        width: 100%;
        height: 100%;
      }
      .title {
        width: 100%;
        height: 70px;
        line-height: 70px;
        display: flex;
        align-items: center;
      }
      .btn{
        width: 200px;
        padding-left: 20px;
        box-sizing: border-box;
      }

      .line {
        height: 42px;
        border-right: 2px solid #263238;
      }
      .title_r {
        flex: 1;
        text-align: center;
      }

      .main {
        width: 100%;
        height: calc(100% - 70px);
        display: flex;
      }
      #port {
        width: 18%;
        height: 100%;
      }

      #viewport {
        box-sizing: border-box;
        flex: 1;
        height: 100%;
        background-color: #abb1b7;
        padding: 10px 40px 40px 40px;
        color: #fff;
      }
      .nav {
        width: 100%;
        height: 100%;
        background: #263238;
        transition: all 0.3s;
        overflow: auto;
      }
      .nav a {
        display: block;
        overflow: hidden;
        padding-left: 20px;
        line-height: 46px;
        max-height: 46px;
        color: #abb1b7;
        transition: all 0.3s;
      }
      .nav a span {
        margin-left: 30px;
      }
      .nav-item {
        position: relative;
      }
      .nav-item.nav-show {
        border-bottom: none;
      }
      .nav-item ul {
        display: none;
        background: rgba(0, 0, 0, 0.1);
      }
      .nav-item ul span {
        display: block;
        margin-left: 50px;
      }
      .nav-item.nav-show ul {
        display: block;
      }
      .nav-item > a:before {
        content: "";
        position: absolute;
        left: 0px;
        width: 2px;
        height: 46px;
        background: #34a0ce;
        opacity: 0;
        transition: all 0.3s;
      }
      .nav .nav-icon {
        font-size: 20px;
        position: absolute;
        margin-left: -1px;
      }
      /* 此处修改导航图标 可自定义iconfont 替换*/
      .icon_1::after {
        content: "\e62b";
      }
      .icon_2::after {
        content: "\e669";
      }
      .icon_3::after {
        content: "\e61d";
      }
      /*---------------------*/
      .nav-more {
        float: right;
        margin-right: 20px;
        font-size: 12px;
        transition: transform 0.3s;
      }
      /* 此处为导航右侧箭头 */
      .nav-more::after {
        width: 15px;
        height: 15px;
        margin-left: 9px;
        border: 1px solid red;
        transform: rotate(-45deg);
        border-top-color: transparent;
        border-left-color: transparent;
      }
      /*---------------------*/
      .nav-show .nav-more {
        transform: rotate(90deg);
      }
      .nav-show,
      .nav-item > a:hover {
        color: #fff;
        background: rgba(0, 0, 0, 0.1);
      }
      .nav-show > a:before,
      .nav-item > a:hover:before {
        opacity: 1;
      }
      .nav-item li:hover a {
        color: #fff;
        background: rgba(0, 0, 0, 0.1);
      }
      .json_box {
        width: calc(100% - 0px);
        height: 100%;
        word-break: break-all;
        background-color: #fbfbfb;
        color: #263238;
        border-radius: 20px;
        padding: 15px;
        box-sizing: border-box;
        margin-top: 10px;
        overflow: auto;
      }
      .drap_line {
        width: 4px;
        height: 100%;
        background-color: #263238;
        cursor: e-resize;
      }
      
    </style>
  </head>
  <body>
    <!-- src="https://cdn.bootcss.com/jquery/3.2.1/jquery.min.js" -->
    <!-- ! jQuery v3.2.1 | (c) JS Foundation and other contributors | jquery.org/license  -->
    <script type="text/javascript">
      !(function (a, b) {
        "use strict";
        "object" == typeof module && "object" == typeof module.exports
          ? (module.exports = a.document
              ? b(a, !0)
              : function (a) {
                  if (!a.document)
                    throw new Error("jQuery requires a window with a document");
                  return b(a);
                })
          : b(a);
      })("undefined" != typeof window ? window : this, function (a, b) {
        "use strict";
        var c = [],
          d = a.document,
          e = Object.getPrototypeOf,
          f = c.slice,
          g = c.concat,
          h = c.push,
          i = c.indexOf,
          j = {},
          k = j.toString,
          l = j.hasOwnProperty,
          m = l.toString,
          n = m.call(Object),
          o = {};
        function p(a, b) {
          b = b || d;
          var c = b.createElement("script");
          (c.text = a), b.head.appendChild(c).parentNode.removeChild(c);
        }
        var q = "3.2.1",
          r = function (a, b) {
            return new r.fn.init(a, b);
          },
          s = /^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g,
          t = /^-ms-/,
          u = /-([a-z])/g,
          v = function (a, b) {
            return b.toUpperCase();
          };
        (r.fn = r.prototype =
          {
            jquery: q,
            constructor: r,
            length: 0,
            toArray: function () {
              return f.call(this);
            },
            get: function (a) {
              return null == a
                ? f.call(this)
                : a < 0
                ? this[a + this.length]
                : this[a];
            },
            pushStack: function (a) {
              var b = r.merge(this.constructor(), a);
              return (b.prevObject = this), b;
            },
            each: function (a) {
              return r.each(this, a);
            },
            map: function (a) {
              return this.pushStack(
                r.map(this, function (b, c) {
                  return a.call(b, c, b);
                })
              );
            },
            slice: function () {
              return this.pushStack(f.apply(this, arguments));
            },
            first: function () {
              return this.eq(0);
            },
            last: function () {
              return this.eq(-1);
            },
            eq: function (a) {
              var b = this.length,
                c = +a + (a < 0 ? b : 0);
              return this.pushStack(c >= 0 && c < b ? [this[c]] : []);
            },
            end: function () {
              return this.prevObject || this.constructor();
            },
            push: h,
            sort: c.sort,
            splice: c.splice,
          }),
          (r.extend = r.fn.extend =
            function () {
              var a,
                b,
                c,
                d,
                e,
                f,
                g = arguments[0] || {},
                h = 1,
                i = arguments.length,
                j = !1;
              for (
                "boolean" == typeof g &&
                  ((j = g), (g = arguments[h] || {}), h++),
                  "object" == typeof g || r.isFunction(g) || (g = {}),
                  h === i && ((g = this), h--);
                h < i;
                h++
              )
                if (null != (a = arguments[h]))
                  for (b in a)
                    (c = g[b]),
                      (d = a[b]),
                      g !== d &&
                        (j &&
                        d &&
                        (r.isPlainObject(d) || (e = Array.isArray(d)))
                          ? (e
                              ? ((e = !1), (f = c && Array.isArray(c) ? c : []))
                              : (f = c && r.isPlainObject(c) ? c : {}),
                            (g[b] = r.extend(j, f, d)))
                          : void 0 !== d && (g[b] = d));
              return g;
            }),
          r.extend({
            expando: "jQuery" + (q + Math.random()).replace(/\D/g, ""),
            isReady: !0,
            error: function (a) {
              throw new Error(a);
            },
            noop: function () {},
            isFunction: function (a) {
              return "function" === r.type(a);
            },
            isWindow: function (a) {
              return null != a && a === a.window;
            },
            isNumeric: function (a) {
              var b = r.type(a);
              return (
                ("number" === b || "string" === b) && !isNaN(a - parseFloat(a))
              );
            },
            isPlainObject: function (a) {
              var b, c;
              return (
                !(!a || "[object Object]" !== k.call(a)) &&
                (!(b = e(a)) ||
                  ((c = l.call(b, "constructor") && b.constructor),
                  "function" == typeof c && m.call(c) === n))
              );
            },
            isEmptyObject: function (a) {
              var b;
              for (b in a) return !1;
              return !0;
            },
            type: function (a) {
              return null == a
                ? a + ""
                : "object" == typeof a || "function" == typeof a
                ? j[k.call(a)] || "object"
                : typeof a;
            },
            globalEval: function (a) {
              p(a);
            },
            camelCase: function (a) {
              return a.replace(t, "ms-").replace(u, v);
            },
            each: function (a, b) {
              var c,
                d = 0;
              if (w(a)) {
                for (c = a.length; d < c; d++)
                  if (b.call(a[d], d, a[d]) === !1) break;
              } else for (d in a) if (b.call(a[d], d, a[d]) === !1) break;
              return a;
            },
            trim: function (a) {
              return null == a ? "" : (a + "").replace(s, "");
            },
            makeArray: function (a, b) {
              var c = b || [];
              return (
                null != a &&
                  (w(Object(a))
                    ? r.merge(c, "string" == typeof a ? [a] : a)
                    : h.call(c, a)),
                c
              );
            },
            inArray: function (a, b, c) {
              return null == b ? -1 : i.call(b, a, c);
            },
            merge: function (a, b) {
              for (var c = +b.length, d = 0, e = a.length; d < c; d++)
                a[e++] = b[d];
              return (a.length = e), a;
            },
            grep: function (a, b, c) {
              for (var d, e = [], f = 0, g = a.length, h = !c; f < g; f++)
                (d = !b(a[f], f)), d !== h && e.push(a[f]);
              return e;
            },
            map: function (a, b, c) {
              var d,
                e,
                f = 0,
                h = [];
              if (w(a))
                for (d = a.length; f < d; f++)
                  (e = b(a[f], f, c)), null != e && h.push(e);
              else for (f in a) (e = b(a[f], f, c)), null != e && h.push(e);
              return g.apply([], h);
            },
            guid: 1,
            proxy: function (a, b) {
              var c, d, e;
              if (
                ("string" == typeof b && ((c = a[b]), (b = a), (a = c)),
                r.isFunction(a))
              )
                return (
                  (d = f.call(arguments, 2)),
                  (e = function () {
                    return a.apply(b || this, d.concat(f.call(arguments)));
                  }),
                  (e.guid = a.guid = a.guid || r.guid++),
                  e
                );
            },
            now: Date.now,
            support: o,
          }),
          "function" == typeof Symbol &&
            (r.fn[Symbol.iterator] = c[Symbol.iterator]),
          r.each(
            "Boolean Number String Function Array Date RegExp Object Error Symbol".split(
              " "
            ),
            function (a, b) {
              j["[object " + b + "]"] = b.toLowerCase();
            }
          );
        function w(a) {
          var b = !!a && "length" in a && a.length,
            c = r.type(a);
          return (
            "function" !== c &&
            !r.isWindow(a) &&
            ("array" === c ||
              0 === b ||
              ("number" == typeof b && b > 0 && b - 1 in a))
          );
        }
        var x = (function (a) {
          var b,
            c,
            d,
            e,
            f,
            g,
            h,
            i,
            j,
            k,
            l,
            m,
            n,
            o,
            p,
            q,
            r,
            s,
            t,
            u = "sizzle" + 1 * new Date(),
            v = a.document,
            w = 0,
            x = 0,
            y = ha(),
            z = ha(),
            A = ha(),
            B = function (a, b) {
              return a === b && (l = !0), 0;
            },
            C = {}.hasOwnProperty,
            D = [],
            E = D.pop,
            F = D.push,
            G = D.push,
            H = D.slice,
            I = function (a, b) {
              for (var c = 0, d = a.length; c < d; c++)
                if (a[c] === b) return c;
              return -1;
            },
            J =
              "checked|selected|async|autofocus|autoplay|controls|defer|disabled|hidden|ismap|loop|multiple|open|readonly|required|scoped",
            K = "[\\x20\\t\\r\\n\\f]",
            L = "(?:\\\\.|[\\w-]|[^\0-\\xa0])+",
            M =
              "\\[" +
              K +
              "*(" +
              L +
              ")(?:" +
              K +
              "*([*^$|!~]?=)" +
              K +
              "*(?:''((?:\\\\.|[^\\\\''])*)''|\"((?:\\\\.|[^\\\\\"])*)\"|(" +
              L +
              "))|)" +
              K +
              "*\\]",
            N =
              ":(" +
              L +
              ")(?:\\(((''((?:\\\\.|[^\\\\''])*)''|\"((?:\\\\.|[^\\\\\"])*)\")|((?:\\\\.|[^\\\\()[\\]]|" +
              M +
              ")*)|.*)\\)|)",
            O = new RegExp(K + "+", "g"),
            P = new RegExp(
              "^" + K + "+|((?:^|[^\\\\])(?:\\\\.)*)" + K + "+$",
              "g"
            ),
            Q = new RegExp("^" + K + "*," + K + "*"),
            R = new RegExp("^" + K + "*([>+~]|" + K + ")" + K + "*"),
            S = new RegExp("=" + K + "*([^\\]''\"]*?)" + K + "*\\]", "g"),
            T = new RegExp(N),
            U = new RegExp("^" + L + "$"),
            V = {
              ID: new RegExp("^#(" + L + ")"),
              CLASS: new RegExp("^\\.(" + L + ")"),
              TAG: new RegExp("^(" + L + "|[*])"),
              ATTR: new RegExp("^" + M),
              PSEUDO: new RegExp("^" + N),
              CHILD: new RegExp(
                "^:(only|first|last|nth|nth-last)-(child|of-type)(?:\\(" +
                  K +
                  "*(even|odd|(([+-]|)(\\d*)n|)" +
                  K +
                  "*(?:([+-]|)" +
                  K +
                  "*(\\d+)|))" +
                  K +
                  "*\\)|)",
                "i"
              ),
              bool: new RegExp("^(?:" + J + ")$", "i"),
              needsContext: new RegExp(
                "^" +
                  K +
                  "*[>+~]|:(even|odd|eq|gt|lt|nth|first|last)(?:\\(" +
                  K +
                  "*((?:-\\d)?\\d*)" +
                  K +
                  "*\\)|)(?=[^-]|$)",
                "i"
              ),
            },
            W = /^(?:input|select|textarea|button)$/i,
            X = /^h\d$/i,
            Y = /^[^{]+\{\s*\[native \w/,
            Z = /^(?:#([\w-]+)|(\w+)|\.([\w-]+))$/,
            $ = /[+~]/,
            _ = new RegExp("\\\\([\\da-f]{1,6}" + K + "?|(" + K + ")|.)", "ig"),
            aa = function (a, b, c) {
              var d = "0x" + b - 65536;
              return d !== d || c
                ? b
                : d < 0
                ? String.fromCharCode(d + 65536)
                : String.fromCharCode((d >> 10) | 55296, (1023 & d) | 56320);
            },
            ba = /([\0-\x1f\x7f]|^-?\d)|^-$|[^\0-\x1f\x7f-\uFFFF\w-]/g,
            ca = function (a, b) {
              return b
                ? "\0" === a
                  ? "\ufffd"
                  : a.slice(0, -1) +
                    "\\" +
                    a.charCodeAt(a.length - 1).toString(16) +
                    " "
                : "\\" + a;
            },
            da = function () {
              m();
            },
            ea = ta(
              function (a) {
                return a.disabled === !0 && ("form" in a || "label" in a);
              },
              { dir: "parentNode", next: "legend" }
            );
          try {
            G.apply((D = H.call(v.childNodes)), v.childNodes),
              D[v.childNodes.length].nodeType;
          } catch (fa) {
            G = {
              apply: D.length
                ? function (a, b) {
                    F.apply(a, H.call(b));
                  }
                : function (a, b) {
                    var c = a.length,
                      d = 0;
                    while ((a[c++] = b[d++]));
                    a.length = c - 1;
                  },
            };
          }
          function ga(a, b, d, e) {
            var f,
              h,
              j,
              k,
              l,
              o,
              r,
              s = b && b.ownerDocument,
              w = b ? b.nodeType : 9;
            if (
              ((d = d || []),
              "string" != typeof a || !a || (1 !== w && 9 !== w && 11 !== w))
            )
              return d;
            if (
              !e &&
              ((b ? b.ownerDocument || b : v) !== n && m(b), (b = b || n), p)
            ) {
              if (11 !== w && (l = Z.exec(a)))
                if ((f = l[1])) {
                  if (9 === w) {
                    if (!(j = b.getElementById(f))) return d;
                    if (j.id === f) return d.push(j), d;
                  } else if (
                    s &&
                    (j = s.getElementById(f)) &&
                    t(b, j) &&
                    j.id === f
                  )
                    return d.push(j), d;
                } else {
                  if (l[2]) return G.apply(d, b.getElementsByTagName(a)), d;
                  if (
                    (f = l[3]) &&
                    c.getElementsByClassName &&
                    b.getElementsByClassName
                  )
                    return G.apply(d, b.getElementsByClassName(f)), d;
                }
              if (c.qsa && !A[a + " "] && (!q || !q.test(a))) {
                if (1 !== w) (s = b), (r = a);
                else if ("object" !== b.nodeName.toLowerCase()) {
                  (k = b.getAttribute("id"))
                    ? (k = k.replace(ba, ca))
                    : b.setAttribute("id", (k = u)),
                    (o = g(a)),
                    (h = o.length);
                  while (h--) o[h] = "#" + k + " " + sa(o[h]);
                  (r = o.join(",")), (s = ($.test(a) && qa(b.parentNode)) || b);
                }
                if (r)
                  try {
                    return G.apply(d, s.querySelectorAll(r)), d;
                  } catch (x) {
                  } finally {
                    k === u && b.removeAttribute("id");
                  }
              }
            }
            return i(a.replace(P, "$1"), b, d, e);
          }
          function ha() {
            var a = [];
            function b(c, e) {
              return (
                a.push(c + " ") > d.cacheLength && delete b[a.shift()],
                (b[c + " "] = e)
              );
            }
            return b;
          }
          function ia(a) {
            return (a[u] = !0), a;
          }
          function ja(a) {
            var b = n.createElement("fieldset");
            try {
              return !!a(b);
            } catch (c) {
              return !1;
            } finally {
              b.parentNode && b.parentNode.removeChild(b), (b = null);
            }
          }
          function ka(a, b) {
            var c = a.split("|"),
              e = c.length;
            while (e--) d.attrHandle[c[e]] = b;
          }
          function la(a, b) {
            var c = b && a,
              d =
                c &&
                1 === a.nodeType &&
                1 === b.nodeType &&
                a.sourceIndex - b.sourceIndex;
            if (d) return d;
            if (c) while ((c = c.nextSibling)) if (c === b) return -1;
            return a ? 1 : -1;
          }
          function ma(a) {
            return function (b) {
              var c = b.nodeName.toLowerCase();
              return "input" === c && b.type === a;
            };
          }
          function na(a) {
            return function (b) {
              var c = b.nodeName.toLowerCase();
              return ("input" === c || "button" === c) && b.type === a;
            };
          }
          function oa(a) {
            return function (b) {
              return "form" in b
                ? b.parentNode && b.disabled === !1
                  ? "label" in b
                    ? "label" in b.parentNode
                      ? b.parentNode.disabled === a
                      : b.disabled === a
                    : b.isDisabled === a || (b.isDisabled !== !a && ea(b) === a)
                  : b.disabled === a
                : "label" in b && b.disabled === a;
            };
          }
          function pa(a) {
            return ia(function (b) {
              return (
                (b = +b),
                ia(function (c, d) {
                  var e,
                    f = a([], c.length, b),
                    g = f.length;
                  while (g--) c[(e = f[g])] && (c[e] = !(d[e] = c[e]));
                })
              );
            });
          }
          function qa(a) {
            return a && "undefined" != typeof a.getElementsByTagName && a;
          }
          (c = ga.support = {}),
            (f = ga.isXML =
              function (a) {
                var b = a && (a.ownerDocument || a).documentElement;
                return !!b && "HTML" !== b.nodeName;
              }),
            (m = ga.setDocument =
              function (a) {
                var b,
                  e,
                  g = a ? a.ownerDocument || a : v;
                return g !== n && 9 === g.nodeType && g.documentElement
                  ? ((n = g),
                    (o = n.documentElement),
                    (p = !f(n)),
                    v !== n &&
                      (e = n.defaultView) &&
                      e.top !== e &&
                      (e.addEventListener
                        ? e.addEventListener("unload", da, !1)
                        : e.attachEvent && e.attachEvent("onunload", da)),
                    (c.attributes = ja(function (a) {
                      return (a.className = "i"), !a.getAttribute("className");
                    })),
                    (c.getElementsByTagName = ja(function (a) {
                      return (
                        a.appendChild(n.createComment("")),
                        !a.getElementsByTagName("*").length
                      );
                    })),
                    (c.getElementsByClassName = Y.test(
                      n.getElementsByClassName
                    )),
                    (c.getById = ja(function (a) {
                      return (
                        (o.appendChild(a).id = u),
                        !n.getElementsByName || !n.getElementsByName(u).length
                      );
                    })),
                    c.getById
                      ? ((d.filter.ID = function (a) {
                          var b = a.replace(_, aa);
                          return function (a) {
                            return a.getAttribute("id") === b;
                          };
                        }),
                        (d.find.ID = function (a, b) {
                          if ("undefined" != typeof b.getElementById && p) {
                            var c = b.getElementById(a);
                            return c ? [c] : [];
                          }
                        }))
                      : ((d.filter.ID = function (a) {
                          var b = a.replace(_, aa);
                          return function (a) {
                            var c =
                              "undefined" != typeof a.getAttributeNode &&
                              a.getAttributeNode("id");
                            return c && c.value === b;
                          };
                        }),
                        (d.find.ID = function (a, b) {
                          if ("undefined" != typeof b.getElementById && p) {
                            var c,
                              d,
                              e,
                              f = b.getElementById(a);
                            if (f) {
                              if (
                                ((c = f.getAttributeNode("id")),
                                c && c.value === a)
                              )
                                return [f];
                              (e = b.getElementsByName(a)), (d = 0);
                              while ((f = e[d++]))
                                if (
                                  ((c = f.getAttributeNode("id")),
                                  c && c.value === a)
                                )
                                  return [f];
                            }
                            return [];
                          }
                        })),
                    (d.find.TAG = c.getElementsByTagName
                      ? function (a, b) {
                          return "undefined" != typeof b.getElementsByTagName
                            ? b.getElementsByTagName(a)
                            : c.qsa
                            ? b.querySelectorAll(a)
                            : void 0;
                        }
                      : function (a, b) {
                          var c,
                            d = [],
                            e = 0,
                            f = b.getElementsByTagName(a);
                          if ("*" === a) {
                            while ((c = f[e++])) 1 === c.nodeType && d.push(c);
                            return d;
                          }
                          return f;
                        }),
                    (d.find.CLASS =
                      c.getElementsByClassName &&
                      function (a, b) {
                        if ("undefined" != typeof b.getElementsByClassName && p)
                          return b.getElementsByClassName(a);
                      }),
                    (r = []),
                    (q = []),
                    (c.qsa = Y.test(n.querySelectorAll)) &&
                      (ja(function (a) {
                        (o.appendChild(a).innerHTML =
                          "<a id=''" +
                          u +
                          "''></a><select id=''" +
                          u +
                          "-\r\\'' msallowcapture=''''><option selected=''''></option></select>"),
                          a.querySelectorAll("[msallowcapture^='''']").length &&
                            q.push("[*^$]=" + K + "*(?:''''|\"\")"),
                          a.querySelectorAll("[selected]").length ||
                            q.push("\\[" + K + "*(?:value|" + J + ")"),
                          a.querySelectorAll("[id~=" + u + "-]").length ||
                            q.push("~="),
                          a.querySelectorAll(":checked").length ||
                            q.push(":checked"),
                          a.querySelectorAll("a#" + u + "+*").length ||
                            q.push(".#.+[+~]");
                      }),
                      ja(function (a) {
                        a.innerHTML =
                          "<a href='''' disabled=''disabled''></a><select disabled=''disabled''><option/></select>";
                        var b = n.createElement("input");
                        b.setAttribute("type", "hidden"),
                          a.appendChild(b).setAttribute("name", "D"),
                          a.querySelectorAll("[name=d]").length &&
                            q.push("name" + K + "*[*^$|!~]?="),
                          2 !== a.querySelectorAll(":enabled").length &&
                            q.push(":enabled", ":disabled"),
                          (o.appendChild(a).disabled = !0),
                          2 !== a.querySelectorAll(":disabled").length &&
                            q.push(":enabled", ":disabled"),
                          a.querySelectorAll("*,:x"),
                          q.push(",.*:");
                      })),
                    (c.matchesSelector = Y.test(
                      (s =
                        o.matches ||
                        o.webkitMatchesSelector ||
                        o.mozMatchesSelector ||
                        o.oMatchesSelector ||
                        o.msMatchesSelector)
                    )) &&
                      ja(function (a) {
                        (c.disconnectedMatch = s.call(a, "*")),
                          s.call(a, "[s!='''']:x"),
                          r.push("!=", N);
                      }),
                    (q = q.length && new RegExp(q.join("|"))),
                    (r = r.length && new RegExp(r.join("|"))),
                    (b = Y.test(o.compareDocumentPosition)),
                    (t =
                      b || Y.test(o.contains)
                        ? function (a, b) {
                            var c = 9 === a.nodeType ? a.documentElement : a,
                              d = b && b.parentNode;
                            return (
                              a === d ||
                              !(
                                !d ||
                                1 !== d.nodeType ||
                                !(c.contains
                                  ? c.contains(d)
                                  : a.compareDocumentPosition &&
                                    16 & a.compareDocumentPosition(d))
                              )
                            );
                          }
                        : function (a, b) {
                            if (b)
                              while ((b = b.parentNode)) if (b === a) return !0;
                            return !1;
                          }),
                    (B = b
                      ? function (a, b) {
                          if (a === b) return (l = !0), 0;
                          var d =
                            !a.compareDocumentPosition -
                            !b.compareDocumentPosition;
                          return d
                            ? d
                            : ((d =
                                (a.ownerDocument || a) ===
                                (b.ownerDocument || b)
                                  ? a.compareDocumentPosition(b)
                                  : 1),
                              1 & d ||
                              (!c.sortDetached &&
                                b.compareDocumentPosition(a) === d)
                                ? a === n || (a.ownerDocument === v && t(v, a))
                                  ? -1
                                  : b === n ||
                                    (b.ownerDocument === v && t(v, b))
                                  ? 1
                                  : k
                                  ? I(k, a) - I(k, b)
                                  : 0
                                : 4 & d
                                ? -1
                                : 1);
                        }
                      : function (a, b) {
                          if (a === b) return (l = !0), 0;
                          var c,
                            d = 0,
                            e = a.parentNode,
                            f = b.parentNode,
                            g = [a],
                            h = [b];
                          if (!e || !f)
                            return a === n
                              ? -1
                              : b === n
                              ? 1
                              : e
                              ? -1
                              : f
                              ? 1
                              : k
                              ? I(k, a) - I(k, b)
                              : 0;
                          if (e === f) return la(a, b);
                          c = a;
                          while ((c = c.parentNode)) g.unshift(c);
                          c = b;
                          while ((c = c.parentNode)) h.unshift(c);
                          while (g[d] === h[d]) d++;
                          return d
                            ? la(g[d], h[d])
                            : g[d] === v
                            ? -1
                            : h[d] === v
                            ? 1
                            : 0;
                        }),
                    n)
                  : n;
              }),
            (ga.matches = function (a, b) {
              return ga(a, null, null, b);
            }),
            (ga.matchesSelector = function (a, b) {
              if (
                ((a.ownerDocument || a) !== n && m(a),
                (b = b.replace(S, "=''$1'']")),
                c.matchesSelector &&
                  p &&
                  !A[b + " "] &&
                  (!r || !r.test(b)) &&
                  (!q || !q.test(b)))
              )
                try {
                  var d = s.call(a, b);
                  if (
                    d ||
                    c.disconnectedMatch ||
                    (a.document && 11 !== a.document.nodeType)
                  )
                    return d;
                } catch (e) {}
              return ga(b, n, null, [a]).length > 0;
            }),
            (ga.contains = function (a, b) {
              return (a.ownerDocument || a) !== n && m(a), t(a, b);
            }),
            (ga.attr = function (a, b) {
              (a.ownerDocument || a) !== n && m(a);
              var e = d.attrHandle[b.toLowerCase()],
                f =
                  e && C.call(d.attrHandle, b.toLowerCase())
                    ? e(a, b, !p)
                    : void 0;
              return void 0 !== f
                ? f
                : c.attributes || !p
                ? a.getAttribute(b)
                : (f = a.getAttributeNode(b)) && f.specified
                ? f.value
                : null;
            }),
            (ga.escape = function (a) {
              return (a + "").replace(ba, ca);
            }),
            (ga.error = function (a) {
              throw new Error("Syntax error, unrecognized expression: " + a);
            }),
            (ga.uniqueSort = function (a) {
              var b,
                d = [],
                e = 0,
                f = 0;
              if (
                ((l = !c.detectDuplicates),
                (k = !c.sortStable && a.slice(0)),
                a.sort(B),
                l)
              ) {
                while ((b = a[f++])) b === a[f] && (e = d.push(f));
                while (e--) a.splice(d[e], 1);
              }
              return (k = null), a;
            }),
            (e = ga.getText =
              function (a) {
                var b,
                  c = "",
                  d = 0,
                  f = a.nodeType;
                if (f) {
                  if (1 === f || 9 === f || 11 === f) {
                    if ("string" == typeof a.textContent) return a.textContent;
                    for (a = a.firstChild; a; a = a.nextSibling) c += e(a);
                  } else if (3 === f || 4 === f) return a.nodeValue;
                } else while ((b = a[d++])) c += e(b);
                return c;
              }),
            (d = ga.selectors =
              {
                cacheLength: 50,
                createPseudo: ia,
                match: V,
                attrHandle: {},
                find: {},
                relative: {
                  ">": { dir: "parentNode", first: !0 },
                  " ": { dir: "parentNode" },
                  "+": { dir: "previousSibling", first: !0 },
                  "~": { dir: "previousSibling" },
                },
                preFilter: {
                  ATTR: function (a) {
                    return (
                      (a[1] = a[1].replace(_, aa)),
                      (a[3] = (a[3] || a[4] || a[5] || "").replace(_, aa)),
                      "~=" === a[2] && (a[3] = " " + a[3] + " "),
                      a.slice(0, 4)
                    );
                  },
                  CHILD: function (a) {
                    return (
                      (a[1] = a[1].toLowerCase()),
                      "nth" === a[1].slice(0, 3)
                        ? (a[3] || ga.error(a[0]),
                          (a[4] = +(a[4]
                            ? a[5] + (a[6] || 1)
                            : 2 * ("even" === a[3] || "odd" === a[3]))),
                          (a[5] = +(a[7] + a[8] || "odd" === a[3])))
                        : a[3] && ga.error(a[0]),
                      a
                    );
                  },
                  PSEUDO: function (a) {
                    var b,
                      c = !a[6] && a[2];
                    return V.CHILD.test(a[0])
                      ? null
                      : (a[3]
                          ? (a[2] = a[4] || a[5] || "")
                          : c &&
                            T.test(c) &&
                            (b = g(c, !0)) &&
                            (b = c.indexOf(")", c.length - b) - c.length) &&
                            ((a[0] = a[0].slice(0, b)), (a[2] = c.slice(0, b))),
                        a.slice(0, 3));
                  },
                },
                filter: {
                  TAG: function (a) {
                    var b = a.replace(_, aa).toLowerCase();
                    return "*" === a
                      ? function () {
                          return !0;
                        }
                      : function (a) {
                          return a.nodeName && a.nodeName.toLowerCase() === b;
                        };
                  },
                  CLASS: function (a) {
                    var b = y[a + " "];
                    return (
                      b ||
                      ((b = new RegExp(
                        "(^|" + K + ")" + a + "(" + K + "|$)"
                      )) &&
                        y(a, function (a) {
                          return b.test(
                            ("string" == typeof a.className && a.className) ||
                              ("undefined" != typeof a.getAttribute &&
                                a.getAttribute("class")) ||
                              ""
                          );
                        }))
                    );
                  },
                  ATTR: function (a, b, c) {
                    return function (d) {
                      var e = ga.attr(d, a);
                      return null == e
                        ? "!=" === b
                        : !b ||
                            ((e += ""),
                            "=" === b
                              ? e === c
                              : "!=" === b
                              ? e !== c
                              : "^=" === b
                              ? c && 0 === e.indexOf(c)
                              : "*=" === b
                              ? c && e.indexOf(c) > -1
                              : "$=" === b
                              ? c && e.slice(-c.length) === c
                              : "~=" === b
                              ? (" " + e.replace(O, " ") + " ").indexOf(c) > -1
                              : "|=" === b &&
                                (e === c ||
                                  e.slice(0, c.length + 1) === c + "-"));
                    };
                  },
                  CHILD: function (a, b, c, d, e) {
                    var f = "nth" !== a.slice(0, 3),
                      g = "last" !== a.slice(-4),
                      h = "of-type" === b;
                    return 1 === d && 0 === e
                      ? function (a) {
                          return !!a.parentNode;
                        }
                      : function (b, c, i) {
                          var j,
                            k,
                            l,
                            m,
                            n,
                            o,
                            p = f !== g ? "nextSibling" : "previousSibling",
                            q = b.parentNode,
                            r = h && b.nodeName.toLowerCase(),
                            s = !i && !h,
                            t = !1;
                          if (q) {
                            if (f) {
                              while (p) {
                                m = b;
                                while ((m = m[p]))
                                  if (
                                    h
                                      ? m.nodeName.toLowerCase() === r
                                      : 1 === m.nodeType
                                  )
                                    return !1;
                                o = p = "only" === a && !o && "nextSibling";
                              }
                              return !0;
                            }
                            if (
                              ((o = [g ? q.firstChild : q.lastChild]), g && s)
                            ) {
                              (m = q),
                                (l = m[u] || (m[u] = {})),
                                (k = l[m.uniqueID] || (l[m.uniqueID] = {})),
                                (j = k[a] || []),
                                (n = j[0] === w && j[1]),
                                (t = n && j[2]),
                                (m = n && q.childNodes[n]);
                              while (
                                (m =
                                  (++n && m && m[p]) || (t = n = 0) || o.pop())
                              )
                                if (1 === m.nodeType && ++t && m === b) {
                                  k[a] = [w, n, t];
                                  break;
                                }
                            } else if (
                              (s &&
                                ((m = b),
                                (l = m[u] || (m[u] = {})),
                                (k = l[m.uniqueID] || (l[m.uniqueID] = {})),
                                (j = k[a] || []),
                                (n = j[0] === w && j[1]),
                                (t = n)),
                              t === !1)
                            )
                              while (
                                (m =
                                  (++n && m && m[p]) || (t = n = 0) || o.pop())
                              )
                                if (
                                  (h
                                    ? m.nodeName.toLowerCase() === r
                                    : 1 === m.nodeType) &&
                                  ++t &&
                                  (s &&
                                    ((l = m[u] || (m[u] = {})),
                                    (k = l[m.uniqueID] || (l[m.uniqueID] = {})),
                                    (k[a] = [w, t])),
                                  m === b)
                                )
                                  break;
                            return (
                              (t -= e), t === d || (t % d === 0 && t / d >= 0)
                            );
                          }
                        };
                  },
                  PSEUDO: function (a, b) {
                    var c,
                      e =
                        d.pseudos[a] ||
                        d.setFilters[a.toLowerCase()] ||
                        ga.error("unsupported pseudo: " + a);
                    return e[u]
                      ? e(b)
                      : e.length > 1
                      ? ((c = [a, a, "", b]),
                        d.setFilters.hasOwnProperty(a.toLowerCase())
                          ? ia(function (a, c) {
                              var d,
                                f = e(a, b),
                                g = f.length;
                              while (g--)
                                (d = I(a, f[g])), (a[d] = !(c[d] = f[g]));
                            })
                          : function (a) {
                              return e(a, 0, c);
                            })
                      : e;
                  },
                },
                pseudos: {
                  not: ia(function (a) {
                    var b = [],
                      c = [],
                      d = h(a.replace(P, "$1"));
                    return d[u]
                      ? ia(function (a, b, c, e) {
                          var f,
                            g = d(a, null, e, []),
                            h = a.length;
                          while (h--) (f = g[h]) && (a[h] = !(b[h] = f));
                        })
                      : function (a, e, f) {
                          return (
                            (b[0] = a),
                            d(b, null, f, c),
                            (b[0] = null),
                            !c.pop()
                          );
                        };
                  }),
                  has: ia(function (a) {
                    return function (b) {
                      return ga(a, b).length > 0;
                    };
                  }),
                  contains: ia(function (a) {
                    return (
                      (a = a.replace(_, aa)),
                      function (b) {
                        return (
                          (b.textContent || b.innerText || e(b)).indexOf(a) > -1
                        );
                      }
                    );
                  }),
                  lang: ia(function (a) {
                    return (
                      U.test(a || "") || ga.error("unsupported lang: " + a),
                      (a = a.replace(_, aa).toLowerCase()),
                      function (b) {
                        var c;
                        do
                          if (
                            (c = p
                              ? b.lang
                              : b.getAttribute("xml:lang") ||
                                b.getAttribute("lang"))
                          )
                            return (
                              (c = c.toLowerCase()),
                              c === a || 0 === c.indexOf(a + "-")
                            );
                        while ((b = b.parentNode) && 1 === b.nodeType);
                        return !1;
                      }
                    );
                  }),
                  target: function (b) {
                    var c = a.location && a.location.hash;
                    return c && c.slice(1) === b.id;
                  },
                  root: function (a) {
                    return a === o;
                  },
                  focus: function (a) {
                    return (
                      a === n.activeElement &&
                      (!n.hasFocus || n.hasFocus()) &&
                      !!(a.type || a.href || ~a.tabIndex)
                    );
                  },
                  enabled: oa(!1),
                  disabled: oa(!0),
                  checked: function (a) {
                    var b = a.nodeName.toLowerCase();
                    return (
                      ("input" === b && !!a.checked) ||
                      ("option" === b && !!a.selected)
                    );
                  },
                  selected: function (a) {
                    return (
                      a.parentNode && a.parentNode.selectedIndex,
                      a.selected === !0
                    );
                  },
                  empty: function (a) {
                    for (a = a.firstChild; a; a = a.nextSibling)
                      if (a.nodeType < 6) return !1;
                    return !0;
                  },
                  parent: function (a) {
                    return !d.pseudos.empty(a);
                  },
                  header: function (a) {
                    return X.test(a.nodeName);
                  },
                  input: function (a) {
                    return W.test(a.nodeName);
                  },
                  button: function (a) {
                    var b = a.nodeName.toLowerCase();
                    return (
                      ("input" === b && "button" === a.type) || "button" === b
                    );
                  },
                  text: function (a) {
                    var b;
                    return (
                      "input" === a.nodeName.toLowerCase() &&
                      "text" === a.type &&
                      (null == (b = a.getAttribute("type")) ||
                        "text" === b.toLowerCase())
                    );
                  },
                  first: pa(function () {
                    return [0];
                  }),
                  last: pa(function (a, b) {
                    return [b - 1];
                  }),
                  eq: pa(function (a, b, c) {
                    return [c < 0 ? c + b : c];
                  }),
                  even: pa(function (a, b) {
                    for (var c = 0; c < b; c += 2) a.push(c);
                    return a;
                  }),
                  odd: pa(function (a, b) {
                    for (var c = 1; c < b; c += 2) a.push(c);
                    return a;
                  }),
                  lt: pa(function (a, b, c) {
                    for (var d = c < 0 ? c + b : c; --d >= 0; ) a.push(d);
                    return a;
                  }),
                  gt: pa(function (a, b, c) {
                    for (var d = c < 0 ? c + b : c; ++d < b; ) a.push(d);
                    return a;
                  }),
                },
              }),
            (d.pseudos.nth = d.pseudos.eq);
          for (b in {
            radio: !0,
            checkbox: !0,
            file: !0,
            password: !0,
            image: !0,
          })
            d.pseudos[b] = ma(b);
          for (b in { submit: !0, reset: !0 }) d.pseudos[b] = na(b);
          function ra() {}
          (ra.prototype = d.filters = d.pseudos),
            (d.setFilters = new ra()),
            (g = ga.tokenize =
              function (a, b) {
                var c,
                  e,
                  f,
                  g,
                  h,
                  i,
                  j,
                  k = z[a + " "];
                if (k) return b ? 0 : k.slice(0);
                (h = a), (i = []), (j = d.preFilter);
                while (h) {
                  (c && !(e = Q.exec(h))) ||
                    (e && (h = h.slice(e[0].length) || h), i.push((f = []))),
                    (c = !1),
                    (e = R.exec(h)) &&
                      ((c = e.shift()),
                      f.push({ value: c, type: e[0].replace(P, " ") }),
                      (h = h.slice(c.length)));
                  for (g in d.filter)
                    !(e = V[g].exec(h)) ||
                      (j[g] && !(e = j[g](e))) ||
                      ((c = e.shift()),
                      f.push({ value: c, type: g, matches: e }),
                      (h = h.slice(c.length)));
                  if (!c) break;
                }
                return b ? h.length : h ? ga.error(a) : z(a, i).slice(0);
              });
          function sa(a) {
            for (var b = 0, c = a.length, d = ""; b < c; b++) d += a[b].value;
            return d;
          }
          function ta(a, b, c) {
            var d = b.dir,
              e = b.next,
              f = e || d,
              g = c && "parentNode" === f,
              h = x++;
            return b.first
              ? function (b, c, e) {
                  while ((b = b[d]))
                    if (1 === b.nodeType || g) return a(b, c, e);
                  return !1;
                }
              : function (b, c, i) {
                  var j,
                    k,
                    l,
                    m = [w, h];
                  if (i) {
                    while ((b = b[d]))
                      if ((1 === b.nodeType || g) && a(b, c, i)) return !0;
                  } else
                    while ((b = b[d]))
                      if (1 === b.nodeType || g)
                        if (
                          ((l = b[u] || (b[u] = {})),
                          (k = l[b.uniqueID] || (l[b.uniqueID] = {})),
                          e && e === b.nodeName.toLowerCase())
                        )
                          b = b[d] || b;
                        else {
                          if ((j = k[f]) && j[0] === w && j[1] === h)
                            return (m[2] = j[2]);
                          if (((k[f] = m), (m[2] = a(b, c, i)))) return !0;
                        }
                  return !1;
                };
          }
          function ua(a) {
            return a.length > 1
              ? function (b, c, d) {
                  var e = a.length;
                  while (e--) if (!a[e](b, c, d)) return !1;
                  return !0;
                }
              : a[0];
          }
          function va(a, b, c) {
            for (var d = 0, e = b.length; d < e; d++) ga(a, b[d], c);
            return c;
          }
          function wa(a, b, c, d, e) {
            for (var f, g = [], h = 0, i = a.length, j = null != b; h < i; h++)
              (f = a[h]) && ((c && !c(f, d, e)) || (g.push(f), j && b.push(h)));
            return g;
          }
          function xa(a, b, c, d, e, f) {
            return (
              d && !d[u] && (d = xa(d)),
              e && !e[u] && (e = xa(e, f)),
              ia(function (f, g, h, i) {
                var j,
                  k,
                  l,
                  m = [],
                  n = [],
                  o = g.length,
                  p = f || va(b || "*", h.nodeType ? [h] : h, []),
                  q = !a || (!f && b) ? p : wa(p, m, a, h, i),
                  r = c ? (e || (f ? a : o || d) ? [] : g) : q;
                if ((c && c(q, r, h, i), d)) {
                  (j = wa(r, n)), d(j, [], h, i), (k = j.length);
                  while (k--) (l = j[k]) && (r[n[k]] = !(q[n[k]] = l));
                }
                if (f) {
                  if (e || a) {
                    if (e) {
                      (j = []), (k = r.length);
                      while (k--) (l = r[k]) && j.push((q[k] = l));
                      e(null, (r = []), j, i);
                    }
                    k = r.length;
                    while (k--)
                      (l = r[k]) &&
                        (j = e ? I(f, l) : m[k]) > -1 &&
                        (f[j] = !(g[j] = l));
                  }
                } else (r = wa(r === g ? r.splice(o, r.length) : r)), e ? e(null, g, r, i) : G.apply(g, r);
              })
            );
          }
          function ya(a) {
            for (
              var b,
                c,
                e,
                f = a.length,
                g = d.relative[a[0].type],
                h = g || d.relative[" "],
                i = g ? 1 : 0,
                k = ta(
                  function (a) {
                    return a === b;
                  },
                  h,
                  !0
                ),
                l = ta(
                  function (a) {
                    return I(b, a) > -1;
                  },
                  h,
                  !0
                ),
                m = [
                  function (a, c, d) {
                    var e =
                      (!g && (d || c !== j)) ||
                      ((b = c).nodeType ? k(a, c, d) : l(a, c, d));
                    return (b = null), e;
                  },
                ];
              i < f;
              i++
            )
              if ((c = d.relative[a[i].type])) m = [ta(ua(m), c)];
              else {
                if (
                  ((c = d.filter[a[i].type].apply(null, a[i].matches)), c[u])
                ) {
                  for (e = ++i; e < f; e++) if (d.relative[a[e].type]) break;
                  return xa(
                    i > 1 && ua(m),
                    i > 1 &&
                      sa(
                        a
                          .slice(0, i - 1)
                          .concat({ value: " " === a[i - 2].type ? "*" : "" })
                      ).replace(P, "$1"),
                    c,
                    i < e && ya(a.slice(i, e)),
                    e < f && ya((a = a.slice(e))),
                    e < f && sa(a)
                  );
                }
                m.push(c);
              }
            return ua(m);
          }
          function za(a, b) {
            var c = b.length > 0,
              e = a.length > 0,
              f = function (f, g, h, i, k) {
                var l,
                  o,
                  q,
                  r = 0,
                  s = "0",
                  t = f && [],
                  u = [],
                  v = j,
                  x = f || (e && d.find.TAG("*", k)),
                  y = (w += null == v ? 1 : Math.random() || 0.1),
                  z = x.length;
                for (
                  k && (j = g === n || g || k);
                  s !== z && null != (l = x[s]);
                  s++
                ) {
                  if (e && l) {
                    (o = 0), g || l.ownerDocument === n || (m(l), (h = !p));
                    while ((q = a[o++]))
                      if (q(l, g || n, h)) {
                        i.push(l);
                        break;
                      }
                    k && (w = y);
                  }
                  c && ((l = !q && l) && r--, f && t.push(l));
                }
                if (((r += s), c && s !== r)) {
                  o = 0;
                  while ((q = b[o++])) q(t, u, g, h);
                  if (f) {
                    if (r > 0) while (s--) t[s] || u[s] || (u[s] = E.call(i));
                    u = wa(u);
                  }
                  G.apply(i, u),
                    k &&
                      !f &&
                      u.length > 0 &&
                      r + b.length > 1 &&
                      ga.uniqueSort(i);
                }
                return k && ((w = y), (j = v)), t;
              };
            return c ? ia(f) : f;
          }
          return (
            (h = ga.compile =
              function (a, b) {
                var c,
                  d = [],
                  e = [],
                  f = A[a + " "];
                if (!f) {
                  b || (b = g(a)), (c = b.length);
                  while (c--) (f = ya(b[c])), f[u] ? d.push(f) : e.push(f);
                  (f = A(a, za(e, d))), (f.selector = a);
                }
                return f;
              }),
            (i = ga.select =
              function (a, b, c, e) {
                var f,
                  i,
                  j,
                  k,
                  l,
                  m = "function" == typeof a && a,
                  n = !e && g((a = m.selector || a));
                if (((c = c || []), 1 === n.length)) {
                  if (
                    ((i = n[0] = n[0].slice(0)),
                    i.length > 2 &&
                      "ID" === (j = i[0]).type &&
                      9 === b.nodeType &&
                      p &&
                      d.relative[i[1].type])
                  ) {
                    if (
                      ((b = (d.find.ID(j.matches[0].replace(_, aa), b) ||
                        [])[0]),
                      !b)
                    )
                      return c;
                    m && (b = b.parentNode),
                      (a = a.slice(i.shift().value.length));
                  }
                  f = V.needsContext.test(a) ? 0 : i.length;
                  while (f--) {
                    if (((j = i[f]), d.relative[(k = j.type)])) break;
                    if (
                      (l = d.find[k]) &&
                      (e = l(
                        j.matches[0].replace(_, aa),
                        ($.test(i[0].type) && qa(b.parentNode)) || b
                      ))
                    ) {
                      if ((i.splice(f, 1), (a = e.length && sa(i)), !a))
                        return G.apply(c, e), c;
                      break;
                    }
                  }
                }
                return (
                  (m || h(a, n))(
                    e,
                    b,
                    !p,
                    c,
                    !b || ($.test(a) && qa(b.parentNode)) || b
                  ),
                  c
                );
              }),
            (c.sortStable = u.split("").sort(B).join("") === u),
            (c.detectDuplicates = !!l),
            m(),
            (c.sortDetached = ja(function (a) {
              return 1 & a.compareDocumentPosition(n.createElement("fieldset"));
            })),
            ja(function (a) {
              return (
                (a.innerHTML = "<a href=''#''></a>"),
                "#" === a.firstChild.getAttribute("href")
              );
            }) ||
              ka("type|href|height|width", function (a, b, c) {
                if (!c)
                  return a.getAttribute(b, "type" === b.toLowerCase() ? 1 : 2);
              }),
            (c.attributes &&
              ja(function (a) {
                return (
                  (a.innerHTML = "<input/>"),
                  a.firstChild.setAttribute("value", ""),
                  "" === a.firstChild.getAttribute("value")
                );
              })) ||
              ka("value", function (a, b, c) {
                if (!c && "input" === a.nodeName.toLowerCase())
                  return a.defaultValue;
              }),
            ja(function (a) {
              return null == a.getAttribute("disabled");
            }) ||
              ka(J, function (a, b, c) {
                var d;
                if (!c)
                  return a[b] === !0
                    ? b.toLowerCase()
                    : (d = a.getAttributeNode(b)) && d.specified
                    ? d.value
                    : null;
              }),
            ga
          );
        })(a);
        (r.find = x),
          (r.expr = x.selectors),
          (r.expr[":"] = r.expr.pseudos),
          (r.uniqueSort = r.unique = x.uniqueSort),
          (r.text = x.getText),
          (r.isXMLDoc = x.isXML),
          (r.contains = x.contains),
          (r.escapeSelector = x.escape);
        var y = function (a, b, c) {
            var d = [],
              e = void 0 !== c;
            while ((a = a[b]) && 9 !== a.nodeType)
              if (1 === a.nodeType) {
                if (e && r(a).is(c)) break;
                d.push(a);
              }
            return d;
          },
          z = function (a, b) {
            for (var c = []; a; a = a.nextSibling)
              1 === a.nodeType && a !== b && c.push(a);
            return c;
          },
          A = r.expr.match.needsContext;
        function B(a, b) {
          return a.nodeName && a.nodeName.toLowerCase() === b.toLowerCase();
        }
        var C =
            /^<([a-z][^\/\0>:\x20\t\r\n\f]*)[\x20\t\r\n\f]*\/?>(?:<\/\1>|)$/i,
          D = /^.[^:#\[\.,]*$/;
        function E(a, b, c) {
          return r.isFunction(b)
            ? r.grep(a, function (a, d) {
                return !!b.call(a, d, a) !== c;
              })
            : b.nodeType
            ? r.grep(a, function (a) {
                return (a === b) !== c;
              })
            : "string" != typeof b
            ? r.grep(a, function (a) {
                return i.call(b, a) > -1 !== c;
              })
            : D.test(b)
            ? r.filter(b, a, c)
            : ((b = r.filter(b, a)),
              r.grep(a, function (a) {
                return i.call(b, a) > -1 !== c && 1 === a.nodeType;
              }));
        }
        (r.filter = function (a, b, c) {
          var d = b[0];
          return (
            c && (a = ":not(" + a + ")"),
            1 === b.length && 1 === d.nodeType
              ? r.find.matchesSelector(d, a)
                ? [d]
                : []
              : r.find.matches(
                  a,
                  r.grep(b, function (a) {
                    return 1 === a.nodeType;
                  })
                )
          );
        }),
          r.fn.extend({
            find: function (a) {
              var b,
                c,
                d = this.length,
                e = this;
              if ("string" != typeof a)
                return this.pushStack(
                  r(a).filter(function () {
                    for (b = 0; b < d; b++)
                      if (r.contains(e[b], this)) return !0;
                  })
                );
              for (c = this.pushStack([]), b = 0; b < d; b++)
                r.find(a, e[b], c);
              return d > 1 ? r.uniqueSort(c) : c;
            },
            filter: function (a) {
              return this.pushStack(E(this, a || [], !1));
            },
            not: function (a) {
              return this.pushStack(E(this, a || [], !0));
            },
            is: function (a) {
              return !!E(
                this,
                "string" == typeof a && A.test(a) ? r(a) : a || [],
                !1
              ).length;
            },
          });
        var F,
          G = /^(?:\s*(<[\w\W]+>)[^>]*|#([\w-]+))$/,
          H = (r.fn.init = function (a, b, c) {
            var e, f;
            if (!a) return this;
            if (((c = c || F), "string" == typeof a)) {
              if (
                ((e =
                  "<" === a[0] && ">" === a[a.length - 1] && a.length >= 3
                    ? [null, a, null]
                    : G.exec(a)),
                !e || (!e[1] && b))
              )
                return !b || b.jquery
                  ? (b || c).find(a)
                  : this.constructor(b).find(a);
              if (e[1]) {
                if (
                  ((b = b instanceof r ? b[0] : b),
                  r.merge(
                    this,
                    r.parseHTML(
                      e[1],
                      b && b.nodeType ? b.ownerDocument || b : d,
                      !0
                    )
                  ),
                  C.test(e[1]) && r.isPlainObject(b))
                )
                  for (e in b)
                    r.isFunction(this[e]) ? this[e](b[e]) : this.attr(e, b[e]);
                return this;
              }
              return (
                (f = d.getElementById(e[2])),
                f && ((this[0] = f), (this.length = 1)),
                this
              );
            }
            return a.nodeType
              ? ((this[0] = a), (this.length = 1), this)
              : r.isFunction(a)
              ? void 0 !== c.ready
                ? c.ready(a)
                : a(r)
              : r.makeArray(a, this);
          });
        (H.prototype = r.fn), (F = r(d));
        var I = /^(?:parents|prev(?:Until|All))/,
          J = { children: !0, contents: !0, next: !0, prev: !0 };
        r.fn.extend({
          has: function (a) {
            var b = r(a, this),
              c = b.length;
            return this.filter(function () {
              for (var a = 0; a < c; a++) if (r.contains(this, b[a])) return !0;
            });
          },
          closest: function (a, b) {
            var c,
              d = 0,
              e = this.length,
              f = [],
              g = "string" != typeof a && r(a);
            if (!A.test(a))
              for (; d < e; d++)
                for (c = this[d]; c && c !== b; c = c.parentNode)
                  if (
                    c.nodeType < 11 &&
                    (g
                      ? g.index(c) > -1
                      : 1 === c.nodeType && r.find.matchesSelector(c, a))
                  ) {
                    f.push(c);
                    break;
                  }
            return this.pushStack(f.length > 1 ? r.uniqueSort(f) : f);
          },
          index: function (a) {
            return a
              ? "string" == typeof a
                ? i.call(r(a), this[0])
                : i.call(this, a.jquery ? a[0] : a)
              : this[0] && this[0].parentNode
              ? this.first().prevAll().length
              : -1;
          },
          add: function (a, b) {
            return this.pushStack(r.uniqueSort(r.merge(this.get(), r(a, b))));
          },
          addBack: function (a) {
            return this.add(
              null == a ? this.prevObject : this.prevObject.filter(a)
            );
          },
        });
        function K(a, b) {
          while ((a = a[b]) && 1 !== a.nodeType);
          return a;
        }
        r.each(
          {
            parent: function (a) {
              var b = a.parentNode;
              return b && 11 !== b.nodeType ? b : null;
            },
            parents: function (a) {
              return y(a, "parentNode");
            },
            parentsUntil: function (a, b, c) {
              return y(a, "parentNode", c);
            },
            next: function (a) {
              return K(a, "nextSibling");
            },
            prev: function (a) {
              return K(a, "previousSibling");
            },
            nextAll: function (a) {
              return y(a, "nextSibling");
            },
            prevAll: function (a) {
              return y(a, "previousSibling");
            },
            nextUntil: function (a, b, c) {
              return y(a, "nextSibling", c);
            },
            prevUntil: function (a, b, c) {
              return y(a, "previousSibling", c);
            },
            siblings: function (a) {
              return z((a.parentNode || {}).firstChild, a);
            },
            children: function (a) {
              return z(a.firstChild);
            },
            contents: function (a) {
              return B(a, "iframe")
                ? a.contentDocument
                : (B(a, "template") && (a = a.content || a),
                  r.merge([], a.childNodes));
            },
          },
          function (a, b) {
            r.fn[a] = function (c, d) {
              var e = r.map(this, b, c);
              return (
                "Until" !== a.slice(-5) && (d = c),
                d && "string" == typeof d && (e = r.filter(d, e)),
                this.length > 1 &&
                  (J[a] || r.uniqueSort(e), I.test(a) && e.reverse()),
                this.pushStack(e)
              );
            };
          }
        );
        var L = /[^\x20\t\r\n\f]+/g;
        function M(a) {
          var b = {};
          return (
            r.each(a.match(L) || [], function (a, c) {
              b[c] = !0;
            }),
            b
          );
        }
        r.Callbacks = function (a) {
          a = "string" == typeof a ? M(a) : r.extend({}, a);
          var b,
            c,
            d,
            e,
            f = [],
            g = [],
            h = -1,
            i = function () {
              for (e = e || a.once, d = b = !0; g.length; h = -1) {
                c = g.shift();
                while (++h < f.length)
                  f[h].apply(c[0], c[1]) === !1 &&
                    a.stopOnFalse &&
                    ((h = f.length), (c = !1));
              }
              a.memory || (c = !1), (b = !1), e && (f = c ? [] : "");
            },
            j = {
              add: function () {
                return (
                  f &&
                    (c && !b && ((h = f.length - 1), g.push(c)),
                    (function d(b) {
                      r.each(b, function (b, c) {
                        r.isFunction(c)
                          ? (a.unique && j.has(c)) || f.push(c)
                          : c && c.length && "string" !== r.type(c) && d(c);
                      });
                    })(arguments),
                    c && !b && i()),
                  this
                );
              },
              remove: function () {
                return (
                  r.each(arguments, function (a, b) {
                    var c;
                    while ((c = r.inArray(b, f, c)) > -1)
                      f.splice(c, 1), c <= h && h--;
                  }),
                  this
                );
              },
              has: function (a) {
                return a ? r.inArray(a, f) > -1 : f.length > 0;
              },
              empty: function () {
                return f && (f = []), this;
              },
              disable: function () {
                return (e = g = []), (f = c = ""), this;
              },
              disabled: function () {
                return !f;
              },
              lock: function () {
                return (e = g = []), c || b || (f = c = ""), this;
              },
              locked: function () {
                return !!e;
              },
              fireWith: function (a, c) {
                return (
                  e ||
                    ((c = c || []),
                    (c = [a, c.slice ? c.slice() : c]),
                    g.push(c),
                    b || i()),
                  this
                );
              },
              fire: function () {
                return j.fireWith(this, arguments), this;
              },
              fired: function () {
                return !!d;
              },
            };
          return j;
        };
        function N(a) {
          return a;
        }
        function O(a) {
          throw a;
        }
        function P(a, b, c, d) {
          var e;
          try {
            a && r.isFunction((e = a.promise))
              ? e.call(a).done(b).fail(c)
              : a && r.isFunction((e = a.then))
              ? e.call(a, b, c)
              : b.apply(void 0, [a].slice(d));
          } catch (a) {
            c.apply(void 0, [a]);
          }
        }
        r.extend({
          Deferred: function (b) {
            var c = [
                [
                  "notify",
                  "progress",
                  r.Callbacks("memory"),
                  r.Callbacks("memory"),
                  2,
                ],
                [
                  "resolve",
                  "done",
                  r.Callbacks("once memory"),
                  r.Callbacks("once memory"),
                  0,
                  "resolved",
                ],
                [
                  "reject",
                  "fail",
                  r.Callbacks("once memory"),
                  r.Callbacks("once memory"),
                  1,
                  "rejected",
                ],
              ],
              d = "pending",
              e = {
                state: function () {
                  return d;
                },
                always: function () {
                  return f.done(arguments).fail(arguments), this;
                },
                catch: function (a) {
                  return e.then(null, a);
                },
                pipe: function () {
                  var a = arguments;
                  return r
                    .Deferred(function (b) {
                      r.each(c, function (c, d) {
                        var e = r.isFunction(a[d[4]]) && a[d[4]];
                        f[d[1]](function () {
                          var a = e && e.apply(this, arguments);
                          a && r.isFunction(a.promise)
                            ? a
                                .promise()
                                .progress(b.notify)
                                .done(b.resolve)
                                .fail(b.reject)
                            : b[d[0] + "With"](this, e ? [a] : arguments);
                        });
                      }),
                        (a = null);
                    })
                    .promise();
                },
                then: function (b, d, e) {
                  var f = 0;
                  function g(b, c, d, e) {
                    return function () {
                      var h = this,
                        i = arguments,
                        j = function () {
                          var a, j;
                          if (!(b < f)) {
                            if (((a = d.apply(h, i)), a === c.promise()))
                              throw new TypeError("Thenable self-resolution");
                            (j =
                              a &&
                              ("object" == typeof a ||
                                "function" == typeof a) &&
                              a.then),
                              r.isFunction(j)
                                ? e
                                  ? j.call(a, g(f, c, N, e), g(f, c, O, e))
                                  : (f++,
                                    j.call(
                                      a,
                                      g(f, c, N, e),
                                      g(f, c, O, e),
                                      g(f, c, N, c.notifyWith)
                                    ))
                                : (d !== N && ((h = void 0), (i = [a])),
                                  (e || c.resolveWith)(h, i));
                          }
                        },
                        k = e
                          ? j
                          : function () {
                              try {
                                j();
                              } catch (a) {
                                r.Deferred.exceptionHook &&
                                  r.Deferred.exceptionHook(a, k.stackTrace),
                                  b + 1 >= f &&
                                    (d !== O && ((h = void 0), (i = [a])),
                                    c.rejectWith(h, i));
                              }
                            };
                      b
                        ? k()
                        : (r.Deferred.getStackHook &&
                            (k.stackTrace = r.Deferred.getStackHook()),
                          a.setTimeout(k));
                    };
                  }
                  return r
                    .Deferred(function (a) {
                      c[0][3].add(
                        g(0, a, r.isFunction(e) ? e : N, a.notifyWith)
                      ),
                        c[1][3].add(g(0, a, r.isFunction(b) ? b : N)),
                        c[2][3].add(g(0, a, r.isFunction(d) ? d : O));
                    })
                    .promise();
                },
                promise: function (a) {
                  return null != a ? r.extend(a, e) : e;
                },
              },
              f = {};
            return (
              r.each(c, function (a, b) {
                var g = b[2],
                  h = b[5];
                (e[b[1]] = g.add),
                  h &&
                    g.add(
                      function () {
                        d = h;
                      },
                      c[3 - a][2].disable,
                      c[0][2].lock
                    ),
                  g.add(b[3].fire),
                  (f[b[0]] = function () {
                    return (
                      f[b[0] + "With"](this === f ? void 0 : this, arguments),
                      this
                    );
                  }),
                  (f[b[0] + "With"] = g.fireWith);
              }),
              e.promise(f),
              b && b.call(f, f),
              f
            );
          },
          when: function (a) {
            var b = arguments.length,
              c = b,
              d = Array(c),
              e = f.call(arguments),
              g = r.Deferred(),
              h = function (a) {
                return function (c) {
                  (d[a] = this),
                    (e[a] = arguments.length > 1 ? f.call(arguments) : c),
                    --b || g.resolveWith(d, e);
                };
              };
            if (
              b <= 1 &&
              (P(a, g.done(h(c)).resolve, g.reject, !b),
              "pending" === g.state() || r.isFunction(e[c] && e[c].then))
            )
              return g.then();
            while (c--) P(e[c], h(c), g.reject);
            return g.promise();
          },
        });
        var Q = /^(Eval|Internal|Range|Reference|Syntax|Type|URI)Error$/;
        (r.Deferred.exceptionHook = function (b, c) {
          a.console &&
            a.console.warn &&
            b &&
            Q.test(b.name) &&
            a.console.warn(
              "jQuery.Deferred exception: " + b.message,
              b.stack,
              c
            );
        }),
          (r.readyException = function (b) {
            a.setTimeout(function () {
              throw b;
            });
          });
        var R = r.Deferred();
        (r.fn.ready = function (a) {
          return (
            R.then(a)["catch"](function (a) {
              r.readyException(a);
            }),
            this
          );
        }),
          r.extend({
            isReady: !1,
            readyWait: 1,
            ready: function (a) {
              (a === !0 ? --r.readyWait : r.isReady) ||
                ((r.isReady = !0),
                (a !== !0 && --r.readyWait > 0) || R.resolveWith(d, [r]));
            },
          }),
          (r.ready.then = R.then);
        function S() {
          d.removeEventListener("DOMContentLoaded", S),
            a.removeEventListener("load", S),
            r.ready();
        }
        "complete" === d.readyState ||
        ("loading" !== d.readyState && !d.documentElement.doScroll)
          ? a.setTimeout(r.ready)
          : (d.addEventListener("DOMContentLoaded", S),
            a.addEventListener("load", S));
        var T = function (a, b, c, d, e, f, g) {
            var h = 0,
              i = a.length,
              j = null == c;
            if ("object" === r.type(c)) {
              e = !0;
              for (h in c) T(a, b, h, c[h], !0, f, g);
            } else if (
              void 0 !== d &&
              ((e = !0),
              r.isFunction(d) || (g = !0),
              j &&
                (g
                  ? (b.call(a, d), (b = null))
                  : ((j = b),
                    (b = function (a, b, c) {
                      return j.call(r(a), c);
                    }))),
              b)
            )
              for (; h < i; h++)
                b(a[h], c, g ? d : d.call(a[h], h, b(a[h], c)));
            return e ? a : j ? b.call(a) : i ? b(a[0], c) : f;
          },
          U = function (a) {
            return 1 === a.nodeType || 9 === a.nodeType || !+a.nodeType;
          };
        function V() {
          this.expando = r.expando + V.uid++;
        }
        (V.uid = 1),
          (V.prototype = {
            cache: function (a) {
              var b = a[this.expando];
              return (
                b ||
                  ((b = {}),
                  U(a) &&
                    (a.nodeType
                      ? (a[this.expando] = b)
                      : Object.defineProperty(a, this.expando, {
                          value: b,
                          configurable: !0,
                        }))),
                b
              );
            },
            set: function (a, b, c) {
              var d,
                e = this.cache(a);
              if ("string" == typeof b) e[r.camelCase(b)] = c;
              else for (d in b) e[r.camelCase(d)] = b[d];
              return e;
            },
            get: function (a, b) {
              return void 0 === b
                ? this.cache(a)
                : a[this.expando] && a[this.expando][r.camelCase(b)];
            },
            access: function (a, b, c) {
              return void 0 === b || (b && "string" == typeof b && void 0 === c)
                ? this.get(a, b)
                : (this.set(a, b, c), void 0 !== c ? c : b);
            },
            remove: function (a, b) {
              var c,
                d = a[this.expando];
              if (void 0 !== d) {
                if (void 0 !== b) {
                  Array.isArray(b)
                    ? (b = b.map(r.camelCase))
                    : ((b = r.camelCase(b)),
                      (b = b in d ? [b] : b.match(L) || [])),
                    (c = b.length);
                  while (c--) delete d[b[c]];
                }
                (void 0 === b || r.isEmptyObject(d)) &&
                  (a.nodeType
                    ? (a[this.expando] = void 0)
                    : delete a[this.expando]);
              }
            },
            hasData: function (a) {
              var b = a[this.expando];
              return void 0 !== b && !r.isEmptyObject(b);
            },
          });
        var W = new V(),
          X = new V(),
          Y = /^(?:\{[\w\W]*\}|\[[\w\W]*\])$/,
          Z = /[A-Z]/g;
        function $(a) {
          return (
            "true" === a ||
            ("false" !== a &&
              ("null" === a
                ? null
                : a === +a + ""
                ? +a
                : Y.test(a)
                ? JSON.parse(a)
                : a))
          );
        }
        function _(a, b, c) {
          var d;
          if (void 0 === c && 1 === a.nodeType)
            if (
              ((d = "data-" + b.replace(Z, "-$&").toLowerCase()),
              (c = a.getAttribute(d)),
              "string" == typeof c)
            ) {
              try {
                c = $(c);
              } catch (e) {}
              X.set(a, b, c);
            } else c = void 0;
          return c;
        }
        r.extend({
          hasData: function (a) {
            return X.hasData(a) || W.hasData(a);
          },
          data: function (a, b, c) {
            return X.access(a, b, c);
          },
          removeData: function (a, b) {
            X.remove(a, b);
          },
          _data: function (a, b, c) {
            return W.access(a, b, c);
          },
          _removeData: function (a, b) {
            W.remove(a, b);
          },
        }),
          r.fn.extend({
            data: function (a, b) {
              var c,
                d,
                e,
                f = this[0],
                g = f && f.attributes;
              if (void 0 === a) {
                if (
                  this.length &&
                  ((e = X.get(f)),
                  1 === f.nodeType && !W.get(f, "hasDataAttrs"))
                ) {
                  c = g.length;
                  while (c--)
                    g[c] &&
                      ((d = g[c].name),
                      0 === d.indexOf("data-") &&
                        ((d = r.camelCase(d.slice(5))), _(f, d, e[d])));
                  W.set(f, "hasDataAttrs", !0);
                }
                return e;
              }
              return "object" == typeof a
                ? this.each(function () {
                    X.set(this, a);
                  })
                : T(
                    this,
                    function (b) {
                      var c;
                      if (f && void 0 === b) {
                        if (((c = X.get(f, a)), void 0 !== c)) return c;
                        if (((c = _(f, a)), void 0 !== c)) return c;
                      } else
                        this.each(function () {
                          X.set(this, a, b);
                        });
                    },
                    null,
                    b,
                    arguments.length > 1,
                    null,
                    !0
                  );
            },
            removeData: function (a) {
              return this.each(function () {
                X.remove(this, a);
              });
            },
          }),
          r.extend({
            queue: function (a, b, c) {
              var d;
              if (a)
                return (
                  (b = (b || "fx") + "queue"),
                  (d = W.get(a, b)),
                  c &&
                    (!d || Array.isArray(c)
                      ? (d = W.access(a, b, r.makeArray(c)))
                      : d.push(c)),
                  d || []
                );
            },
            dequeue: function (a, b) {
              b = b || "fx";
              var c = r.queue(a, b),
                d = c.length,
                e = c.shift(),
                f = r._queueHooks(a, b),
                g = function () {
                  r.dequeue(a, b);
                };
              "inprogress" === e && ((e = c.shift()), d--),
                e &&
                  ("fx" === b && c.unshift("inprogress"),
                  delete f.stop,
                  e.call(a, g, f)),
                !d && f && f.empty.fire();
            },
            _queueHooks: function (a, b) {
              var c = b + "queueHooks";
              return (
                W.get(a, c) ||
                W.access(a, c, {
                  empty: r.Callbacks("once memory").add(function () {
                    W.remove(a, [b + "queue", c]);
                  }),
                })
              );
            },
          }),
          r.fn.extend({
            queue: function (a, b) {
              var c = 2;
              return (
                "string" != typeof a && ((b = a), (a = "fx"), c--),
                arguments.length < c
                  ? r.queue(this[0], a)
                  : void 0 === b
                  ? this
                  : this.each(function () {
                      var c = r.queue(this, a, b);
                      r._queueHooks(this, a),
                        "fx" === a &&
                          "inprogress" !== c[0] &&
                          r.dequeue(this, a);
                    })
              );
            },
            dequeue: function (a) {
              return this.each(function () {
                r.dequeue(this, a);
              });
            },
            clearQueue: function (a) {
              return this.queue(a || "fx", []);
            },
            promise: function (a, b) {
              var c,
                d = 1,
                e = r.Deferred(),
                f = this,
                g = this.length,
                h = function () {
                  --d || e.resolveWith(f, [f]);
                };
              "string" != typeof a && ((b = a), (a = void 0)), (a = a || "fx");
              while (g--)
                (c = W.get(f[g], a + "queueHooks")),
                  c && c.empty && (d++, c.empty.add(h));
              return h(), e.promise(b);
            },
          });
        var aa = /[+-]?(?:\d*\.|)\d+(?:[eE][+-]?\d+|)/.source,
          ba = new RegExp("^(?:([+-])=|)(" + aa + ")([a-z%]*)$", "i"),
          ca = ["Top", "Right", "Bottom", "Left"],
          da = function (a, b) {
            return (
              (a = b || a),
              "none" === a.style.display ||
                ("" === a.style.display &&
                  r.contains(a.ownerDocument, a) &&
                  "none" === r.css(a, "display"))
            );
          },
          ea = function (a, b, c, d) {
            var e,
              f,
              g = {};
            for (f in b) (g[f] = a.style[f]), (a.style[f] = b[f]);
            e = c.apply(a, d || []);
            for (f in b) a.style[f] = g[f];
            return e;
          };
        function fa(a, b, c, d) {
          var e,
            f = 1,
            g = 20,
            h = d
              ? function () {
                  return d.cur();
                }
              : function () {
                  return r.css(a, b, "");
                },
            i = h(),
            j = (c && c[3]) || (r.cssNumber[b] ? "" : "px"),
            k = (r.cssNumber[b] || ("px" !== j && +i)) && ba.exec(r.css(a, b));
          if (k && k[3] !== j) {
            (j = j || k[3]), (c = c || []), (k = +i || 1);
            do (f = f || ".5"), (k /= f), r.style(a, b, k + j);
            while (f !== (f = h() / i) && 1 !== f && --g);
          }
          return (
            c &&
              ((k = +k || +i || 0),
              (e = c[1] ? k + (c[1] + 1) * c[2] : +c[2]),
              d && ((d.unit = j), (d.start = k), (d.end = e))),
            e
          );
        }
        var ga = {};
        function ha(a) {
          var b,
            c = a.ownerDocument,
            d = a.nodeName,
            e = ga[d];
          return e
            ? e
            : ((b = c.body.appendChild(c.createElement(d))),
              (e = r.css(b, "display")),
              b.parentNode.removeChild(b),
              "none" === e && (e = "block"),
              (ga[d] = e),
              e);
        }
        function ia(a, b) {
          for (var c, d, e = [], f = 0, g = a.length; f < g; f++)
            (d = a[f]),
              d.style &&
                ((c = d.style.display),
                b
                  ? ("none" === c &&
                      ((e[f] = W.get(d, "display") || null),
                      e[f] || (d.style.display = "")),
                    "" === d.style.display && da(d) && (e[f] = ha(d)))
                  : "none" !== c && ((e[f] = "none"), W.set(d, "display", c)));
          for (f = 0; f < g; f++) null != e[f] && (a[f].style.display = e[f]);
          return a;
        }
        r.fn.extend({
          show: function () {
            return ia(this, !0);
          },
          hide: function () {
            return ia(this);
          },
          toggle: function (a) {
            return "boolean" == typeof a
              ? a
                ? this.show()
                : this.hide()
              : this.each(function () {
                  da(this) ? r(this).show() : r(this).hide();
                });
          },
        });
        var ja = /^(?:checkbox|radio)$/i,
          ka = /<([a-z][^\/\0>\x20\t\r\n\f]+)/i,
          la = /^$|\/(?:java|ecma)script/i,
          ma = {
            option: [1, "<select multiple=''multiple''>", "</select>"],
            thead: [1, "<table>", "</table>"],
            col: [2, "<table><colgroup>", "</colgroup></table>"],
            tr: [2, "<table><tbody>", "</tbody></table>"],
            td: [3, "<table><tbody><tr>", "</tr></tbody></table>"],
            _default: [0, "", ""],
          };
        (ma.optgroup = ma.option),
          (ma.tbody = ma.tfoot = ma.colgroup = ma.caption = ma.thead),
          (ma.th = ma.td);
        function na(a, b) {
          var c;
          return (
            (c =
              "undefined" != typeof a.getElementsByTagName
                ? a.getElementsByTagName(b || "*")
                : "undefined" != typeof a.querySelectorAll
                ? a.querySelectorAll(b || "*")
                : []),
            void 0 === b || (b && B(a, b)) ? r.merge([a], c) : c
          );
        }
        function oa(a, b) {
          for (var c = 0, d = a.length; c < d; c++)
            W.set(a[c], "globalEval", !b || W.get(b[c], "globalEval"));
        }
        var pa = /<|&#?\w+;/;
        function qa(a, b, c, d, e) {
          for (
            var f,
              g,
              h,
              i,
              j,
              k,
              l = b.createDocumentFragment(),
              m = [],
              n = 0,
              o = a.length;
            n < o;
            n++
          )
            if (((f = a[n]), f || 0 === f))
              if ("object" === r.type(f)) r.merge(m, f.nodeType ? [f] : f);
              else if (pa.test(f)) {
                (g = g || l.appendChild(b.createElement("div"))),
                  (h = (ka.exec(f) || ["", ""])[1].toLowerCase()),
                  (i = ma[h] || ma._default),
                  (g.innerHTML = i[1] + r.htmlPrefilter(f) + i[2]),
                  (k = i[0]);
                while (k--) g = g.lastChild;
                r.merge(m, g.childNodes),
                  (g = l.firstChild),
                  (g.textContent = "");
              } else m.push(b.createTextNode(f));
          (l.textContent = ""), (n = 0);
          while ((f = m[n++]))
            if (d && r.inArray(f, d) > -1) e && e.push(f);
            else if (
              ((j = r.contains(f.ownerDocument, f)),
              (g = na(l.appendChild(f), "script")),
              j && oa(g),
              c)
            ) {
              k = 0;
              while ((f = g[k++])) la.test(f.type || "") && c.push(f);
            }
          return l;
        }
        !(function () {
          var a = d.createDocumentFragment(),
            b = a.appendChild(d.createElement("div")),
            c = d.createElement("input");
          c.setAttribute("type", "radio"),
            c.setAttribute("checked", "checked"),
            c.setAttribute("name", "t"),
            b.appendChild(c),
            (o.checkClone = b.cloneNode(!0).cloneNode(!0).lastChild.checked),
            (b.innerHTML = "<textarea>x</textarea>"),
            (o.noCloneChecked = !!b.cloneNode(!0).lastChild.defaultValue);
        })();
        var ra = d.documentElement,
          sa = /^key/,
          ta = /^(?:mouse|pointer|contextmenu|drag|drop)|click/,
          ua = /^([^.]*)(?:\.(.+)|)/;
        function va() {
          return !0;
        }
        function wa() {
          return !1;
        }
        function xa() {
          try {
            return d.activeElement;
          } catch (a) {}
        }
        function ya(a, b, c, d, e, f) {
          var g, h;
          if ("object" == typeof b) {
            "string" != typeof c && ((d = d || c), (c = void 0));
            for (h in b) ya(a, h, c, d, b[h], f);
            return a;
          }
          if (
            (null == d && null == e
              ? ((e = c), (d = c = void 0))
              : null == e &&
                ("string" == typeof c
                  ? ((e = d), (d = void 0))
                  : ((e = d), (d = c), (c = void 0))),
            e === !1)
          )
            e = wa;
          else if (!e) return a;
          return (
            1 === f &&
              ((g = e),
              (e = function (a) {
                return r().off(a), g.apply(this, arguments);
              }),
              (e.guid = g.guid || (g.guid = r.guid++))),
            a.each(function () {
              r.event.add(this, b, e, d, c);
            })
          );
        }
        (r.event = {
          global: {},
          add: function (a, b, c, d, e) {
            var f,
              g,
              h,
              i,
              j,
              k,
              l,
              m,
              n,
              o,
              p,
              q = W.get(a);
            if (q) {
              c.handler && ((f = c), (c = f.handler), (e = f.selector)),
                e && r.find.matchesSelector(ra, e),
                c.guid || (c.guid = r.guid++),
                (i = q.events) || (i = q.events = {}),
                (g = q.handle) ||
                  (g = q.handle =
                    function (b) {
                      return "undefined" != typeof r &&
                        r.event.triggered !== b.type
                        ? r.event.dispatch.apply(a, arguments)
                        : void 0;
                    }),
                (b = (b || "").match(L) || [""]),
                (j = b.length);
              while (j--)
                (h = ua.exec(b[j]) || []),
                  (n = p = h[1]),
                  (o = (h[2] || "").split(".").sort()),
                  n &&
                    ((l = r.event.special[n] || {}),
                    (n = (e ? l.delegateType : l.bindType) || n),
                    (l = r.event.special[n] || {}),
                    (k = r.extend(
                      {
                        type: n,
                        origType: p,
                        data: d,
                        handler: c,
                        guid: c.guid,
                        selector: e,
                        needsContext: e && r.expr.match.needsContext.test(e),
                        namespace: o.join("."),
                      },
                      f
                    )),
                    (m = i[n]) ||
                      ((m = i[n] = []),
                      (m.delegateCount = 0),
                      (l.setup && l.setup.call(a, d, o, g) !== !1) ||
                        (a.addEventListener && a.addEventListener(n, g))),
                    l.add &&
                      (l.add.call(a, k),
                      k.handler.guid || (k.handler.guid = c.guid)),
                    e ? m.splice(m.delegateCount++, 0, k) : m.push(k),
                    (r.event.global[n] = !0));
            }
          },
          remove: function (a, b, c, d, e) {
            var f,
              g,
              h,
              i,
              j,
              k,
              l,
              m,
              n,
              o,
              p,
              q = W.hasData(a) && W.get(a);
            if (q && (i = q.events)) {
              (b = (b || "").match(L) || [""]), (j = b.length);
              while (j--)
                if (
                  ((h = ua.exec(b[j]) || []),
                  (n = p = h[1]),
                  (o = (h[2] || "").split(".").sort()),
                  n)
                ) {
                  (l = r.event.special[n] || {}),
                    (n = (d ? l.delegateType : l.bindType) || n),
                    (m = i[n] || []),
                    (h =
                      h[2] &&
                      new RegExp(
                        "(^|\\.)" + o.join("\\.(?:.*\\.|)") + "(\\.|$)"
                      )),
                    (g = f = m.length);
                  while (f--)
                    (k = m[f]),
                      (!e && p !== k.origType) ||
                        (c && c.guid !== k.guid) ||
                        (h && !h.test(k.namespace)) ||
                        (d &&
                          d !== k.selector &&
                          ("**" !== d || !k.selector)) ||
                        (m.splice(f, 1),
                        k.selector && m.delegateCount--,
                        l.remove && l.remove.call(a, k));
                  g &&
                    !m.length &&
                    ((l.teardown && l.teardown.call(a, o, q.handle) !== !1) ||
                      r.removeEvent(a, n, q.handle),
                    delete i[n]);
                } else for (n in i) r.event.remove(a, n + b[j], c, d, !0);
              r.isEmptyObject(i) && W.remove(a, "handle events");
            }
          },
          dispatch: function (a) {
            var b = r.event.fix(a),
              c,
              d,
              e,
              f,
              g,
              h,
              i = new Array(arguments.length),
              j = (W.get(this, "events") || {})[b.type] || [],
              k = r.event.special[b.type] || {};
            for (i[0] = b, c = 1; c < arguments.length; c++)
              i[c] = arguments[c];
            if (
              ((b.delegateTarget = this),
              !k.preDispatch || k.preDispatch.call(this, b) !== !1)
            ) {
              (h = r.event.handlers.call(this, b, j)), (c = 0);
              while ((f = h[c++]) && !b.isPropagationStopped()) {
                (b.currentTarget = f.elem), (d = 0);
                while (
                  (g = f.handlers[d++]) &&
                  !b.isImmediatePropagationStopped()
                )
                  (b.rnamespace && !b.rnamespace.test(g.namespace)) ||
                    ((b.handleObj = g),
                    (b.data = g.data),
                    (e = (
                      (r.event.special[g.origType] || {}).handle || g.handler
                    ).apply(f.elem, i)),
                    void 0 !== e &&
                      (b.result = e) === !1 &&
                      (b.preventDefault(), b.stopPropagation()));
              }
              return k.postDispatch && k.postDispatch.call(this, b), b.result;
            }
          },
          handlers: function (a, b) {
            var c,
              d,
              e,
              f,
              g,
              h = [],
              i = b.delegateCount,
              j = a.target;
            if (i && j.nodeType && !("click" === a.type && a.button >= 1))
              for (; j !== this; j = j.parentNode || this)
                if (
                  1 === j.nodeType &&
                  ("click" !== a.type || j.disabled !== !0)
                ) {
                  for (f = [], g = {}, c = 0; c < i; c++)
                    (d = b[c]),
                      (e = d.selector + " "),
                      void 0 === g[e] &&
                        (g[e] = d.needsContext
                          ? r(e, this).index(j) > -1
                          : r.find(e, this, null, [j]).length),
                      g[e] && f.push(d);
                  f.length && h.push({ elem: j, handlers: f });
                }
            return (
              (j = this),
              i < b.length && h.push({ elem: j, handlers: b.slice(i) }),
              h
            );
          },
          addProp: function (a, b) {
            Object.defineProperty(r.Event.prototype, a, {
              enumerable: !0,
              configurable: !0,
              get: r.isFunction(b)
                ? function () {
                    if (this.originalEvent) return b(this.originalEvent);
                  }
                : function () {
                    if (this.originalEvent) return this.originalEvent[a];
                  },
              set: function (b) {
                Object.defineProperty(this, a, {
                  enumerable: !0,
                  configurable: !0,
                  writable: !0,
                  value: b,
                });
              },
            });
          },
          fix: function (a) {
            return a[r.expando] ? a : new r.Event(a);
          },
          special: {
            load: { noBubble: !0 },
            focus: {
              trigger: function () {
                if (this !== xa() && this.focus) return this.focus(), !1;
              },
              delegateType: "focusin",
            },
            blur: {
              trigger: function () {
                if (this === xa() && this.blur) return this.blur(), !1;
              },
              delegateType: "focusout",
            },
            click: {
              trigger: function () {
                if ("checkbox" === this.type && this.click && B(this, "input"))
                  return this.click(), !1;
              },
              _default: function (a) {
                return B(a.target, "a");
              },
            },
            beforeunload: {
              postDispatch: function (a) {
                void 0 !== a.result &&
                  a.originalEvent &&
                  (a.originalEvent.returnValue = a.result);
              },
            },
          },
        }),
          (r.removeEvent = function (a, b, c) {
            a.removeEventListener && a.removeEventListener(b, c);
          }),
          (r.Event = function (a, b) {
            return this instanceof r.Event
              ? (a && a.type
                  ? ((this.originalEvent = a),
                    (this.type = a.type),
                    (this.isDefaultPrevented =
                      a.defaultPrevented ||
                      (void 0 === a.defaultPrevented && a.returnValue === !1)
                        ? va
                        : wa),
                    (this.target =
                      a.target && 3 === a.target.nodeType
                        ? a.target.parentNode
                        : a.target),
                    (this.currentTarget = a.currentTarget),
                    (this.relatedTarget = a.relatedTarget))
                  : (this.type = a),
                b && r.extend(this, b),
                (this.timeStamp = (a && a.timeStamp) || r.now()),
                void (this[r.expando] = !0))
              : new r.Event(a, b);
          }),
          (r.Event.prototype = {
            constructor: r.Event,
            isDefaultPrevented: wa,
            isPropagationStopped: wa,
            isImmediatePropagationStopped: wa,
            isSimulated: !1,
            preventDefault: function () {
              var a = this.originalEvent;
              (this.isDefaultPrevented = va),
                a && !this.isSimulated && a.preventDefault();
            },
            stopPropagation: function () {
              var a = this.originalEvent;
              (this.isPropagationStopped = va),
                a && !this.isSimulated && a.stopPropagation();
            },
            stopImmediatePropagation: function () {
              var a = this.originalEvent;
              (this.isImmediatePropagationStopped = va),
                a && !this.isSimulated && a.stopImmediatePropagation(),
                this.stopPropagation();
            },
          }),
          r.each(
            {
              altKey: !0,
              bubbles: !0,
              cancelable: !0,
              changedTouches: !0,
              ctrlKey: !0,
              detail: !0,
              eventPhase: !0,
              metaKey: !0,
              pageX: !0,
              pageY: !0,
              shiftKey: !0,
              view: !0,
              char: !0,
              charCode: !0,
              key: !0,
              keyCode: !0,
              button: !0,
              buttons: !0,
              clientX: !0,
              clientY: !0,
              offsetX: !0,
              offsetY: !0,
              pointerId: !0,
              pointerType: !0,
              screenX: !0,
              screenY: !0,
              targetTouches: !0,
              toElement: !0,
              touches: !0,
              which: function (a) {
                var b = a.button;
                return null == a.which && sa.test(a.type)
                  ? null != a.charCode
                    ? a.charCode
                    : a.keyCode
                  : !a.which && void 0 !== b && ta.test(a.type)
                  ? 1 & b
                    ? 1
                    : 2 & b
                    ? 3
                    : 4 & b
                    ? 2
                    : 0
                  : a.which;
              },
            },
            r.event.addProp
          ),
          r.each(
            {
              mouseenter: "mouseover",
              mouseleave: "mouseout",
              pointerenter: "pointerover",
              pointerleave: "pointerout",
            },
            function (a, b) {
              r.event.special[a] = {
                delegateType: b,
                bindType: b,
                handle: function (a) {
                  var c,
                    d = this,
                    e = a.relatedTarget,
                    f = a.handleObj;
                  return (
                    (e && (e === d || r.contains(d, e))) ||
                      ((a.type = f.origType),
                      (c = f.handler.apply(this, arguments)),
                      (a.type = b)),
                    c
                  );
                },
              };
            }
          ),
          r.fn.extend({
            on: function (a, b, c, d) {
              return ya(this, a, b, c, d);
            },
            one: function (a, b, c, d) {
              return ya(this, a, b, c, d, 1);
            },
            off: function (a, b, c) {
              var d, e;
              if (a && a.preventDefault && a.handleObj)
                return (
                  (d = a.handleObj),
                  r(a.delegateTarget).off(
                    d.namespace ? d.origType + "." + d.namespace : d.origType,
                    d.selector,
                    d.handler
                  ),
                  this
                );
              if ("object" == typeof a) {
                for (e in a) this.off(e, b, a[e]);
                return this;
              }
              return (
                (b !== !1 && "function" != typeof b) || ((c = b), (b = void 0)),
                c === !1 && (c = wa),
                this.each(function () {
                  r.event.remove(this, a, c, b);
                })
              );
            },
          });
        var za =
            /<(?!area|br|col|embed|hr|img|input|link|meta|param)(([a-z][^\/\0>\x20\t\r\n\f]*)[^>]*)\/>/gi,
          Aa = /<script|<style|<link/i,
          Ba = /checked\s*(?:[^=]|=\s*.checked.)/i,
          Ca = /^true\/(.*)/,
          Da = /^\s*<!(?:\[CDATA\[|--)|(?:\]\]|--)>\s*$/g;
        function Ea(a, b) {
          return B(a, "table") && B(11 !== b.nodeType ? b : b.firstChild, "tr")
            ? r(">tbody", a)[0] || a
            : a;
        }
        function Fa(a) {
          return (a.type = (null !== a.getAttribute("type")) + "/" + a.type), a;
        }
        function Ga(a) {
          var b = Ca.exec(a.type);
          return b ? (a.type = b[1]) : a.removeAttribute("type"), a;
        }
        function Ha(a, b) {
          var c, d, e, f, g, h, i, j;
          if (1 === b.nodeType) {
            if (
              W.hasData(a) &&
              ((f = W.access(a)), (g = W.set(b, f)), (j = f.events))
            ) {
              delete g.handle, (g.events = {});
              for (e in j)
                for (c = 0, d = j[e].length; c < d; c++)
                  r.event.add(b, e, j[e][c]);
            }
            X.hasData(a) &&
              ((h = X.access(a)), (i = r.extend({}, h)), X.set(b, i));
          }
        }
        function Ia(a, b) {
          var c = b.nodeName.toLowerCase();
          "input" === c && ja.test(a.type)
            ? (b.checked = a.checked)
            : ("input" !== c && "textarea" !== c) ||
              (b.defaultValue = a.defaultValue);
        }
        function Ja(a, b, c, d) {
          b = g.apply([], b);
          var e,
            f,
            h,
            i,
            j,
            k,
            l = 0,
            m = a.length,
            n = m - 1,
            q = b[0],
            s = r.isFunction(q);
          if (
            s ||
            (m > 1 && "string" == typeof q && !o.checkClone && Ba.test(q))
          )
            return a.each(function (e) {
              var f = a.eq(e);
              s && (b[0] = q.call(this, e, f.html())), Ja(f, b, c, d);
            });
          if (
            m &&
            ((e = qa(b, a[0].ownerDocument, !1, a, d)),
            (f = e.firstChild),
            1 === e.childNodes.length && (e = f),
            f || d)
          ) {
            for (h = r.map(na(e, "script"), Fa), i = h.length; l < m; l++)
              (j = e),
                l !== n &&
                  ((j = r.clone(j, !0, !0)), i && r.merge(h, na(j, "script"))),
                c.call(a[l], j, l);
            if (i)
              for (
                k = h[h.length - 1].ownerDocument, r.map(h, Ga), l = 0;
                l < i;
                l++
              )
                (j = h[l]),
                  la.test(j.type || "") &&
                    !W.access(j, "globalEval") &&
                    r.contains(k, j) &&
                    (j.src
                      ? r._evalUrl && r._evalUrl(j.src)
                      : p(j.textContent.replace(Da, ""), k));
          }
          return a;
        }
        function Ka(a, b, c) {
          for (
            var d, e = b ? r.filter(b, a) : a, f = 0;
            null != (d = e[f]);
            f++
          )
            c || 1 !== d.nodeType || r.cleanData(na(d)),
              d.parentNode &&
                (c && r.contains(d.ownerDocument, d) && oa(na(d, "script")),
                d.parentNode.removeChild(d));
          return a;
        }
        r.extend({
          htmlPrefilter: function (a) {
            return a.replace(za, "<$1></$2>");
          },
          clone: function (a, b, c) {
            var d,
              e,
              f,
              g,
              h = a.cloneNode(!0),
              i = r.contains(a.ownerDocument, a);
            if (
              !(
                o.noCloneChecked ||
                (1 !== a.nodeType && 11 !== a.nodeType) ||
                r.isXMLDoc(a)
              )
            )
              for (g = na(h), f = na(a), d = 0, e = f.length; d < e; d++)
                Ia(f[d], g[d]);
            if (b)
              if (c)
                for (
                  f = f || na(a), g = g || na(h), d = 0, e = f.length;
                  d < e;
                  d++
                )
                  Ha(f[d], g[d]);
              else Ha(a, h);
            return (
              (g = na(h, "script")),
              g.length > 0 && oa(g, !i && na(a, "script")),
              h
            );
          },
          cleanData: function (a) {
            for (
              var b, c, d, e = r.event.special, f = 0;
              void 0 !== (c = a[f]);
              f++
            )
              if (U(c)) {
                if ((b = c[W.expando])) {
                  if (b.events)
                    for (d in b.events)
                      e[d]
                        ? r.event.remove(c, d)
                        : r.removeEvent(c, d, b.handle);
                  c[W.expando] = void 0;
                }
                c[X.expando] && (c[X.expando] = void 0);
              }
          },
        }),
          r.fn.extend({
            detach: function (a) {
              return Ka(this, a, !0);
            },
            remove: function (a) {
              return Ka(this, a);
            },
            text: function (a) {
              return T(
                this,
                function (a) {
                  return void 0 === a
                    ? r.text(this)
                    : this.empty().each(function () {
                        (1 !== this.nodeType &&
                          11 !== this.nodeType &&
                          9 !== this.nodeType) ||
                          (this.textContent = a);
                      });
                },
                null,
                a,
                arguments.length
              );
            },
            append: function () {
              return Ja(this, arguments, function (a) {
                if (
                  1 === this.nodeType ||
                  11 === this.nodeType ||
                  9 === this.nodeType
                ) {
                  var b = Ea(this, a);
                  b.appendChild(a);
                }
              });
            },
            prepend: function () {
              return Ja(this, arguments, function (a) {
                if (
                  1 === this.nodeType ||
                  11 === this.nodeType ||
                  9 === this.nodeType
                ) {
                  var b = Ea(this, a);
                  b.insertBefore(a, b.firstChild);
                }
              });
            },
            before: function () {
              return Ja(this, arguments, function (a) {
                this.parentNode && this.parentNode.insertBefore(a, this);
              });
            },
            after: function () {
              return Ja(this, arguments, function (a) {
                this.parentNode &&
                  this.parentNode.insertBefore(a, this.nextSibling);
              });
            },
            empty: function () {
              for (var a, b = 0; null != (a = this[b]); b++)
                1 === a.nodeType &&
                  (r.cleanData(na(a, !1)), (a.textContent = ""));
              return this;
            },
            clone: function (a, b) {
              return (
                (a = null != a && a),
                (b = null == b ? a : b),
                this.map(function () {
                  return r.clone(this, a, b);
                })
              );
            },
            html: function (a) {
              return T(
                this,
                function (a) {
                  var b = this[0] || {},
                    c = 0,
                    d = this.length;
                  if (void 0 === a && 1 === b.nodeType) return b.innerHTML;
                  if (
                    "string" == typeof a &&
                    !Aa.test(a) &&
                    !ma[(ka.exec(a) || ["", ""])[1].toLowerCase()]
                  ) {
                    a = r.htmlPrefilter(a);
                    try {
                      for (; c < d; c++)
                        (b = this[c] || {}),
                          1 === b.nodeType &&
                            (r.cleanData(na(b, !1)), (b.innerHTML = a));
                      b = 0;
                    } catch (e) {}
                  }
                  b && this.empty().append(a);
                },
                null,
                a,
                arguments.length
              );
            },
            replaceWith: function () {
              var a = [];
              return Ja(
                this,
                arguments,
                function (b) {
                  var c = this.parentNode;
                  r.inArray(this, a) < 0 &&
                    (r.cleanData(na(this)), c && c.replaceChild(b, this));
                },
                a
              );
            },
          }),
          r.each(
            {
              appendTo: "append",
              prependTo: "prepend",
              insertBefore: "before",
              insertAfter: "after",
              replaceAll: "replaceWith",
            },
            function (a, b) {
              r.fn[a] = function (a) {
                for (
                  var c, d = [], e = r(a), f = e.length - 1, g = 0;
                  g <= f;
                  g++
                )
                  (c = g === f ? this : this.clone(!0)),
                    r(e[g])[b](c),
                    h.apply(d, c.get());
                return this.pushStack(d);
              };
            }
          );
        var La = /^margin/,
          Ma = new RegExp("^(" + aa + ")(?!px)[a-z%]+$", "i"),
          Na = function (b) {
            var c = b.ownerDocument.defaultView;
            return (c && c.opener) || (c = a), c.getComputedStyle(b);
          };
        !(function () {
          function b() {
            if (i) {
              (i.style.cssText =
                "box-sizing:border-box;position:relative;display:block;margin:auto;border:1px;padding:1px;top:1%;width:50%"),
                (i.innerHTML = ""),
                ra.appendChild(h);
              var b = a.getComputedStyle(i);
              (c = "1%" !== b.top),
                (g = "2px" === b.marginLeft),
                (e = "4px" === b.width),
                (i.style.marginRight = "50%"),
                (f = "4px" === b.marginRight),
                ra.removeChild(h),
                (i = null);
            }
          }
          var c,
            e,
            f,
            g,
            h = d.createElement("div"),
            i = d.createElement("div");
          i.style &&
            ((i.style.backgroundClip = "content-box"),
            (i.cloneNode(!0).style.backgroundClip = ""),
            (o.clearCloneStyle = "content-box" === i.style.backgroundClip),
            (h.style.cssText =
              "border:0;width:8px;height:0;top:0;left:-9999px;padding:0;margin-top:1px;position:absolute"),
            h.appendChild(i),
            r.extend(o, {
              pixelPosition: function () {
                return b(), c;
              },
              boxSizingReliable: function () {
                return b(), e;
              },
              pixelMarginRight: function () {
                return b(), f;
              },
              reliableMarginLeft: function () {
                return b(), g;
              },
            }));
        })();
        function Oa(a, b, c) {
          var d,
            e,
            f,
            g,
            h = a.style;
          return (
            (c = c || Na(a)),
            c &&
              ((g = c.getPropertyValue(b) || c[b]),
              "" !== g || r.contains(a.ownerDocument, a) || (g = r.style(a, b)),
              !o.pixelMarginRight() &&
                Ma.test(g) &&
                La.test(b) &&
                ((d = h.width),
                (e = h.minWidth),
                (f = h.maxWidth),
                (h.minWidth = h.maxWidth = h.width = g),
                (g = c.width),
                (h.width = d),
                (h.minWidth = e),
                (h.maxWidth = f))),
            void 0 !== g ? g + "" : g
          );
        }
        function Pa(a, b) {
          return {
            get: function () {
              return a()
                ? void delete this.get
                : (this.get = b).apply(this, arguments);
            },
          };
        }
        var Qa = /^(none|table(?!-c[ea]).+)/,
          Ra = /^--/,
          Sa = { position: "absolute", visibility: "hidden", display: "block" },
          Ta = { letterSpacing: "0", fontWeight: "400" },
          Ua = ["Webkit", "Moz", "ms"],
          Va = d.createElement("div").style;
        function Wa(a) {
          if (a in Va) return a;
          var b = a[0].toUpperCase() + a.slice(1),
            c = Ua.length;
          while (c--) if (((a = Ua[c] + b), a in Va)) return a;
        }
        function Xa(a) {
          var b = r.cssProps[a];
          return b || (b = r.cssProps[a] = Wa(a) || a), b;
        }
        function Ya(a, b, c) {
          var d = ba.exec(b);
          return d ? Math.max(0, d[2] - (c || 0)) + (d[3] || "px") : b;
        }
        function Za(a, b, c, d, e) {
          var f,
            g = 0;
          for (
            f = c === (d ? "border" : "content") ? 4 : "width" === b ? 1 : 0;
            f < 4;
            f += 2
          )
            "margin" === c && (g += r.css(a, c + ca[f], !0, e)),
              d
                ? ("content" === c && (g -= r.css(a, "padding" + ca[f], !0, e)),
                  "margin" !== c &&
                    (g -= r.css(a, "border" + ca[f] + "Width", !0, e)))
                : ((g += r.css(a, "padding" + ca[f], !0, e)),
                  "padding" !== c &&
                    (g += r.css(a, "border" + ca[f] + "Width", !0, e)));
          return g;
        }
        function $a(a, b, c) {
          var d,
            e = Na(a),
            f = Oa(a, b, e),
            g = "border-box" === r.css(a, "boxSizing", !1, e);
          return Ma.test(f)
            ? f
            : ((d = g && (o.boxSizingReliable() || f === a.style[b])),
              "auto" === f &&
                (f = a["offset" + b[0].toUpperCase() + b.slice(1)]),
              (f = parseFloat(f) || 0),
              f + Za(a, b, c || (g ? "border" : "content"), d, e) + "px");
        }
        r.extend({
          cssHooks: {
            opacity: {
              get: function (a, b) {
                if (b) {
                  var c = Oa(a, "opacity");
                  return "" === c ? "1" : c;
                }
              },
            },
          },
          cssNumber: {
            animationIterationCount: !0,
            columnCount: !0,
            fillOpacity: !0,
            flexGrow: !0,
            flexShrink: !0,
            fontWeight: !0,
            lineHeight: !0,
            opacity: !0,
            order: !0,
            orphans: !0,
            widows: !0,
            zIndex: !0,
            zoom: !0,
          },
          cssProps: { float: "cssFloat" },
          style: function (a, b, c, d) {
            if (a && 3 !== a.nodeType && 8 !== a.nodeType && a.style) {
              var e,
                f,
                g,
                h = r.camelCase(b),
                i = Ra.test(b),
                j = a.style;
              return (
                i || (b = Xa(h)),
                (g = r.cssHooks[b] || r.cssHooks[h]),
                void 0 === c
                  ? g && "get" in g && void 0 !== (e = g.get(a, !1, d))
                    ? e
                    : j[b]
                  : ((f = typeof c),
                    "string" === f &&
                      (e = ba.exec(c)) &&
                      e[1] &&
                      ((c = fa(a, b, e)), (f = "number")),
                    null != c &&
                      c === c &&
                      ("number" === f &&
                        (c += (e && e[3]) || (r.cssNumber[h] ? "" : "px")),
                      o.clearCloneStyle ||
                        "" !== c ||
                        0 !== b.indexOf("background") ||
                        (j[b] = "inherit"),
                      (g && "set" in g && void 0 === (c = g.set(a, c, d))) ||
                        (i ? j.setProperty(b, c) : (j[b] = c))),
                    void 0)
              );
            }
          },
          css: function (a, b, c, d) {
            var e,
              f,
              g,
              h = r.camelCase(b),
              i = Ra.test(b);
            return (
              i || (b = Xa(h)),
              (g = r.cssHooks[b] || r.cssHooks[h]),
              g && "get" in g && (e = g.get(a, !0, c)),
              void 0 === e && (e = Oa(a, b, d)),
              "normal" === e && b in Ta && (e = Ta[b]),
              "" === c || c
                ? ((f = parseFloat(e)), c === !0 || isFinite(f) ? f || 0 : e)
                : e
            );
          },
        }),
          r.each(["height", "width"], function (a, b) {
            r.cssHooks[b] = {
              get: function (a, c, d) {
                if (c)
                  return !Qa.test(r.css(a, "display")) ||
                    (a.getClientRects().length &&
                      a.getBoundingClientRect().width)
                    ? $a(a, b, d)
                    : ea(a, Sa, function () {
                        return $a(a, b, d);
                      });
              },
              set: function (a, c, d) {
                var e,
                  f = d && Na(a),
                  g =
                    d &&
                    Za(
                      a,
                      b,
                      d,
                      "border-box" === r.css(a, "boxSizing", !1, f),
                      f
                    );
                return (
                  g &&
                    (e = ba.exec(c)) &&
                    "px" !== (e[3] || "px") &&
                    ((a.style[b] = c), (c = r.css(a, b))),
                  Ya(a, c, g)
                );
              },
            };
          }),
          (r.cssHooks.marginLeft = Pa(o.reliableMarginLeft, function (a, b) {
            if (b)
              return (
                (parseFloat(Oa(a, "marginLeft")) ||
                  a.getBoundingClientRect().left -
                    ea(a, { marginLeft: 0 }, function () {
                      return a.getBoundingClientRect().left;
                    })) + "px"
              );
          })),
          r.each({ margin: "", padding: "", border: "Width" }, function (a, b) {
            (r.cssHooks[a + b] = {
              expand: function (c) {
                for (
                  var d = 0,
                    e = {},
                    f = "string" == typeof c ? c.split(" ") : [c];
                  d < 4;
                  d++
                )
                  e[a + ca[d] + b] = f[d] || f[d - 2] || f[0];
                return e;
              },
            }),
              La.test(a) || (r.cssHooks[a + b].set = Ya);
          }),
          r.fn.extend({
            css: function (a, b) {
              return T(
                this,
                function (a, b, c) {
                  var d,
                    e,
                    f = {},
                    g = 0;
                  if (Array.isArray(b)) {
                    for (d = Na(a), e = b.length; g < e; g++)
                      f[b[g]] = r.css(a, b[g], !1, d);
                    return f;
                  }
                  return void 0 !== c ? r.style(a, b, c) : r.css(a, b);
                },
                a,
                b,
                arguments.length > 1
              );
            },
          });
        function _a(a, b, c, d, e) {
          return new _a.prototype.init(a, b, c, d, e);
        }
        (r.Tween = _a),
          (_a.prototype = {
            constructor: _a,
            init: function (a, b, c, d, e, f) {
              (this.elem = a),
                (this.prop = c),
                (this.easing = e || r.easing._default),
                (this.options = b),
                (this.start = this.now = this.cur()),
                (this.end = d),
                (this.unit = f || (r.cssNumber[c] ? "" : "px"));
            },
            cur: function () {
              var a = _a.propHooks[this.prop];
              return a && a.get ? a.get(this) : _a.propHooks._default.get(this);
            },
            run: function (a) {
              var b,
                c = _a.propHooks[this.prop];
              return (
                this.options.duration
                  ? (this.pos = b =
                      r.easing[this.easing](
                        a,
                        this.options.duration * a,
                        0,
                        1,
                        this.options.duration
                      ))
                  : (this.pos = b = a),
                (this.now = (this.end - this.start) * b + this.start),
                this.options.step &&
                  this.options.step.call(this.elem, this.now, this),
                c && c.set ? c.set(this) : _a.propHooks._default.set(this),
                this
              );
            },
          }),
          (_a.prototype.init.prototype = _a.prototype),
          (_a.propHooks = {
            _default: {
              get: function (a) {
                var b;
                return 1 !== a.elem.nodeType ||
                  (null != a.elem[a.prop] && null == a.elem.style[a.prop])
                  ? a.elem[a.prop]
                  : ((b = r.css(a.elem, a.prop, "")),
                    b && "auto" !== b ? b : 0);
              },
              set: function (a) {
                r.fx.step[a.prop]
                  ? r.fx.step[a.prop](a)
                  : 1 !== a.elem.nodeType ||
                    (null == a.elem.style[r.cssProps[a.prop]] &&
                      !r.cssHooks[a.prop])
                  ? (a.elem[a.prop] = a.now)
                  : r.style(a.elem, a.prop, a.now + a.unit);
              },
            },
          }),
          (_a.propHooks.scrollTop = _a.propHooks.scrollLeft =
            {
              set: function (a) {
                a.elem.nodeType &&
                  a.elem.parentNode &&
                  (a.elem[a.prop] = a.now);
              },
            }),
          (r.easing = {
            linear: function (a) {
              return a;
            },
            swing: function (a) {
              return 0.5 - Math.cos(a * Math.PI) / 2;
            },
            _default: "swing",
          }),
          (r.fx = _a.prototype.init),
          (r.fx.step = {});
        var ab,
          bb,
          cb = /^(?:toggle|show|hide)$/,
          db = /queueHooks$/;
        function eb() {
          bb &&
            (d.hidden === !1 && a.requestAnimationFrame
              ? a.requestAnimationFrame(eb)
              : a.setTimeout(eb, r.fx.interval),
            r.fx.tick());
        }
        function fb() {
          return (
            a.setTimeout(function () {
              ab = void 0;
            }),
            (ab = r.now())
          );
        }
        function gb(a, b) {
          var c,
            d = 0,
            e = { height: a };
          for (b = b ? 1 : 0; d < 4; d += 2 - b)
            (c = ca[d]), (e["margin" + c] = e["padding" + c] = a);
          return b && (e.opacity = e.width = a), e;
        }
        function hb(a, b, c) {
          for (
            var d,
              e = (kb.tweeners[b] || []).concat(kb.tweeners["*"]),
              f = 0,
              g = e.length;
            f < g;
            f++
          )
            if ((d = e[f].call(c, b, a))) return d;
        }
        function ib(a, b, c) {
          var d,
            e,
            f,
            g,
            h,
            i,
            j,
            k,
            l = "width" in b || "height" in b,
            m = this,
            n = {},
            o = a.style,
            p = a.nodeType && da(a),
            q = W.get(a, "fxshow");
          c.queue ||
            ((g = r._queueHooks(a, "fx")),
            null == g.unqueued &&
              ((g.unqueued = 0),
              (h = g.empty.fire),
              (g.empty.fire = function () {
                g.unqueued || h();
              })),
            g.unqueued++,
            m.always(function () {
              m.always(function () {
                g.unqueued--, r.queue(a, "fx").length || g.empty.fire();
              });
            }));
          for (d in b)
            if (((e = b[d]), cb.test(e))) {
              if (
                (delete b[d],
                (f = f || "toggle" === e),
                e === (p ? "hide" : "show"))
              ) {
                if ("show" !== e || !q || void 0 === q[d]) continue;
                p = !0;
              }
              n[d] = (q && q[d]) || r.style(a, d);
            }
          if (((i = !r.isEmptyObject(b)), i || !r.isEmptyObject(n))) {
            l &&
              1 === a.nodeType &&
              ((c.overflow = [o.overflow, o.overflowX, o.overflowY]),
              (j = q && q.display),
              null == j && (j = W.get(a, "display")),
              (k = r.css(a, "display")),
              "none" === k &&
                (j
                  ? (k = j)
                  : (ia([a], !0),
                    (j = a.style.display || j),
                    (k = r.css(a, "display")),
                    ia([a]))),
              ("inline" === k || ("inline-block" === k && null != j)) &&
                "none" === r.css(a, "float") &&
                (i ||
                  (m.done(function () {
                    o.display = j;
                  }),
                  null == j && ((k = o.display), (j = "none" === k ? "" : k))),
                (o.display = "inline-block"))),
              c.overflow &&
                ((o.overflow = "hidden"),
                m.always(function () {
                  (o.overflow = c.overflow[0]),
                    (o.overflowX = c.overflow[1]),
                    (o.overflowY = c.overflow[2]);
                })),
              (i = !1);
            for (d in n)
              i ||
                (q
                  ? "hidden" in q && (p = q.hidden)
                  : (q = W.access(a, "fxshow", { display: j })),
                f && (q.hidden = !p),
                p && ia([a], !0),
                m.done(function () {
                  p || ia([a]), W.remove(a, "fxshow");
                  for (d in n) r.style(a, d, n[d]);
                })),
                (i = hb(p ? q[d] : 0, d, m)),
                d in q ||
                  ((q[d] = i.start), p && ((i.end = i.start), (i.start = 0)));
          }
        }
        function jb(a, b) {
          var c, d, e, f, g;
          for (c in a)
            if (
              ((d = r.camelCase(c)),
              (e = b[d]),
              (f = a[c]),
              Array.isArray(f) && ((e = f[1]), (f = a[c] = f[0])),
              c !== d && ((a[d] = f), delete a[c]),
              (g = r.cssHooks[d]),
              g && "expand" in g)
            ) {
              (f = g.expand(f)), delete a[d];
              for (c in f) c in a || ((a[c] = f[c]), (b[c] = e));
            } else b[d] = e;
        }
        function kb(a, b, c) {
          var d,
            e,
            f = 0,
            g = kb.prefilters.length,
            h = r.Deferred().always(function () {
              delete i.elem;
            }),
            i = function () {
              if (e) return !1;
              for (
                var b = ab || fb(),
                  c = Math.max(0, j.startTime + j.duration - b),
                  d = c / j.duration || 0,
                  f = 1 - d,
                  g = 0,
                  i = j.tweens.length;
                g < i;
                g++
              )
                j.tweens[g].run(f);
              return (
                h.notifyWith(a, [j, f, c]),
                f < 1 && i
                  ? c
                  : (i || h.notifyWith(a, [j, 1, 0]), h.resolveWith(a, [j]), !1)
              );
            },
            j = h.promise({
              elem: a,
              props: r.extend({}, b),
              opts: r.extend(
                !0,
                { specialEasing: {}, easing: r.easing._default },
                c
              ),
              originalProperties: b,
              originalOptions: c,
              startTime: ab || fb(),
              duration: c.duration,
              tweens: [],
              createTween: function (b, c) {
                var d = r.Tween(
                  a,
                  j.opts,
                  b,
                  c,
                  j.opts.specialEasing[b] || j.opts.easing
                );
                return j.tweens.push(d), d;
              },
              stop: function (b) {
                var c = 0,
                  d = b ? j.tweens.length : 0;
                if (e) return this;
                for (e = !0; c < d; c++) j.tweens[c].run(1);
                return (
                  b
                    ? (h.notifyWith(a, [j, 1, 0]), h.resolveWith(a, [j, b]))
                    : h.rejectWith(a, [j, b]),
                  this
                );
              },
            }),
            k = j.props;
          for (jb(k, j.opts.specialEasing); f < g; f++)
            if ((d = kb.prefilters[f].call(j, a, k, j.opts)))
              return (
                r.isFunction(d.stop) &&
                  (r._queueHooks(j.elem, j.opts.queue).stop = r.proxy(
                    d.stop,
                    d
                  )),
                d
              );
          return (
            r.map(k, hb, j),
            r.isFunction(j.opts.start) && j.opts.start.call(a, j),
            j
              .progress(j.opts.progress)
              .done(j.opts.done, j.opts.complete)
              .fail(j.opts.fail)
              .always(j.opts.always),
            r.fx.timer(r.extend(i, { elem: a, anim: j, queue: j.opts.queue })),
            j
          );
        }
        (r.Animation = r.extend(kb, {
          tweeners: {
            "*": [
              function (a, b) {
                var c = this.createTween(a, b);
                return fa(c.elem, a, ba.exec(b), c), c;
              },
            ],
          },
          tweener: function (a, b) {
            r.isFunction(a) ? ((b = a), (a = ["*"])) : (a = a.match(L));
            for (var c, d = 0, e = a.length; d < e; d++)
              (c = a[d]),
                (kb.tweeners[c] = kb.tweeners[c] || []),
                kb.tweeners[c].unshift(b);
          },
          prefilters: [ib],
          prefilter: function (a, b) {
            b ? kb.prefilters.unshift(a) : kb.prefilters.push(a);
          },
        })),
          (r.speed = function (a, b, c) {
            var d =
              a && "object" == typeof a
                ? r.extend({}, a)
                : {
                    complete: c || (!c && b) || (r.isFunction(a) && a),
                    duration: a,
                    easing: (c && b) || (b && !r.isFunction(b) && b),
                  };
            return (
              r.fx.off
                ? (d.duration = 0)
                : "number" != typeof d.duration &&
                  (d.duration in r.fx.speeds
                    ? (d.duration = r.fx.speeds[d.duration])
                    : (d.duration = r.fx.speeds._default)),
              (null != d.queue && d.queue !== !0) || (d.queue = "fx"),
              (d.old = d.complete),
              (d.complete = function () {
                r.isFunction(d.old) && d.old.call(this),
                  d.queue && r.dequeue(this, d.queue);
              }),
              d
            );
          }),
          r.fn.extend({
            fadeTo: function (a, b, c, d) {
              return this.filter(da)
                .css("opacity", 0)
                .show()
                .end()
                .animate({ opacity: b }, a, c, d);
            },
            animate: function (a, b, c, d) {
              var e = r.isEmptyObject(a),
                f = r.speed(b, c, d),
                g = function () {
                  var b = kb(this, r.extend({}, a), f);
                  (e || W.get(this, "finish")) && b.stop(!0);
                };
              return (
                (g.finish = g),
                e || f.queue === !1 ? this.each(g) : this.queue(f.queue, g)
              );
            },
            stop: function (a, b, c) {
              var d = function (a) {
                var b = a.stop;
                delete a.stop, b(c);
              };
              return (
                "string" != typeof a && ((c = b), (b = a), (a = void 0)),
                b && a !== !1 && this.queue(a || "fx", []),
                this.each(function () {
                  var b = !0,
                    e = null != a && a + "queueHooks",
                    f = r.timers,
                    g = W.get(this);
                  if (e) g[e] && g[e].stop && d(g[e]);
                  else for (e in g) g[e] && g[e].stop && db.test(e) && d(g[e]);
                  for (e = f.length; e--; )
                    f[e].elem !== this ||
                      (null != a && f[e].queue !== a) ||
                      (f[e].anim.stop(c), (b = !1), f.splice(e, 1));
                  (!b && c) || r.dequeue(this, a);
                })
              );
            },
            finish: function (a) {
              return (
                a !== !1 && (a = a || "fx"),
                this.each(function () {
                  var b,
                    c = W.get(this),
                    d = c[a + "queue"],
                    e = c[a + "queueHooks"],
                    f = r.timers,
                    g = d ? d.length : 0;
                  for (
                    c.finish = !0,
                      r.queue(this, a, []),
                      e && e.stop && e.stop.call(this, !0),
                      b = f.length;
                    b--;

                  )
                    f[b].elem === this &&
                      f[b].queue === a &&
                      (f[b].anim.stop(!0), f.splice(b, 1));
                  for (b = 0; b < g; b++)
                    d[b] && d[b].finish && d[b].finish.call(this);
                  delete c.finish;
                })
              );
            },
          }),
          r.each(["toggle", "show", "hide"], function (a, b) {
            var c = r.fn[b];
            r.fn[b] = function (a, d, e) {
              return null == a || "boolean" == typeof a
                ? c.apply(this, arguments)
                : this.animate(gb(b, !0), a, d, e);
            };
          }),
          r.each(
            {
              slideDown: gb("show"),
              slideUp: gb("hide"),
              slideToggle: gb("toggle"),
              fadeIn: { opacity: "show" },
              fadeOut: { opacity: "hide" },
              fadeToggle: { opacity: "toggle" },
            },
            function (a, b) {
              r.fn[a] = function (a, c, d) {
                return this.animate(b, a, c, d);
              };
            }
          ),
          (r.timers = []),
          (r.fx.tick = function () {
            var a,
              b = 0,
              c = r.timers;
            for (ab = r.now(); b < c.length; b++)
              (a = c[b]), a() || c[b] !== a || c.splice(b--, 1);
            c.length || r.fx.stop(), (ab = void 0);
          }),
          (r.fx.timer = function (a) {
            r.timers.push(a), r.fx.start();
          }),
          (r.fx.interval = 13),
          (r.fx.start = function () {
            bb || ((bb = !0), eb());
          }),
          (r.fx.stop = function () {
            bb = null;
          }),
          (r.fx.speeds = { slow: 600, fast: 200, _default: 400 }),
          (r.fn.delay = function (b, c) {
            return (
              (b = r.fx ? r.fx.speeds[b] || b : b),
              (c = c || "fx"),
              this.queue(c, function (c, d) {
                var e = a.setTimeout(c, b);
                d.stop = function () {
                  a.clearTimeout(e);
                };
              })
            );
          }),
          (function () {
            var a = d.createElement("input"),
              b = d.createElement("select"),
              c = b.appendChild(d.createElement("option"));
            (a.type = "checkbox"),
              (o.checkOn = "" !== a.value),
              (o.optSelected = c.selected),
              (a = d.createElement("input")),
              (a.value = "t"),
              (a.type = "radio"),
              (o.radioValue = "t" === a.value);
          })();
        var lb,
          mb = r.expr.attrHandle;
        r.fn.extend({
          attr: function (a, b) {
            return T(this, r.attr, a, b, arguments.length > 1);
          },
          removeAttr: function (a) {
            return this.each(function () {
              r.removeAttr(this, a);
            });
          },
        }),
          r.extend({
            attr: function (a, b, c) {
              var d,
                e,
                f = a.nodeType;
              if (3 !== f && 8 !== f && 2 !== f)
                return "undefined" == typeof a.getAttribute
                  ? r.prop(a, b, c)
                  : ((1 === f && r.isXMLDoc(a)) ||
                      (e =
                        r.attrHooks[b.toLowerCase()] ||
                        (r.expr.match.bool.test(b) ? lb : void 0)),
                    void 0 !== c
                      ? null === c
                        ? void r.removeAttr(a, b)
                        : e && "set" in e && void 0 !== (d = e.set(a, c, b))
                        ? d
                        : (a.setAttribute(b, c + ""), c)
                      : e && "get" in e && null !== (d = e.get(a, b))
                      ? d
                      : ((d = r.find.attr(a, b)), null == d ? void 0 : d));
            },
            attrHooks: {
              type: {
                set: function (a, b) {
                  if (!o.radioValue && "radio" === b && B(a, "input")) {
                    var c = a.value;
                    return a.setAttribute("type", b), c && (a.value = c), b;
                  }
                },
              },
            },
            removeAttr: function (a, b) {
              var c,
                d = 0,
                e = b && b.match(L);
              if (e && 1 === a.nodeType)
                while ((c = e[d++])) a.removeAttribute(c);
            },
          }),
          (lb = {
            set: function (a, b, c) {
              return b === !1 ? r.removeAttr(a, c) : a.setAttribute(c, c), c;
            },
          }),
          r.each(r.expr.match.bool.source.match(/\w+/g), function (a, b) {
            var c = mb[b] || r.find.attr;
            mb[b] = function (a, b, d) {
              var e,
                f,
                g = b.toLowerCase();
              return (
                d ||
                  ((f = mb[g]),
                  (mb[g] = e),
                  (e = null != c(a, b, d) ? g : null),
                  (mb[g] = f)),
                e
              );
            };
          });
        var nb = /^(?:input|select|textarea|button)$/i,
          ob = /^(?:a|area)$/i;
        r.fn.extend({
          prop: function (a, b) {
            return T(this, r.prop, a, b, arguments.length > 1);
          },
          removeProp: function (a) {
            return this.each(function () {
              delete this[r.propFix[a] || a];
            });
          },
        }),
          r.extend({
            prop: function (a, b, c) {
              var d,
                e,
                f = a.nodeType;
              if (3 !== f && 8 !== f && 2 !== f)
                return (
                  (1 === f && r.isXMLDoc(a)) ||
                    ((b = r.propFix[b] || b), (e = r.propHooks[b])),
                  void 0 !== c
                    ? e && "set" in e && void 0 !== (d = e.set(a, c, b))
                      ? d
                      : (a[b] = c)
                    : e && "get" in e && null !== (d = e.get(a, b))
                    ? d
                    : a[b]
                );
            },
            propHooks: {
              tabIndex: {
                get: function (a) {
                  var b = r.find.attr(a, "tabindex");
                  return b
                    ? parseInt(b, 10)
                    : nb.test(a.nodeName) || (ob.test(a.nodeName) && a.href)
                    ? 0
                    : -1;
                },
              },
            },
            propFix: { for: "htmlFor", class: "className" },
          }),
          o.optSelected ||
            (r.propHooks.selected = {
              get: function (a) {
                var b = a.parentNode;
                return b && b.parentNode && b.parentNode.selectedIndex, null;
              },
              set: function (a) {
                var b = a.parentNode;
                b &&
                  (b.selectedIndex, b.parentNode && b.parentNode.selectedIndex);
              },
            }),
          r.each(
            [
              "tabIndex",
              "readOnly",
              "maxLength",
              "cellSpacing",
              "cellPadding",
              "rowSpan",
              "colSpan",
              "useMap",
              "frameBorder",
              "contentEditable",
            ],
            function () {
              r.propFix[this.toLowerCase()] = this;
            }
          );
        function pb(a) {
          var b = a.match(L) || [];
          return b.join(" ");
        }
        function qb(a) {
          return (a.getAttribute && a.getAttribute("class")) || "";
        }
        r.fn.extend({
          addClass: function (a) {
            var b,
              c,
              d,
              e,
              f,
              g,
              h,
              i = 0;
            if (r.isFunction(a))
              return this.each(function (b) {
                r(this).addClass(a.call(this, b, qb(this)));
              });
            if ("string" == typeof a && a) {
              b = a.match(L) || [];
              while ((c = this[i++]))
                if (
                  ((e = qb(c)), (d = 1 === c.nodeType && " " + pb(e) + " "))
                ) {
                  g = 0;
                  while ((f = b[g++]))
                    d.indexOf(" " + f + " ") < 0 && (d += f + " ");
                  (h = pb(d)), e !== h && c.setAttribute("class", h);
                }
            }
            return this;
          },
          removeClass: function (a) {
            var b,
              c,
              d,
              e,
              f,
              g,
              h,
              i = 0;
            if (r.isFunction(a))
              return this.each(function (b) {
                r(this).removeClass(a.call(this, b, qb(this)));
              });
            if (!arguments.length) return this.attr("class", "");
            if ("string" == typeof a && a) {
              b = a.match(L) || [];
              while ((c = this[i++]))
                if (
                  ((e = qb(c)), (d = 1 === c.nodeType && " " + pb(e) + " "))
                ) {
                  g = 0;
                  while ((f = b[g++]))
                    while (d.indexOf(" " + f + " ") > -1)
                      d = d.replace(" " + f + " ", " ");
                  (h = pb(d)), e !== h && c.setAttribute("class", h);
                }
            }
            return this;
          },
          toggleClass: function (a, b) {
            var c = typeof a;
            return "boolean" == typeof b && "string" === c
              ? b
                ? this.addClass(a)
                : this.removeClass(a)
              : r.isFunction(a)
              ? this.each(function (c) {
                  r(this).toggleClass(a.call(this, c, qb(this), b), b);
                })
              : this.each(function () {
                  var b, d, e, f;
                  if ("string" === c) {
                    (d = 0), (e = r(this)), (f = a.match(L) || []);
                    while ((b = f[d++]))
                      e.hasClass(b) ? e.removeClass(b) : e.addClass(b);
                  } else (void 0 !== a && "boolean" !== c) || ((b = qb(this)), b && W.set(this, "__className__", b), this.setAttribute && this.setAttribute("class", b || a === !1 ? "" : W.get(this, "__className__") || ""));
                });
          },
          hasClass: function (a) {
            var b,
              c,
              d = 0;
            b = " " + a + " ";
            while ((c = this[d++]))
              if (1 === c.nodeType && (" " + pb(qb(c)) + " ").indexOf(b) > -1)
                return !0;
            return !1;
          },
        });
        var rb = /\r/g;
        r.fn.extend({
          val: function (a) {
            var b,
              c,
              d,
              e = this[0];
            {
              if (arguments.length)
                return (
                  (d = r.isFunction(a)),
                  this.each(function (c) {
                    var e;
                    1 === this.nodeType &&
                      ((e = d ? a.call(this, c, r(this).val()) : a),
                      null == e
                        ? (e = "")
                        : "number" == typeof e
                        ? (e += "")
                        : Array.isArray(e) &&
                          (e = r.map(e, function (a) {
                            return null == a ? "" : a + "";
                          })),
                      (b =
                        r.valHooks[this.type] ||
                        r.valHooks[this.nodeName.toLowerCase()]),
                      (b && "set" in b && void 0 !== b.set(this, e, "value")) ||
                        (this.value = e));
                  })
                );
              if (e)
                return (
                  (b =
                    r.valHooks[e.type] || r.valHooks[e.nodeName.toLowerCase()]),
                  b && "get" in b && void 0 !== (c = b.get(e, "value"))
                    ? c
                    : ((c = e.value),
                      "string" == typeof c
                        ? c.replace(rb, "")
                        : null == c
                        ? ""
                        : c)
                );
            }
          },
        }),
          r.extend({
            valHooks: {
              option: {
                get: function (a) {
                  var b = r.find.attr(a, "value");
                  return null != b ? b : pb(r.text(a));
                },
              },
              select: {
                get: function (a) {
                  var b,
                    c,
                    d,
                    e = a.options,
                    f = a.selectedIndex,
                    g = "select-one" === a.type,
                    h = g ? null : [],
                    i = g ? f + 1 : e.length;
                  for (d = f < 0 ? i : g ? f : 0; d < i; d++)
                    if (
                      ((c = e[d]),
                      (c.selected || d === f) &&
                        !c.disabled &&
                        (!c.parentNode.disabled ||
                          !B(c.parentNode, "optgroup")))
                    ) {
                      if (((b = r(c).val()), g)) return b;
                      h.push(b);
                    }
                  return h;
                },
                set: function (a, b) {
                  var c,
                    d,
                    e = a.options,
                    f = r.makeArray(b),
                    g = e.length;
                  while (g--)
                    (d = e[g]),
                      (d.selected =
                        r.inArray(r.valHooks.option.get(d), f) > -1) &&
                        (c = !0);
                  return c || (a.selectedIndex = -1), f;
                },
              },
            },
          }),
          r.each(["radio", "checkbox"], function () {
            (r.valHooks[this] = {
              set: function (a, b) {
                if (Array.isArray(b))
                  return (a.checked = r.inArray(r(a).val(), b) > -1);
              },
            }),
              o.checkOn ||
                (r.valHooks[this].get = function (a) {
                  return null === a.getAttribute("value") ? "on" : a.value;
                });
          });
        var sb = /^(?:focusinfocus|focusoutblur)$/;
        r.extend(r.event, {
          trigger: function (b, c, e, f) {
            var g,
              h,
              i,
              j,
              k,
              m,
              n,
              o = [e || d],
              p = l.call(b, "type") ? b.type : b,
              q = l.call(b, "namespace") ? b.namespace.split(".") : [];
            if (
              ((h = i = e = e || d),
              3 !== e.nodeType &&
                8 !== e.nodeType &&
                !sb.test(p + r.event.triggered) &&
                (p.indexOf(".") > -1 &&
                  ((q = p.split(".")), (p = q.shift()), q.sort()),
                (k = p.indexOf(":") < 0 && "on" + p),
                (b = b[r.expando]
                  ? b
                  : new r.Event(p, "object" == typeof b && b)),
                (b.isTrigger = f ? 2 : 3),
                (b.namespace = q.join(".")),
                (b.rnamespace = b.namespace
                  ? new RegExp("(^|\\.)" + q.join("\\.(?:.*\\.|)") + "(\\.|$)")
                  : null),
                (b.result = void 0),
                b.target || (b.target = e),
                (c = null == c ? [b] : r.makeArray(c, [b])),
                (n = r.event.special[p] || {}),
                f || !n.trigger || n.trigger.apply(e, c) !== !1))
            ) {
              if (!f && !n.noBubble && !r.isWindow(e)) {
                for (
                  j = n.delegateType || p, sb.test(j + p) || (h = h.parentNode);
                  h;
                  h = h.parentNode
                )
                  o.push(h), (i = h);
                i === (e.ownerDocument || d) &&
                  o.push(i.defaultView || i.parentWindow || a);
              }
              g = 0;
              while ((h = o[g++]) && !b.isPropagationStopped())
                (b.type = g > 1 ? j : n.bindType || p),
                  (m =
                    (W.get(h, "events") || {})[b.type] && W.get(h, "handle")),
                  m && m.apply(h, c),
                  (m = k && h[k]),
                  m &&
                    m.apply &&
                    U(h) &&
                    ((b.result = m.apply(h, c)),
                    b.result === !1 && b.preventDefault());
              return (
                (b.type = p),
                f ||
                  b.isDefaultPrevented() ||
                  (n._default && n._default.apply(o.pop(), c) !== !1) ||
                  !U(e) ||
                  (k &&
                    r.isFunction(e[p]) &&
                    !r.isWindow(e) &&
                    ((i = e[k]),
                    i && (e[k] = null),
                    (r.event.triggered = p),
                    e[p](),
                    (r.event.triggered = void 0),
                    i && (e[k] = i))),
                b.result
              );
            }
          },
          simulate: function (a, b, c) {
            var d = r.extend(new r.Event(), c, { type: a, isSimulated: !0 });
            r.event.trigger(d, null, b);
          },
        }),
          r.fn.extend({
            trigger: function (a, b) {
              return this.each(function () {
                r.event.trigger(a, b, this);
              });
            },
            triggerHandler: function (a, b) {
              var c = this[0];
              if (c) return r.event.trigger(a, b, c, !0);
            },
          }),
          r.each(
            "blur focus focusin focusout resize scroll click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup contextmenu".split(
              " "
            ),
            function (a, b) {
              r.fn[b] = function (a, c) {
                return arguments.length > 0
                  ? this.on(b, null, a, c)
                  : this.trigger(b);
              };
            }
          ),
          r.fn.extend({
            hover: function (a, b) {
              return this.mouseenter(a).mouseleave(b || a);
            },
          }),
          (o.focusin = "onfocusin" in a),
          o.focusin ||
            r.each({ focus: "focusin", blur: "focusout" }, function (a, b) {
              var c = function (a) {
                r.event.simulate(b, a.target, r.event.fix(a));
              };
              r.event.special[b] = {
                setup: function () {
                  var d = this.ownerDocument || this,
                    e = W.access(d, b);
                  e || d.addEventListener(a, c, !0),
                    W.access(d, b, (e || 0) + 1);
                },
                teardown: function () {
                  var d = this.ownerDocument || this,
                    e = W.access(d, b) - 1;
                  e
                    ? W.access(d, b, e)
                    : (d.removeEventListener(a, c, !0), W.remove(d, b));
                },
              };
            });
        var tb = a.location,
          ub = r.now(),
          vb = /\?/;
        r.parseXML = function (b) {
          var c;
          if (!b || "string" != typeof b) return null;
          try {
            c = new a.DOMParser().parseFromString(b, "text/xml");
          } catch (d) {
            c = void 0;
          }
          return (
            (c && !c.getElementsByTagName("parsererror").length) ||
              r.error("Invalid XML: " + b),
            c
          );
        };
        var wb = /\[\]$/,
          xb = /\r?\n/g,
          yb = /^(?:submit|button|image|reset|file)$/i,
          zb = /^(?:input|select|textarea|keygen)/i;
        function Ab(a, b, c, d) {
          var e;
          if (Array.isArray(b))
            r.each(b, function (b, e) {
              c || wb.test(a)
                ? d(a, e)
                : Ab(
                    a +
                      "[" +
                      ("object" == typeof e && null != e ? b : "") +
                      "]",
                    e,
                    c,
                    d
                  );
            });
          else if (c || "object" !== r.type(b)) d(a, b);
          else for (e in b) Ab(a + "[" + e + "]", b[e], c, d);
        }
        (r.param = function (a, b) {
          var c,
            d = [],
            e = function (a, b) {
              var c = r.isFunction(b) ? b() : b;
              d[d.length] =
                encodeURIComponent(a) +
                "=" +
                encodeURIComponent(null == c ? "" : c);
            };
          if (Array.isArray(a) || (a.jquery && !r.isPlainObject(a)))
            r.each(a, function () {
              e(this.name, this.value);
            });
          else for (c in a) Ab(c, a[c], b, e);
          return d.join("&");
        }),
          r.fn.extend({
            serialize: function () {
              return r.param(this.serializeArray());
            },
            serializeArray: function () {
              return this.map(function () {
                var a = r.prop(this, "elements");
                return a ? r.makeArray(a) : this;
              })
                .filter(function () {
                  var a = this.type;
                  return (
                    this.name &&
                    !r(this).is(":disabled") &&
                    zb.test(this.nodeName) &&
                    !yb.test(a) &&
                    (this.checked || !ja.test(a))
                  );
                })
                .map(function (a, b) {
                  var c = r(this).val();
                  return null == c
                    ? null
                    : Array.isArray(c)
                    ? r.map(c, function (a) {
                        return { name: b.name, value: a.replace(xb, "\r\n") };
                      })
                    : { name: b.name, value: c.replace(xb, "\r\n") };
                })
                .get();
            },
          });
        var Bb = /%20/g,
          Cb = /#.*$/,
          Db = /([?&])_=[^&]*/,
          Eb = /^(.*?):[ \t]*([^\r\n]*)$/gm,
          Fb = /^(?:about|app|app-storage|.+-extension|file|res|widget):$/,
          Gb = /^(?:GET|HEAD)$/,
          Hb = /^\/\//,
          Ib = {},
          Jb = {},
          Kb = "*/".concat("*"),
          Lb = d.createElement("a");
        Lb.href = tb.href;
        function Mb(a) {
          return function (b, c) {
            "string" != typeof b && ((c = b), (b = "*"));
            var d,
              e = 0,
              f = b.toLowerCase().match(L) || [];
            if (r.isFunction(c))
              while ((d = f[e++]))
                "+" === d[0]
                  ? ((d = d.slice(1) || "*"), (a[d] = a[d] || []).unshift(c))
                  : (a[d] = a[d] || []).push(c);
          };
        }
        function Nb(a, b, c, d) {
          var e = {},
            f = a === Jb;
          function g(h) {
            var i;
            return (
              (e[h] = !0),
              r.each(a[h] || [], function (a, h) {
                var j = h(b, c, d);
                return "string" != typeof j || f || e[j]
                  ? f
                    ? !(i = j)
                    : void 0
                  : (b.dataTypes.unshift(j), g(j), !1);
              }),
              i
            );
          }
          return g(b.dataTypes[0]) || (!e["*"] && g("*"));
        }
        function Ob(a, b) {
          var c,
            d,
            e = r.ajaxSettings.flatOptions || {};
          for (c in b)
            void 0 !== b[c] && ((e[c] ? a : d || (d = {}))[c] = b[c]);
          return d && r.extend(!0, a, d), a;
        }
        function Pb(a, b, c) {
          var d,
            e,
            f,
            g,
            h = a.contents,
            i = a.dataTypes;
          while ("*" === i[0])
            i.shift(),
              void 0 === d &&
                (d = a.mimeType || b.getResponseHeader("Content-Type"));
          if (d)
            for (e in h)
              if (h[e] && h[e].test(d)) {
                i.unshift(e);
                break;
              }
          if (i[0] in c) f = i[0];
          else {
            for (e in c) {
              if (!i[0] || a.converters[e + " " + i[0]]) {
                f = e;
                break;
              }
              g || (g = e);
            }
            f = f || g;
          }
          if (f) return f !== i[0] && i.unshift(f), c[f];
        }
        function Qb(a, b, c, d) {
          var e,
            f,
            g,
            h,
            i,
            j = {},
            k = a.dataTypes.slice();
          if (k[1])
            for (g in a.converters) j[g.toLowerCase()] = a.converters[g];
          f = k.shift();
          while (f)
            if (
              (a.responseFields[f] && (c[a.responseFields[f]] = b),
              !i && d && a.dataFilter && (b = a.dataFilter(b, a.dataType)),
              (i = f),
              (f = k.shift()))
            )
              if ("*" === f) f = i;
              else if ("*" !== i && i !== f) {
                if (((g = j[i + " " + f] || j["* " + f]), !g))
                  for (e in j)
                    if (
                      ((h = e.split(" ")),
                      h[1] === f && (g = j[i + " " + h[0]] || j["* " + h[0]]))
                    ) {
                      g === !0
                        ? (g = j[e])
                        : j[e] !== !0 && ((f = h[0]), k.unshift(h[1]));
                      break;
                    }
                if (g !== !0)
                  if (g && a["throws"]) b = g(b);
                  else
                    try {
                      b = g(b);
                    } catch (l) {
                      return {
                        state: "parsererror",
                        error: g ? l : "No conversion from " + i + " to " + f,
                      };
                    }
              }
          return { state: "success", data: b };
        }
        r.extend({
          active: 0,
          lastModified: {},
          etag: {},
          ajaxSettings: {
            url: tb.href,
            type: "GET",
            isLocal: Fb.test(tb.protocol),
            global: !0,
            processData: !0,
            async: !0,
            contentType: "application/x-www-form-urlencoded; charset=UTF-8",
            accepts: {
              "*": Kb,
              text: "text/plain",
              html: "text/html",
              xml: "application/xml, text/xml",
              json: "application/json, text/javascript",
            },
            contents: { xml: /\bxml\b/, html: /\bhtml/, json: /\bjson\b/ },
            responseFields: {
              xml: "responseXML",
              text: "responseText",
              json: "responseJSON",
            },
            converters: {
              "* text": String,
              "text html": !0,
              "text json": JSON.parse,
              "text xml": r.parseXML,
            },
            flatOptions: { url: !0, context: !0 },
          },
          ajaxSetup: function (a, b) {
            return b ? Ob(Ob(a, r.ajaxSettings), b) : Ob(r.ajaxSettings, a);
          },
          ajaxPrefilter: Mb(Ib),
          ajaxTransport: Mb(Jb),
          ajax: function (b, c) {
            "object" == typeof b && ((c = b), (b = void 0)), (c = c || {});
            var e,
              f,
              g,
              h,
              i,
              j,
              k,
              l,
              m,
              n,
              o = r.ajaxSetup({}, c),
              p = o.context || o,
              q = o.context && (p.nodeType || p.jquery) ? r(p) : r.event,
              s = r.Deferred(),
              t = r.Callbacks("once memory"),
              u = o.statusCode || {},
              v = {},
              w = {},
              x = "canceled",
              y = {
                readyState: 0,
                getResponseHeader: function (a) {
                  var b;
                  if (k) {
                    if (!h) {
                      h = {};
                      while ((b = Eb.exec(g))) h[b[1].toLowerCase()] = b[2];
                    }
                    b = h[a.toLowerCase()];
                  }
                  return null == b ? null : b;
                },
                getAllResponseHeaders: function () {
                  return k ? g : null;
                },
                setRequestHeader: function (a, b) {
                  return (
                    null == k &&
                      ((a = w[a.toLowerCase()] = w[a.toLowerCase()] || a),
                      (v[a] = b)),
                    this
                  );
                },
                overrideMimeType: function (a) {
                  return null == k && (o.mimeType = a), this;
                },
                statusCode: function (a) {
                  var b;
                  if (a)
                    if (k) y.always(a[y.status]);
                    else for (b in a) u[b] = [u[b], a[b]];
                  return this;
                },
                abort: function (a) {
                  var b = a || x;
                  return e && e.abort(b), A(0, b), this;
                },
              };
            if (
              (s.promise(y),
              (o.url = ((b || o.url || tb.href) + "").replace(
                Hb,
                tb.protocol + "//"
              )),
              (o.type = c.method || c.type || o.method || o.type),
              (o.dataTypes = (o.dataType || "*").toLowerCase().match(L) || [
                "",
              ]),
              null == o.crossDomain)
            ) {
              j = d.createElement("a");
              try {
                (j.href = o.url),
                  (j.href = j.href),
                  (o.crossDomain =
                    Lb.protocol + "//" + Lb.host != j.protocol + "//" + j.host);
              } catch (z) {
                o.crossDomain = !0;
              }
            }
            if (
              (o.data &&
                o.processData &&
                "string" != typeof o.data &&
                (o.data = r.param(o.data, o.traditional)),
              Nb(Ib, o, c, y),
              k)
            )
              return y;
            (l = r.event && o.global),
              l && 0 === r.active++ && r.event.trigger("ajaxStart"),
              (o.type = o.type.toUpperCase()),
              (o.hasContent = !Gb.test(o.type)),
              (f = o.url.replace(Cb, "")),
              o.hasContent
                ? o.data &&
                  o.processData &&
                  0 ===
                    (o.contentType || "").indexOf(
                      "application/x-www-form-urlencoded"
                    ) &&
                  (o.data = o.data.replace(Bb, "+"))
                : ((n = o.url.slice(f.length)),
                  o.data &&
                    ((f += (vb.test(f) ? "&" : "?") + o.data), delete o.data),
                  o.cache === !1 &&
                    ((f = f.replace(Db, "$1")),
                    (n = (vb.test(f) ? "&" : "?") + "_=" + ub++ + n)),
                  (o.url = f + n)),
              o.ifModified &&
                (r.lastModified[f] &&
                  y.setRequestHeader("If-Modified-Since", r.lastModified[f]),
                r.etag[f] && y.setRequestHeader("If-None-Match", r.etag[f])),
              ((o.data && o.hasContent && o.contentType !== !1) ||
                c.contentType) &&
                y.setRequestHeader("Content-Type", o.contentType),
              y.setRequestHeader(
                "Accept",
                o.dataTypes[0] && o.accepts[o.dataTypes[0]]
                  ? o.accepts[o.dataTypes[0]] +
                      ("*" !== o.dataTypes[0] ? ", " + Kb + "; q=0.01" : "")
                  : o.accepts["*"]
              );
            for (m in o.headers) y.setRequestHeader(m, o.headers[m]);
            if (o.beforeSend && (o.beforeSend.call(p, y, o) === !1 || k))
              return y.abort();
            if (
              ((x = "abort"),
              t.add(o.complete),
              y.done(o.success),
              y.fail(o.error),
              (e = Nb(Jb, o, c, y)))
            ) {
              if (((y.readyState = 1), l && q.trigger("ajaxSend", [y, o]), k))
                return y;
              o.async &&
                o.timeout > 0 &&
                (i = a.setTimeout(function () {
                  y.abort("timeout");
                }, o.timeout));
              try {
                (k = !1), e.send(v, A);
              } catch (z) {
                if (k) throw z;
                A(-1, z);
              }
            } else A(-1, "No Transport");
            function A(b, c, d, h) {
              var j,
                m,
                n,
                v,
                w,
                x = c;
              k ||
                ((k = !0),
                i && a.clearTimeout(i),
                (e = void 0),
                (g = h || ""),
                (y.readyState = b > 0 ? 4 : 0),
                (j = (b >= 200 && b < 300) || 304 === b),
                d && (v = Pb(o, y, d)),
                (v = Qb(o, v, y, j)),
                j
                  ? (o.ifModified &&
                      ((w = y.getResponseHeader("Last-Modified")),
                      w && (r.lastModified[f] = w),
                      (w = y.getResponseHeader("etag")),
                      w && (r.etag[f] = w)),
                    204 === b || "HEAD" === o.type
                      ? (x = "nocontent")
                      : 304 === b
                      ? (x = "notmodified")
                      : ((x = v.state), (m = v.data), (n = v.error), (j = !n)))
                  : ((n = x), (!b && x) || ((x = "error"), b < 0 && (b = 0))),
                (y.status = b),
                (y.statusText = (c || x) + ""),
                j ? s.resolveWith(p, [m, x, y]) : s.rejectWith(p, [y, x, n]),
                y.statusCode(u),
                (u = void 0),
                l &&
                  q.trigger(j ? "ajaxSuccess" : "ajaxError", [y, o, j ? m : n]),
                t.fireWith(p, [y, x]),
                l &&
                  (q.trigger("ajaxComplete", [y, o]),
                  --r.active || r.event.trigger("ajaxStop")));
            }
            return y;
          },
          getJSON: function (a, b, c) {
            return r.get(a, b, c, "json");
          },
          getScript: function (a, b) {
            return r.get(a, void 0, b, "script");
          },
        }),
          r.each(["get", "post"], function (a, b) {
            r[b] = function (a, c, d, e) {
              return (
                r.isFunction(c) && ((e = e || d), (d = c), (c = void 0)),
                r.ajax(
                  r.extend(
                    { url: a, type: b, dataType: e, data: c, success: d },
                    r.isPlainObject(a) && a
                  )
                )
              );
            };
          }),
          (r._evalUrl = function (a) {
            return r.ajax({
              url: a,
              type: "GET",
              dataType: "script",
              cache: !0,
              async: !1,
              global: !1,
              throws: !0,
            });
          }),
          r.fn.extend({
            wrapAll: function (a) {
              var b;
              return (
                this[0] &&
                  (r.isFunction(a) && (a = a.call(this[0])),
                  (b = r(a, this[0].ownerDocument).eq(0).clone(!0)),
                  this[0].parentNode && b.insertBefore(this[0]),
                  b
                    .map(function () {
                      var a = this;
                      while (a.firstElementChild) a = a.firstElementChild;
                      return a;
                    })
                    .append(this)),
                this
              );
            },
            wrapInner: function (a) {
              return r.isFunction(a)
                ? this.each(function (b) {
                    r(this).wrapInner(a.call(this, b));
                  })
                : this.each(function () {
                    var b = r(this),
                      c = b.contents();
                    c.length ? c.wrapAll(a) : b.append(a);
                  });
            },
            wrap: function (a) {
              var b = r.isFunction(a);
              return this.each(function (c) {
                r(this).wrapAll(b ? a.call(this, c) : a);
              });
            },
            unwrap: function (a) {
              return (
                this.parent(a)
                  .not("body")
                  .each(function () {
                    r(this).replaceWith(this.childNodes);
                  }),
                this
              );
            },
          }),
          (r.expr.pseudos.hidden = function (a) {
            return !r.expr.pseudos.visible(a);
          }),
          (r.expr.pseudos.visible = function (a) {
            return !!(
              a.offsetWidth ||
              a.offsetHeight ||
              a.getClientRects().length
            );
          }),
          (r.ajaxSettings.xhr = function () {
            try {
              return new a.XMLHttpRequest();
            } catch (b) {}
          });
        var Rb = { 0: 200, 1223: 204 },
          Sb = r.ajaxSettings.xhr();
        (o.cors = !!Sb && "withCredentials" in Sb),
          (o.ajax = Sb = !!Sb),
          r.ajaxTransport(function (b) {
            var c, d;
            if (o.cors || (Sb && !b.crossDomain))
              return {
                send: function (e, f) {
                  var g,
                    h = b.xhr();
                  if (
                    (h.open(b.type, b.url, b.async, b.username, b.password),
                    b.xhrFields)
                  )
                    for (g in b.xhrFields) h[g] = b.xhrFields[g];
                  b.mimeType &&
                    h.overrideMimeType &&
                    h.overrideMimeType(b.mimeType),
                    b.crossDomain ||
                      e["X-Requested-With"] ||
                      (e["X-Requested-With"] = "XMLHttpRequest");
                  for (g in e) h.setRequestHeader(g, e[g]);
                  (c = function (a) {
                    return function () {
                      c &&
                        ((c =
                          d =
                          h.onload =
                          h.onerror =
                          h.onabort =
                          h.onreadystatechange =
                            null),
                        "abort" === a
                          ? h.abort()
                          : "error" === a
                          ? "number" != typeof h.status
                            ? f(0, "error")
                            : f(h.status, h.statusText)
                          : f(
                              Rb[h.status] || h.status,
                              h.statusText,
                              "text" !== (h.responseType || "text") ||
                                "string" != typeof h.responseText
                                ? { binary: h.response }
                                : { text: h.responseText },
                              h.getAllResponseHeaders()
                            ));
                    };
                  }),
                    (h.onload = c()),
                    (d = h.onerror = c("error")),
                    void 0 !== h.onabort
                      ? (h.onabort = d)
                      : (h.onreadystatechange = function () {
                          4 === h.readyState &&
                            a.setTimeout(function () {
                              c && d();
                            });
                        }),
                    (c = c("abort"));
                  try {
                    h.send((b.hasContent && b.data) || null);
                  } catch (i) {
                    if (c) throw i;
                  }
                },
                abort: function () {
                  c && c();
                },
              };
          }),
          r.ajaxPrefilter(function (a) {
            a.crossDomain && (a.contents.script = !1);
          }),
          r.ajaxSetup({
            accepts: {
              script:
                "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript",
            },
            contents: { script: /\b(?:java|ecma)script\b/ },
            converters: {
              "text script": function (a) {
                return r.globalEval(a), a;
              },
            },
          }),
          r.ajaxPrefilter("script", function (a) {
            void 0 === a.cache && (a.cache = !1),
              a.crossDomain && (a.type = "GET");
          }),
          r.ajaxTransport("script", function (a) {
            if (a.crossDomain) {
              var b, c;
              return {
                send: function (e, f) {
                  (b = r("<script>")
                    .prop({ charset: a.scriptCharset, src: a.url })
                    .on(
                      "load error",
                      (c = function (a) {
                        b.remove(),
                          (c = null),
                          a && f("error" === a.type ? 404 : 200, a.type);
                      })
                    )),
                    d.head.appendChild(b[0]);
                },
                abort: function () {
                  c && c();
                },
              };
            }
          });
        var Tb = [],
          Ub = /(=)\?(?=&|$)|\?\?/;
        r.ajaxSetup({
          jsonp: "callback",
          jsonpCallback: function () {
            var a = Tb.pop() || r.expando + "_" + ub++;
            return (this[a] = !0), a;
          },
        }),
          r.ajaxPrefilter("json jsonp", function (b, c, d) {
            var e,
              f,
              g,
              h =
                b.jsonp !== !1 &&
                (Ub.test(b.url)
                  ? "url"
                  : "string" == typeof b.data &&
                    0 ===
                      (b.contentType || "").indexOf(
                        "application/x-www-form-urlencoded"
                      ) &&
                    Ub.test(b.data) &&
                    "data");
            if (h || "jsonp" === b.dataTypes[0])
              return (
                (e = b.jsonpCallback =
                  r.isFunction(b.jsonpCallback)
                    ? b.jsonpCallback()
                    : b.jsonpCallback),
                h
                  ? (b[h] = b[h].replace(Ub, "$1" + e))
                  : b.jsonp !== !1 &&
                    (b.url += (vb.test(b.url) ? "&" : "?") + b.jsonp + "=" + e),
                (b.converters["script json"] = function () {
                  return g || r.error(e + " was not called"), g[0];
                }),
                (b.dataTypes[0] = "json"),
                (f = a[e]),
                (a[e] = function () {
                  g = arguments;
                }),
                d.always(function () {
                  void 0 === f ? r(a).removeProp(e) : (a[e] = f),
                    b[e] && ((b.jsonpCallback = c.jsonpCallback), Tb.push(e)),
                    g && r.isFunction(f) && f(g[0]),
                    (g = f = void 0);
                }),
                "script"
              );
          }),
          (o.createHTMLDocument = (function () {
            var a = d.implementation.createHTMLDocument("").body;
            return (
              (a.innerHTML = "<form></form><form></form>"),
              2 === a.childNodes.length
            );
          })()),
          (r.parseHTML = function (a, b, c) {
            if ("string" != typeof a) return [];
            "boolean" == typeof b && ((c = b), (b = !1));
            var e, f, g;
            return (
              b ||
                (o.createHTMLDocument
                  ? ((b = d.implementation.createHTMLDocument("")),
                    (e = b.createElement("base")),
                    (e.href = d.location.href),
                    b.head.appendChild(e))
                  : (b = d)),
              (f = C.exec(a)),
              (g = !c && []),
              f
                ? [b.createElement(f[1])]
                : ((f = qa([a], b, g)),
                  g && g.length && r(g).remove(),
                  r.merge([], f.childNodes))
            );
          }),
          (r.fn.load = function (a, b, c) {
            var d,
              e,
              f,
              g = this,
              h = a.indexOf(" ");
            return (
              h > -1 && ((d = pb(a.slice(h))), (a = a.slice(0, h))),
              r.isFunction(b)
                ? ((c = b), (b = void 0))
                : b && "object" == typeof b && (e = "POST"),
              g.length > 0 &&
                r
                  .ajax({ url: a, type: e || "GET", dataType: "html", data: b })
                  .done(function (a) {
                    (f = arguments),
                      g.html(d ? r("<div>").append(r.parseHTML(a)).find(d) : a);
                  })
                  .always(
                    c &&
                      function (a, b) {
                        g.each(function () {
                          c.apply(this, f || [a.responseText, b, a]);
                        });
                      }
                  ),
              this
            );
          }),
          r.each(
            [
              "ajaxStart",
              "ajaxStop",
              "ajaxComplete",
              "ajaxError",
              "ajaxSuccess",
              "ajaxSend",
            ],
            function (a, b) {
              r.fn[b] = function (a) {
                return this.on(b, a);
              };
            }
          ),
          (r.expr.pseudos.animated = function (a) {
            return r.grep(r.timers, function (b) {
              return a === b.elem;
            }).length;
          }),
          (r.offset = {
            setOffset: function (a, b, c) {
              var d,
                e,
                f,
                g,
                h,
                i,
                j,
                k = r.css(a, "position"),
                l = r(a),
                m = {};
              "static" === k && (a.style.position = "relative"),
                (h = l.offset()),
                (f = r.css(a, "top")),
                (i = r.css(a, "left")),
                (j =
                  ("absolute" === k || "fixed" === k) &&
                  (f + i).indexOf("auto") > -1),
                j
                  ? ((d = l.position()), (g = d.top), (e = d.left))
                  : ((g = parseFloat(f) || 0), (e = parseFloat(i) || 0)),
                r.isFunction(b) && (b = b.call(a, c, r.extend({}, h))),
                null != b.top && (m.top = b.top - h.top + g),
                null != b.left && (m.left = b.left - h.left + e),
                "using" in b ? b.using.call(a, m) : l.css(m);
            },
          }),
          r.fn.extend({
            offset: function (a) {
              if (arguments.length)
                return void 0 === a
                  ? this
                  : this.each(function (b) {
                      r.offset.setOffset(this, a, b);
                    });
              var b,
                c,
                d,
                e,
                f = this[0];
              if (f)
                return f.getClientRects().length
                  ? ((d = f.getBoundingClientRect()),
                    (b = f.ownerDocument),
                    (c = b.documentElement),
                    (e = b.defaultView),
                    {
                      top: d.top + e.pageYOffset - c.clientTop,
                      left: d.left + e.pageXOffset - c.clientLeft,
                    })
                  : { top: 0, left: 0 };
            },
            position: function () {
              if (this[0]) {
                var a,
                  b,
                  c = this[0],
                  d = { top: 0, left: 0 };
                return (
                  "fixed" === r.css(c, "position")
                    ? (b = c.getBoundingClientRect())
                    : ((a = this.offsetParent()),
                      (b = this.offset()),
                      B(a[0], "html") || (d = a.offset()),
                      (d = {
                        top: d.top + r.css(a[0], "borderTopWidth", !0),
                        left: d.left + r.css(a[0], "borderLeftWidth", !0),
                      })),
                  {
                    top: b.top - d.top - r.css(c, "marginTop", !0),
                    left: b.left - d.left - r.css(c, "marginLeft", !0),
                  }
                );
              }
            },
            offsetParent: function () {
              return this.map(function () {
                var a = this.offsetParent;
                while (a && "static" === r.css(a, "position"))
                  a = a.offsetParent;
                return a || ra;
              });
            },
          }),
          r.each(
            { scrollLeft: "pageXOffset", scrollTop: "pageYOffset" },
            function (a, b) {
              var c = "pageYOffset" === b;
              r.fn[a] = function (d) {
                return T(
                  this,
                  function (a, d, e) {
                    var f;
                    return (
                      r.isWindow(a)
                        ? (f = a)
                        : 9 === a.nodeType && (f = a.defaultView),
                      void 0 === e
                        ? f
                          ? f[b]
                          : a[d]
                        : void (f
                            ? f.scrollTo(
                                c ? f.pageXOffset : e,
                                c ? e : f.pageYOffset
                              )
                            : (a[d] = e))
                    );
                  },
                  a,
                  d,
                  arguments.length
                );
              };
            }
          ),
          r.each(["top", "left"], function (a, b) {
            r.cssHooks[b] = Pa(o.pixelPosition, function (a, c) {
              if (c)
                return (
                  (c = Oa(a, b)), Ma.test(c) ? r(a).position()[b] + "px" : c
                );
            });
          }),
          r.each({ Height: "height", Width: "width" }, function (a, b) {
            r.each(
              { padding: "inner" + a, content: b, "": "outer" + a },
              function (c, d) {
                r.fn[d] = function (e, f) {
                  var g = arguments.length && (c || "boolean" != typeof e),
                    h = c || (e === !0 || f === !0 ? "margin" : "border");
                  return T(
                    this,
                    function (b, c, e) {
                      var f;
                      return r.isWindow(b)
                        ? 0 === d.indexOf("outer")
                          ? b["inner" + a]
                          : b.document.documentElement["client" + a]
                        : 9 === b.nodeType
                        ? ((f = b.documentElement),
                          Math.max(
                            b.body["scroll" + a],
                            f["scroll" + a],
                            b.body["offset" + a],
                            f["offset" + a],
                            f["client" + a]
                          ))
                        : void 0 === e
                        ? r.css(b, c, h)
                        : r.style(b, c, e, h);
                    },
                    b,
                    g ? e : void 0,
                    g
                  );
                };
              }
            );
          }),
          r.fn.extend({
            bind: function (a, b, c) {
              return this.on(a, null, b, c);
            },
            unbind: function (a, b) {
              return this.off(a, null, b);
            },
            delegate: function (a, b, c, d) {
              return this.on(b, a, c, d);
            },
            undelegate: function (a, b, c) {
              return 1 === arguments.length
                ? this.off(a, "**")
                : this.off(b, a || "**", c);
            },
          }),
          (r.holdReady = function (a) {
            a ? r.readyWait++ : r.ready(!0);
          }),
          (r.isArray = Array.isArray),
          (r.parseJSON = JSON.parse),
          (r.nodeName = B),
          "function" == typeof define &&
            define.amd &&
            define("jquery", [], function () {
              return r;
            });
        var Vb = a.jQuery,
          Wb = a.$;
        return (
          (r.noConflict = function (b) {
            return (
              a.$ === r && (a.$ = Wb), b && a.jQuery === r && (a.jQuery = Vb), r
            );
          }),
          b || (a.jQuery = a.$ = r),
          r
        );
      });
    </script>
    <div class="content">
      <div class="title">
        <div class="btn">
        <button class="title_l" id="showAll">显示全部文档</button>
        </div>
        <div class="line"></div>
        <div class="title_r">
          <h1>nginxdb接口帮助</h1>
        </div>
      </div>

      <div class="main">
        <div id="port">
          <ul class="nav"></ul>
        </div>
        <div id="drapLine" class="drap_line"></div>
        <div id="viewport">
          <div id="nav">全部文档</div>
          <div id="jsonBox" class="json_box">
            <div>device / barcode_edit</div>
            <div>barcode:条码，为空则返回当前生产状态，为新条码则生成新订单</div><br>
            <div>device / brand_add</div>
            <div>null</div>
          </div>
        </div>
      </div>
    </div>

    <script>
      $(function () {
        let jsonData =',';



        let htmlTxt = "";
        let jsonHTMl = [];
        let jsonAlltext="";
        let jsonTextArr=[];

        getHTML(jsonData);
        function getHTML(jsonData) {
          let jsonObj = [];
          jsonData.forEach((v, i) => {
            getT(v.c)
            jsonAlltext+=`
            <div style="color: red;">${v.a} / ${v.b}</div>
            <div>${t}</div><br>
            `

            jsonObj.push({ name: v.a, item: [] });
          });
          
          function uniqueFunc(arr, uniId) {
            const res = new Map();
            return arr.filter(
              (item) => !res.has(item[uniId]) && res.set(item[uniId], 1)
            );
          }

          function getT(c){
          t = JSON.stringify(c)
                  .replaceAll("\\r\\n", "<br>")
                  .replaceAll(''\\"'', ''"'')
                  .replaceAll("\\t", "&nbsp&nbsp&nbsp&nbsp")
                  .replaceAll(" ", "&nbsp");
                if (t.length > 4) t = t.substring(1, t.length - 1);
                return t;
          }

          let newArr = uniqueFunc(jsonObj, "name");
          for (let i = 0; i < newArr.length; i++) {
            jsonHTMl.push([]);
          }

          jsonData.forEach((v, i) => {
            newArr.forEach((j, n) => {
              if (v.a == j.name) {
                newArr[n].item.push(v.b);
                getT(v.c);
                jsonHTMl[n].push(t);
              }
            });
            
          });

          for (const key in newArr) {
            let html=""
            newArr[key].item.forEach((v,i)=>{
            let text=jsonHTMl[key][i]
            html+=`
            <div style="color: red;">${ newArr[key].name} / ${v}</div>
            <div>${text}</div><br>
            `
            })
            jsonTextArr.push(html)
          }
         
          htmlTxt = "";
          newArr.forEach((v, n) => {
            htmlTxt += `
            <li class="nav-item">
            <a href="javascript:;"
              ><i class="nav-icon"></i><span>${v.name}</span><i class="nav-more"></i
            ></a>
            <ul>`;
            v.item.forEach((j, i) => {
              if (v.item.length - 1 != i) {
                htmlTxt += ` 
              <li one=${n} two=${i}>
                <a href="javascript:;" ><span>${v.item[i]}</span></a>
              </li>`;
              } else {
                htmlTxt += `
              <li one=${n} two=${i}>
                <a href="javascript:;"><span>${v.item[i]}</span></a>
              </li>
            </ul>
            </li>`;
              }
            });
          });
          return htmlTxt;
        }

        $(".nav").html(htmlTxt);
        // nav收缩展开
        $(".nav-item>a").on("click", function () {
          $("#nav").text($(this).text())
          $("#jsonBox").html(jsonTextArr[$(this).parent().index()]);
          if (!$(".nav").hasClass("nav-mini")) {
            if ($(this).next().css("display") == "none") {
              $(".nav-item").children("ul").slideUp(300);
              $(this).next("ul").slideDown(300);
              $(this)
                .parent("li")
                .addClass("nav-show")
                .siblings("li")
                .removeClass("nav-show");
            } else {
              //收缩已展开
              $(this).next("ul").slideUp(300);
              $(".nav-item.nav-show").removeClass("nav-show");
            }
          }
        });

        $(".nav-item").on("click", "ul>li", function () {
          $("#nav").text(
            `${$(this).parents(".nav-item").children("a").text()} / ${$(
              this
            ).text()}`
          );
          let one = $(this).attr("one");
          let two = $(this).attr("two");
          $("#jsonBox").html(jsonHTMl[one][two]);
        });

        //设置最大/最小宽度
        var max_width = "400",
          min_width = "200";
        var drapLine = $("#drapLine")[0],
          left = $("#port")[0],
          right = $("#viewport")[0];
        var mouse_x = 0;

        function mouseMove(e) {
          var e = e || window.event;
          var left_width = e.clientX - mouse_x;
          left_width = left_width < min_width ? min_width : left_width;
          left_width = left_width > max_width ? max_width : left_width;
          console.log(left_width);
          left.style.width = left_width + "px";
        }

        function mouseUp() {
          document.onmousemove = null;
          document.onmouseup = null;
          //localStorage设置
          localStorage.setItem("sliderWidth", left.style.width);
        }

        var history_width = localStorage.getItem("sliderWidth");
        if (history_width) {
          left.style.width = history_width;
        }

        drapLine.onmousedown = function (e) {
          var e = e || window.event;
          //阻止默认事件
          e.preventDefault();
          mouse_x = e.clientX - left.offsetWidth;
          document.onmousemove = mouseMove;
          document.onmouseup = mouseUp;
        };

        $("#jsonBox").html(jsonAlltext);
        $("#showAll").on("click",  function () {
          $("#nav").text("全部文档")
          $("#jsonBox").html(jsonAlltext); 
        });
      });
    </script>
  </body>
</html>
');
