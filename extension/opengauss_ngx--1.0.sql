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

SET search_path = sysinfo;

SET default_tablespace = '';

SET default_with_oids = false;

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
