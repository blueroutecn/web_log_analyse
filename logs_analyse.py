# coding:utf-8
import re
import pexpect
import pymongo
from conver import urldecode,htmlunescape

# -----mongo连接
mongo_host = '127.0.0.1'
mongo_port = 27017

# ---- 日志处理正则
request_re= re.compile(r'(?P<request_method>(GET|POST|HEAD|DELETE|PUT|OPTIONS)?)\s+(?P<request_uri>.*?)\s+(?P<server_protocol>.*)$')
log_line_re = re.compile(r'(?P<remote_host>((\d{1,3}\.){3}\d{1,3})+) - - (\[(?P<date_time>\S+)\s+\S+\])\s+\"(?P<request>(.*?))\"\s+(?P<status>([1-9]\d*))\s+(?P<body_bytes_sent>([1-9]\d*))\s+\"(?P<http_referer>.*?)\"\s+\"(?P<http_user_agent>.*?)\"')

def my_connect(db_name):
    mongo_client = pymongo.MongoClient(mongo_host, mongo_port)
    mongo_db = mongo_client["httplog"]
    collection = mongo_db.db[db_name]
    return collection

def log_parse(logfile):
    processed = {}
    this_h_m = ''
    result = log_line_re.search(logfile)
    if result:
        # remote_addr (客户若不经过代理，则可认为用户的真实ip)
        processed["remote_host"] = result.group('remote_host')
        processed["time_local"] = result.group('date_time')
        request = result.group('request')
        # 处理uri和args
        request_ur = request_re.search(request)
        if request_ur:
            processed["method"] = request_ur.group('request_method')
            processed["path"] =  urldecode(request_ur.group('request_uri'))
            processed["protocol"] = request_ur.group('server_protocol')
        # 状态码,字节数
        processed["status"] = result.group('status')
        processed["bbytes"] = result.group('body_bytes_sent')
        referer = result.group('http_referer')
        if referer == "-":
            referer = ""
        processed["referer"] = urldecode(referer)
        user_agent = result.group('http_user_agent')
        if user_agent == "-":
            user_agent = ""
        processed["user_agent"] = user_agent

    return processed

def check(file_data):
    import json,os
    results = []
    default_conf_path = os.path.abspath(os.path.dirname(__file__)) + "/"
    flist = default_conf_path+"rule.json"
    patterns_list = json.load(file(flist))
    for patterns in patterns_list:
        sensitive = True
        for pattern in patterns['patterns']:
            if pattern['type'] == 'match':
                if not re.search(pattern['part'], file_data):
                    sensitive = False
                    break
            elif pattern['type'] == 'regex':
                re_pattern = re.compile(str(pattern['part']), re.I)
                if re_pattern.search(file_data) == None:
                    sensitive = False
                    break

            if sensitive:
                results.append({
                    'tag': patterns['tag'],
                    'level': patterns['level']
                })

    return results


def main_loop(log_name):
    invalid = 0  # 无效的请求数
    mongo_db_name = log_name.split('.access')[0].replace('.', '')
    collection = my_connect(mongo_db_name.replace("/","_"))
    #先获取总行数
    numcmd = "wc -l %s" %(log_name)
    child = pexpect.spawn(numcmd)
    num = int(str(child.readlines()[0]).strip().replace(' '+log_name,''))
    i = 0
    with open(logfile) as fp:
        for line in fp:
            # 接下来对本次应该处理的并且正常的行进行处理
            line_res = log_parse(line.strip())

            if not line_res or str(line_res) == "{}":
                invalid += 1
                continue
            i += 1
            collection.insert(line_res)
            try:
                if line_res['path']:
                    if check(line_res['path']):
                        print "have %s times with %s %s %s " % (str(i),line_res['status'],line_res['path'],check(line_res['path']))
                    else:
                        print "have %s times with %s %s " % (str(i),line_res['status'],line_res['path'])
            except Exception as e:
                print line_res,str(e)
    return num

if __name__ == '__main__':
    logfile = "access.log"
    print main_loop(logfile)
