# -*- coding: UTF-8 -*-

import json
import sys
from datetime import datetime

import requests
from aliyunsdkalidns.request.v20150109 import DescribeDomainRecordsRequest, UpdateDomainRecordRequest, \
    AddDomainRecordRequest
from aliyunsdkcore import client

# 尝试打开配置文件
try:
    config_r = open(sys.path[0] + '/config.json', 'r')
except Exception as e:
    print('An error occurred, open config file fail! Error MSG: ')
    print(e)
    print('Script exit!')
    sys.exit(0)
else:
    config_content = config_r.read()

# 尝试格式化配置文件
try:
    config_json = json.loads(config_content)
except Exception as e:
    print('Load json fail, please recheck config file! Error MSG: ')
    print(e)
    print('Script exit!')
    sys.exit(0)
else:
    pass

# 定义变量
rc_access_key_id = config_json['access_key_id']
rc_access_Key_secret = config_json['access_Key_secret']
rc_domain = config_json['domain']
rc_sub_domain = config_json['sub_domain']
rc_ttl = config_json['ttl']


# 通过淘宝API获取本地公网IP
def my_ip():
    get_ip_method = requests.get('http://ip.taobao.com/service/getIpInfo.php?ip=myip').content.decode()
    get_ip_value = json.loads(get_ip_method)
    get_ip_value = get_ip_value['data']['ip']
    return get_ip_value


# 获取域名信息
# 输出格式：[RecordId, Value]
def get_record_info():
    clt = client.AcsClient(rc_access_key_id, rc_access_Key_secret, 'cn-hangzhou')
    request = DescribeDomainRecordsRequest.DescribeDomainRecordsRequest()
    request.set_DomainName(rc_domain)
    request.set_accept_format('json')
    try:
        result = clt.do_action_with_exception(request)
    except Exception as f:
        return 'An error occurred! Error MSG: ' + str(f)
    else:
        result = result.decode()
        result_dict = json.JSONDecoder().decode(result)
        result_list = result_dict['DomainRecords']['Record']
        result = []
        for i in result_list:
            if rc_sub_domain == i['RR']:
                result.append(i['RecordId'])
                result.append(i['Value'])
                break
        return result


# 更新子域名信息
def update_dns(dns_value, dns_record_id):
    clt = client.AcsClient(rc_access_key_id, rc_access_Key_secret, 'cn-hangzhou')
    request = UpdateDomainRecordRequest.UpdateDomainRecordRequest()
    request.set_RR(rc_sub_domain)
    request.set_Type('A')
    request.set_Value(dns_value)
    request.set_RecordId(dns_record_id)
    request.set_TTL(rc_ttl)
    request.set_accept_format('json')
    result = clt.do_action_with_exception(request)
    return result


# 新增子域名解析
def add_dns(dns_value):
    clt = client.AcsClient(rc_access_key_id, rc_access_Key_secret, 'cn-hangzhou')
    request = AddDomainRecordRequest.AddDomainRecordRequest()
    request.set_DomainName(rc_domain)
    request.set_RR(rc_sub_domain)
    request.set_Type('A')
    request.set_Value(dns_value)
    request.set_TTL(rc_ttl)
    result = clt.do_action_with_exception(request)
    return result


# 写入日志
def write_to_file(dns_value, dns_output):
    time_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    write = open('./aliyun_ddns.log', 'a')
    write.write(time_now + ' ' + str(dns_value) + ' ' + dns_output + '\n')
    write.close()


# 运行
if __name__ == '__main__':
    result_list = get_record_info()
    current_ip = my_ip()
    if len(result_list) == 0:
        aliyun_output = add_dns(current_ip).decode()
        write_to_file(current_ip, aliyun_output)
        print(aliyun_output)
    else:
        result_record_id = result_list[0]
        old_ip = result_list[1]
        if old_ip == current_ip:
            print('The specified value of parameter Value is the same as old')
        else:
            aliyun_output = update_dns(current_ip, result_record_id).decode()
            write_to_file(current_ip, aliyun_output)
            print(aliyun_output)
