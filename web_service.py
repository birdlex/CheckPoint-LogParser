import sys, os, configparser, requests, re
sys.path.append('lib')
from flask import Flask
from flask import request
import ujson
#from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import redis

from lib.database_handler import DatabaseHandler
from lib.tcp_config_client import TcpConfigClient
from lib.udp_client import UdpClient

import logging
logging.basicConfig(filename='log/web_service.log', encoding='utf-8', level=logging.INFO)

redis_host = os.getenv('REDIS_HOST', default='localhost')
redis_conn_pool = redis.ConnectionPool(host=redis_host, port=6379, decode_responses=True)
redis_conn = redis.Redis(connection_pool=redis_conn_pool)

app = Flask(__name__)
db_handler = DatabaseHandler(app)
db = db_handler.db
TbOutput = db_handler.TbOutput
TbOplog = db_handler.TbOplog
TbConfig = db_handler.TbConfig
TbConfigLastModifyTime = db_handler.TbConfigLastModifyTime

default_ttl = 0
notify = False
ifttt_webhook_url = ''
tcp_config_client = TcpConfigClient(server_ip="127.0.0.1", server_port=8888)
#udp_client = UdpClient()


def get_config():
    global default_ttl, notify, ifttt_webhook_url
    db.session.commit()
    config_dict = db_handler.getConfig_to_dict()
    default_ttl = config_dict['default_ttl']
    notify = config_dict['notify']
    ifttt_webhook_url = config_dict['ifttt_webhook_url']
    tcp_config_client.send_message('config-reload')

@app.route('/settings', methods=['GET','POST'])
def config_data():
    get_config()
    global default_ttl, ifttt_webhook_url, tcp_config_client
    XXX = ifttt_webhook_url
    response_text = []
    response_text.append(f"{XXX}")
    return '\n'.join(response_text)

@app.route('/test/syslog', methods=['GET','POST'])
def syslog_test():
    udp_client = UdpClient()
    response_text = []
    if request.method == 'POST' and request.is_json:
        data = request.get_json()
        udp_client.send_message(data['log'])
        msg = '{"msg": "Syslog sent"}'
        response_text.append(msg)
        return '\n'.join(response_text)

@app.route('/settings/config', methods=['GET','POST'])
def config_update():
    response_text = []
    if request.method == 'GET':
        config_dict = db_handler.getConfig_to_dict()
        response_text.append(ujson.dumps(config_dict))
    if request.method == 'POST' and request.is_json:
        data = request.get_json()
        setConfig = db_handler.setConfig(data)
        if setConfig:
            get_config()
            msg = '{"msg": "' + 'Config Updated !' + '"}'
            response_text.append(msg)
            app.logger.info(msg)
        else:
            msg = '{"msg": "' + setConfig + '"}'
            response_text.append(msg)
            app.logger.info(msg)
    return '\n'.join(response_text)

@app.route('/settings/del/regex', methods=['GET','POST'])
def regex_delete():
    response_text = []
    src_ip = request.headers['X-Real-IP']
    data = request.get_json()
    regex_entry = db.session.get(TbConfig, data['k'])
    if request.method == 'POST' and request.is_json and regex_entry:
        db.session.delete(regex_entry)
        db.session.commit()
        get_config()
        OpLog = 'Delete RegEx ' + data['k'] + ' from web, ClientIP = ' + str(src_ip)
        write_OpLog('del', OpLog)
        msg = '{"msg": "' + 'RegEx ' + data['k'] + ' has been deleted."}'
        response_text.append(msg)
        return '\n'.join(response_text)
    msg = '{"msg": "' + 'No entry found for RegEx ' + data['k'] + '"}'
    response_text.append(msg)
    return '\n'.join(response_text)

@app.route('/settings/regex', methods=['GET','POST'])
def regex_update():
    response_text = []
    src_ip = request.headers['X-Real-IP']
    if request.method == 'GET':
        all_regex = TbConfig.query.with_entities(TbConfig.k, TbConfig.v, TbConfig.modifytime).filter_by(section='REGEX').order_by(TbConfig.modifytime.desc()).all()
        for row in all_regex:
            k = row[0]
            v = row[1]
            modifytime = row[2]
            response_text.append({
                "k": k,
                "v": v,
                "modifytime": str(modifytime)
            })
        # app.logger.info(f'{all_regex}')
        return ujson.dumps(response_text)
    if request.method == 'POST' and request.is_json:
        data = request.get_json()
        regex_entry = db.session.get(TbConfig, data['k'])
        if regex_entry:
            msg = '{"msg": "' + 'Error: RegEx name ' + data['k'] + ' already exists."}'
            response_text.append(msg)
        else:
            if len(data['v']) == 0 :
                msg = '{"msg": "' + 'Error: Content cannot be empty"}'
                response_text.append(msg)
            else:
                app.logger.info(f'{regex_entry}')
                data_k = fuckoff_cmd_inj(data['k'])
                new_RegEx = TbConfig(section='REGEX', k=data_k, v=data['v'])
                db.session.add(new_RegEx)
                db.session.commit()
                get_config()
                OpLog = 'Add RegEx ' + data_k + ' from web, ClientIP = ' + str(src_ip)
                write_OpLog('add', OpLog)
                msg = '{"msg": "' + 'RegEx Added !' + '"}'
                response_text.append(msg)
        return '\n'.join(response_text)

@app.route('/networkfeed', methods=['GET'])
def list_data():
    global redis_conn
    all_data = TbOutput.query.with_entities(TbOutput.data, TbOutput.ttl, TbOutput.createtime, TbOutput.comment).all()
    try:
        redis_conn.ltrim('syslog', 0, 299)
    except:
        pass
    
    if not all_data:  # If no data in the table
        return "#Just for test\n111.111.111.111"
    response_text = []
    current_time = datetime.utcnow()
    for row in all_data:
        ttl = row[1]
        createtime = row[2]
        time_diff = (current_time - createtime).total_seconds() / 60  # Convert to minutes
        if ttl == 0 or time_diff <= ttl:
            data = row[0]
            comment = row[3]
            ttl_str = ', TTL = ' + str(ttl)
            createtime_str = ', CreateTime = ' + str(createtime) + '\n'
            response_text.append(f"{comment}{ttl_str}{createtime_str}{data}")
        elif ttl != 0 and time_diff > ttl:
            expired_data = db.session.get(TbOutput, row[0])
            db.session.delete(expired_data)
            db.session.commit()
            OpLog = 'TTL timeout, Delete ' + row[0]
            write_OpLog('del', OpLog)
            ifttt_notify(OpLog)
    return '\n'.join(response_text)

@app.route('/networkfeed/del/<ip>', methods=['GET'])
def delete_data(ip):
    ip_entry = db.session.get(TbOutput, ip)
    src_ip = request.headers['X-Real-IP']
    if ip_entry:
        db.session.delete(ip_entry)
        db.session.commit()
        OpLog = 'Delete ' + ip + ' from web, ClientIP = ' + str(src_ip)
        write_OpLog('del', OpLog)
        ifttt_notify(OpLog)
        return f"IP {ip} has been deleted."
    return f"No entry found for IP {ip}."

@app.route('/networkfeed/add/<ip>', methods=['GET'])
@app.route('/networkfeed/add/<ip>/<int:ttl>', methods=['GET'])
def add_data(ip, ttl=None):
    global default_ttl
    app.logger.info(type(ttl))
    app.logger.info(str(default_ttl))
    ip_entry = db.session.get(TbOutput, ip)
    src_ip = request.headers['X-Real-IP']
    if ip_entry:
        return f"Error: IP {ip} already exists."
    else:
        IPv4_match = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", ip)
        if bool(IPv4_match):
            ttl_value = default_ttl if ttl is None else ttl
            new_entry = TbOutput(data=ip, ttl=ttl_value, comment='# Add from web, ClientIP = ' + str(src_ip))
            db.session.add(new_entry)
            db.session.commit()
            OpLog = 'Add ' + ip + ' from web, ClientIP = ' + str(src_ip) + ', TTL = ' + str(ttl_value)
            write_OpLog('add', OpLog)
            ifttt_notify(OpLog)
            return f"IP {ip} with TTL {ttl_value} has been added."
        else:
            return f"Error: IPv4 {ip} format incorrect."

    
@app.route('/networkfeed/oplog', methods=['GET'])
def list_OpLog():
    all_OpLog = TbOplog.query.with_entities(TbOplog.action, TbOplog.oplog, TbOplog.createtime).all()
    response_text = []
    for row in all_OpLog:
        createtime = row[2]
        action = ', ' + row[0]
        oplog = ', ' + row[1] + '<br>'
        response_text.append(f"{createtime}{action}{oplog}")
    return '\n'.join(response_text)

@app.route('/json/networkfeed', methods=['GET'])
def list_data_json():
    all_data = TbOutput.query.with_entities(TbOutput.data, TbOutput.ttl, TbOutput.createtime, TbOutput.comment).order_by(TbOutput.createtime.desc()).all()
    response_data = []
    current_time = datetime.utcnow()
    for row in all_data:
        ttl = row[1]
        createtime = row[2]
        time_diff = (current_time - createtime).total_seconds() / 60  # Convert to minutes
        if ttl == 0 or time_diff <= ttl:
            data = row[0]
            comment = row[3]
            response_data.append({
                "Data": data,
                "TTL": ttl,
                "CreateTime": str(createtime),
                "Comment": comment
            })
        elif ttl != 0 and time_diff > ttl:
            expired_data = db.session.get(TbOutput, row[0])
            db.session.delete(expired_data)
            db.session.commit()
            OpLog = 'TTL timeout, Delete ' + row[0]
            write_OpLog('del', OpLog)
            ifttt_notify(OpLog)
    return ujson.dumps(response_data)

@app.route('/json/networkfeed/oplog', methods=['GET'])
def list_OpLog_json():
    all_OpLog = TbOplog.query.with_entities(TbOplog.action, TbOplog.oplog, TbOplog.createtime).order_by(TbOplog.createtime.desc()).all()
    response_data = []
    for row in all_OpLog:
        createtime = row[2]
        action = row[0]
        oplog = row[1]
        response_data.append({
            "CreateTime": str(createtime),
            "Action": action,
            "OpLog": oplog
        })
    return ujson.dumps(response_data)

@app.route('/json/syslog', methods=['GET'])
def list_syslog_json():
    global redis_conn
    try:
        redis_conn.ltrim('syslog', 0, 299)
    except:
        pass
    response_data = []
    syslog_data = redis_conn.lrange( "syslog", 0, -1)
    for row in syslog_data:
        syslog_str = row
        response_data.append({
            "Syslog": syslog_str
        })
    return ujson.dumps(response_data)

def fuckoff_cmd_inj(StrA):
    encoded_string = StrA.encode("ascii", "ignore")
    decode_string = encoded_string.decode()
    decode_string = decode_string.replace(' ', "-")
    decode_string = decode_string.replace('+', "-")
    decode_string = decode_string.replace('&', "-")
    decode_string = decode_string.replace('\'', "-")
    decode_string = decode_string.replace('*', "-")
    decode_string = decode_string.replace('"', "-")
    decode_string = decode_string.replace('%', "-")
    decode_string = decode_string.replace('.', "-")
    decode_string = decode_string.replace('$', "-")
    decode_string = decode_string.replace('`', "-")
    decode_string = decode_string.replace('/', "-")
    decode_string = decode_string.replace('#', "-")
    decode_string = decode_string.replace('|', "-")
    decode_string = decode_string.replace('^', "-")
    decode_string = decode_string.replace('~', "-")
    decode_string = decode_string.replace(';', "-")
    decode_string = decode_string.replace('>', "-")
    decode_string = decode_string.replace('<', "-")
    decode_string = decode_string.replace('=', "-")
    decode_string = decode_string.replace('(', "-")
    decode_string = decode_string.replace(')', "-")
    decode_string = decode_string.replace('[', "-")
    decode_string = decode_string.replace(']', "-")
    decode_string = decode_string.replace('{', "-")
    decode_string = decode_string.replace('}', "-")
    decode_string = decode_string.replace('\\', "-")
    return decode_string
    
def write_OpLog(action, oplog):
    new_entry = TbOplog(action=action, oplog=oplog)
    db.session.add(new_entry)
    db.session.commit()

def ifttt_notify(notify_data):
    global notify, ifttt_webhook_url
    if notify:
        url = ifttt_webhook_url
        params = {"value1": notify_data}
        try:
            requests.get(url, params=params)
        except:
            pass

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5080)
    get_config()
    
