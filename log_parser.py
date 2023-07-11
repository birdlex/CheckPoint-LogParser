#!/usr/bin/env python3

import sys, os, re, socket, configparser, sqlite3, requests
sys.path.append('lib')
from datetime import datetime, timedelta
from collections import defaultdict
from async_tail import atail
import subprocess
import threading
import redis
from pathlib import Path

#from lib.syslogserver import ThreadedUDPServer
from lib.database_handler import DatabaseHandler

from flask import Flask
from flask import current_app
# from tcp_config_server import TcpConfigServer
import logging

redis_conn_pool = redis.ConnectionPool(host='localhost', port=6379, decode_responses=True)
redis_conn = redis.Redis(connection_pool=redis_conn_pool)

app = Flask(__name__)
db_handler = DatabaseHandler(app)
db = db_handler.db
TbOutput = db_handler.TbOutput
TbOplog = db_handler.TbOplog
TbConfig = db_handler.TbConfig
TbConfigLastModifyTime = db_handler.TbConfigLastModifyTime

RegEx_Data = dict()

# Configuration
sqlite_path = os.path.join(os.path.dirname(__file__), 'db/list.db')
ip_list = defaultdict(list)  # Stores a list of timestamps for each IP
block_ip_list = set()  # Stores blocked IPs
config_update_flag = False

threshold = 1
interval = 1
default_ttl = 0
notify = False
syslog_server_enable = True
ifttt_webhook_url = ''

syslog_port = 6514
secs = interval * 60

if not os.path.isfile(os.path.join(os.path.dirname(__file__), '.inited')):
    db_handler.db_init(app)
    try:
        os.remove(os.path.join(os.path.dirname(__file__), 'log/log_parser.log'))
        os.remove(os.path.join(os.path.dirname(__file__), 'log/web_service.log'))
    except:
        pass
    redis_conn.delete('syslog')
    Path(os.path.join(os.path.dirname(__file__), '.inited')).touch()

logging.basicConfig(filename='log/log_parser.log', encoding='utf-8', level=logging.INFO)
logging.info('Started')

def config_server(stop_event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 8888))
    server.listen()

    while not stop_event.is_set():
        conn, addr = server.accept()
        handle_log_tcp_config(conn, addr)

def handle_log_tcp_config(conn, addr):
    while True:
        data = conn.recv(1024)
        if not data:
            break
        if len(data):
            data = data.decode('utf-8')
            if data == 'config-reload':
                get_config()
                logging.debug('Recive: [' + data + ']')
                logging.debug('Config threshold: [' + str(threshold) + ']')
                logging.debug('Config interval: [' + str(interval) + ']')
                logging.debug('Config default_ttl: [' + str(default_ttl) + ']')
                logging.debug('Config logfile_path: [' + str(logfile_path) + ']')
                logging.debug('Config syslog_server_enable: [' + str(int(syslog_server_enable)) + ']')
                logging.debug('Config notify: [' + str(int(notify)) + ']')
                logging.debug('Config ifttt_webhook_url: [' + str(ifttt_webhook_url) + ']')
                RegEx_Data_str = f'{RegEx_Data}'
                logging.debug('RegEx_Data: [' + RegEx_Data_str + ']')

def get_config():
    with app.app_context():
        global threshold, interval, default_ttl, logfile_path, syslog_server_enable, notify, ifttt_webhook_url, RegEx_Data
        db.session.commit()
        config_dict = db_handler.getConfig_to_dict()
        threshold = config_dict['threshold']
        interval = config_dict['interval']
        default_ttl = config_dict['default_ttl']
        logfile_path = config_dict['logfile_path']
        syslog_server_enable = config_dict['syslog_server_enable']
        notify = config_dict['notify']
        ifttt_webhook_url = config_dict['ifttt_webhook_url']
        RegEx_Data = db_handler.getRegEx_to_dict()


# Check if the IP should be blocked based on its activity
def action_IP_list(ip):
    global ip_list, threshold, secs
    interval_time = datetime.now() - timedelta(seconds=secs)
    ip_list[ip].sort()  # Sort the timestamps
    logging.debug(f"action_IP_list_ip_list[ip][0]: {ip_list[ip][0]}")
    logging.debug(f"action_IP_list_interval_time: {interval_time}")
    logging.debug(f"action_IP_list_LEN: {len(ip_list[ip])}")

    if ip_list[ip] and ip_list[ip][0] < interval_time:
        i = 0
        while i < len(ip_list[ip]):
            if ip_list[ip][i] < interval_time:
                ip_list[ip].pop(i)
            else:
                i += 1
    # Check if the number of timestamps for the IP exceeds the threshold within the allowed interval
    return len(ip_list[ip]) >= threshold and ip_list[ip][0] >= interval_time

# Update the list of IPs and block the IP if necessary
def update_IP_list(IP, addr, regex_matches):
    global ip_list, block_ip_list, default_ttl
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ip_address = re.findall(ip_pattern, str(addr))
    syslog_addr = ip_address[0]
    comment_text = '# syslog_src = ' + str(syslog_addr) + ', Hit = ' + str(regex_matches)
    ip_list[IP].append(datetime.now())  # Add a new timestamp for the IP
    logging.debug(f"ip_list: {ip_list}")
    # ip_list[IP].append(comment_text)
    # Check if the IP should be blocked and add it to the block list
    if action_IP_list(IP) and IP not in block_ip_list:
        block_ip_list.add(IP)
        if write_IP_list(IP, default_ttl, comment_text):
            comment_text = comment_text.replace('# ', '')
            comment_text = comment_text.replace('#', '')
            OpLog = 'Add ' + IP + ', ' + comment_text + ', TTL = ' + str(default_ttl)
            write_OpLog('add', OpLog)
            ifttt_notify(OpLog)
        try:
            block_ip_list.remove(IP)
        except:
            pass

# Write the blocked IP list to the SQLite database
def write_IP_list(ip, ttl, comment_text):
    global sqlite_path
    con = sqlite3.connect(sqlite_path)
    cur = con.cursor()
    cur.execute("INSERT OR IGNORE INTO tb_output (data, ttl, comment) VALUES (?, ?, ?)", (ip, ttl, comment_text))  # Remove the single quotes around comment_text
    inserted = cur.rowcount == 1
    con.commit()
    con.close()
    return inserted

def write_OpLog(action, oplog):
    with app.app_context():
        success = db_handler.write_op_log(action, oplog)
        if not success:
            print("Error occurred while writing OpLog.")

def ifttt_notify(notify_data):
    if notify:
        url = ifttt_webhook_url
        params = {"value1": notify_data}
        try:
            requests.get(url, params=params)
        except:
            pass

def handle_log(log_data, addr = ''):
    global syslog_server_enable, logfile_path, redis_conn
    if not syslog_server_enable:
        addr = logfile_path
    logging.debug(f"handle_log from {addr}:")
    try:
        redis_conn.lpush("syslog", log_data.decode('utf-8'))
    except:
        pass
    regex_parser(log_data.decode('utf-8'), addr)

# Extract IP addresses from the input text and update the IP list
def regex_parser(txt, addr):
    global RegEx_Data
    logging.debug(f"SYSLOG: {txt}")
    for key, value in RegEx_Data.items():
        #print(value)
        regex = r'{}'.format(value)
        matches = re.finditer(regex, txt, re.UNICODE | re.MULTILINE)
        #logging.info(f"REGE_KEY: {key}")
        # Update the IP list for each matched IP address
        for match in matches:
            logging.debug(f"match_group: {match.group(1)}, match_key: {key}")
            update_IP_list(match.group(1), addr, key)

def syslogs_udp_server(stop_event):
    global syslog_port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', syslog_port))

    while not stop_event.is_set():
        data, addr = server_socket.recvfrom(8192)
        logging.debug(f"syslogs_udp_server from {addr}:")
        handle_log(data, addr)

def tail_file(stop_event):
    if os.path.exists(logfile_path):
        print(f"Starting tail file on " + logfile_path)
        for line in atail(logfile_path):
            if stop_event.is_set():
                break
            handle_log(line.encode('utf-8'))
    else:
        sys.exit("file does not exist: " + logfile_path)

def main():
    web_service_process = subprocess.Popen(['python3', 'web_service.py'])
    get_config()
    try:
        stop_event = threading.Event()
        tasks = []
        tasks.append(threading.Thread(target=config_server, args=(stop_event,)))
        print('Entering server_program - 1')

        if syslog_server_enable:
            tasks.append(threading.Thread(target=syslogs_udp_server, args=(stop_event,)))
        else:
            tasks.append(threading.Thread(target=tail_file, args=(stop_event,)))

        for task in tasks:
            task.start()

        for task in tasks:
            task.join()

    except KeyboardInterrupt:
        print("\nShutting down...")
        stop_event.set()

    finally:
        web_service_process.terminate()

if __name__ == '__main__':
    main()