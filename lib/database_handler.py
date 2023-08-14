import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

class DatabaseHandler:
    def __init__(self, app):
        
        self.sqlite_list_db_path = os.path.join(os.path.dirname(__file__), "../db/list.db")
        self.sqlite_op_log_db_path = os.path.join(os.path.dirname(__file__), "../db/op_log.db")
        self.sqlite_config_db_path = os.path.join(os.path.dirname(__file__), "../db/config.db")
        
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + self.sqlite_list_db_path
        app.config["SQLALCHEMY_BINDS"] = {
            "config": "sqlite:///" + self.sqlite_config_db_path,
            "op_log": "sqlite:///" + self.sqlite_op_log_db_path,
        }
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        self.db = SQLAlchemy(app)

        class TbOutput(self.db.Model):
            data = self.db.Column(self.db.Text, nullable=False, primary_key=True, unique=True)
            ttl = self.db.Column(self.db.Integer)
            createtime = self.db.Column(self.db.DateTime, default=self.db.func.current_timestamp())
            comment = self.db.Column(self.db.Text)

        self.TbOutput = TbOutput

        class TbOplog(self.db.Model):
            __bind_key__ = "op_log"
            __tablename__ = "tb_oplog"
            id = self.db.Column(self.db.Integer, primary_key=True, autoincrement=True, nullable=False)
            action = self.db.Column(self.db.Text, nullable=False)
            oplog = self.db.Column(self.db.Text, nullable=False)
            createtime = self.db.Column(self.db.TIMESTAMP, default=self.db.func.current_timestamp())

        self.TbOplog = TbOplog

        class TbConfigLastModifyTime(self.db.Model):
            __bind_key__ = "config"
            __tablename__ = "tb_config_last_modifytime"
            modifytime = self.db.Column(self.db.TIMESTAMP, primary_key=True, nullable=False, default=self.db.func.current_timestamp())

        self.TbConfigLastModifyTime = TbConfigLastModifyTime

        class TbConfig(self.db.Model):
            __bind_key__ = "config"
            __tablename__ = "tb_config"
            section = self.db.Column(self.db.Text, nullable=False)
            k = self.db.Column(self.db.Text, primary_key=True, nullable=False, unique=True)
            v = self.db.Column(self.db.Text, nullable=False)
            modifytime = self.db.Column(self.db.TIMESTAMP, nullable=False, default=self.db.func.current_timestamp())

        self.TbConfig = TbConfig

        with app.app_context():
            self.check_and_create_db()
            if not self.conut_tb_config():
                self.init_configs()

    def check_and_create_db(self):
        if not os.path.exists(self.sqlite_list_db_path):
            self.db.create_all()
        if not os.path.exists(self.sqlite_op_log_db_path):
            self.db.create_all()
        if not os.path.exists(self.sqlite_config_db_path):
            self.db.create_all()

    def conut_tb_config(self):    
        return self.db.session.query(self.TbConfig).count() >= 1

    def init_configs(self):
        configs = [
            ("GLOBAL","interval",1),
            ("GLOBAL","threshold",3),
            ("GLOBAL","syslog_server",1),
            ("GLOBAL","default_ttl",0),
            ("NOTIFICATION","notify",0),
            ("NOTIFICATION","ifttt_webhook_url","https://maker.ifttt.com/trigger/CheckPointLogParser/with/key/xxxxxxxxxxxxxx"),
            ("FILE","logfile_path","/var/log/xxx.log"),
            ("REGEX","Synology-SMB","NT_STATUS_WRONG_PASSWORD.*remote\\ host\\ \\[ipv4:(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"),
            ("REGEX","CheckPoint-Harmony-Detect","action:\"Detect\".*src:\"(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\""),
            ("REGEX","CheckPoint-Harmony-Prevent","action:\"Prevent\".*src:\"(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\"")
        ]
        for cfg in configs:
            new_config = self.TbConfig(section=cfg[0], k=cfg[1], v=cfg[2])
            try:
                self.db.session.add(new_config)
                self.db.session.commit()
            except Exception as e:
                print("Error while writing config:", e)
                self.db.session.rollback()

    def kv_to_dict(self, data):
        result_dict = dict()
        for x in data:
            result_dict[x.k] = x.v
        return result_dict

    def getRegEx_to_dict(self):
        data = self.TbConfig.query.with_entities(self.TbConfig.k, self.TbConfig.v).filter_by(section='REGEX').all()
        return self.kv_to_dict(data)

    def getConfig_to_dict(self):
        config_dict = dict()
        config_dict['interval'] = int(self.TbConfig.query.filter_by(section='GLOBAL', k='interval').first().v)
        config_dict['threshold'] = int(self.TbConfig.query.filter_by(section='GLOBAL', k='threshold').first().v)
        config_dict['default_ttl'] = int(self.TbConfig.query.filter_by(section='GLOBAL', k='default_ttl').first().v)
        config_dict['syslog_server_enable'] = bool(int(self.TbConfig.query.filter_by(section='GLOBAL', k='syslog_server').first().v))
        config_dict['logfile_path'] = str(self.TbConfig.query.filter_by(section='FILE', k='logfile_path').first().v)
        config_dict['notify'] = bool(int(self.TbConfig.query.filter_by(section='NOTIFICATION', k='notify').first().v))
        config_dict['ifttt_webhook_url'] = str(self.TbConfig.query.filter_by(section='NOTIFICATION', k='ifttt_webhook_url').first().v)
        return config_dict

    def setConfig(self, data):
        try:
            config_dict = data
            if config_dict['notify']:
                config_dict['notify'] = '1'
            else:
                config_dict['notify'] = '0'
            self.TbConfig.query.filter_by(section='GLOBAL', k='interval').update(dict(v=str(config_dict['interval'])))
            self.TbConfig.query.filter_by(section='GLOBAL', k='threshold').update(dict(v=str(config_dict['threshold'])))
            self.TbConfig.query.filter_by(section='GLOBAL', k='default_ttl').update(dict(v=str(config_dict['default_ttl'])))
            # self.TbConfig.query.filter_by(section='GLOBAL', k='syslog_server').update(dict(v=str(config_dict['syslog_server'])))
            # self.TbConfig.query.filter_by(section='GLOBAL', k='FILE').update(dict(v=str(config_dict['logfile_path'])))
            self.TbConfig.query.filter_by(section='NOTIFICATION', k='notify').update(dict(v=str(config_dict['notify'])))
            ifttt_webhook_url_v = str(config_dict['ifttt_webhook_url']).replace('/json', '')
            self.TbConfig.query.filter_by(section='NOTIFICATION', k='ifttt_webhook_url').update(dict(v=ifttt_webhook_url_v))
            self.db.session.commit()
            return True
        except Exception as e:
            print("Error while writing OpLog:", e)
            self.db.session.rollback()
            return e
        

    def write_op_log(self, action, oplog):
        new_record = self.TbOplog(action=action, oplog=oplog)
        try:
            self.db.session.add(new_record)
            self.db.session.commit()
            return True
        except Exception as e:
            print("Error while writing OpLog:", e)
            self.db.session.rollback()
            return False
    
    def write_ip_list(self, ip, ttl, comment_text):
        new_record = self.TbOutput(data=ip, ttl=ttl, comment=comment_text)
        try:
            self.db.session.add(new_record)
            self.db.session.commit()
            return True
        except Exception as e:
            print("Error while writing IP list:", e)
            self.db.session.rollback()
            return False

    def db_init(self, app):
        with app.app_context():
            self.db.session.query(self.TbOutput).delete()
            self.db.session.query(self.TbOplog).delete()
            self.db.session.commit()


