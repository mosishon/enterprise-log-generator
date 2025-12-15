"""
سیستم رویدادهای مرتبط - یک رویداد می‌تواند چند لاگ در دستگاه‌های مختلف ایجاد کند
"""
import random
import uuid
from datetime import datetime
from config import USERS
from log_generators import (
    NetworkLogGenerator, WebLogGenerator, ClientLogGenerator, SOCLogGenerator,
    ADLogGenerator, DatabaseLogGenerator, DNSLogGenerator, DHCPLogGenerator, EmailLogGenerator
)


class CorrelatedEventSystem:
    """سیستم مدیریت رویدادهای مرتبط"""
    
    def __init__(self, network_devices, web_servers, client_devices, ad_servers, db_servers, dns_servers, dhcp_servers, email_servers):
        self.network_devices = network_devices
        self.web_servers = web_servers
        self.client_devices = client_devices
        self.ad_servers = ad_servers
        self.db_servers = db_servers
        self.dns_servers = dns_servers
        self.dhcp_servers = dhcp_servers
        self.email_servers = email_servers
        self.soc_generator = SOCLogGenerator()
        self.correlation_id = None
    
    def generate_user_login_event(self):
        """رویداد لاگین کاربر - چند لاگ مرتبط ایجاد می‌کند"""
        correlation_id = str(uuid.uuid4())
        user = random.choice(USERS)
        client = random.choice(self.client_devices)
        web_server = random.choice(self.web_servers)
        network_device = random.choice(self.network_devices)
        
        logs = []
        
        # 1. لاگ کلاینت: لاگین کاربر
        client_gen = ClientLogGenerator(client)
        client_log = client_gen.generate_login_log()
        client_log["event"]["correlation_id"] = correlation_id
        client_log["event"]["user"] = user
        logs.append(client_log)
        
        # 2. لاگ وب: درخواست احراز هویت
        web_gen = WebLogGenerator(web_server)
        web_log = web_gen.generate_authentication_log()
        web_log["event"]["correlation_id"] = correlation_id
        web_log["event"]["user"] = user
        web_log["event"]["client_ip"] = client.ip
        logs.append(web_log)
        
        # 3. لاگ شبکه: اتصال جدید
        network_gen = NetworkLogGenerator(network_device)
        network_log = network_gen.generate_connection_log()
        network_log["event"]["correlation_id"] = correlation_id
        network_log["event"]["src_ip"] = client.ip
        network_log["event"]["dst_ip"] = web_server.ip
        logs.append(network_log)
        
        # 4. لاگ SOC: Authentication
        soc_log = self.soc_generator.generate_auth_log(
            user, client.ip, client.get_info()
        )
        soc_log["event"]["correlation_id"] = correlation_id
        logs.append(soc_log)
        
        return logs
    
    def generate_file_access_event(self):
        """رویداد دسترسی به فایل - چند لاگ مرتبط"""
        correlation_id = str(uuid.uuid4())
        user = random.choice(USERS)
        client = random.choice(self.client_devices)
        file_path = random.choice([
            "/var/www/index.html", "/etc/passwd", "/home/user/document.pdf",
            "C:\\Windows\\System32\\config\\sam", "D:\\Data\\secret.txt"
        ])
        
        logs = []
        
        # 1. لاگ کلاینت: دسترسی به فایل
        client_gen = ClientLogGenerator(client)
        file_log = client_gen.generate_file_access_log()
        file_log["event"]["correlation_id"] = correlation_id
        file_log["event"]["user"] = user
        file_log["event"]["file_path"] = file_path
        logs.append(file_log)
        
        # 2. لاگ SOC: Access Control
        soc_access_log = self.soc_generator.generate_access_control_log(
            user, file_path, client.get_info()
        )
        soc_access_log["event"]["correlation_id"] = correlation_id
        logs.append(soc_access_log)
        
        # 3. اگر فایل حساس باشد، لاگ Compliance
        if "secret" in file_path.lower() or "passwd" in file_path.lower() or "sam" in file_path.lower():
            soc_compliance_log = self.soc_generator.generate_compliance_log(
                user, client.get_info()
            )
            soc_compliance_log["event"]["correlation_id"] = correlation_id
            soc_compliance_log["event"]["compliance_event"] = "sensitive_data_access"
            logs.append(soc_compliance_log)
        
        return logs
    
    def generate_password_change_event(self):
        """رویداد تغییر پسورد - چند لاگ مرتبط"""
        correlation_id = str(uuid.uuid4())
        user = random.choice(USERS)
        client = random.choice(self.client_devices)
        web_server = random.choice(self.web_servers)
        
        logs = []
        
        # 1. لاگ کلاینت: تغییر پسورد
        client_gen = ClientLogGenerator(client)
        pwd_log = client_gen.generate_password_change_log()
        pwd_log["event"]["correlation_id"] = correlation_id
        pwd_log["event"]["user"] = user
        pwd_log["event"]["target_user"] = user
        logs.append(pwd_log)
        
        # 2. لاگ وب: تغییر پسورد در سیستم
        web_gen = WebLogGenerator(web_server)
        web_auth_log = web_gen.generate_authentication_log()
        web_auth_log["event"]["correlation_id"] = correlation_id
        web_auth_log["event"]["auth_type"] = "password_change"
        web_auth_log["event"]["user"] = user
        logs.append(web_auth_log)
        
        # 3. لاگ SOC: Authentication
        soc_log = self.soc_generator.generate_auth_log(
            user, client.ip, client.get_info()
        )
        soc_log["event"]["correlation_id"] = correlation_id
        soc_log["event"]["auth_event"] = "password_change"
        logs.append(soc_log)
        
        return logs
    
    def generate_permission_change_event(self):
        """رویداد تغییر پرمیشن - چند لاگ مرتبط"""
        correlation_id = str(uuid.uuid4())
        user = random.choice(USERS)
        client = random.choice(self.client_devices)
        
        logs = []
        
        # 1. لاگ کلاینت: تغییر پرمیشن
        client_gen = ClientLogGenerator(client)
        perm_log = client_gen.generate_permission_change_log()
        perm_log["event"]["correlation_id"] = correlation_id
        perm_log["event"]["user"] = user
        logs.append(perm_log)
        
        # 2. لاگ SOC: Access Control
        soc_log = self.soc_generator.generate_access_control_log(
            user, perm_log["event"]["target_file"], client.get_info()
        )
        soc_log["event"]["correlation_id"] = correlation_id
        soc_log["event"]["access_event"] = "permission_modify"
        logs.append(soc_log)
        
        # 3. لاگ SOC: Compliance
        soc_compliance = self.soc_generator.generate_compliance_log(
            user, client.get_info()
        )
        soc_compliance["event"]["correlation_id"] = correlation_id
        soc_compliance["event"]["compliance_event"] = "configuration_change"
        logs.append(soc_compliance)
        
        return logs
    
    def generate_security_threat_event(self):
        """رویداد تهدید امنیتی - چند لاگ مرتبط"""
        correlation_id = str(uuid.uuid4())
        source_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        network_device = random.choice(self.network_devices)
        web_server = random.choice(self.web_servers)
        client = random.choice(self.client_devices)
        
        logs = []
        
        # 1. لاگ شبکه: رویداد امنیتی
        network_gen = NetworkLogGenerator(network_device)
        network_security = network_gen.generate_security_event()
        network_security["event"]["correlation_id"] = correlation_id
        network_security["event"]["src_ip"] = source_ip
        logs.append(network_security)
        
        # 2. لاگ وب: حمله امنیتی
        web_gen = WebLogGenerator(web_server)
        web_security = web_gen.generate_security_log()
        web_security["event"]["correlation_id"] = correlation_id
        web_security["event"]["client_ip"] = source_ip
        logs.append(web_security)
        
        # 3. لاگ SOC: Threat Detection
        soc_threat = self.soc_generator.generate_threat_detection_log(
            source_ip, network_device.get_info()
        )
        soc_threat["event"]["correlation_id"] = correlation_id
        logs.append(soc_threat)
        
        # 4. لاگ SOC: Incident
        incident_type = random.choice([
            "malware_detection", "intrusion_attempt", "data_exfiltration_attempt"
        ])
        soc_incident = self.soc_generator.generate_incident_log(
            incident_type, network_device.get_info()
        )
        soc_incident["event"]["correlation_id"] = correlation_id
        logs.append(soc_incident)
        
        return logs
    
    def generate_api_request_event(self):
        """رویداد درخواست API - چند لاگ مرتبط"""
        correlation_id = str(uuid.uuid4())
        user = random.choice(USERS)
        client = random.choice(self.client_devices)
        web_server = random.choice(self.web_servers)
        network_device = random.choice(self.network_devices)
        
        logs = []
        
        # 1. لاگ وب: درخواست HTTP
        web_gen = WebLogGenerator(web_server)
        http_log = web_gen.generate_http_request()
        http_log["event"]["correlation_id"] = correlation_id
        http_log["event"]["client_ip"] = client.ip
        logs.append(http_log)
        
        # 2. لاگ وب: API Call
        api_log = web_gen.generate_api_log()
        api_log["event"]["correlation_id"] = correlation_id
        logs.append(api_log)
        
        # 3. لاگ شبکه: اتصال
        network_gen = NetworkLogGenerator(network_device)
        network_log = network_gen.generate_connection_log()
        network_log["event"]["correlation_id"] = correlation_id
        network_log["event"]["src_ip"] = client.ip
        network_log["event"]["dst_ip"] = web_server.ip
        network_log["event"]["protocol"] = "HTTPS"
        logs.append(network_log)
        
        return logs
    
    def generate_privilege_escalation_event(self):
        """رویداد افزایش سطح دسترسی - چند لاگ مرتبط"""
        correlation_id = str(uuid.uuid4())
        user = random.choice(USERS)
        client = random.choice(self.client_devices)
        
        logs = []
        
        # 1. لاگ کلاینت: Privilege Escalation
        client_gen = ClientLogGenerator(client)
        priv_log = client_gen.generate_privilege_escalation_log()
        priv_log["event"]["correlation_id"] = correlation_id
        priv_log["event"]["user"] = user
        logs.append(priv_log)
        
        # 2. لاگ SOC: Access Control
        soc_access = self.soc_generator.generate_access_control_log(
            user, "system", client.get_info()
        )
        soc_access["event"]["correlation_id"] = correlation_id
        soc_access["event"]["access_event"] = "privilege_escalation"
        logs.append(soc_access)
        
        # 3. لاگ SOC: Threat Detection (اگر ناموفق باشد)
        if not priv_log["event"]["success"]:
            soc_threat = self.soc_generator.generate_threat_detection_log(
                client.ip, client.get_info()
            )
            soc_threat["event"]["correlation_id"] = correlation_id
            soc_threat["event"]["threat_type"] = "unauthorized_access_attempt"
            logs.append(soc_threat)
        
        # 4. لاگ SOC: Incident
        soc_incident = self.soc_generator.generate_incident_log(
            "privilege_escalation_attempt", client.get_info()
        )
        soc_incident["event"]["correlation_id"] = correlation_id
        logs.append(soc_incident)
        
        return logs
    
    def generate_random_correlated_event(self):
        """تولید یک رویداد مرتبط رندوم"""
        event_types = [
            self.generate_user_login_event,
            self.generate_file_access_event,
            self.generate_password_change_event,
            self.generate_permission_change_event,
            self.generate_security_threat_event,
            self.generate_api_request_event,
            self.generate_privilege_escalation_event,
            self.generate_ad_login_event,
            self.generate_ad_password_change_event,
            self.generate_ad_group_change_event,
            self.generate_database_query_event
        ]
        return random.choice(event_types)()
    
    def generate_ad_login_event(self):
        """رویداد لاگین AD - چند لاگ مرتبط"""
        correlation_id = str(uuid.uuid4())
        user = random.choice(USERS)
        client = random.choice(self.client_devices)
        ad_server = random.choice(self.ad_servers)
        network_device = random.choice(self.network_devices)
        
        logs = []
        
        # 1. لاگ AD: Authentication
        ad_gen = ADLogGenerator(ad_server)
        ad_log = ad_gen.generate_authentication_log()
        ad_log["event"]["correlation_id"] = correlation_id
        ad_log["event"]["user"] = user
        ad_log["event"]["source_ip"] = client.ip
        logs.append(ad_log)
        
        # 2. لاگ کلاینت: Login
        client_gen = ClientLogGenerator(client)
        client_log = client_gen.generate_login_log()
        client_log["event"]["correlation_id"] = correlation_id
        client_log["event"]["user"] = user
        logs.append(client_log)
        
        # 3. لاگ شبکه: Connection
        network_gen = NetworkLogGenerator(network_device)
        network_log = network_gen.generate_connection_log()
        network_log["event"]["correlation_id"] = correlation_id
        network_log["event"]["src_ip"] = client.ip
        network_log["event"]["dst_ip"] = ad_server.ip
        network_log["event"]["protocol"] = "LDAP"
        logs.append(network_log)
        
        # 4. لاگ SOC: Authentication
        soc_log = self.soc_generator.generate_auth_log(
            user, client.ip, client.get_info()
        )
        soc_log["event"]["correlation_id"] = correlation_id
        logs.append(soc_log)
        
        return logs
    
    def generate_ad_password_change_event(self):
        """رویداد تغییر پسورد AD - چند لاگ مرتبط"""
        correlation_id = str(uuid.uuid4())
        user = random.choice(USERS)
        client = random.choice(self.client_devices)
        ad_server = random.choice(self.ad_servers)
        
        logs = []
        
        # 1. لاگ AD: Password Change
        ad_gen = ADLogGenerator(ad_server)
        ad_pwd_log = ad_gen.generate_password_change_log()
        ad_pwd_log["event"]["correlation_id"] = correlation_id
        ad_pwd_log["event"]["user"] = user
        ad_pwd_log["event"]["target_user"] = user
        logs.append(ad_pwd_log)
        
        # 2. لاگ کلاینت: Password Change
        client_gen = ClientLogGenerator(client)
        client_pwd_log = client_gen.generate_password_change_log()
        client_pwd_log["event"]["correlation_id"] = correlation_id
        client_pwd_log["event"]["user"] = user
        logs.append(client_pwd_log)
        
        # 3. لاگ SOC: Authentication
        soc_log = self.soc_generator.generate_auth_log(
            user, client.ip, client.get_info()
        )
        soc_log["event"]["correlation_id"] = correlation_id
        soc_log["event"]["auth_event"] = "password_change"
        logs.append(soc_log)
        
        return logs
    
    def generate_ad_group_change_event(self):
        """رویداد تغییر گروه AD - چند لاگ مرتبط"""
        correlation_id = str(uuid.uuid4())
        user = random.choice(USERS)
        ad_server = random.choice(self.ad_servers)
        
        logs = []
        
        # 1. لاگ AD: Group Management
        ad_gen = ADLogGenerator(ad_server)
        ad_group_log = ad_gen.generate_group_management_log()
        ad_group_log["event"]["correlation_id"] = correlation_id
        ad_group_log["event"]["user"] = user
        logs.append(ad_group_log)
        
        # 2. لاگ AD: Permission Change
        ad_perm_log = ad_gen.generate_permission_change_log()
        ad_perm_log["event"]["correlation_id"] = correlation_id
        logs.append(ad_perm_log)
        
        # 3. لاگ SOC: Access Control
        soc_log = self.soc_generator.generate_access_control_log(
            user, ad_group_log["event"]["group_name"], ad_server.get_info()
        )
        soc_log["event"]["correlation_id"] = correlation_id
        logs.append(soc_log)
        
        return logs
    
    def generate_database_query_event(self):
        """رویداد Query دیتابیس - چند لاگ مرتبط"""
        correlation_id = str(uuid.uuid4())
        user = random.choice(USERS)
        web_server = random.choice(self.web_servers)
        db_server = random.choice(self.db_servers)
        network_device = random.choice(self.network_devices)
        
        logs = []
        
        # 1. لاگ دیتابیس: Query
        db_gen = DatabaseLogGenerator(db_server)
        db_log = db_gen.generate_query_log()
        db_log["event"]["correlation_id"] = correlation_id
        db_log["event"]["user"] = user
        logs.append(db_log)
        
        # 2. لاگ وب: API Call
        web_gen = WebLogGenerator(web_server)
        api_log = web_gen.generate_api_log()
        api_log["event"]["correlation_id"] = correlation_id
        logs.append(api_log)
        
        # 3. لاگ شبکه: Connection
        network_gen = NetworkLogGenerator(network_device)
        network_log = network_gen.generate_connection_log()
        network_log["event"]["correlation_id"] = correlation_id
        network_log["event"]["src_ip"] = web_server.ip
        network_log["event"]["dst_ip"] = db_server.ip
        network_log["event"]["protocol"] = random.choice(["MySQL", "PostgreSQL", "MSSQL"])
        logs.append(network_log)
        
        return logs


