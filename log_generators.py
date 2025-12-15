"""
تولیدکننده‌های لاگ برای انواع مختلف دستگاه‌ها
"""
import random
import uuid
from datetime import datetime, timedelta
from config import (
    NETWORK_PROTOCOLS, HTTP_METHODS, HTTP_RESPONSE_CODES,
    SEVERITY_LEVELS, USERS, FILE_PATHS, APPLICATIONS, SPLUNK_INDEX,
    AD_GROUPS, DATABASE_TYPES, DNS_RECORD_TYPES, EMAIL_DOMAINS
)


class NetworkLogGenerator:
    """تولیدکننده لاگ‌های شبکه"""
    
    def __init__(self, device):
        self.device = device
    
    def generate_connection_log(self):
        """لاگ اتصال شبکه"""
        protocol = random.choice(NETWORK_PROTOCOLS)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 21, 25, 53, 3389, 3306, 5432])
        src_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        dst_ip = self.device.ip
        
        return {
            "event": {
                "type": "network_connection",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.device.hostname,
                "device_type": self.device.device_type,
                "vendor": self.device.vendor,
                "severity": random.choice(["INFO", "WARN"]),
                "protocol": protocol,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "connection_status": random.choice(["established", "closed", "timeout", "reset"]),
                "bytes_sent": random.randint(0, 10000000),
                "bytes_received": random.randint(0, 10000000),
                "duration_ms": random.randint(1, 300000),
                "message": f"{protocol} connection {random.choice(['established', 'closed', 'timeout'])}"
            },
            "sourcetype": f"network:{self.device.device_type}",
            "index": SPLUNK_INDEX
        }
    
    def generate_packet_filter_log(self):
        """لاگ فیلترینگ پکت"""
        action = random.choice(["allowed", "blocked", "dropped", "rejected"])
        protocol = random.choice(NETWORK_PROTOCOLS)
        src_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        return {
            "event": {
                "type": "packet_filter",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.device.hostname,
                "device_type": self.device.device_type,
                "severity": "WARN" if action != "allowed" else "INFO",
                "action": action,
                "protocol": protocol,
                "src_ip": src_ip,
                "dst_ip": self.device.ip,
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 22, 21, 25, 53]),
                "rule_id": f"FW-{random.randint(1000, 9999)}",
                "reason": random.choice([
                    "Firewall rule match",
                    "IP blacklist",
                    "Port scan detected",
                    "Rate limit exceeded",
                    "Geo-blocked"
                ]) if action != "allowed" else "Rule allowed",
                "message": f"Packet {action} from {src_ip}"
            },
            "sourcetype": f"network:firewall",
            "index": SPLUNK_INDEX
        }
    
    def generate_routing_log(self):
        """لاگ مسیریابی"""
        return {
            "event": {
                "type": "routing_event",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.device.hostname,
                "device_type": self.device.device_type,
                "severity": "INFO",
                "route_type": random.choice(["static", "dynamic", "BGP", "OSPF", "EIGRP"]),
                "destination": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24",
                "next_hop": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "metric": random.randint(1, 100),
                "status": random.choice(["added", "removed", "updated", "failed"]),
                "message": f"Route {random.choice(['added', 'removed', 'updated'])}"
            },
            "sourcetype": f"network:routing",
            "index": SPLUNK_INDEX
        }
    
    def generate_bandwidth_log(self):
        """لاگ استفاده از پهنای باند"""
        return {
            "event": {
                "type": "bandwidth_usage",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.device.hostname,
                "device_type": self.device.device_type,
                "severity": "INFO",
                "interface": f"eth{random.randint(0, 7)}",
                "bytes_in": random.randint(0, 1000000000),
                "bytes_out": random.randint(0, 1000000000),
                "packets_in": random.randint(0, 1000000),
                "packets_out": random.randint(0, 1000000),
                "utilization_percent": round(random.uniform(0, 100), 2),
                "message": "Bandwidth usage recorded"
            },
            "sourcetype": f"network:bandwidth",
            "index": SPLUNK_INDEX
        }
    
    def generate_security_event(self):
        """رویداد امنیتی شبکه"""
        event_type = random.choice([
            "port_scan", "intrusion_attempt", "ddos_attempt",
            "malicious_traffic", "suspicious_connection", "anomaly_detected"
        ])
        
        return {
            "event": {
                "type": "network_security",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.device.hostname,
                "device_type": self.device.device_type,
                "severity": random.choice(["WARN", "ERROR", "CRITICAL"]),
                "security_event_type": event_type,
                "src_ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "dst_ip": self.device.ip,
                "protocol": random.choice(NETWORK_PROTOCOLS),
                "port": random.choice([22, 80, 443, 3389, 3306]),
                "threat_level": random.choice(["low", "medium", "high", "critical"]),
                "action_taken": random.choice(["blocked", "logged", "alerted", "quarantined"]),
                "message": f"{event_type.replace('_', ' ').title()} detected from {random.choice(['internal', 'external'])} source"
            },
            "sourcetype": f"network:security",
            "index": SPLUNK_INDEX
        }
    
    def generate_vpn_log(self):
        """لاگ VPN"""
        action = random.choice(["connect", "disconnect", "reconnect", "failed"])
        
        return {
            "event": {
                "type": "vpn_event",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.device.hostname,
                "device_type": self.device.device_type,
                "severity": "ERROR" if action == "failed" else "INFO",
                "action": action,
                "user": random.choice(USERS),
                "src_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "vpn_type": random.choice(["IPSec", "SSL", "PPTP", "L2TP"]),
                "duration_seconds": random.randint(60, 86400) if action == "disconnect" else None,
                "message": f"VPN {action} for user {random.choice(USERS)}"
            },
            "sourcetype": f"network:vpn",
            "index": SPLUNK_INDEX
        }
    
    def generate_random_log(self):
        """تولید یک لاگ رندوم شبکه"""
        log_types = [
            self.generate_connection_log,
            self.generate_packet_filter_log,
            self.generate_routing_log,
            self.generate_bandwidth_log,
            self.generate_security_event,
            self.generate_vpn_log
        ]
        return random.choice(log_types)()


class WebLogGenerator:
    """تولیدکننده لاگ‌های وب سرور"""
    
    def __init__(self, server):
        self.server = server
    
    def generate_http_request(self):
        """لاگ درخواست HTTP"""
        method = random.choice(HTTP_METHODS)
        status_code = random.choice(HTTP_RESPONSE_CODES)
        user_agent = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "curl/7.68.0",
            "PostmanRuntime/7.28.4"
        ])
        endpoint = random.choice([
            "/api/users", "/api/products", "/api/orders", "/login", "/logout",
            "/dashboard", "/admin", "/api/data", "/search", "/upload"
        ])
        
        return {
            "event": {
                "type": "http_request",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.server.hostname,
                "server_type": self.server.server_type,
                "severity": "ERROR" if status_code >= 500 else ("WARN" if status_code >= 400 else "INFO"),
                "method": method,
                "url": f"https://{self.server.domain}{endpoint}",
                "endpoint": endpoint,
                "status_code": status_code,
                "response_time_ms": random.randint(1, 5000),
                "bytes_sent": random.randint(100, 1000000),
                "bytes_received": random.randint(50, 50000),
                "user_agent": user_agent,
                "client_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "referer": random.choice([None, f"https://{self.server.domain}/", "https://google.com"]),
                "message": f"{method} {endpoint} - {status_code}"
            },
            "sourcetype": f"web:{self.server.server_type}",
            "index": SPLUNK_INDEX
        }
    
    def generate_authentication_log(self):
        """لاگ احراز هویت"""
        auth_type = random.choice(["login", "logout", "login_failed", "session_expired", "token_refresh"])
        success = auth_type in ["login", "logout", "token_refresh"]
        
        return {
            "event": {
                "type": "authentication",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.server.hostname,
                "server_type": self.server.server_type,
                "severity": "WARN" if not success else "INFO",
                "auth_type": auth_type,
                "user": random.choice(USERS),
                "client_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "success": success,
                "session_id": str(uuid.uuid4()) if success else None,
                "failure_reason": random.choice([
                    "Invalid password", "User not found", "Account locked",
                    "Too many attempts", "Token expired"
                ]) if not success else None,
                "mfa_used": random.choice([True, False]) if success else False,
                "message": f"Authentication {auth_type} for user {random.choice(USERS)}"
            },
            "sourcetype": f"web:auth",
            "index": SPLUNK_INDEX
        }
    
    def generate_api_log(self):
        """لاگ API"""
        api_type = random.choice(["REST", "GraphQL", "SOAP", "gRPC"])
        method = random.choice(HTTP_METHODS) if api_type == "REST" else "POST"
        
        return {
            "event": {
                "type": "api_call",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.server.hostname,
                "server_type": self.server.server_type,
                "severity": "INFO",
                "api_type": api_type,
                "method": method,
                "endpoint": f"/api/v{random.randint(1, 3)}/{random.choice(['users', 'products', 'orders', 'analytics'])}",
                "status_code": random.choice(HTTP_RESPONSE_CODES),
                "response_time_ms": random.randint(10, 2000),
                "api_key": f"key_{random.randint(1000, 9999)}" if random.choice([True, False]) else None,
                "rate_limit_remaining": random.randint(0, 1000),
                "message": f"{api_type} API call - {method}"
            },
            "sourcetype": f"web:api",
            "index": SPLUNK_INDEX
        }
    
    def generate_error_log(self):
        """لاگ خطا"""
        error_type = random.choice([
            "application_error", "database_error", "timeout_error",
            "connection_error", "validation_error", "internal_error"
        ])
        
        return {
            "event": {
                "type": "error",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.server.hostname,
                "server_type": self.server.server_type,
                "severity": random.choice(["ERROR", "CRITICAL"]),
                "error_type": error_type,
                "error_message": random.choice([
                    "Database connection timeout",
                    "Invalid SQL query",
                    "Out of memory",
                    "File not found",
                    "Permission denied",
                    "Internal server error"
                ]),
                "stack_trace": f"Error at line {random.randint(1, 1000)} in {random.choice(['app.py', 'models.py', 'utils.py'])}",
                "request_id": str(uuid.uuid4()),
                "message": f"{error_type.replace('_', ' ').title()} occurred"
            },
            "sourcetype": f"web:error",
            "index": SPLUNK_INDEX
        }
    
    def generate_security_log(self):
        """لاگ امنیتی وب"""
        attack_type = random.choice([
            "sql_injection", "xss_attempt", "csrf_attempt", "brute_force",
            "path_traversal", "file_upload_attack", "command_injection"
        ])
        
        return {
            "event": {
                "type": "web_security",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.server.hostname,
                "server_type": self.server.server_type,
                "severity": random.choice(["WARN", "ERROR", "CRITICAL"]),
                "attack_type": attack_type,
                "client_ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "user_agent": random.choice([
                    "sqlmap/1.6", "nikto", "nmap", "Mozilla/5.0"
                ]),
                "endpoint": random.choice([
                    "/login", "/api/users", "/admin", "/upload", "/search"
                ]),
                "payload": random.choice([
                    "'; DROP TABLE users--",
                    "<script>alert('xss')</script>",
                    "../../etc/passwd",
                    "| cat /etc/passwd"
                ]) if attack_type in ["sql_injection", "xss_attempt", "path_traversal", "command_injection"] else None,
                "action_taken": random.choice(["blocked", "logged", "alerted", "rate_limited"]),
                "message": f"{attack_type.replace('_', ' ').title()} attempt detected"
            },
            "sourcetype": f"web:security",
            "index": SPLUNK_INDEX
        }
    
    def generate_random_log(self):
        """تولید یک لاگ رندوم وب"""
        log_types = [
            self.generate_http_request,
            self.generate_authentication_log,
            self.generate_api_log,
            self.generate_error_log,
            self.generate_security_log
        ]
        return random.choice(log_types)()


class ClientLogGenerator:
    """تولیدکننده لاگ‌های کلاینت"""
    
    def __init__(self, client):
        self.client = client
    
    def generate_login_log(self):
        """لاگ ورود کاربر"""
        login_type = random.choice(["login", "login_failed", "logout"])
        success = login_type == "login" or login_type == "logout"
        
        return {
            "event": {
                "type": "user_login",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.client.hostname,
                "os_type": self.client.os_type,
                "severity": "WARN" if not success else "INFO",
                "login_type": login_type,
                "user": random.choice(USERS),
                "source_ip": self.client.ip,
                "success": success,
                "session_id": str(uuid.uuid4()) if success else None,
                "failure_reason": random.choice([
                    "Invalid password", "User not found", "Account disabled",
                    "Too many attempts", "MFA required"
                ]) if not success else None,
                "login_method": random.choice(["local", "domain", "SSO", "LDAP"]),
                "message": f"User {login_type} - {random.choice(USERS)}"
            },
            "sourcetype": f"client:auth",
            "index": SPLUNK_INDEX
        }
    
    def generate_password_change_log(self):
        """لاگ تغییر پسورد"""
        success = random.choice([True, False])
        admin_initiated = random.choice([True, False])
        
        return {
            "event": {
                "type": "password_change",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.client.hostname,
                "os_type": self.client.os_type,
                "severity": "WARN" if not success else "INFO",
                "user": random.choice(USERS),
                "target_user": random.choice(USERS),
                "success": success,
                "admin_initiated": admin_initiated,
                "source_ip": self.client.ip,
                "failure_reason": random.choice([
                    "Password too weak", "Password reuse not allowed",
                    "Invalid current password", "Account locked"
                ]) if not success else None,
                "message": f"Password change {'attempt' if not success else ''} for user {random.choice(USERS)}"
            },
            "sourcetype": f"client:security",
            "index": SPLUNK_INDEX
        }
    
    def generate_file_access_log(self):
        """لاگ دسترسی به فایل"""
        access_type = random.choice(["read", "write", "execute", "delete", "access_denied"])
        success = access_type != "access_denied"
        
        return {
            "event": {
                "type": "file_access",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.client.hostname,
                "os_type": self.client.os_type,
                "severity": "WARN" if not success else "INFO",
                "access_type": access_type,
                "user": random.choice(USERS),
                "file_path": random.choice(FILE_PATHS) + random.choice([
                    "document.pdf", "data.txt", "config.json", "script.sh",
                    "database.db", "log.txt", "secret.key"
                ]),
                "success": success,
                "file_size_bytes": random.randint(100, 10000000) if success else None,
                "denial_reason": random.choice([
                    "Permission denied", "File not found", "Access control list",
                    "File locked", "Insufficient privileges"
                ]) if not success else None,
                "message": f"File {access_type} {'denied' if not success else 'granted'}"
            },
            "sourcetype": f"client:file_access",
            "index": SPLUNK_INDEX
        }
    
    def generate_permission_change_log(self):
        """لاگ تغییر پرمیشن"""
        change_type = random.choice(["chmod", "chown", "acl_modify", "group_change"])
        
        return {
            "event": {
                "type": "permission_change",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.client.hostname,
                "os_type": self.client.os_type,
                "severity": "WARN",
                "change_type": change_type,
                "user": random.choice(USERS),
                "target_file": random.choice(FILE_PATHS) + random.choice([
                    "document.pdf", "script.sh", "config.json"
                ]),
                "old_permission": f"{random.randint(0, 7)}{random.randint(0, 7)}{random.randint(0, 7)}" if change_type == "chmod" else None,
                "new_permission": f"{random.randint(0, 7)}{random.randint(0, 7)}{random.randint(0, 7)}" if change_type == "chmod" else None,
                "old_owner": random.choice(USERS),
                "new_owner": random.choice(USERS) if change_type == "chown" else None,
                "message": f"Permission change: {change_type}"
            },
            "sourcetype": f"client:permissions",
            "index": SPLUNK_INDEX
        }
    
    def generate_privilege_escalation_log(self):
        """لاگ افزایش سطح دسترسی"""
        escalation_type = random.choice(["sudo", "runas", "su", "escalation_attempt"])
        success = escalation_type != "escalation_attempt"
        
        return {
            "event": {
                "type": "privilege_escalation",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.client.hostname,
                "os_type": self.client.os_type,
                "severity": "WARN" if success else "ERROR",
                "escalation_type": escalation_type,
                "user": random.choice(USERS),
                "target_user": "root" if self.client.os_type != "Windows" else "Administrator",
                "success": success,
                "command": random.choice([
                    "rm -rf /tmp/*", "systemctl restart service",
                    "net user administrator password", "chmod 777 /etc/passwd"
                ]),
                "failure_reason": random.choice([
                    "Insufficient privileges", "Password incorrect",
                    "User not in sudoers", "Account locked"
                ]) if not success else None,
                "message": f"Privilege escalation {'attempt' if not success else ''}: {escalation_type}"
            },
            "sourcetype": f"client:security",
            "index": SPLUNK_INDEX
        }
    
    def generate_application_log(self):
        """لاگ اجرای برنامه"""
        action = random.choice(["launch", "terminate", "crash"])
        
        return {
            "event": {
                "type": "application_execution",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.client.hostname,
                "os_type": self.client.os_type,
                "severity": "ERROR" if action == "crash" else "INFO",
                "action": action,
                "user": random.choice(USERS),
                "application": random.choice(APPLICATIONS),
                "process_id": random.randint(1000, 99999),
                "parent_process_id": random.randint(1, 9999),
                "command_line": f"{random.choice(APPLICATIONS)} {random.choice(['--debug', '--verbose', '--config=/etc/app.conf'])}",
                "exit_code": random.randint(0, 255) if action != "launch" else None,
                "message": f"Application {action}: {random.choice(APPLICATIONS)}"
            },
            "sourcetype": f"client:application",
            "index": SPLUNK_INDEX
        }
    
    def generate_system_event_log(self):
        """لاگ رویداد سیستم"""
        event_type = random.choice([
            "system_startup", "system_shutdown", "service_start",
            "service_stop", "configuration_change", "registry_change"
        ])
        
        return {
            "event": {
                "type": "system_event",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.client.hostname,
                "os_type": self.client.os_type,
                "severity": "INFO",
                "event_type": event_type,
                "user": random.choice(["system", "SYSTEM", "root", "Administrator"]),
                "service_name": random.choice([
                    "apache2", "nginx", "mysql", "postgresql",
                    "ssh", "httpd", "winlogon"
                ]) if "service" in event_type else None,
                "configuration_key": random.choice([
                    "HKEY_LOCAL_MACHINE\\Software",
                    "/etc/ssh/sshd_config",
                    "C:\\Windows\\System32\\config"
                ]) if "configuration" in event_type or "registry" in event_type else None,
                "message": f"System event: {event_type.replace('_', ' ').title()}"
            },
            "sourcetype": f"client:system",
            "index": SPLUNK_INDEX
        }
    
    def generate_random_log(self):
        """تولید یک لاگ رندوم کلاینت"""
        log_types = [
            self.generate_login_log,
            self.generate_password_change_log,
            self.generate_file_access_log,
            self.generate_permission_change_log,
            self.generate_privilege_escalation_log,
            self.generate_application_log,
            self.generate_system_event_log
        ]
        return random.choice(log_types)()


class SOCLogGenerator:
    """تولیدکننده لاگ‌های امنیتی SOC"""
    
    def __init__(self):
        pass
    
    def generate_auth_log(self, user, source_ip, device_info):
        """لاگ احراز هویت SOC"""
        auth_event = random.choice([
            "login_success", "login_failed", "logout", "account_locked",
            "password_change", "password_reset", "token_generated", "token_revoked",
            "session_hijack_attempt", "mfa_success", "mfa_failed"
        ])
        
        return {
            "event": {
                "type": "soc_authentication",
                "timestamp": datetime.utcnow().isoformat(),
                "host": device_info.get("hostname", "unknown"),
                "severity": "ERROR" if "failed" in auth_event or "hijack" in auth_event else "INFO",
                "auth_event": auth_event,
                "user": user,
                "source_ip": source_ip,
                "device_type": device_info.get("device_type") or device_info.get("os_type") or device_info.get("server_type"),
                "success": "failed" not in auth_event and "hijack" not in auth_event,
                "session_id": str(uuid.uuid4()) if "login" in auth_event or "token" in auth_event else None,
                "mfa_method": random.choice(["SMS", "TOTP", "Email", "Biometric"]) if "mfa" in auth_event else None,
                "failure_count": random.randint(1, 10) if "failed" in auth_event else None,
                "message": f"SOC Auth: {auth_event.replace('_', ' ').title()} for {user}"
            },
            "sourcetype": "soc:authentication",
            "index": SPLUNK_INDEX
        }
    
    def generate_access_control_log(self, user, resource, device_info):
        """لاگ کنترل دسترسی SOC"""
        access_event = random.choice([
            "file_access_granted", "file_access_denied", "directory_access",
            "permission_modify", "privilege_escalation", "unauthorized_access_attempt",
            "sensitive_data_access", "resource_access_pattern"
        ])
        
        return {
            "event": {
                "type": "soc_access_control",
                "timestamp": datetime.utcnow().isoformat(),
                "host": device_info.get("hostname", "unknown"),
                "severity": "ERROR" if "denied" in access_event or "unauthorized" in access_event else "WARN",
                "access_event": access_event,
                "user": user,
                "resource": resource,
                "device_type": device_info.get("device_type") or device_info.get("os_type") or device_info.get("server_type"),
                "action": random.choice(["read", "write", "execute", "delete", "modify"]),
                "success": "denied" not in access_event and "unauthorized" not in access_event,
                "permission_level": random.choice(["read", "write", "execute", "admin"]),
                "message": f"SOC Access: {access_event.replace('_', ' ').title()} - {resource}"
            },
            "sourcetype": "soc:access_control",
            "index": SPLUNK_INDEX
        }
    
    def generate_threat_detection_log(self, source_ip, device_info):
        """لاگ تشخیص تهدید SOC"""
        threat_type = random.choice([
            "malware_detected", "malware_quarantined", "intrusion_detected",
            "anomaly_detected", "suspicious_process", "data_exfiltration_attempt",
            "command_injection", "port_scan", "ddos_attempt"
        ])
        
        return {
            "event": {
                "type": "soc_threat_detection",
                "timestamp": datetime.utcnow().isoformat(),
                "host": device_info.get("hostname", "unknown"),
                "severity": random.choice(["WARN", "ERROR", "CRITICAL"]),
                "threat_type": threat_type,
                "source_ip": source_ip,
                "device_type": device_info.get("device_type") or device_info.get("os_type") or device_info.get("server_type"),
                "threat_level": random.choice(["low", "medium", "high", "critical"]),
                "malware_name": random.choice([
                    "Trojan.Win32.Generic", "Backdoor.Linux.Bash",
                    "Ransomware.CryptoLocker", "Spyware.Keylogger"
                ]) if "malware" in threat_type else None,
                "action_taken": random.choice([
                    "blocked", "quarantined", "alerted", "investigating", "remediated"
                ]),
                "threat_intelligence_match": random.choice([True, False]),
                "message": f"SOC Threat: {threat_type.replace('_', ' ').title()} detected"
            },
            "sourcetype": "soc:threat_detection",
            "index": SPLUNK_INDEX
        }
    
    def generate_compliance_log(self, user, device_info):
        """لاگ Compliance SOC"""
        compliance_event = random.choice([
            "policy_violation", "configuration_change", "compliance_check",
            "audit_trail", "data_access", "data_retention"
        ])
        
        return {
            "event": {
                "type": "soc_compliance",
                "timestamp": datetime.utcnow().isoformat(),
                "host": device_info.get("hostname", "unknown"),
                "severity": "WARN" if "violation" in compliance_event else "INFO",
                "compliance_event": compliance_event,
                "user": user,
                "device_type": device_info.get("device_type") or device_info.get("os_type") or device_info.get("server_type"),
                "policy_name": random.choice([
                    "Password Policy", "Access Control Policy",
                    "Data Retention Policy", "Network Security Policy"
                ]),
                "violation_type": random.choice([
                    "Weak password", "Unauthorized access",
                    "Data retention violation", "Configuration drift"
                ]) if "violation" in compliance_event else None,
                "compliance_standard": random.choice(["ISO27001", "PCI-DSS", "GDPR", "HIPAA"]),
                "message": f"SOC Compliance: {compliance_event.replace('_', ' ').title()}"
            },
            "sourcetype": "soc:compliance",
            "index": SPLUNK_INDEX
        }
    
    def generate_incident_log(self, incident_type, device_info):
        """لاگ Incident Response SOC"""
        return {
            "event": {
                "type": "soc_incident",
                "timestamp": datetime.utcnow().isoformat(),
                "host": device_info.get("hostname", "unknown"),
                "severity": random.choice(["WARN", "ERROR", "CRITICAL"]),
                "incident_type": incident_type,
                "incident_id": f"INC-{random.randint(10000, 99999)}",
                "device_type": device_info.get("device_type") or device_info.get("os_type") or device_info.get("server_type"),
                "status": random.choice(["open", "investigating", "contained", "remediated", "closed"]),
                "assigned_analyst": random.choice(["analyst1", "analyst2", "analyst3"]),
                "investigation_activities": random.choice([
                    "Log analysis", "Network traffic analysis",
                    "Malware analysis", "User behavior analysis"
                ]),
                "remediation_actions": random.choice([
                    "Blocked IP", "Quarantined device",
                    "Reset credentials", "Applied patch"
                ]),
                "message": f"SOC Incident: {incident_type.replace('_', ' ').title()} - INC-{random.randint(10000, 99999)}"
            },
            "sourcetype": "soc:incident",
            "index": SPLUNK_INDEX
        }


class ADLogGenerator:
    """تولیدکننده لاگ‌های Active Directory"""
    
    def __init__(self, ad_server):
        self.ad_server = ad_server
    
    def generate_authentication_log(self):
        """لاگ احراز هویت AD"""
        auth_event = random.choice([
            "login_success", "login_failure", "logout", "account_locked",
            "account_unlocked", "kerberos_ticket_issued", "kerberos_ticket_failed"
        ])
        success = auth_event in ["login_success", "logout", "account_unlocked", "kerberos_ticket_issued"]
        
        return {
            "event": {
                "type": "ad_authentication",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.ad_server.hostname,
                "domain": self.ad_server.domain,
                "severity": "ERROR" if "failure" in auth_event or "locked" in auth_event else "INFO",
                "auth_event": auth_event,
                "user": random.choice(USERS),
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "workstation": f"WS-{random.randint(1, 100)}",
                "success": success,
                "failure_reason": random.choice([
                    "Invalid password", "User account disabled", "Account locked",
                    "Password expired", "Kerberos pre-authentication failed"
                ]) if not success else None,
                "logon_type": random.choice([2, 3, 4, 5, 7, 8, 10, 11]),  # Windows logon types
                "authentication_package": random.choice(["Kerberos", "NTLM", "Negotiate"]),
                "message": f"AD Authentication: {auth_event.replace('_', ' ').title()} for {random.choice(USERS)}"
            },
            "sourcetype": "ad:authentication",
            "index": SPLUNK_INDEX
        }
    
    def generate_password_change_log(self):
        """لاگ تغییر پسورد AD"""
        change_type = random.choice([
            "password_change", "password_reset", "password_change_failed",
            "password_reset_failed", "password_expired"
        ])
        success = "failed" not in change_type and "expired" not in change_type
        
        return {
            "event": {
                "type": "ad_password",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.ad_server.hostname,
                "domain": self.ad_server.domain,
                "severity": "WARN" if not success else "INFO",
                "password_event": change_type,
                "user": random.choice(USERS),
                "target_user": random.choice(USERS),
                "admin_initiated": random.choice([True, False]) if "reset" in change_type else False,
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "success": success,
                "failure_reason": random.choice([
                    "Password too weak", "Password history violation",
                    "Minimum password age not met", "Invalid current password"
                ]) if not success else None,
                "message": f"AD Password: {change_type.replace('_', ' ').title()} for {random.choice(USERS)}"
            },
            "sourcetype": "ad:password",
            "index": SPLUNK_INDEX
        }
    
    def generate_account_management_log(self):
        """لاگ مدیریت حساب کاربری AD"""
        account_event = random.choice([
            "user_created", "user_deleted", "user_enabled", "user_disabled",
            "user_modified", "account_expired", "account_unlocked"
        ])
        
        return {
            "event": {
                "type": "ad_account_management",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.ad_server.hostname,
                "domain": self.ad_server.domain,
                "severity": "WARN" if "deleted" in account_event or "disabled" in account_event else "INFO",
                "account_event": account_event,
                "target_user": random.choice(USERS),
                "admin_user": random.choice(USERS),
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "attributes_changed": random.choice([
                    "displayName", "mail", "telephoneNumber", "department",
                    "title", "memberOf", "userAccountControl"
                ]) if "modified" in account_event else None,
                "message": f"AD Account: {account_event.replace('_', ' ').title()} - {random.choice(USERS)}"
            },
            "sourcetype": "ad:account",
            "index": SPLUNK_INDEX
        }
    
    def generate_group_management_log(self):
        """لاگ مدیریت گروه AD"""
        group_event = random.choice([
            "group_created", "group_deleted", "user_added_to_group",
            "user_removed_from_group", "group_modified"
        ])
        
        return {
            "event": {
                "type": "ad_group_management",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.ad_server.hostname,
                "domain": self.ad_server.domain,
                "severity": "WARN" if "deleted" in group_event else "INFO",
                "group_event": group_event,
                "group_name": random.choice(AD_GROUPS),
                "user": random.choice(USERS) if "user" in group_event else None,
                "admin_user": random.choice(USERS),
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "message": f"AD Group: {group_event.replace('_', ' ').title()} - {random.choice(AD_GROUPS)}"
            },
            "sourcetype": "ad:group",
            "index": SPLUNK_INDEX
        }
    
    def generate_permission_change_log(self):
        """لاگ تغییر پرمیشن AD"""
        perm_event = random.choice([
            "acl_modified", "delegation_granted", "delegation_removed",
            "permission_granted", "permission_denied"
        ])
        
        return {
            "event": {
                "type": "ad_permission",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.ad_server.hostname,
                "domain": self.ad_server.domain,
                "severity": "WARN",
                "permission_event": perm_event,
                "target_object": random.choice([
                    f"CN={random.choice(USERS)},OU=Users,DC=example,DC=com",
                    f"CN={random.choice(AD_GROUPS)},OU=Groups,DC=example,DC=com",
                    f"OU=Servers,DC=example,DC=com"
                ]),
                "admin_user": random.choice(USERS),
                "permission_type": random.choice([
                    "Full Control", "Read", "Write", "Delete", "Modify",
                    "Create Child", "Delete Child"
                ]),
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "message": f"AD Permission: {perm_event.replace('_', ' ').title()}"
            },
            "sourcetype": "ad:permission",
            "index": SPLUNK_INDEX
        }
    
    def generate_kerberos_log(self):
        """لاگ Kerberos"""
        kerberos_event = random.choice([
            "ticket_granted", "ticket_renewed", "ticket_expired",
            "pre_authentication_failed", "service_ticket_request"
        ])
        
        return {
            "event": {
                "type": "ad_kerberos",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.ad_server.hostname,
                "domain": self.ad_server.domain,
                "severity": "ERROR" if "failed" in kerberos_event else "INFO",
                "kerberos_event": kerberos_event,
                "user": random.choice(USERS),
                "service": random.choice([
                    "HTTP/web-server.example.com",
                    "LDAP/dc.example.com",
                    "CIFS/file-server.example.com"
                ]),
                "ticket_type": random.choice(["TGT", "TGS"]),
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "message": f"AD Kerberos: {kerberos_event.replace('_', ' ').title()}"
            },
            "sourcetype": "ad:kerberos",
            "index": SPLUNK_INDEX
        }
    
    def generate_computer_account_log(self):
        """لاگ Computer Account"""
        computer_event = random.choice([
            "computer_joined_domain", "computer_left_domain",
            "computer_account_created", "computer_account_deleted"
        ])
        
        return {
            "event": {
                "type": "ad_computer",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.ad_server.hostname,
                "domain": self.ad_server.domain,
                "severity": "WARN" if "left" in computer_event or "deleted" in computer_event else "INFO",
                "computer_event": computer_event,
                "computer_name": f"PC-{random.randint(1, 1000)}",
                "computer_dn": f"CN=PC-{random.randint(1, 1000)},OU=Computers,DC=example,DC=com",
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "message": f"AD Computer: {computer_event.replace('_', ' ').title()}"
            },
            "sourcetype": "ad:computer",
            "index": SPLUNK_INDEX
        }
    
    def generate_ldap_log(self):
        """لاگ LDAP"""
        ldap_event = random.choice([
            "ldap_bind_success", "ldap_bind_failure", "ldap_search",
            "ldap_modify", "ldap_add", "ldap_delete"
        ])
        
        return {
            "event": {
                "type": "ad_ldap",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.ad_server.hostname,
                "domain": self.ad_server.domain,
                "severity": "ERROR" if "failure" in ldap_event else "INFO",
                "ldap_event": ldap_event,
                "user": random.choice(USERS),
                "ldap_operation": random.choice(["bind", "search", "modify", "add", "delete"]),
                "base_dn": random.choice([
                    "DC=example,DC=com",
                    "OU=Users,DC=example,DC=com",
                    "OU=Groups,DC=example,DC=com"
                ]),
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "message": f"AD LDAP: {ldap_event.replace('_', ' ').title()}"
            },
            "sourcetype": "ad:ldap",
            "index": SPLUNK_INDEX
        }
    
    def generate_random_log(self):
        """تولید یک لاگ رندوم AD"""
        log_types = [
            self.generate_authentication_log,
            self.generate_password_change_log,
            self.generate_account_management_log,
            self.generate_group_management_log,
            self.generate_permission_change_log,
            self.generate_kerberos_log,
            self.generate_computer_account_log,
            self.generate_ldap_log
        ]
        return random.choice(log_types)()


class DatabaseLogGenerator:
    """تولیدکننده لاگ‌های دیتابیس"""
    
    def __init__(self, db_server):
        self.db_server = db_server
    
    def generate_connection_log(self):
        """لاگ اتصال دیتابیس"""
        conn_event = random.choice([
            "connection_established", "connection_closed", "connection_failed",
            "connection_timeout", "connection_pool_exhausted"
        ])
        success = conn_event == "connection_established"
        
        return {
            "event": {
                "type": "database_connection",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.db_server.hostname,
                "db_type": self.db_server.db_type,
                "severity": "ERROR" if not success else "INFO",
                "connection_event": conn_event,
                "user": random.choice(USERS),
                "database": random.choice(["app_db", "user_db", "log_db", "analytics_db"]),
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "connection_id": random.randint(1000, 99999),
                "duration_ms": random.randint(1, 5000) if conn_event == "connection_closed" else None,
                "failure_reason": random.choice([
                    "Authentication failed", "Database not found",
                    "Connection limit exceeded", "Network timeout"
                ]) if not success else None,
                "message": f"Database Connection: {conn_event.replace('_', ' ').title()}"
            },
            "sourcetype": f"database:{self.db_server.db_type.lower()}",
            "index": SPLUNK_INDEX
        }
    
    def generate_query_log(self):
        """لاگ Query دیتابیس"""
        query_type = random.choice(["SELECT", "INSERT", "UPDATE", "DELETE"])
        
        return {
            "event": {
                "type": "database_query",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.db_server.hostname,
                "db_type": self.db_server.db_type,
                "severity": "INFO",
                "query_type": query_type,
                "user": random.choice(USERS),
                "database": random.choice(["app_db", "user_db", "log_db"]),
                "table": random.choice(["users", "orders", "products", "logs", "transactions"]),
                "query": f"{query_type} FROM {random.choice(['users', 'orders', 'products'])} WHERE id = {random.randint(1, 1000)}",
                "rows_affected": random.randint(0, 10000) if query_type != "SELECT" else None,
                "rows_returned": random.randint(0, 1000) if query_type == "SELECT" else None,
                "execution_time_ms": random.randint(1, 5000),
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "message": f"Database Query: {query_type} executed"
            },
            "sourcetype": f"database:query",
            "index": SPLUNK_INDEX
        }
    
    def generate_transaction_log(self):
        """لاگ Transaction دیتابیس"""
        tx_event = random.choice([
            "transaction_begin", "transaction_commit", "transaction_rollback",
            "transaction_timeout", "deadlock_detected"
        ])
        
        return {
            "event": {
                "type": "database_transaction",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.db_server.hostname,
                "db_type": self.db_server.db_type,
                "severity": "ERROR" if "timeout" in tx_event or "deadlock" in tx_event else "INFO",
                "transaction_event": tx_event,
                "user": random.choice(USERS),
                "database": random.choice(["app_db", "user_db", "log_db"]),
                "transaction_id": random.randint(100000, 999999),
                "duration_ms": random.randint(10, 30000) if tx_event in ["transaction_commit", "transaction_rollback"] else None,
                "tables_affected": random.choice([["users"], ["orders"], ["products"], ["users", "orders"]]),
                "message": f"Database Transaction: {tx_event.replace('_', ' ').title()}"
            },
            "sourcetype": f"database:transaction",
            "index": SPLUNK_INDEX
        }
    
    def generate_permission_log(self):
        """لاگ Permission دیتابیس"""
        perm_event = random.choice([
            "permission_granted", "permission_revoked", "role_assigned",
            "role_removed", "schema_modified"
        ])
        
        return {
            "event": {
                "type": "database_permission",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.db_server.hostname,
                "db_type": self.db_server.db_type,
                "severity": "WARN",
                "permission_event": perm_event,
                "target_user": random.choice(USERS),
                "admin_user": random.choice(USERS),
                "database": random.choice(["app_db", "user_db", "log_db"]),
                "permission": random.choice(["SELECT", "INSERT", "UPDATE", "DELETE", "ALL"]),
                "object": random.choice(["users", "orders", "products", "schema"]),
                "message": f"Database Permission: {perm_event.replace('_', ' ').title()}"
            },
            "sourcetype": f"database:permission",
            "index": SPLUNK_INDEX
        }
    
    def generate_security_log(self):
        """لاگ امنیتی دیتابیس"""
        security_event = random.choice([
            "sql_injection_attempt", "unauthorized_access", "privilege_escalation",
            "data_export_detected", "suspicious_query_pattern"
        ])
        
        return {
            "event": {
                "type": "database_security",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.db_server.hostname,
                "db_type": self.db_server.db_type,
                "severity": random.choice(["WARN", "ERROR", "CRITICAL"]),
                "security_event": security_event,
                "user": random.choice(USERS),
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "query": random.choice([
                    "'; DROP TABLE users--",
                    "UNION SELECT * FROM passwords",
                    "1' OR '1'='1",
                    "SELECT * FROM sensitive_data"
                ]) if "injection" in security_event else None,
                "action_taken": random.choice(["blocked", "logged", "alerted"]),
                "message": f"Database Security: {security_event.replace('_', ' ').title()}"
            },
            "sourcetype": f"database:security",
            "index": SPLUNK_INDEX
        }
    
    def generate_random_log(self):
        """تولید یک لاگ رندوم دیتابیس"""
        log_types = [
            self.generate_connection_log,
            self.generate_query_log,
            self.generate_transaction_log,
            self.generate_permission_log,
            self.generate_security_log
        ]
        return random.choice(log_types)()


class DNSLogGenerator:
    """تولیدکننده لاگ‌های DNS"""
    
    def __init__(self, dns_server):
        self.dns_server = dns_server
    
    def generate_query_log(self):
        """لاگ Query DNS"""
        record_type = random.choice(DNS_RECORD_TYPES)
        domain = random.choice([
            "example.com", "google.com", "microsoft.com", "amazon.com",
            "internal.corp", "test.local"
        ])
        
        return {
            "event": {
                "type": "dns_query",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.dns_server.hostname,
                "dns_type": self.dns_server.dns_type,
                "severity": "INFO",
                "query_type": record_type,
                "domain": domain,
                "client_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "response_code": random.choice([0, 2, 3]),  # 0=Success, 2=ServerFailure, 3=NameError
                "response_time_ms": random.randint(1, 100),
                "cached": random.choice([True, False]),
                "message": f"DNS Query: {record_type} for {domain}"
            },
            "sourcetype": "dns:query",
            "index": SPLUNK_INDEX
        }
    
    def generate_zone_transfer_log(self):
        """لاگ Zone Transfer DNS"""
        transfer_event = random.choice([
            "zone_transfer_request", "zone_transfer_success", "zone_transfer_denied"
        ])
        success = transfer_event == "zone_transfer_success"
        
        return {
            "event": {
                "type": "dns_zone_transfer",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.dns_server.hostname,
                "dns_type": self.dns_server.dns_type,
                "severity": "WARN" if not success else "INFO",
                "transfer_event": transfer_event,
                "zone": random.choice(["example.com", "corp.local", "internal"]),
                "requestor_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "success": success,
                "denial_reason": random.choice([
                    "Not authorized", "IP not in allow list",
                    "Rate limit exceeded"
                ]) if not success else None,
                "message": f"DNS Zone Transfer: {transfer_event.replace('_', ' ').title()}"
            },
            "sourcetype": "dns:zone_transfer",
            "index": SPLUNK_INDEX
        }
    
    def generate_security_log(self):
        """لاگ امنیتی DNS"""
        security_event = random.choice([
            "dns_tunneling_detected", "dns_amplification_attempt",
            "malicious_domain_query", "cache_poisoning_attempt"
        ])
        
        return {
            "event": {
                "type": "dns_security",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.dns_server.hostname,
                "dns_type": self.dns_server.dns_type,
                "severity": random.choice(["WARN", "ERROR", "CRITICAL"]),
                "security_event": security_event,
                "domain": random.choice([
                    "malicious-domain.com", "suspicious-site.net",
                    "data-exfil.com"
                ]),
                "client_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "action_taken": random.choice(["blocked", "logged", "alerted"]),
                "message": f"DNS Security: {security_event.replace('_', ' ').title()}"
            },
            "sourcetype": "dns:security",
            "index": SPLUNK_INDEX
        }
    
    def generate_random_log(self):
        """تولید یک لاگ رندوم DNS"""
        log_types = [
            self.generate_query_log,
            self.generate_zone_transfer_log,
            self.generate_security_log
        ]
        return random.choice(log_types)()


class DHCPLogGenerator:
    """تولیدکننده لاگ‌های DHCP"""
    
    def __init__(self, dhcp_server):
        self.dhcp_server = dhcp_server
    
    def generate_lease_log(self):
        """لاگ IP Lease DHCP"""
        lease_event = random.choice([
            "lease_assigned", "lease_renewed", "lease_released",
            "lease_expired", "lease_declined"
        ])
        
        return {
            "event": {
                "type": "dhcp_lease",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.dhcp_server.hostname,
                "dhcp_type": self.dhcp_server.dhcp_type,
                "severity": "INFO",
                "lease_event": lease_event,
                "client_mac": ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)]),
                "assigned_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "lease_duration_seconds": random.randint(3600, 86400),
                "client_hostname": f"client-{random.randint(1, 1000)}",
                "scope": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24",
                "message": f"DHCP Lease: {lease_event.replace('_', ' ').title()}"
            },
            "sourcetype": "dhcp:lease",
            "index": SPLUNK_INDEX
        }
    
    def generate_conflict_log(self):
        """لاگ Conflict DHCP"""
        return {
            "event": {
                "type": "dhcp_conflict",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.dhcp_server.hostname,
                "dhcp_type": self.dhcp_server.dhcp_type,
                "severity": "WARN",
                "conflict_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "existing_mac": ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)]),
                "conflicting_mac": ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)]),
                "scope": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24",
                "message": "DHCP Conflict: IP address conflict detected"
            },
            "sourcetype": "dhcp:conflict",
            "index": SPLUNK_INDEX
        }
    
    def generate_scope_log(self):
        """لاگ Scope Management DHCP"""
        scope_event = random.choice([
            "scope_exhausted", "scope_created", "scope_modified",
            "reservation_created", "reservation_deleted"
        ])
        
        return {
            "event": {
                "type": "dhcp_scope",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.dhcp_server.hostname,
                "dhcp_type": self.dhcp_server.dhcp_type,
                "severity": "WARN" if "exhausted" in scope_event else "INFO",
                "scope_event": scope_event,
                "scope": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24",
                "available_ips": random.randint(0, 254) if "exhausted" not in scope_event else 0,
                "total_ips": 254,
                "admin_user": random.choice(USERS) if "created" in scope_event or "modified" in scope_event else None,
                "message": f"DHCP Scope: {scope_event.replace('_', ' ').title()}"
            },
            "sourcetype": "dhcp:scope",
            "index": SPLUNK_INDEX
        }
    
    def generate_random_log(self):
        """تولید یک لاگ رندوم DHCP"""
        log_types = [
            self.generate_lease_log,
            self.generate_conflict_log,
            self.generate_scope_log
        ]
        return random.choice(log_types)()


class EmailLogGenerator:
    """تولیدکننده لاگ‌های Email"""
    
    def __init__(self, email_server):
        self.email_server = email_server
    
    def generate_smtp_log(self):
        """لاگ SMTP"""
        smtp_event = random.choice([
            "email_sent", "email_received", "email_delivered",
            "email_failed", "email_bounced", "email_rejected"
        ])
        success = smtp_event in ["email_sent", "email_received", "email_delivered"]
        
        return {
            "event": {
                "type": "email_smtp",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.email_server.hostname,
                "email_type": self.email_server.email_type,
                "domain": self.email_server.domain,
                "severity": "ERROR" if not success else "INFO",
                "smtp_event": smtp_event,
                "from": f"{random.choice(USERS)}@{self.email_server.domain}",
                "to": f"{random.choice(USERS)}@{random.choice(EMAIL_DOMAINS)}",
                "subject": random.choice([
                    "Meeting Request", "Report", "Invoice",
                    "Security Alert", "Password Reset"
                ]),
                "message_id": f"<{uuid.uuid4()}@{self.email_server.domain}>",
                "size_bytes": random.randint(1000, 10000000),
                "failure_reason": random.choice([
                    "Recipient not found", "Mailbox full",
                    "Spam detected", "Connection timeout"
                ]) if not success else None,
                "message": f"Email SMTP: {smtp_event.replace('_', ' ').title()}"
            },
            "sourcetype": "email:smtp",
            "index": SPLUNK_INDEX
        }
    
    def generate_delivery_log(self):
        """لاگ Delivery Status Email"""
        delivery_status = random.choice([
            "delivered", "delayed", "failed", "bounced",
            "deferred", "expired"
        ])
        
        return {
            "event": {
                "type": "email_delivery",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.email_server.hostname,
                "email_type": self.email_server.email_type,
                "domain": self.email_server.domain,
                "severity": "ERROR" if delivery_status in ["failed", "bounced", "expired"] else "INFO",
                "delivery_status": delivery_status,
                "recipient": f"{random.choice(USERS)}@{random.choice(EMAIL_DOMAINS)}",
                "message_id": f"<{uuid.uuid4()}@{self.email_server.domain}>",
                "retry_count": random.randint(0, 5) if delivery_status == "delayed" else None,
                "next_retry": (datetime.utcnow() + timedelta(minutes=random.randint(5, 60))).isoformat() if delivery_status == "deferred" else None,
                "bounce_reason": random.choice([
                    "User unknown", "Mailbox full", "Domain not found"
                ]) if delivery_status == "bounced" else None,
                "message": f"Email Delivery: {delivery_status.title()}"
            },
            "sourcetype": "email:delivery",
            "index": SPLUNK_INDEX
        }
    
    def generate_spam_log(self):
        """لاگ Spam Detection Email"""
        spam_action = random.choice([
            "spam_detected", "spam_quarantined", "spam_released",
            "false_positive", "phishing_detected"
        ])
        
        return {
            "event": {
                "type": "email_spam",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.email_server.hostname,
                "email_type": self.email_server.email_type,
                "domain": self.email_server.domain,
                "severity": "WARN" if "detected" in spam_action or "phishing" in spam_action else "INFO",
                "spam_action": spam_action,
                "from": f"{random.choice(USERS)}@{random.choice(EMAIL_DOMAINS)}",
                "to": f"{random.choice(USERS)}@{self.email_server.domain}",
                "subject": random.choice([
                    "You've won!", "Urgent action required",
                    "Click here now", "Free money"
                ]),
                "spam_score": round(random.uniform(5.0, 10.0), 2) if "detected" in spam_action else None,
                "spam_engine": random.choice(["SpamAssassin", "Microsoft EOP", "Barracuda"]),
                "action_taken": random.choice(["quarantined", "blocked", "tagged"]),
                "message": f"Email Spam: {spam_action.replace('_', ' ').title()}"
            },
            "sourcetype": "email:spam",
            "index": SPLUNK_INDEX
        }
    
    def generate_authentication_log(self):
        """لاگ Authentication Email"""
        auth_event = random.choice([
            "smtp_auth_success", "smtp_auth_failed", "imap_login",
            "pop3_login", "oauth_token_issued"
        ])
        success = "failed" not in auth_event
        
        return {
            "event": {
                "type": "email_auth",
                "timestamp": datetime.utcnow().isoformat(),
                "host": self.email_server.hostname,
                "email_type": self.email_server.email_type,
                "domain": self.email_server.domain,
                "severity": "ERROR" if not success else "INFO",
                "auth_event": auth_event,
                "user": f"{random.choice(USERS)}@{self.email_server.domain}",
                "protocol": random.choice(["SMTP", "IMAP", "POP3"]),
                "source_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "success": success,
                "failure_reason": random.choice([
                    "Invalid credentials", "Account locked",
                    "IP blocked", "Rate limit exceeded"
                ]) if not success else None,
                "message": f"Email Auth: {auth_event.replace('_', ' ').title()}"
            },
            "sourcetype": "email:auth",
            "index": SPLUNK_INDEX
        }
    
    def generate_random_log(self):
        """تولید یک لاگ رندوم Email"""
        log_types = [
            self.generate_smtp_log,
            self.generate_delivery_log,
            self.generate_spam_log,
            self.generate_authentication_log
        ]
        return random.choice(log_types)()


