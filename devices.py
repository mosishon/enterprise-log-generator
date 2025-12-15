"""
کلاس‌های دستگاه برای شبیه‌سازی سازمان
"""
import random
from config import IP_RANGES, USERS, DATABASE_TYPES, EMAIL_DOMAINS


class NetworkDevice:
    """تجهیزات شبکه (روتر، سوئیچ، فایروال)"""
    
    DEVICE_TYPES = ["router", "switch", "firewall", "load_balancer", "gateway"]
    
    def __init__(self, device_id):
        self.device_id = device_id
        self.device_type = random.choice(self.DEVICE_TYPES)
        self.hostname = f"{self.device_type}-{device_id:03d}"
        self.ip = self._generate_ip("network")
        self.status = "online"
        self.vendor = random.choice(["Cisco", "Juniper", "Fortinet", "Palo Alto", "Check Point"])
        self.model = f"{self.vendor}-{random.choice(['ASR', 'MX', 'SRX', 'PA', 'CP'])}-{random.randint(100, 999)}"
        
    def _generate_ip(self, device_category):
        """تولید IP آدرس"""
        ip_template = random.choice(IP_RANGES[device_category])
        return ip_template.format(random.randint(1, 254))
    
    def get_info(self):
        """اطلاعات دستگاه"""
        return {
            "device_id": self.device_id,
            "device_type": self.device_type,
            "hostname": self.hostname,
            "ip": self.ip,
            "status": self.status,
            "vendor": self.vendor,
            "model": self.model
        }


class WebServer:
    """سرورهای وب"""
    
    SERVER_TYPES = ["apache", "nginx", "iis", "tomcat", "nodejs"]
    
    def __init__(self, server_id):
        self.server_id = server_id
        self.server_type = random.choice(self.SERVER_TYPES)
        self.hostname = f"web-{self.server_type}-{server_id:03d}"
        self.ip = self._generate_ip("web")
        self.status = "online"
        self.domain = f"{self.hostname}.example.com"
        self.port = random.choice([80, 443, 8080, 8443])
        
    def _generate_ip(self, device_category):
        """تولید IP آدرس"""
        ip_template = random.choice(IP_RANGES[device_category])
        return ip_template.format(random.randint(1, 254))
    
    def get_info(self):
        """اطلاعات سرور"""
        return {
            "server_id": self.server_id,
            "server_type": self.server_type,
            "hostname": self.hostname,
            "ip": self.ip,
            "status": self.status,
            "domain": self.domain,
            "port": self.port
        }


class ClientDevice:
    """کلاینت‌ها (کاربران، ایستگاه‌های کاری)"""
    
    OS_TYPES = ["Windows", "Linux", "macOS", "Android", "iOS"]
    
    def __init__(self, client_id):
        self.client_id = client_id
        self.os_type = random.choice(self.OS_TYPES)
        self.hostname = f"client-{self.os_type.lower()}-{client_id:03d}"
        self.ip = self._generate_ip("client")
        self.status = "online"
        self.mac_address = self._generate_mac()
        self.current_user = random.choice(USERS)
        
    def _generate_ip(self, device_category):
        """تولید IP آدرس"""
        ip_template = random.choice(IP_RANGES[device_category])
        return ip_template.format(random.randint(1, 254))
    
    def _generate_mac(self):
        """تولید MAC Address"""
        return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
    
    def get_info(self):
        """اطلاعات کلاینت"""
        return {
            "client_id": self.client_id,
            "os_type": self.os_type,
            "hostname": self.hostname,
            "ip": self.ip,
            "status": self.status,
            "mac_address": self.mac_address,
            "current_user": self.current_user
        }


class ADServer:
    """Domain Controller / Active Directory Server"""
    
    def __init__(self, server_id):
        self.server_id = server_id
        self.hostname = f"dc-{server_id:03d}"
        self.ip = self._generate_ip("ad")
        self.status = "online"
        self.domain = random.choice(["example.com", "corp.local", "company.local"])
        self.dc_role = random.choice(["Primary", "Secondary", "Read-Only"])
        self.forest = random.choice(["Forest1", "Forest2"])
        
    def _generate_ip(self, device_category):
        """تولید IP آدرس"""
        ip_template = random.choice(IP_RANGES[device_category])
        return ip_template.format(random.randint(1, 254))
    
    def get_info(self):
        """اطلاعات Domain Controller"""
        return {
            "server_id": self.server_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "status": self.status,
            "domain": self.domain,
            "dc_role": self.dc_role,
            "forest": self.forest
        }


class DatabaseServer:
    """Database Server"""
    
    def __init__(self, server_id):
        self.server_id = server_id
        from config import DATABASE_TYPES
        self.db_type = random.choice(DATABASE_TYPES)
        self.hostname = f"db-{self.db_type.lower().replace(' ', '-')}-{server_id:03d}"
        self.ip = self._generate_ip("database")
        self.status = "online"
        self.port = random.choice([3306, 5432, 1433, 1521, 27017, 6379])
        self.version = f"{random.randint(1, 20)}.{random.randint(0, 9)}.{random.randint(0, 9)}"
        
    def _generate_ip(self, device_category):
        """تولید IP آدرس"""
        ip_template = random.choice(IP_RANGES[device_category])
        return ip_template.format(random.randint(1, 254))
    
    def get_info(self):
        """اطلاعات Database Server"""
        return {
            "server_id": self.server_id,
            "db_type": self.db_type,
            "hostname": self.hostname,
            "ip": self.ip,
            "status": self.status,
            "port": self.port,
            "version": self.version
        }


class DNSServer:
    """DNS Server"""
    
    def __init__(self, server_id):
        self.server_id = server_id
        self.hostname = f"dns-{server_id:03d}"
        self.ip = self._generate_ip("dns")
        self.status = "online"
        self.dns_type = random.choice(["BIND", "Windows DNS", "PowerDNS", "Unbound"])
        
    def _generate_ip(self, device_category):
        """تولید IP آدرس"""
        ip_template = random.choice(IP_RANGES[device_category])
        return ip_template.format(random.randint(1, 254))
    
    def get_info(self):
        """اطلاعات DNS Server"""
        return {
            "server_id": self.server_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "status": self.status,
            "dns_type": self.dns_type
        }


class DHCPServer:
    """DHCP Server"""
    
    def __init__(self, server_id):
        self.server_id = server_id
        self.hostname = f"dhcp-{server_id:03d}"
        self.ip = self._generate_ip("dhcp")
        self.status = "online"
        self.dhcp_type = random.choice(["Windows DHCP", "ISC DHCP", "dnsmasq"])
        
    def _generate_ip(self, device_category):
        """تولید IP آدرس"""
        ip_template = random.choice(IP_RANGES[device_category])
        return ip_template.format(random.randint(1, 254))
    
    def get_info(self):
        """اطلاعات DHCP Server"""
        return {
            "server_id": self.server_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "status": self.status,
            "dhcp_type": self.dhcp_type
        }


class EmailServer:
    """Email Server (SMTP/IMAP/POP3)"""
    
    def __init__(self, server_id):
        self.server_id = server_id
        self.hostname = f"mail-{server_id:03d}"
        self.ip = self._generate_ip("email")
        self.status = "online"
        self.email_type = random.choice(["Exchange", "Postfix", "Sendmail", "Zimbra"])
        from config import EMAIL_DOMAINS
        self.domain = random.choice(EMAIL_DOMAINS)
        
    def _generate_ip(self, device_category):
        """تولید IP آدرس"""
        ip_template = random.choice(IP_RANGES[device_category])
        return ip_template.format(random.randint(1, 254))
    
    def get_info(self):
        """اطلاعات Email Server"""
        return {
            "server_id": self.server_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "status": self.status,
            "email_type": self.email_type,
            "domain": self.domain
        }


