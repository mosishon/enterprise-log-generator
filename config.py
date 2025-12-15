# تنظیمات سیستم تولید لاگ سازمانی

# تعداد دستگاه‌ها
NUM_NETWORK_DEVICES = 50
NUM_WEB_SERVERS = 15
NUM_CLIENT_DEVICES = 1000
NUM_AD_SERVERS = 3  # Domain Controllers
NUM_DATABASE_SERVERS = 2
NUM_DNS_SERVERS = 2
NUM_DHCP_SERVERS = 2
NUM_EMAIL_SERVERS = 2

# تنظیمات Splunk
SPLUNK_HEC_URL = "http://127.0.0.1:8088/services/collector"
SPLUNK_TOKEN = "06037014-9be5-4616-aa2b-c118fde0cefe"
SPLUNK_INDEX = "main"  # نام index در Splunk (معمولاً "main" به صورت پیش‌فرض وجود دارد)

# تنظیمات تولید لاگ
LOG_INTERVAL = 0.3  # ثانیه
CORRELATED_EVENT_PROBABILITY = 0.6  # احتمال رویدادهای مرتبط (30%)

# لیست کاربران
USERS = [
    "alice", "bob", "charlie", "david", "eve", "frank", "grace", "henry",
    "ivy", "jack", "kate", "liam", "mia", "noah", "olivia", "peter",
    "quinn", "rachel", "sam", "tina", "umar", "violet", "william", "xara",
    "yuki", "zoe", "admin", "root", "system", "service"
]

# لیست IP آدرس‌ها
IP_RANGES = {
    "network": ["10.0.0.{}", "192.168.1.{}", "172.16.0.{}"],
    "web": ["10.1.0.{}", "192.168.2.{}"],
    "client": ["10.2.0.{}", "192.168.3.{}"],
    "ad": ["10.3.0.{}", "192.168.4.{}"],
    "database": ["10.4.0.{}", "192.168.5.{}"],
    "dns": ["10.5.0.{}", "192.168.6.{}"],
    "dhcp": ["10.6.0.{}", "192.168.7.{}"],
    "email": ["10.7.0.{}", "192.168.8.{}"]
}

# پروتکل‌های شبکه
NETWORK_PROTOCOLS = [
    "HTTP", "HTTPS", "FTP", "FTPS", "SFTP", "SSH", "Telnet",
    "SMTP", "POP3", "IMAP", "DNS", "DHCP", "SNMP", "LDAP",
    "RDP", "VNC", "SMB", "CIFS", "NFS", "ICMP", "TCP", "UDP"
]

# HTTP Methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# HTTP Response Codes
HTTP_RESPONSE_CODES = [200, 201, 301, 302, 400, 401, 403, 404, 500, 502, 503]

# Severity Levels
SEVERITY_LEVELS = ["INFO", "WARN", "ERROR", "DEBUG", "CRITICAL"]

# فایل‌ها و مسیرها
FILE_PATHS = [
    "/var/log/", "/etc/", "/home/", "/opt/", "/usr/bin/",
    "C:\\Windows\\System32\\", "C:\\Users\\", "D:\\Data\\",
    "/var/www/", "/tmp/", "/root/"
]

# برنامه‌ها
APPLICATIONS = [
    "chrome.exe", "firefox.exe", "notepad.exe", "cmd.exe", "powershell.exe",
    "python", "java", "node", "apache2", "nginx", "mysql", "postgresql"
]

# AD Groups
AD_GROUPS = [
    "Domain Admins", "Domain Users", "Domain Computers", "Enterprise Admins",
    "Schema Admins", "Account Operators", "Backup Operators", "Server Operators",
    "Print Operators", "Network Configuration Operators", "Remote Desktop Users",
    "Sales", "IT", "HR", "Finance", "Marketing", "Engineering"
]

# Database Types
DATABASE_TYPES = ["MySQL", "PostgreSQL", "SQL Server", "Oracle", "MongoDB", "Redis"]

# DNS Record Types
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "PTR", "SRV", "SOA"]

# Email Domains
EMAIL_DOMAINS = ["example.com", "company.com", "corp.local", "test.org"]

