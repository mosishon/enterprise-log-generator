# سیستم تولید لاگ سازمانی (Enterprise Log Generator)

یک سیستم جامع و پیچیده برای تولید و شبیه‌سازی لاگ‌های سازمانی با قابلیت شبیه‌سازی انواع دستگاه‌ها و رویدادهای مرتبط.

## هدف پروژه

این پروژه به‌طور خاص برای **یادگیری و تمرین با Splunk** طراحی شده است و از **HTTP Event Collector (HEC)** برای ارسال لاگ‌ها استفاده می‌کند. هدف اصلی ایجاد یک منبع غنی از لاگ‌های mock و واقع‌گرا است که به شما امکان می‌دهد بدون نیاز به زیرساخت واقعی، مهارت‌های خود در Splunk را تقویت کنید. با استفاده از این سیستم می‌توانید با انواع مختلف لاگ‌های سازمانی (شبکه، وب، امنیتی، AD، دیتابیس و...) کار کنید، کوئری‌های پیچیده بنویسید، dashboard بسازید و سناریوهای مختلف امنیتی و عملیاتی را شبیه‌سازی کنید. این ابزار برای دانشجویان، متخصصان امنیت و تحلیل‌گران لاگ که می‌خواهند در محیطی کنترل‌شده با Splunk HEC کار کنند، ایده‌آل است.

## ویژگی‌ها

- ✅ شبیه‌سازی تجهیزات شبکه (روتر، سوئیچ، فایروال)
- ✅ شبیه‌سازی سرورهای وب (Apache, Nginx, IIS, etc.)
- ✅ شبیه‌سازی کلاینت‌ها (Windows, Linux, macOS)
- ✅ تولید لاگ‌های امنیتی جامع برای SOC
- ✅ رویدادهای مرتبط (یک رویداد چند لاگ در دستگاه‌های مختلف ایجاد می‌کند)
- ✅ ارسال خودکار به Splunk از طریق HTTP Event Collector (HEC)
- ✅ قابلیت تنظیم تعداد دستگاه‌ها

## ساختار فایل‌ها

```
mock-log-generator/
├── config.py              # تنظیمات سیستم (تعداد دستگاه‌ها، Splunk config)
├── devices.py             # کلاس‌های دستگاه (NetworkDevice, WebServer, ClientDevice)
├── log_generators.py      # تولیدکننده‌های لاگ برای هر نوع دستگاه
├── correlated_events.py   # سیستم رویدادهای مرتبط
├── splunk_client.py       # کلاینت ارسال به Splunk
├── main.py                # فایل اصلی اجرا
└── README.md              # این فایل
```

## نصب و راه‌اندازی

### پیش‌نیازها

```bash
pip install requests
```

### تنظیمات

فایل `config.py` را باز کنید و تنظیمات را تغییر دهید:

```python
# تعداد دستگاه‌ها
NUM_NETWORK_DEVICES = 10
NUM_WEB_SERVERS = 5
NUM_CLIENT_DEVICES = 20

# تنظیمات Splunk HTTP Event Collector (HEC)
SPLUNK_HEC_URL = "http://127.0.0.1:8088/services/collector"
SPLUNK_TOKEN = "your-splunk-hec-token-here"

# تنظیمات تولید لاگ
LOG_INTERVAL = 0.1  # ثانیه
CORRELATED_EVENT_PROBABILITY = 0.3  # احتمال رویدادهای مرتبط (30%)
```

**نکته:** برای استفاده از این سیستم، باید HTTP Event Collector (HEC) را در Splunk فعال کنید و یک HEC Token ایجاد کنید. HEC یک روش ساده و امن برای ارسال داده‌ها به Splunk از طریق HTTP/HTTPS است که برای یادگیری و تست ایده‌آل است.

### اجرا

```bash
python main.py
```

## انواع لاگ‌های تولید شده

### لاگ‌های شبکه
- اتصالات شبکه (TCP/UDP)
- فیلترینگ پکت‌ها
- رویدادهای مسیریابی
- استفاده از پهنای باند
- رویدادهای امنیتی (port scan, intrusion, DDoS)
- اتصالات VPN

### لاگ‌های وب سرور
- درخواست‌های HTTP (GET, POST, PUT, DELETE, etc.)
- احراز هویت (login, logout, failed attempts)
- فراخوانی‌های API (REST, GraphQL)
- خطاهای برنامه
- رویدادهای امنیتی (SQL injection, XSS, CSRF, brute force)

### لاگ‌های کلاینت
- ورود/خروج کاربران
- تغییر پسورد
- دسترسی به فایل‌ها
- تغییر پرمیشن‌ها
- افزایش سطح دسترسی (privilege escalation)
- اجرای برنامه‌ها
- رویدادهای سیستم

### لاگ‌های امنیتی SOC
- **Authentication & Authorization**: login, logout, password changes, MFA
- **Access Control**: file access, permission changes, privilege escalation
- **Network Security**: port scans, VPN connections, firewall events
- **Threat Detection**: malware, intrusion, anomaly detection
- **Compliance**: policy violations, audit trails, configuration changes
- **Incident Response**: security alerts, investigations, remediation

## رویدادهای مرتبط

سیستم می‌تواند رویدادهای مرتبط تولید کند که یک رویداد اصلی چند لاگ در دستگاه‌های مختلف ایجاد می‌کند:

- **User Login Event**: لاگ کلاینت + لاگ وب + لاگ شبکه + لاگ SOC
- **File Access Event**: لاگ کلاینت + لاگ SOC Access Control + لاگ Compliance
- **Password Change Event**: لاگ کلاینت + لاگ وب + لاگ SOC
- **Permission Change Event**: لاگ کلاینت + لاگ SOC Access Control + لاگ Compliance
- **Security Threat Event**: لاگ شبکه + لاگ وب + لاگ SOC Threat Detection + لاگ Incident
- **API Request Event**: لاگ وب HTTP + لاگ وب API + لاگ شبکه
- **Privilege Escalation Event**: لاگ کلاینت + لاگ SOC Access Control + لاگ Threat Detection + لاگ Incident

## پروتکل‌های پشتیبانی شده

HTTP, HTTPS, FTP, FTPS, SFTP, SSH, Telnet, SMTP, POP3, IMAP, DNS, DHCP, SNMP, LDAP, RDP, VNC, SMB, CIFS, NFS, ICMP, TCP, UDP

## مثال خروجی

```json
{
  "event": {
    "type": "user_login",
    "timestamp": "2024-01-15T10:30:45.123456",
    "host": "client-windows-001",
    "os_type": "Windows",
    "severity": "INFO",
    "login_type": "login",
    "user": "alice",
    "source_ip": "10.2.0.45",
    "success": true,
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "correlation_id": "660e8400-e29b-41d4-a716-446655440001"
  },
  "sourcetype": "client:auth",
  "index": "security"
}
```

## نکات مهم

1. **تعداد دستگاه‌ها**: می‌توانید تعداد دستگاه‌ها را در `config.py` تغییر دهید
2. **احتمال رویدادهای مرتبط**: با تغییر `CORRELATED_EVENT_PROBABILITY` می‌توانید نسبت رویدادهای مرتبط به مستقل را تنظیم کنید
3. **فاصله زمانی**: با تغییر `LOG_INTERVAL` می‌توانید سرعت تولید لاگ را تنظیم کنید
4. **Splunk Token**: حتماً token صحیح Splunk را در `config.py` وارد کنید

## توسعه

برای افزودن انواع جدید لاگ یا دستگاه:

1. کلاس دستگاه جدید را در `devices.py` اضافه کنید
2. Generator لاگ را در `log_generators.py` اضافه کنید
3. رویدادهای مرتبط جدید را در `correlated_events.py` اضافه کنید

## مجوز

این پروژه برای استفاده داخلی و تست طراحی شده است.


