"""
فایل اصلی سیستم تولید لاگ سازمانی
"""
import time
import random
from config import (
    NUM_NETWORK_DEVICES, NUM_WEB_SERVERS, NUM_CLIENT_DEVICES,
    NUM_AD_SERVERS, NUM_DATABASE_SERVERS, NUM_DNS_SERVERS,
    NUM_DHCP_SERVERS, NUM_EMAIL_SERVERS,
    LOG_INTERVAL, CORRELATED_EVENT_PROBABILITY
)
from devices import (
    NetworkDevice, WebServer, ClientDevice, ADServer,
    DatabaseServer, DNSServer, DHCPServer, EmailServer
)
from log_generators import (
    NetworkLogGenerator, WebLogGenerator, ClientLogGenerator,
    ADLogGenerator, DatabaseLogGenerator, DNSLogGenerator,
    DHCPLogGenerator, EmailLogGenerator
)
from correlated_events import CorrelatedEventSystem
from splunk_client import SplunkClient


def initialize_devices():
    """ایجاد و مقداردهی اولیه دستگاه‌ها"""
    print("=" * 60)
    print("🚀 Initializing Enterprise Log Generator System")
    print("=" * 60)
    
    # ایجاد دستگاه‌های شبکه
    print(f"\n📡 Creating {NUM_NETWORK_DEVICES} network devices...")
    network_devices = [NetworkDevice(i) for i in range(1, NUM_NETWORK_DEVICES + 1)]
    for device in network_devices:
        print(f"   ✓ {device.hostname} ({device.device_type}) - {device.ip}")
    
    # ایجاد سرورهای وب
    print(f"\n🌐 Creating {NUM_WEB_SERVERS} web servers...")
    web_servers = [WebServer(i) for i in range(1, NUM_WEB_SERVERS + 1)]
    for server in web_servers:
        print(f"   ✓ {server.hostname} ({server.server_type}) - {server.ip}:{server.port}")
    
    # ایجاد کلاینت‌ها
    print(f"\n💻 Creating {NUM_CLIENT_DEVICES} client devices...")
    client_devices = [ClientDevice(i) for i in range(1, NUM_CLIENT_DEVICES + 1)]
    for client in client_devices[:5]:  # فقط 5 تا اول را نمایش بده
        print(f"   ✓ {client.hostname} ({client.os_type}) - {client.ip}")
    if NUM_CLIENT_DEVICES > 5:
        print(f"   ... and {NUM_CLIENT_DEVICES - 5} more clients")
    
    # ایجاد AD Servers
    print(f"\n🔐 Creating {NUM_AD_SERVERS} AD servers (Domain Controllers)...")
    ad_servers = [ADServer(i) for i in range(1, NUM_AD_SERVERS + 1)]
    for ad in ad_servers:
        print(f"   ✓ {ad.hostname} ({ad.dc_role}) - {ad.ip} - {ad.domain}")
    
    # ایجاد Database Servers
    print(f"\n🗄️  Creating {NUM_DATABASE_SERVERS} database servers...")
    db_servers = [DatabaseServer(i) for i in range(1, NUM_DATABASE_SERVERS + 1)]
    for db in db_servers:
        print(f"   ✓ {db.hostname} ({db.db_type}) - {db.ip}:{db.port}")
    
    # ایجاد DNS Servers
    print(f"\n🌍 Creating {NUM_DNS_SERVERS} DNS servers...")
    dns_servers = [DNSServer(i) for i in range(1, NUM_DNS_SERVERS + 1)]
    for dns in dns_servers:
        print(f"   ✓ {dns.hostname} ({dns.dns_type}) - {dns.ip}")
    
    # ایجاد DHCP Servers
    print(f"\n📶 Creating {NUM_DHCP_SERVERS} DHCP servers...")
    dhcp_servers = [DHCPServer(i) for i in range(1, NUM_DHCP_SERVERS + 1)]
    for dhcp in dhcp_servers:
        print(f"   ✓ {dhcp.hostname} ({dhcp.dhcp_type}) - {dhcp.ip}")
    
    # ایجاد Email Servers
    print(f"\n📧 Creating {NUM_EMAIL_SERVERS} email servers...")
    email_servers = [EmailServer(i) for i in range(1, NUM_EMAIL_SERVERS + 1)]
    for email in email_servers:
        print(f"   ✓ {email.hostname} ({email.email_type}) - {email.ip} - {email.domain}")
    
    print("\n" + "=" * 60)
    print("✅ All devices initialized successfully!")
    print("=" * 60)
    print(f"\n📊 Configuration:")
    print(f"   - Network Devices: {NUM_NETWORK_DEVICES}")
    print(f"   - Web Servers: {NUM_WEB_SERVERS}")
    print(f"   - Client Devices: {NUM_CLIENT_DEVICES}")
    print(f"   - AD Servers: {NUM_AD_SERVERS}")
    print(f"   - Database Servers: {NUM_DATABASE_SERVERS}")
    print(f"   - DNS Servers: {NUM_DNS_SERVERS}")
    print(f"   - DHCP Servers: {NUM_DHCP_SERVERS}")
    print(f"   - Email Servers: {NUM_EMAIL_SERVERS}")
    print(f"   - Log Interval: {LOG_INTERVAL}s")
    print(f"   - Correlated Event Probability: {CORRELATED_EVENT_PROBABILITY * 100}%")
    print("\n🔄 Starting log generation...\n")
    
    return network_devices, web_servers, client_devices, ad_servers, db_servers, dns_servers, dhcp_servers, email_servers


def generate_independent_log(network_devices, web_servers, client_devices, ad_servers, db_servers, dns_servers, dhcp_servers, email_servers):
    """تولید یک لاگ مستقل"""
    device_type = random.choice([
        "network", "web", "client", "ad", "database", "dns", "dhcp", "email"
    ])
    
    if device_type == "network":
        device = random.choice(network_devices)
        generator = NetworkLogGenerator(device)
        return generator.generate_random_log()
    
    elif device_type == "web":
        server = random.choice(web_servers)
        generator = WebLogGenerator(server)
        return generator.generate_random_log()
    
    elif device_type == "client":
        client = random.choice(client_devices)
        generator = ClientLogGenerator(client)
        return generator.generate_random_log()
    
    elif device_type == "ad":
        ad_server = random.choice(ad_servers)
        generator = ADLogGenerator(ad_server)
        return generator.generate_random_log()
    
    elif device_type == "database":
        db_server = random.choice(db_servers)
        generator = DatabaseLogGenerator(db_server)
        return generator.generate_random_log()
    
    elif device_type == "dns":
        dns_server = random.choice(dns_servers)
        generator = DNSLogGenerator(dns_server)
        return generator.generate_random_log()
    
    elif device_type == "dhcp":
        dhcp_server = random.choice(dhcp_servers)
        generator = DHCPLogGenerator(dhcp_server)
        return generator.generate_random_log()
    
    else:  # email
        email_server = random.choice(email_servers)
        generator = EmailLogGenerator(email_server)
        return generator.generate_random_log()


def main():
    """تابع اصلی"""
    # مقداردهی اولیه
    network_devices, web_servers, client_devices, ad_servers, db_servers, dns_servers, dhcp_servers, email_servers = initialize_devices()
    
    # ایجاد سیستم رویدادهای مرتبط
    correlated_system = CorrelatedEventSystem(
        network_devices, web_servers, client_devices,
        ad_servers, db_servers, dns_servers, dhcp_servers, email_servers
    )
    
    # ایجاد کلاینت Splunk
    splunk_client = SplunkClient()
    
    log_count = 0
    
    try:
        while True:
            # تصمیم‌گیری: رویداد مرتبط یا مستقل
            if random.random() < CORRELATED_EVENT_PROBABILITY:
                # تولید رویداد مرتبط
                logs = correlated_system.generate_random_correlated_event()
                log_count += len(logs)
                print(f"🔗 Correlated Event: Generated {len(logs)} related logs")
                splunk_client.send_batch(logs)
            else:
                # تولید لاگ مستقل
                log = generate_independent_log(
                    network_devices, web_servers, client_devices,
                    ad_servers, db_servers, dns_servers, dhcp_servers, email_servers
                )
                log_count += 1
                device_name = log["event"].get("host", "unknown")
                event_type = log["event"].get("type", "unknown")
                print(f"📝 Independent Log: {device_name} - {event_type}")
                splunk_client.send_log(log)
            
            # نمایش آمار
            if log_count % 50 == 0:
                print(f"\n📈 Total logs generated: {log_count}\n")
            
            # انتظار
            time.sleep(LOG_INTERVAL)
    
    except KeyboardInterrupt:
        print("\n\n" + "=" * 60)
        print("🛑 Log generation stopped by user")
        print(f"📊 Total logs generated: {log_count}")
        print("=" * 60)
        # ارسال batch باقیمانده
        splunk_client.flush_batch()
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        splunk_client.flush_batch()


if __name__ == "__main__":
    main()


