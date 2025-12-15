"""
کلاینت ارسال لاگ به Splunk HEC
"""
import json
import requests
from config import SPLUNK_HEC_URL, SPLUNK_TOKEN


class SplunkClient:
    """کلاینت برای ارسال لاگ‌ها به Splunk"""
    
    def __init__(self):
        self.url = SPLUNK_HEC_URL
        self.token = SPLUNK_TOKEN
        self.headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json"
        }
        self.batch_size = 10
        self.batch = []
    
    def send_log(self, log_data):
        """ارسال یک لاگ به Splunk"""
        try:
            response = requests.post(
                self.url,
                data=json.dumps(log_data),
                headers=self.headers,
                verify=False,
                timeout=5
            )
            if response.status_code in [200, 201]:
                return True
            else:
                print(f"Error sending log: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"Exception sending log: {str(e)}")
            return False
    
    def send_batch(self, logs):
        """ارسال دسته‌ای لاگ‌ها به Splunk"""
        if not logs:
            return
        
        try:
            # Splunk HEC می‌تواند چند لاگ را در یک درخواست دریافت کند
            batch_data = "\n".join([json.dumps(log) for log in logs])
            
            response = requests.post(
                self.url,
                data=batch_data,
                headers=self.headers,
                verify=False,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                print(f"✓ Sent batch of {len(logs)} logs to Splunk")
                return True
            else:
                print(f"✗ Error sending batch: {response.status_code} - {response.text}")
                # در صورت خطا، لاگ‌ها را یکی یکی ارسال کن
                return self._send_individually(logs)
        except Exception as e:
            print(f"✗ Exception sending batch: {str(e)}")
            # در صورت خطا، لاگ‌ها را یکی یکی ارسال کن
            return self._send_individually(logs)
    
    def _send_individually(self, logs):
        """ارسال لاگ‌ها به صورت جداگانه در صورت خطای batch"""
        success_count = 0
        for log in logs:
            if self.send_log(log):
                success_count += 1
        print(f"Sent {success_count}/{len(logs)} logs individually")
        return success_count == len(logs)
    
    def add_to_batch(self, log_data):
        """افزودن لاگ به batch"""
        self.batch.append(log_data)
        if len(self.batch) >= self.batch_size:
            self.flush_batch()
    
    def flush_batch(self):
        """ارسال batch و پاک کردن"""
        if self.batch:
            self.send_batch(self.batch)
            self.batch = []


