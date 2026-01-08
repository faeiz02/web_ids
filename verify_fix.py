from managers import AlertManager
from models import Alert

try:
    am = AlertManager()
    print("AlertManager initialized.")
    alert = am.generate_alert("Test Alert", source_ip="1.2.3.4")
    print(f"Generated Alert: {alert}")
    print(f"Source IP: {alert.source_ip}")
    
    if alert.source_ip == "1.2.3.4":
        print("SUCCESS: Source IP verified.")
    else:
        print("FAILURE: Source IP not set.")
        
except Exception as e:
    print(f"ERROR: {e}")
