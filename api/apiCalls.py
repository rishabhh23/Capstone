import requests
import json
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv() 

VIRUSTOTAL_API_KEY = os.getenv('VT_API_KEY')
IPQUALITYSCORE_API_KEY = os.getenv('IPQS_API_KEY')

# mock API calls
# def check_ip_reputation(ip_address):
#     if ip_address == "192.0.2.1":
#         return {
#             "malicious": 5, 
#             "country": "United States",
#             "isp": "Example ISP",
#             "raw_data": {"mock": True}  
#         }
#     else:
#         return {"error": "Invalid test IP"}

# # mock API call
# def check_ip_quality(ip_address):
#     if ip_address == "203.0.113.10":
#         return {
#             "fraud_score": 30,  
#             "proxy": False,
#             "vpn": False,
#             "recent_abuse": "low"
#         }
#     else:
#         return {"error": "Invalid test IP"}

# virustotal API call
import requests

def check_ip_reputation(ip_address):
    """Check IP reputation using VirusTotal (v3) with safe key‐access."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        payload = resp.json()
        
        # drill into the attributes dict (may not have all keys)
        attrs = payload.get('data', {}).get('attributes', {})
        
        # analysis stats are always present but still guard
        stats = attrs.get('last_analysis_stats', {})
        malicious  = stats.get('malicious',  0)
        suspicious = stats.get('suspicious', 0)
        harmless   = stats.get('harmless',   0)
        
        # these may be missing
        country   = attrs.get('country')    # returns None if absent
        as_owner  = attrs.get('as_owner')   # returns None if absent

        return {
            'malicious':  malicious,
            'suspicious': suspicious,
            'harmless':   harmless,
            'country':    country,
            'as_owner':   as_owner,
            'raw_data':   payload
        }

    except requests.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text}"}
    except ValueError:
        return {"error": "Invalid JSON received from VirusTotal"}
    except Exception as e:
        return {"error": str(e)}

def check_ip_quality(ip_address):
    """Check IP quality and risk factors"""
    url = f"https://www.ipqualityscore.com/api/json/ip/{IPQUALITYSCORE_API_KEY}/{ip_address}"
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            
            return {
                'fraud_score': data.get('fraud_score'),
                'proxy': data.get('proxy'),
                'vpn': data.get('vpn'),
                'tor': data.get('tor'),
                'bot_status': data.get('bot_status'),
                'recent_abuse': data.get('abuse_velocity')
            }
        return {"error": f"API request failed with status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}