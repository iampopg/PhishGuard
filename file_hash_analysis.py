import requests
from collections import Counter

def get_virus_total_report(api_key, md5_hash):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{md5_hash}"

        headers = {
            "x-apikey": api_key
        }

        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            report = response.json()
            return report
        elif response.status_code == 404:
            return None
        else:
            print(f"Failed to get report: {response.status_code}")
            print(response.json())
            return None
    except:
        pass

def analyze_file(api_key, md5_hash):
    report = get_virus_total_report(api_key, md5_hash)
    
    if report:
        data = report.get('data', {})
        attributes = data.get('attributes', {})
        
        scans = attributes.get('last_analysis_results', {})
        malicious_count = 0
        reasons = []
        
        for vendor, result in scans.items():
            if result['result'] and 'malicious' in result['category']:
                malicious_count += 1
                reasons.append(result['result'])
        
        print(f"\nTagged vendors count: {malicious_count}")
        if malicious_count == 0:
            return "safe"
        
        elif reasons:
            most_common_reason = Counter(reasons).most_common(1)[0]
            print(f"Most common malicious reason: {most_common_reason[0]} ({most_common_reason[1]} times)")
            reasons = {'tagged_count':malicious_count,'reason':most_common_reason,'appear_time':most_common_reason[1]}
            return reasons
    return "safe"
