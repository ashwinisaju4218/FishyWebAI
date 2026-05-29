import requests

API_KEY = "f58f531b18cddf97ba4ebd779e685f7ca0679ce89bd04603c128c0a56243f747"

def check_virustotal(url):

    headers = {
        "x-apikey": API_KEY
    }

    scan_url = "https://www.virustotal.com/api/v3/urls"

    data = {
        "url": url
    }

    try:

        # Submit URL
        response = requests.post(
            scan_url,
            headers=headers,
            data=data
        )

        result = response.json()

        analysis_id = result["data"]["id"]

        # Get Report
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        analysis_response = requests.get(
            analysis_url,
            headers=headers
        )

        analysis_data = analysis_response.json()

        stats = analysis_data["data"]["attributes"]["stats"]

        malicious = stats["malicious"]
        suspicious = stats["suspicious"]

        return malicious, suspicious

    except:
        return None, None