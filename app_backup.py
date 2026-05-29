from flask import Flask, render_template, request
import pandas as pd
import joblib

from feature_extractor import extract_features
from virustotal_checker import check_virustotal
from database import save_scan, get_scans, get_dashboard_stats

app = Flask(__name__)

# Load trained AI model
model = joblib.load("model/phishing_detector.pkl")

# Dataset columns
columns = [
    'having_IPhaving_IP_Address',
    'URLURL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'SSLfinal_State',
    'Domain_registeration_length',
    'Favicon',
    'port',
    'HTTPS_token',
    'Request_URL',
    'URL_of_Anchor',
    'Links_in_tags',
    'SFH',
    'Submitting_to_email',
    'Abnormal_URL',
    'Redirect',
    'on_mouseover',
    'RightClick',
    'popUpWidnow',
    'Iframe',
    'age_of_domain',
    'DNSRecord',
    'web_traffic',
    'Page_Rank',
    'Google_Index',
    'Links_pointing_to_page',
    'Statistical_report'
]

@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    confidence = 0
    live_checks = []
    vt_result = None

    if request.method == "POST":

        url = request.form["url"]

        # Extract Features
        features, live_checks = extract_features(url)

        # VirusTotal Scan
        malicious, suspicious = check_virustotal(url)

        if malicious is not None:
            vt_result = f"""
⚠️ VirusTotal Threat Intelligence

Malicious Flags: {malicious}
Suspicious Flags: {suspicious}
"""
        else:
            vt_result = """
⚠️ VirusTotal scan unavailable
"""

        # Fill remaining features
        while len(features) < 30:
            features.append(0)

        # Create dataframe
        input_data = pd.DataFrame([features], columns=columns)

        # AI Prediction
        prediction = model.predict(input_data)

        # Confidence Score
        probabilities = model.predict_proba(input_data)
        confidence = round(max(probabilities[0]) * 100, 2)

        # Threat Level Logic
        if prediction[0] == -1:

            if confidence > 85:
                threat = "HIGH"
            elif confidence > 65:
                threat = "MEDIUM"
            else:
                threat = "LOW"

            result = f"""
⚠️ PHISHING WEBSITE DETECTED

Threat Level: {threat}
Confidence: {confidence}%
"""

        else:

            result = f"""
✅ LEGITIMATE WEBSITE

Confidence: {confidence}%
"""

        # Save Scan to Database
        save_scan(
            url,
            result,
            confidence
        )

    return render_template(
        "index.html",
        result=result,
        confidence=confidence,
        live_checks=live_checks,
        vt_result=vt_result
    )

@app.route("/history")
def history():

    scans = get_scans()

    return render_template(
        "history.html",
        scans=scans
    )

@app.route("/dashboard")
def dashboard():

    stats = get_dashboard_stats()

    return render_template(
        "dashboard.html",
        stats=stats
    )

if __name__ == "__main__":
    app.run(debug=True)