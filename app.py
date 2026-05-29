from flask import Flask, render_template, request, send_file
import pandas as pd
import joblib
import socket
import whois

from feature_extractor import extract_features
from virustotal_checker import check_virustotal
from database import (
    save_scan,
    get_scans,
    get_dashboard_stats,
    get_top_threats,
    get_trend_data
)
from report_generator import generate_report

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
    domain_info = {}

    if request.method == "POST":

        url = request.form["url"]

        # Domain Information
        try:
            domain = (
                url.replace("https://", "")
                .replace("http://", "")
                .split("/")[0]
            )

            domain_data = whois.whois(domain)

            domain_info = {
                "ip": socket.gethostbyname(domain),
                "registrar": domain_data.registrar,
                "creation": str(domain_data.creation_date)
            }

        except Exception as e:
            print("WHOIS Error:", e)

        # Feature Extraction
        try:
            features, live_checks = extract_features(url)
        except Exception as e:
            print("Feature Extraction Error:", e)
            features = [0] * 30

        # VirusTotal Scan
        try:
            malicious, suspicious = check_virustotal(url)

            if malicious is not None:
                vt_result = f"""
VirusTotal Threat Intelligence

Malicious Flags: {malicious}
Suspicious Flags: {suspicious}
"""
            else:
                vt_result = "VirusTotal scan unavailable"

        except Exception as e:
            print("VirusTotal Error:", e)
            vt_result = "VirusTotal scan unavailable"

        # Ensure 30 Features
        while len(features) < 30:
            features.append(0)

        # Create DataFrame
        input_data = pd.DataFrame([features], columns=columns)

        try:
            # Prediction
            prediction = model.predict(input_data)
            print("\nAPP COLUMNS:")
            for col in input_data.columns:
             print(col)

            # Confidence Score
            probabilities = model.predict_proba(input_data)
            confidence = round(max(probabilities[0]) * 100, 2)

            if prediction[0] == -1:

                if confidence > 85:
                    threat = "HIGH"
                elif confidence > 65:
                    threat = "MEDIUM"
                else:
                    threat = "LOW"

                result = f"""
PHISHING WEBSITE DETECTED

Threat Level: {threat}
Confidence: {confidence}%
"""

            else:

                result = f"""
LEGITIMATE WEBSITE

Confidence: {confidence}%
"""

            # Save Result
            db_result = (
                "PHISHING"
                if prediction[0] == -1
                else "LEGITIMATE"
            )

            save_scan(
                url,
                db_result,
                confidence
            )

            generate_report(
                url,
                result,
                confidence,
                vt_result
            )

        except Exception as e:
            result = f"Prediction Error: {str(e)}"
            print("Prediction Error:", e)

    return render_template(
        "index.html",
        result=result,
        confidence=confidence,
        live_checks=live_checks,
        vt_result=vt_result,
        domain_info=domain_info
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

    total = stats["total"]
    safe = stats["safe"]
    phishing = stats["phishing"]

    if total > 0:

        safe_percent = round(
            (safe / total) * 100,
            1
        )

        phishing_percent = round(
            (phishing / total) * 100,
            1
        )

    else:

        safe_percent = 0
        phishing_percent = 0

    top_threats = get_top_threats()

    trend_data = get_trend_data()

    return render_template(
        "dashboard.html",
        stats=stats,
        safe_percent=safe_percent,
        phishing_percent=phishing_percent,
        top_threats=top_threats,
        trend_data=trend_data
    )


@app.route("/download-report")
def download_report():

    return send_file(
        "report.pdf",
        as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)