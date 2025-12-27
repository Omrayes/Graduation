from flask import Flask, render_template, jsonify
import logging
import os
from flask import make_response
import io
from datetime import datetime

# Import the correlation function from your parser script
# Ensure zeek_ml_parser.py is in the same folder as this file.
try:
    from zeek_ml_parser import parse_snort_and_correlate
except ImportError:
    print("ERROR: zeek_ml_parser.py not found. Please ensure both files are in the same directory.")

# 1. FLASK CONFIGURATION
app = Flask(__name__)

# Configure logging to show errors in the terminal
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# ----------------------------------------------------
# 2. API ROUTE: The "Engine" of the Dashboard
# This route is called every 5 seconds by the JavaScript in your HTML.
# ----------------------------------------------------
@app.route('/api/alerts')
def get_alerts_json():
    alerts = []
    total_alerts = 0
    total_drops = 0
    attack_summary = []
    error = None

    try:
        # Call the "Real" correlation function that reads Snort/Zeek/ML
        alerts, total_alerts, total_drops, attack_summary = parse_snort_and_correlate()

        # Limit to the most recent 50 alerts to keep the dashboard fast
        alerts = alerts[:50]

    except FileNotFoundError as e:
        logging.error(f"File Error: {e}")
        error = f"Log file not found. Check if Snort/Zeek are running: {str(e)}"
    except Exception as e:
        logging.error(f"System Error: {e}")
        error = f"An unexpected error occurred: {str(e)}"

    # Construct the JSON response
    response_data = {
        'alerts': alerts,
        'total_alerts': total_alerts,
        'total_drops': total_drops,
        'summary': attack_summary,
        'error': error
    }

    # Add no-cache headers so the browser always fetches fresh live data
    response = jsonify(response_data)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response


# ----------------------------------------------------
# 3. HOME ROUTE: Serves the HTML Interface
# ----------------------------------------------------
@app.route('/')
def index():
    # This renders the templates/dashboard.html file
    return render_template('dashboard.html')


@app.route('/api/download_report')
def download_report():
    try:
        # Get the latest data from your parser
        alerts, _, _, _ = parse_snort_and_correlate()

        # Take the last 10 attacks
        last_10 = alerts[:10]

        # Create the report text
        report_content = "=== SECURITY INCIDENT REPORT: LAST 10 ATTACKS ===\n"
        report_content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report_content += "=================================================\n\n"

        if not last_10:
            report_content += "No attacks recorded in the current session."
        else:
            for i, alert in enumerate(last_10, 1):
                report_content += f"{i}. [{alert['timestamp']}] ALERT\n"
                report_content += f"   Type: {alert['msg']}\n"
                report_content += f"   Source IP: {alert['src_ip']}\n"
                report_content += f"   Target IP: {alert['dst_ip']}\n"
                report_content += f"   AI Anomaly Score: {float(alert['anomaly_score']) * 100:.1f}%\n"
                report_content += "   ----------------------------------------------\n"

        # Create a response that prompts a file download
        output = io.StringIO()
        output.write(report_content)

        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=attack_report.txt"
        response.headers["Content-type"] = "text/plain"

        return response
    except Exception as e:
        return f"Error generating report: {str(e)}", 500
# ----------------------------------------------------
# 4. EXECUTION BLOCK
# ----------------------------------------------------
if __name__ == '__main__':
    print("--- AI Cyber Defense Console Starting ---")
    print(" * Access the dashboard at: http://localhost:5000")

    # Check for root/sudo since we are reading system logs
    if os.geteuid() != 0:
        print("WARNING: You are not running as root. This script may fail to read Snort/Zeek logs.")
        print("Try: sudo python3 app.py")

    # Run the server
    # '0.0.0.0' allows you to access the dashboard from other devices on your network
    app.run(host='0.0.0.0', port=5550, debug=True)
