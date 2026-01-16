from flask import Flask, render_template, jsonify, make_response
import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from zeek_ml_parser import parse_snort_and_correlate

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/alerts')
def get_alerts_json():
    try:
        # Remove the [:50] limit here to show more data
        alerts, total_alerts, _, attack_summary = parse_snort_and_correlate()
        return jsonify({
            'alerts': alerts[:200], # Increased to 200 for performance, or use alerts for all
            'total_alerts': total_alerts,
            'summary': attack_summary
        })
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/api/download_report')
def download_report():
    try:
        # 1. Fetch live data from your parser
        alerts, total_count, _, top_offenders = parse_snort_and_correlate()

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # 2. EXECUTIVE SUMMARY HEADER
        # Matches Source 1 & 2 from your sample
        elements.append(Paragraph("SIEM.PHILADELPHIA | AI-SOC EXECUTIVE SUMMARY", styles['Title']))
        elements.append(
            Paragraph(f"Analysis of {total_count} total ingress events from the log stream.", styles['Normal']))
        elements.append(Spacer(1, 20))

        # 3. SECTION I: CRITICAL ACTIVITY LOG
        # Matches Source 3, 4 & 5 from your sample
        elements.append(Paragraph("I. Critical Activity Log (Last 10 Events)", styles['Heading2']))
        elements.append(Paragraph("Displaying the most recent threats captured by the Snort engine.", styles['Italic']))
        elements.append(Spacer(1, 10))

        # Table 1: Recent Threats
        data1 = [["Time", "Classification", "Source IP", "Target IP", "AI Score"]]
        for a in alerts[:10]:
            # Convert decimal score to percentage string like '72.0%'
            score_pct = f"{float(a.get('anomaly_score', 0)) * 100:.1f}%"
            data1.append([
                str(a.get('timestamp', 'Recent')),
                f"({a.get('proto', 'TCP')}) {a.get('src_ip')}:{a.get('src_port', '0')}",
                a.get('src_ip'),
                a.get('dst_ip'),
                score_pct
            ])

        t1 = Table(data1, colWidths=[90, 180, 95, 95, 60])
        t1.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('LINEBELOW', (0, 0), (-1, 0), 1, colors.black),
            ('GRID', (0, 1), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
        ]))
        elements.append(t1)
        elements.append(Spacer(1, 30))

        # 4. SECTION II: HIGH-VOLUME SOURCE OFFENDERS
        # Matches Source 6, 7 & 8 from your sample
        elements.append(Paragraph("II. High-Volume Source Offenders", styles['Heading2']))
        elements.append(
            Paragraph("Calculated from the total dataset to identify persistent attackers.", styles['Italic']))
        elements.append(Spacer(1, 10))

        # Table 2: Top Offenders
        data2 = [["Rank", "Attacker IP", "Total Hits", "Risk Level"]]
        for i, (ip, count) in enumerate(top_offenders[:5], 1):
            # Assign risk level based on hit volume
            risk = "CRITICAL" if count > 1000 else "STABLE"
            data2.append([f"#{i}", ip, str(count), risk])

        t2 = Table(data2, colWidths=[60, 200, 100, 100])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ]))
        elements.append(t2)

        # 5. GENERATE PDF
        doc.build(elements)
        pdf_out = buffer.getvalue()
        buffer.close()

        response = make_response(pdf_out)
        response.headers["Content-Disposition"] = "attachment; filename=SOC_Summary.pdf"
        response.headers["Content-type"] = "application/pdf"
        return response

    except Exception as e:
        # Debugging print for the terminal
        print(f"Internal PDF Error: {e}")
        return f"PDF Error: {str(e)}", 500

if __name__ == '__main__':
    # Running on 5550 as per your requirements
    app.run(host='0.0.0.0', port=5550, debug=True)
