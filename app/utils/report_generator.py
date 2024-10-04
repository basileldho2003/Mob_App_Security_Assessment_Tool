from fpdf import FPDF

def generate_pdf_report(scan_result, output_path):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)

    pdf.cell(200, 10, txt="Mobile App Security Assessment Report", ln=True, align='C')

    pdf.set_font('Arial', '', 12)
    pdf.cell(200, 10, txt=f"APK Name: {scan_result['apk_name']}", ln=True)
    pdf.cell(200, 10, txt="Scan Issues:", ln=True)

    for issue in scan_result['issues']:
        pdf.cell(200, 10, txt=issue, ln=True)

    pdf.output(output_path)
