from weasyprint import HTML
import os

def generate_pdf_report(html_input_path, pdf_output_path):
    """
    Generate a PDF report from an HTML file using WeasyPrint.
    """
    if not os.path.exists(html_input_path):
        print(f"HTML input file not found at {html_input_path}")
        return

    try:
        HTML(html_input_path).write_pdf(pdf_output_path)
        print(f"PDF report generated successfully at {pdf_output_path}")
    except Exception as e:
        print(f"Error generating PDF report: {e}")

# Testing code (for development purposes)
# if __name__ == "__main__":
#     # Example paths for testing purposes
#     html_input_path = "output/report.html"
#     pdf_output_path = "output/report.pdf"
#     generate_pdf_report(html_input_path, pdf_output_path)
