import os
import logging
from pypdf import PdfWriter, PdfReader
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PDFReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir

    def generate_report(self, context, output_filename="report.pdf"):
        """
        Generates a PDF report using the provided context.
        """
        try:
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)

            # Create a temporary PDF using ReportLab
            temp_pdf_path = os.path.join(self.output_dir, "temp_report.pdf")
            c = canvas.Canvas(temp_pdf_path, pagesize=letter)

            # Title
            c.setFont("Helvetica-Bold", 16)
            c.drawString(72, 750, context.get("title", "Security Assessment Report"))

            # Summary
            c.setFont("Helvetica", 12)
            c.drawString(72, 730, context.get("summary", "This report contains the findings of the APK security assessment."))

            # Findings
            y_position = 700
            findings = context.get("findings", [])
            for finding in findings:
                c.setFont("Helvetica-Bold", 14)
                c.drawString(72, y_position, f"- {finding['type']}")
                y_position -= 20
                c.setFont("Helvetica", 12)
                c.drawString(90, y_position, f"Detail: {finding['detail']}")
                y_position -= 30

            c.save()

            # Read the temporary PDF and write to the final PDF using pypdf
            output_pdf_path = os.path.join(self.output_dir, output_filename)
            pdf_writer = PdfWriter()
            with open(temp_pdf_path, "rb") as temp_pdf:
                pdf_reader = PdfReader(temp_pdf)
                for page_num in range(len(pdf_reader.pages)):
                    pdf_writer.add_page(pdf_reader.pages[page_num])

                with open(output_pdf_path, "wb") as output_pdf:
                    pdf_writer.write(output_pdf)
            
            # Remove the temporary PDF
            os.remove(temp_pdf_path)

            logger.info(f"PDF report generated successfully at {output_pdf_path}")
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            raise Exception(f"Failed to generate PDF report: {e}")