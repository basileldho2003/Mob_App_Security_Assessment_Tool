from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import os

def generate_html_report(scan_id, manifest_issues, source_code_issues, output_dir):
    """
    Generate an HTML report based on the scan results.
    
    Parameters:
    - scan_id: The ID of the scan being reported.
    - manifest_issues: A list of manifest issues detected.
    - source_code_issues: A list of source code issues detected.
    - output_dir: The directory to save the HTML report.
    
    Returns:
    - The path to the generated HTML report.
    """
    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Load the HTML template using Jinja2
    env = Environment(loader=FileSystemLoader('app/templates'))
    template = env.get_template('report.html')

    # Render the template with provided data
    html_content = template.render(
        scan_id=scan_id,
        manifest_issues=manifest_issues,
        source_code_issues=source_code_issues
    )

    # Save the rendered HTML content to a file
    html_report_path = os.path.join(output_dir, f'report_{scan_id}.html')
    with open(html_report_path, 'w') as html_file:
        html_file.write(html_content)

    return html_report_path

def generate_pdf_report(html_report_path, output_dir):
    """
    Generate a PDF report from the HTML report.
    
    Parameters:
    - html_report_path: The path to the generated HTML report.
    - output_dir: The directory to save the PDF report.
    
    Returns:
    - The path to the generated PDF report.
    """
    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Generate the PDF from the HTML report
    pdf_report_path = os.path.join(output_dir, os.path.basename(html_report_path).replace('.html', '.pdf'))
    HTML(html_report_path).write_pdf(pdf_report_path)

    return pdf_report_path
