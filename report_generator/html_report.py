from jinja2 import Environment, FileSystemLoader

def generate_html_report(output_path, report_data):
    """
    Generate an HTML report from the provided data using Jinja2 templates.
    """
    try:
        # Set up Jinja2 environment and load the template
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('report_template.html')

        # Render the HTML with the provided report data
        rendered_html = template.render(report_data=report_data)

        # Write the rendered HTML to the output path
        with open(output_path, 'w', encoding='utf-8') as report_file:
            report_file.write(rendered_html)

        print(f"HTML report generated successfully at {output_path}")
    except Exception as e:
        print(f"Error generating HTML report: {e}")

# Testing code (for development purposes)
# if __name__ == "__main__":
#     # Example report data for testing purposes
#     report_data = {
#         'title': 'Security Scan Report',
#         'date': '2024-10-01',
#         'summary': 'Summary of scan results',
#         'issues': [
#             {'issue_type': 'Permission', 'detail': 'Potentially dangerous permission requested: INTERNET', 'severity': 'medium'},
#             {'issue_type': 'Configuration', 'detail': 'Application is set to be debuggable, which poses a security risk.', 'severity': 'high'}
#         ]
#     }
#     output_path = "output/report.html"
#     generate_html_report(output_path, report_data)
