import os
import logging
from jinja2 import Environment, FileSystemLoader

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HTMLReportGenerator:
    def __init__(self, template_dir, output_dir):
        self.template_dir = template_dir
        self.output_dir = output_dir
        self.env = Environment(loader=FileSystemLoader(self.template_dir))

    def generate_report(self, template_name, context, output_filename="report.html"):
        """
        Generates an HTML report using the specified template and context.
        """
        try:
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)

            template = self.env.get_template(template_name)
            html_content = template.render(context)

            file_path = os.path.join(self.output_dir, output_filename)
            with open(file_path, 'w', encoding='utf-8') as html_file:
                html_file.write(html_content)
            logger.info(f"HTML report generated successfully at {file_path}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise Exception(f"Failed to generate HTML report: {e}")