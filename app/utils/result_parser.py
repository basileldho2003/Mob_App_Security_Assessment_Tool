import json
import os
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom.minidom import parseString

# Import the logger from the logger module
from .logger import logger

class ResultParser:
    def __init__(self, result_data, output_dir):
        self.result_data = result_data
        self.output_dir = output_dir

    def save_as_json(self, filename="result.json"):
        """
        Saves the result data as a JSON file.
        """
        try:
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)

            file_path = os.path.join(self.output_dir, filename)
            with open(file_path, 'w', encoding='utf-8') as json_file:
                json.dump(self.result_data, json_file, indent=4)
            logger.info(f"Result saved as JSON at {file_path}")
        except Exception as e:
            logger.error(f"Failed to save result as JSON: {e}")
            raise Exception(f"Failed to save result as JSON: {e}")

    def save_as_xml(self, filename="result.xml"):
        """
        Saves the result data as an XML file.
        """
        try:
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)

            root = Element('Results')
            for key, value in self.result_data.items():
                item = SubElement(root, 'Item', name=key)
                item.text = str(value)

            xml_str = tostring(root, 'utf-8')
            pretty_xml_str = parseString(xml_str).toprettyxml(indent="  ")

            file_path = os.path.join(self.output_dir, filename)
            with open(file_path, 'w', encoding='utf-8') as xml_file:
                xml_file.write(pretty_xml_str)
            logger.info(f"Result saved as XML at {file_path}")
        except Exception as e:
            logger.error(f"Failed to save result as XML: {e}")
            raise Exception(f"Failed to save result as XML: {e}")