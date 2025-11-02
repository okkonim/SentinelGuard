import yara
import os
import logging
from database import Database

logger = logging.getLogger(__name__)

class YARAScanner:
    def __init__(self, db_name='firewall.db'):
        self.db = Database(db_name)
        self.rules = None

    def compile_rules(self, rule_files):
        """Compile YARA rules from one or more .yar files."""
        try:
            self.rules = yara.compile(filepaths=rule_files)
            logger.info(f"YARA rules compiled from: {list(rule_files.keys())}")
            return True
        except yara.Error as e:
            logger.error(f"YARA compilation error: {e}")
            return False

    def scan_file(self, file_path):
        """Scan a single file with compiled YARA rules."""
        if not self.rules:
            logger.error("No YARA rules compiled")
            return []

        if not os.path.exists(file_path):
            logger.warning(f"File does not exist: {file_path}")
            return []

        try:
            matches = self.rules.match(file_path)
            results = []
            for match in matches:
                result = {
                    'rule_name': match.rule,
                    'file_path': file_path,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [{'offset': s[0], 'string': s[1], 'identifier': s[2]} for s in match.strings]
                }
                results.append(result)
                # Log to database
                self.db.insert_yara_event(file_path, match.rule, 'MATCH', 'CRITICAL', str(result))
            return results
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []

    def scan_directory(self, directory_path):
        """Recursively scan all files in a directory."""
        results = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_results = self.scan_file(file_path)
                results.extend(file_results)
        return results

    def reload_rules(self, rule_files):
        """Reload YARA rules without restarting."""
        return self.compile_rules(rule_files)
