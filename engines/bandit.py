import os
from engines.base_engine import SAST


class Bandit(SAST):
    def run(self):
        self.set_output_path(f"{self.OUTPUT_FOLDER_PATH}/{self.__class__.__name__}.txt")
        # Activate the venv
        # Execute the command
        os.system(f"source venv/bin/activate && bandit -r python/ > {self.output_path}")
        with open(self.output_path) as analysis_result:
            self.set_analysis_result(analysis_result.read())

    def is_positive(self, test_case):
        return test_case in self.analysis_result

    def is_negative(self, test_case):
        return not self.is_positive()
