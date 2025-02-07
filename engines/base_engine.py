from abc import ABC, abstractmethod


class SAST(ABC):
    def __init__(self):
        self.OUTPUT_FOLDER_PATH = "./output"
        self.BENCHMARK_FILE = "./python/test.py"
        self.output_path = ""
        self.analysis_result = ""  # Should show the line

    @abstractmethod
    def run():
        pass

    @abstractmethod
    def is_positive():
        pass

    @abstractmethod
    def is_negative():
        pass

    def set_analysis_result(self, result: str):
        self.analysis_result = result

    def set_output_path(self, path: str):
        self.output_path = path
