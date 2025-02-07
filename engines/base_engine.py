from abc import ABC, abstractmethod


class SAST(ABC):
    def __init__(self):
        self.ORIGINAL_BENCHMARK_FILE = "./python/test.py"
        self.BENCHMARK_FILE = "./python/mod_test.py"
        self.OUTPUT_FOLDER_PATH = "./output"
        self.output_path = ""
        self.analysis_result = ""
        self.manipulate_benchmark_file()

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

    def manipulate_benchmark_file(self, repeatition=5):
        with open(self.ORIGINAL_BENCHMARK_FILE, "r") as original_bm:
            original_bm_content = original_bm.read()
        with open(self.BENCHMARK_FILE, "w") as mod_bm:
            mod_bm.write(original_bm_content * repeatition)
