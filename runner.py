from abc import ABC, abstractmethod
import os
import sys
import json

SUPPORTED_TOOLS = ["bearer", "codeql"]
OUTPUT_FOLDER_PATH = "./output"
BENCHMARK_FILE = "./python/test.py"


class SAST(ABC):
    def __init__(self):
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


class Bearer(SAST):
    def run(self):
        self.set_output_path(f"{OUTPUT_FOLDER_PATH}/{self.__class__.__name__}.txt")
        # Execute the command
        os.system(f"./bin/bearer scan python/*.py > {self.output_path}")
        with open(self.output_path) as analysis_result:
            self.set_analysis_result(analysis_result.read())

    def is_positive(self, test_case):
        return test_case in self.analysis_result

    def is_negative(self, test_case):
        return not self.is_positive()


class CodeQL(SAST):
    def run(self):
        database_name = "py-sast-db"
        format = "sarif-latest"
        self.set_output_path(f"{OUTPUT_FOLDER_PATH}/{self.__class__.__name__}.sarif")

        # 1. Create the DB
        os.system(
            f"codeql database create {database_name} --language=python --overwrite"
        )
        # 2. Run the analyzer
        os.system(
            f"codeql database analyze py-sast-db --format={format} --output={self.output_path} python-code-scanning.qls python-lgtm-full.qls python-lgtm.qls python-security-and-quality.qls python-security-experimental.qls python-security-extended.qls --download githubsecuritylab/codeql-python-queries githubsecuritylab/codeql-python-queries:security/CWE-798/HardcodedFrameworkSecrets.ql"
        )
        # 3. Read the output
        with open(self.output_path) as analysis_result:
            json_output = json.load(analysis_result)
            results = json_output["runs"][0]["results"]

        benchmarkLines = {}
        with open(BENCHMARK_FILE) as benchmark:
            l_i = 1
            for line in benchmark.readlines():
                benchmarkLines[l_i] = line.strip()
                l_i += 1

        tmp_results = ""

        for result in results:
            rule_id = result["ruleId"]
            locations = result["locations"][0]
            physical_locations = locations["physicalLocation"]
            filename = physical_locations["artifactLocation"]["uri"]
            if "test" not in filename:  # as we just want to use our benchmark files
                continue
            line_num = physical_locations["region"]["startLine"]
            line = benchmarkLines[line_num]
            tmp_results += f"{rule_id}@{filename}-L:{line_num} - {line}\n"

        self.set_analysis_result(tmp_results)
        print(self.analysis_result)

    def is_positive(self, test_case):
        return test_case in self.analysis_result

    def is_negative(self, test_case):
        return not self.is_positive()


class Bandit(SAST):
    def run(self):
        self.set_output_path(f"{OUTPUT_FOLDER_PATH}/{self.__class__.__name__}.txt")
        # Execute the command
        os.system(f"bandit -r python/ > {self.output_path}")
        with open(self.output_path) as analysis_result:
            self.set_analysis_result(analysis_result.read())

    def is_positive(self, test_case):
        return test_case in self.analysis_result

    def is_negative(self, test_case):
        return not self.is_positive()


tool_to_class = {"bearer": Bearer, "codeql": CodeQL, "bandit": Bandit}


def is_positive_bm(test):
    return "+" in test["category"]


def is_negative_bm(test):
    return "-" in test["category"]


def calculate_percentages(sast_tp, sast_fp, sast_tn, sast_fn):
    total_positives = sast_tp + sast_fn
    total_negatives = sast_fp + sast_tn

    # Initialize percentages
    tp_percentage = fp_percentage = fn_percentage = tn_percentage = 0.0

    # Calculate TP Percentage
    if total_positives > 0:
        tp_percentage = (sast_tp / total_positives) * 100

    # Calculate FP Percentage
    if total_negatives > 0:
        fp_percentage = (sast_fp / total_negatives) * 100

    # Calculate FN Percentage
    if total_positives > 0:
        fn_percentage = (sast_fn / total_positives) * 100

    # Calculate TN Percentage
    if total_negatives > 0:
        tn_percentage = (sast_tn / total_negatives) * 100

    return tp_percentage, fp_percentage, tn_percentage, fn_percentage


if __name__ == "__main__":

    assert len(sys.argv) > 1, f"Choose a SAST {SUPPORTED_TOOLS}"

    used_tool = sys.argv[1]

    # init variables
    # Benchmark file
    test_lines = []
    bm_pos = bm_neg = 0

    # Analysis results
    # false_negatives = false_positives = [] # <- same reference
    false_negatives, false_positives = [], []
    sast_tp = sast_tn = sast_fp = sast_fn = 0

    """
        ###############################
        Setting up the benchmark values
        ###############################
    """
    # read the used benchmark file
    with open(BENCHMARK_FILE) as benchmark:
        for line in benchmark.readlines():
            line = line.strip()
            last_hash = line.split("#")[-1]  # should be the comment
            category = None
            if "+" in last_hash:
                bm_pos += 1
                category = "+"
            elif "-" in last_hash:
                bm_neg += 1
                category = "-"
            if category:
                test_lines.append({"line": line, "category": category})

    """
        ############################
        Setting and running the SAST
        ############################
    """
    # run the sast tool
    sast = tool_to_class[used_tool]()
    sast.run()

    """
        ###################################
        Analysis and comparing the outcomes
        ###################################
    """

    analysis_output = sast.analysis_result
    print(analysis_output)
    for test in test_lines:
        if sast.is_positive(test["line"]):  # means it was classified as positive
            if is_positive_bm(test):  # TP
                sast_tp += 1
            elif is_negative_bm(test):  # FP
                sast_fp += 1
                false_positives.append(test["line"])
        else:  # means it was classified as negative
            if is_positive_bm(test):
                sast_fn += 1
                false_negatives.append(test["line"])
            elif is_negative_bm(test):
                sast_tn += 1

    print("------------")
    print(f"Benchmark Positives: {bm_pos}")
    print(f"Benchmark Negatives: {bm_neg}")
    print("------------")
    print(f"SAST TP: {sast_tp}")
    print(f"SAST FP: {sast_fp}")
    print(f"SAST TN {sast_tn}")
    print(f"SAST FN: {sast_fn}")
    print("------------")
    print(f"False Negatives {len(false_negatives), sast_fn}")
    for fn in false_negatives:
        print(fn)
    print("------------")
    print(f"False Positives {len(false_positives), sast_fp}")
    for fp in false_positives:
        print(fp)
    print("------------")
    print("Percentages")
    percentages = calculate_percentages(sast_tp, sast_fp, sast_tn, sast_fn)
    print(f"TP Percentage: {percentages[0]:.2f}%")
    print(f"FP Percentage: {percentages[1]:.2f}%")
    print(f"TN Percentage: {percentages[2]:.2f}%")
    print(f"FN Percentage: {percentages[3]:.2f}%")
