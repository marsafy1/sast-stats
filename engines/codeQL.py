import os
import json
from engines.base_engine import SAST


class CodeQL(SAST):
    def run(self):
        database_name = "py-sast-db"
        format = "sarif-latest"
        self.set_output_path(
            f"{self.OUTPUT_FOLDER_PATH}/{self.__class__.__name__}.sarif"
        )

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
        with open(self.BENCHMARK_FILE) as benchmark:
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
