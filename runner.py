import threading
import sys
import psutil
import time
from datetime import datetime
from engines.bandit import Bandit
from engines.bearer import Bearer
from engines.codeQL import CodeQL
from engines.semgrep import Semgrep
from engines.horu_sec import Horusec

# Get the current process
CURRENT_PROCESS = psutil.Process()

ORIGINAL_BENCHMARK_FILE = "./python/test.py"

tool_to_class = {
    "bearer": Bearer,
    "codeql": CodeQL,
    "bandit": Bandit,
    "semgrep": Semgrep,
    "horu_sec": Horusec,
}


def not_empty(test):
    line = test["line"].replace(" ", "")
    return len(line) > 0


def is_positive_bm(test):
    return not_empty(test) and test["category"] and "+" in test["category"]


def is_negative_bm(test):

    return not_empty(test) and (
        (test["category"] and "-" in test["category"]) or (not test["category"])
    )


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


def perform_analysis(anaysis_stopped):

    assert (
        len(sys.argv) > 1
    ), f"Choose a SAST tool from {[tool for tool in tool_to_class.keys()]}"

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
    with open(ORIGINAL_BENCHMARK_FILE) as benchmark:
        for line in benchmark.readlines():
            line = line.strip()
            last_hash = line.split("#")[-1]  # should be the comment
            category = None
            if "+" in last_hash:
                bm_pos += 1
                category = "+"
            else:
                bm_neg += 1
                category = "-"
            test_lines.append({"line": line, "category": category})

    """
        ############################
        Setting and running the SAST
        ############################
    """
    # Capture starting time
    start_time = datetime.now()

    # run the sast tool
    sast = tool_to_class[used_tool]()
    sast.run()

    endtime = datetime.now()
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
    anaysis_stopped.set()
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
        print(f"{fp}, {len(fp)}")
    print("------------")
    print("Percentages")
    percentages = calculate_percentages(sast_tp, sast_fp, sast_tn, sast_fn)
    print(f"TP Percentage: {percentages[0]:.2f}%")
    print(f"FN Percentage: {percentages[3]:.2f}%")
    print(f"FP Percentage: {percentages[1]:.2f}%")
    print(f"TN Percentage: {percentages[2]:.2f}%")
    print("------------")
    print(f"Runtime: {str(endtime - start_time).split(":")[-1]}s")


def measure_sys(anaysis_stopped):
    def bytes_to_mb(bytes_value):
        return bytes_value / (1024**2)

    cpu_percentages = []
    mem_percentages = []
    while True and not anaysis_stopped.is_set():
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_usage = psutil.virtual_memory()
        cpu_percentages.append(cpu_percent)
        mem_percentages.append(memory_usage.percent)
        time.sleep(1)
    avg_cpu = sum(cpu_percentages) / len(cpu_percentages)
    avg_mem = sum(mem_percentages) / len(mem_percentages)
    print(cpu_percentages)
    print(mem_percentages)
    print(f"Average CPU Usage {avg_cpu}% per second")
    print(f"Average Memory Usage {bytes_to_mb(avg_mem)} MBs")


if __name__ == "__main__":
    anaysis_stopped = threading.Event()

    sys_resources_thrd = threading.Thread(target=measure_sys, args=(anaysis_stopped,))
    sast_analysis_thrd = threading.Thread(
        target=perform_analysis, args=(anaysis_stopped,)
    )

    # Start threads execution
    sys_resources_thrd.start()
    sast_analysis_thrd.start()

    # Stop the execution of the main program
    sys_resources_thrd.join()
    sast_analysis_thrd.join()
