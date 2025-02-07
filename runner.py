import sys
from engines.bandit import Bandit
from engines.bearer import Bearer
from engines.codeQL import CodeQL

SUPPORTED_TOOLS = ["bearer", "codeql"]
BENCHMARK_FILE = "./python/test.py"

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
