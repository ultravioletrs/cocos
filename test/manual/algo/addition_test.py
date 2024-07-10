import sys
import joblib

results_file = sys.argv[1]

results = joblib.load(results_file)

print("Results: ", results)