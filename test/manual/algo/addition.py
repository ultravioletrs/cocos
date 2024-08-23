import os
import zipfile
import argparse

RESULTS_DIR = "results"
RESULTS_FILE = "result.txt"


class Computation:
    result = 0

    def __init__(self):
        """
        Initializes a new instance of the Computation class.
        """
        pass

    def compute(self, a, b):
        """
        Computes the sum of two numbers.
        """
        self.result = a + b

    def save_result(self):
        """
        Sends the result to a file.
        """
        try:
            os.makedirs(RESULTS_DIR)
        except FileExistsError:
            pass

        with open(RESULTS_DIR + os.sep + RESULTS_FILE, "w") as f:
            f.write(str(self.result))

    def read_results_from_file(self, results_file):
        """
        Reads the results from a file.
        """
        if results_file.endswith(".zip"):
            try:
                os.makedirs(RESULTS_DIR)
            except FileExistsError:
                pass
            with zipfile.ZipFile(results_file, "r") as zip_ref:
                zip_ref.extractall(RESULTS_DIR)
            with open(RESULTS_FILE, "r") as f:
                print(f.read())
        else:
            with open(results_file, "r") as f:
                print(f.read())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument('--a', type=int, help="First number", default=5)
    parser.add_argument('--b', type=int, help="Second number", default=10)
    parser.add_argument('--test', type=str, help="Test with a results file", required=False)

    args = parser.parse_args()

    computation = Computation()

    try:
        if args.test:
            computation.read_results_from_file(args.test)
        else:
            computation.compute(args.a, args.b)
            computation.save_result()
    except Exception as e:
        print(f"An error occurred: {e}")
        exit(1)
