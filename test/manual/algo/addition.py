import os
import sys
import zipfile

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
    a = 5
    b = 10

    computation = Computation()

    if len(sys.argv) == 1:
        computation.compute(a, b)
        computation.save_result()
    elif len(sys.argv) == 3 and sys.argv[1] == "test":
        computation.read_results_from_file(sys.argv[2])
    elif len(sys.argv) == 3:
        try:
            a = int(sys.argv[1])
            b = int(sys.argv[2])
            computation.compute(a, b)
            computation.save_result()
        except ValueError:
            print("Please provide two valid integers.")
            exit(1)
    else:
        print("Invalid arguments")
        exit(1)
