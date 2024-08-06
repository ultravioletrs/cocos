import os
import sys
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
import zipfile
from sklearn import metrics

DATA_DIR = "datasets"
RESULTS_DIR = "results"
RESULTS_FILE = "model.bin"


class Computation:
    model = None

    def __init__(self):
        """
        Initializes a new instance of the Computation class.
        """
        pass

    def _read_csv(self, data_path=""):
        """
        Reads the CSV file.
        """
        files = os.listdir(data_path)
        if len(files) != 1:
            print("No files found in the directory")
            exit(1)
        csv_file_path = data_path + os.sep + files[0]
        return pd.read_csv(csv_file_path)

    def compute(self):
        """
        Trains a logistic regression model.
        """
        iris = self._read_csv(DATA_DIR)

        # Droping the Species since we only need the measurements
        X = iris.drop(["Species"], axis=1)

        # converting into numpy array and assigning petal length and petal width
        X = X.to_numpy()[:, (3, 4)]
        y = iris["Species"]

        X_train, _, y_train, _ = train_test_split(X, y, test_size=0.5, random_state=42)

        log_reg = LogisticRegression()
        log_reg.fit(X_train, y_train)
        self.model = log_reg

    def save_result(self):
        """
        Sends the result to a file.
        """
        try:
            os.makedirs(RESULTS_DIR)
        except FileExistsError:
            pass

        results_file = RESULTS_DIR + os.sep + RESULTS_FILE
        joblib.dump(self.model, results_file)

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
            self.model = joblib.load(RESULTS_DIR + os.sep + RESULTS_FILE)
        else:
            self.model = joblib.load(results_file)

    def predict(self, data_path=""):
        iris = self._read_csv(data_path)

        # Droping the Species since we only need the measurements
        X = iris.drop(["Species"], axis=1)

        # converting into numpy array and assigning petal length and petal width
        X = X.to_numpy()[:, (3, 4)]
        y = iris["Species"]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.5, random_state=42
        )

        training_prediction = self.model.predict(X_train)
        test_prediction = self.model.predict(X_test)

        print("Precision, Recall, Confusion matrix, in training\n")
        print(metrics.classification_report(y_train, training_prediction, digits=3))
        print(metrics.confusion_matrix(y_train, training_prediction))
        print("Precision, Recall, Confusion matrix, in testing\n")
        print(metrics.classification_report(y_test, test_prediction, digits=3))
        print(metrics.confusion_matrix(y_test, test_prediction))


if __name__ == "__main__":
    computation = Computation()
    if len(sys.argv) == 1:
        computation.compute()
        computation.save_result()
    elif len(sys.argv) == 4 and sys.argv[1] == "predict":
        computation.read_results_from_file(sys.argv[2])
        computation.predict(sys.argv[3])
    else:
        print("Invalid arguments")
        exit(1)
