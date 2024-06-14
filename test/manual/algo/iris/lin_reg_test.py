import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn import metrics
import joblib

import sys

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)

csv_file_path = sys.argv[1]
model_filename = sys.argv[2]

# Load the CSV file into a Pandas DataFrame
iris = pd.read_csv(csv_file_path)

log_reg = joblib.load(model_filename)

# Now you have the Iris dataset loaded into the iris_df DataFrame
print(iris.head())  # Display the first few rows of the DataFrame

# Droping the Species since we only need the measurements
X = iris.drop(['Species'], axis=1)

# converting into numpy array and assigning petal length and petal width
X = X.to_numpy()[:, (3,4)]
y = iris['Species']

# Splitting into train and test
X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.5, random_state=42)

training_prediction = log_reg.predict(X_train)
test_prediction = log_reg.predict(X_test)

print("Precision, Recall, Confusion matrix, in training\n")

# Precision Recall scores
print(metrics.classification_report(y_train, training_prediction, digits=3))

# Confusion matrix
print(metrics.confusion_matrix(y_train, training_prediction))

print("Precision, Recall, Confusion matrix, in testing\n")

# Precision Recall scores
print(metrics.classification_report(y_test, test_prediction, digits=3))

# Confusion matrix
print(metrics.confusion_matrix(y_test, test_prediction))
