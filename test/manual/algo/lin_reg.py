import sys
import io
import joblib

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression

csv_file_path = sys.argv[1]
iris = pd.read_csv(csv_file_path)

# Log data loading completion
print(f"Finished loading data from {csv_file_path}", file=sys.stderr)

# Droping the Species since we only need the measurements
X = iris.drop(['Species'], axis=1)

# converting into numpy array and assigning petal length and petal width
X = X.to_numpy()[:, (3,4)]
y = iris['Species']

# Log feature selection completion
print(f"Selected features: Petal Length & Petal Width", file=sys.stderr)

# Splitting into train and test
X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.5, random_state=42)

# Log data splitting completion with test size information
print(f"Train-Test split completed (Test Size: {0.5})", file=sys.stderr)

log_reg = LogisticRegression()
log_reg.fit(X_train,y_train)

# Serialize the trained model to a byte buffer
model_buffer = io.BytesIO()
joblib.dump(log_reg, model_buffer)

# Get the serialized model as a bytes object
model_bytes = model_buffer.getvalue()

# Write the serialized model to stdout
sys.stdout.buffer.write(model_bytes)
