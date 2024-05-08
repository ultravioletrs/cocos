import sys, io
import joblib
import socket

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression

csv_file_path = sys.argv[2]
iris = pd.read_csv(csv_file_path)

# Droping the Species since we only need the measurements
X = iris.drop(['Species'], axis=1)

# converting into numpy array and assigning petal length and petal width
X = X.to_numpy()[:, (3,4)]
y = iris['Species']

# Splitting into train and test
X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.5, random_state=42)

log_reg = LogisticRegression()
log_reg.fit(X_train,y_train)

# Serialize the trained model to a byte buffer
model_buffer = io.BytesIO()
joblib.dump(log_reg, model_buffer)

# Get the serialized model as a bytes object
model_bytes = model_buffer.getvalue()

# Define the path for the Unix domain socket
socket_path = sys.argv[1]

# Create a Unix domain socket client
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

try:
    # Connect to the server
    client.connect(socket_path)

    # Send the serialized model over the socket
    client.send(model_bytes)

finally:
    # Close the socket
    client.close()
