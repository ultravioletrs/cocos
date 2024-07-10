import sys, io
import joblib
import socket

a = 5
b = 10
result = a + b

buffer = io.BytesIO()
joblib.dump(result, buffer)

data = buffer.getvalue()

socket_path = sys.argv[1]

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

try:
    client.connect(socket_path)

    client.send(data)

finally:
    client.close()
