import sys, io
import joblib
import socket

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

    def send_result(self, socket_path):
        """
        Sends the result to a socket.
        """
        buffer = io.BytesIO()
        
        try:
            joblib.dump(self.result, buffer)
        except Exception as e:
            print("Failed to dump the result to the buffer: ", e)
            return

        data = buffer.getvalue()

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            try:
                client.connect(socket_path)
            except Exception as e:
                print("Failed to connect to the socket: ", e)
                return
            try:
                client.send(data)
            except Exception as e:
                print("Failed to send data to the socket: ", e)
                return
        finally:
            client.close()
    
    def read_results_from_file(self, results_file):
        """
        Reads the results from a file.
        """
        try:
            results = joblib.load(results_file)
            print("Results: ", results)
        except Exception as e:
            print("Failed to load results from file: ", e)
            return

if __name__ == "__main__":
    a = 5
    b = 10
    computation = Computation()

    if len(sys.argv) == 1:
        print("Please provide a socket path or a file path")
        exit(1)
    
    if sys.argv[1] == "test" and len(sys.argv) == 3:
        computation.read_results_from_file(sys.argv[2])
    elif len(sys.argv) == 2:
        computation.compute(a, b)
        computation.send_result(sys.argv[1])
    else:
        print("Invalid arguments")
        exit(1)

