# Algorithm

Agent accepts binaries programs. To use the python program you need to bundle or compile it.
In this example we'll use [pyinstaller](https://pypi.org/project/pyinstaller/)

```shell
pip install pandas scikit-learn
pip install -U pyinstaller
pyinstaller --onefile lin_reg.py
```

Make the binary static:

```shell
pip install staticx
staticx <dynamic_binary_file_path> <output_file_path> 
```
