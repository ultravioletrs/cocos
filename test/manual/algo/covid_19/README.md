## Algorihm covid19.py

To download dataset first you have to sign in Keggle. https://www.kaggle.com/
Then follow this documentation. https://github.com/Kaggle/kaggle-api

Go to settings and download API key. Copy it into keggle folder.
Run divide_save_data.py
You should have now 3 datasets, named Hospital_1, Hospital_2, Hospital_3

`covid19.py` trains the the model and produces model.
run :
`python covid19.py Hospital_1 Hospital_2 Hospital_3 --model model.pth`
in this example dataset is Hospital_1, Hospital_2, and Hospital_3 and it produces model.pth

`covid.19.py` produced model, and now you should be able to use that model in `predict.py`
run :
`python predict.py --model model.pth --image Hospital_2/COVID/images/COVID-3.png`
in this example you have trained model (model.pth) that runs tests on images (this example is image from Hospital_2 in COVID/images/COVID-3.png)

