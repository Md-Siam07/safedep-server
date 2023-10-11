# import the libraries we'll need
import pandas as pd
import seaborn as sns
import numpy as np
import json
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer, HashingVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, recall_score, confusion_matrix
from sklearn.model_selection import GridSearchCV
from collections import Counter
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt

#file_path = "../../..//data//dataset//change-features.csv"
file_path = "dataset-train.csv"

# Load the CSV file into a pandas DataFrame
data = pd.read_csv(file_path)

