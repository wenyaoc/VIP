#Import knearest neighbors Classifier model
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder  
from sklearn import metrics
import numpy as np

from collections import defaultdict

path_addr = "./output/training/21Feb_train_SW.csv"
df = pd.read_csv (path_addr)
# df['host type'] = df['host type'].astype(int)
# X = df.iloc[:,4:]
# index = np.r_[4:8, 12:13, 15, 19]
df['top proto(pkt)'] = pd.factorize(df['top proto(pkt)'])[0].astype(np.uint16)
df['top proto(byte)'] = pd.factorize(df['top proto(byte)'])[0].astype(np.uint16)
print(df.head())

df = df.drop(df.columns[[4,5,6,7,10,11,14,16,18,20,22,24]], axis=1)
X = df.iloc[:, 4:]
Y = df.iloc[:,1]


train_X, test_X, train_Y, test_Y = train_test_split(X, Y, test_size = 0.3)

# le = LabelEncoder()
# le.fit(train_Y)
# le.transform(train_Y)
# le.transform(test_Y)
# print(train_Y)
# print(test_Y)
#Create KNN Classifier
# knn = KNeighborsClassifier(n_neighbors=6)

# #Train the model using the training sets
# knn.fit(train_X, train_Y)

# #Predict the response for test dataset
# y_pred = knn.predict(test_X)
# print("KNN Accuracy:",metrics.accuracy_score(test_Y, y_pred))



rf = RandomForestClassifier()

#Train the model using the training sets
rf.fit(train_X, train_Y)

#Predict the response for test dataset
y_pred_rf = rf.predict(test_X)
print("Random Forest Accuracy:",metrics.accuracy_score(test_Y, y_pred_rf))


importance = rf.feature_importances_
# summarize feature importance
for i,v in enumerate(importance):
	print('Feature: %s, Score: %.5f' % (df.columns[i + 4],v))