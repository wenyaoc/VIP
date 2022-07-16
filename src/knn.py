#Import knearest neighbors Classifier model
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder  
from sklearn import metrics



path_addr = "/home/wenyao/21Feb.csv"
df = pd.read_csv (path_addr)
# df['host type'] = df['host type'].astype(int)
X = df.iloc[:,4:]
Y = df.iloc[:,1]
# print(df.head())
# print(X.head())
# print(Y)
# le = LabelEncoder()
# le.fit_transform(Y)

# print(Y)

train_X, test_X, train_Y, test_Y = train_test_split(X, Y, test_size = 0.3)

le = LabelEncoder()
le.fit(train_Y)
le.transform(train_Y)
le.transform(test_Y)
# print(train_Y)
# print(test_Y)
#Create KNN Classifier
knn = KNeighborsClassifier(n_neighbors=6)

#Train the model using the training sets
knn.fit(train_X, train_Y)

#Predict the response for test dataset
y_pred = knn.predict(test_X)
print("KNN Accuracy:",metrics.accuracy_score(test_Y, y_pred))



rf = RandomForestClassifier()

#Train the model using the training sets
rf.fit(train_X, train_Y)

#Predict the response for test dataset
y_pred_rf = rf.predict(test_X)
print("Random Forest Accuracy:",metrics.accuracy_score(test_Y, y_pred_rf))


importance = rf.feature_importances_
# summarize feature importance
for i,v in enumerate(importance):
	print('Feature: %s, Score: %.5f' % (df.columns[i],v))