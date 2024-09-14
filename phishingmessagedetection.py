import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder
import re
import requests
api_key = 'VIRUS_TOTAL_API_KEY'
data = pd.read_csv('spam1.csv', encoding='ISO-8859-1')
X = data['v2']  
y = data['v1']  
X = X.fillna('').astype(str)
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)
vectorizer = CountVectorizer()
X_transformed = vectorizer.fit_transform(X)
X_train, X_test, y_train, y_test = train_test_split(X_transformed, y, test_size=0.01, random_state=42)
model = DecisionTreeClassifier()
model.fit(X_train, y_train)
def check_message(message):
    prediction = model.predict(vectorizer.transform([message]))

    if prediction[0]: 
        print("Spam detected!")
        url_regex = re.compile(r'(https://\S+)')
        match = url_regex.search(message)
        if match:
            print("Link found in the message.")
            url = match.group(0)
            url_virustotal = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': api_key, 'resource': url}
            response = requests.get(url_virustotal, params=params)
            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:
                    positives = result.get('positives', 0)
                    if positives >= 1:
                        print("The link is flagged as a scam.")
                    else:
                        print("The link appears safe.")
                else:
                    print("No data available for this URL.")
            else:
                print("Error with the VirusTotal request.")
        else:
            print("No URL found in the message.")
    else:
        print("Message is not spam.")
def main():
    while True:
        message = input("Enter a message to check or exit to exit script: ")
        if message == "exit":
            print("exiting script")
            break
        else:
            check_message(message)
main()