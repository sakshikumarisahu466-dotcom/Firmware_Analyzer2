Module 4 – ML Classifier & Risk Scoring
Purpose
This module uses Machine Learning to classify firmware-related strings as Normal or Suspicious and calculates a security risk score.


Technologies Used -----

Python
Pandas
Scikit-learn
TF-IDF Vectorizer
Logistic Regression


Input-----

The module reads suspicious/normal strings from:
scanner_output.txt 


Processing -----

Text data is converted into numerical features using TF-IDF.
Logistic Regression classifies each string as Normal or Suspicious.
Risk points are assigned based on suspicious patterns.
A final risk score is calculated.
The final risk level is displayed.


Risk Levels -----

LOW
MEDIUM
HIGH

Output ----

The results are displayed in the terminal and saved to:
results.csv

How to Run----

Install required libraries:
pip install -r requirements.txt
Then run:
python ml_classifier.py

Example -----
The system can detect patterns such as:
password
api_key
secret_key
backdoor
and assign an appropriate risk score.

Module Output-----

The module provides:

Classification: Normal / Suspicious
Indivisual Risk Score

Individual Risk Score
Total Items Scanned
Suspicious Items
Normal Items
Final Risk Score
Final Risk Level
