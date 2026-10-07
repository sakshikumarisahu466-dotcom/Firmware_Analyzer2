import pandas as pd

# Sample data for our ML model
data = {
    "text": [
        "hello world",
        "normal configuration file",
        "password=admin123",
        "api_key=ABCD123456",
        "system information",
        "secret_key=XYZ987",
        "normal user settings",
        "backdoor shell command"
    ],

    "label": [
        "Normal",
        "Normal",
        "Suspicious",
        "Suspicious",
        "Normal",
        "Suspicious",
        "Normal",
        "Suspicious"
    ]
}

# Convert data into a table
df = pd.DataFrame(data)

# Display the data
print("Sample Dataset:")
print(df)

# ML libraries
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Convert text into numerical features
vectorizer = TfidfVectorizer()

X = vectorizer.fit_transform(df["text"])
y = df["label"]

# Create and train the ML model
model = LogisticRegression()
model.fit(X, y)

print("\nML Model trained successfully!")

# Read data from Module 3 output file
with open("Module4_ML/scanner_output.txt", "r", encoding="utf-8") as file:
    test_data = [line.strip() for line in file if line.strip()]

# Convert test data into numerical form
test_X = vectorizer.transform(test_data)

# Predict Normal or Suspicious
predictions = model.predict(test_X)

print("\nPredictions:")

for text, prediction in zip(test_data, predictions):
    print(f"{text} --> {prediction}")

    # Risk scoring function
def calculate_risk(text, prediction):
    score = 0

    text_lower = text.lower()

    # Risk points based on suspicious patterns
    if "password" in text_lower:
        score += 30

    if "api_key" in text_lower or "api key" in text_lower:
        score += 30

    if "secret" in text_lower:
        score += 25

    if "backdoor" in text_lower:
        score += 40

    # Additional points if ML classified it as suspicious
    if prediction == "Suspicious":
        score += 20

    return score



# Calculate risk for all scanned items
print("\nRisk Analysis:")

results = []
total_risk = 0
suspicious_count = 0
normal_count = 0

for text, prediction in zip(test_data, predictions):

    risk = calculate_risk(text, prediction)

    # Keep each item's score between 0 and 100
    risk = min(risk, 100)

    total_risk += risk

    if prediction == "Suspicious":
        suspicious_count += 1
    else:
        normal_count += 1

    print(f"{text}")
    print(f"Classification: {prediction}")
    print(f"Risk Score: {risk}")
    print("--------------------")

    results.append({
        "Text": text,
        "Classification": prediction,
        "Risk Score": risk
    })


# Calculate final risk score from 0 to 100
if len(test_data) > 0:
    final_score = round(total_risk / len(test_data))
else:
    final_score = 0


# Decide final risk level
if final_score <= 30:
    risk_level = "LOW"
elif final_score <= 60:
    risk_level = "MEDIUM"
else:
    risk_level = "HIGH"


# Final security summary
print("\n========================")
print("FINAL SECURITY RESULT")
print("========================")

print(f"Total Items Scanned: {len(test_data)}")
print(f"Suspicious Items: {suspicious_count}")
print(f"Normal Items: {normal_count}")
print(f"Risk Score: {final_score}/100")
print(f"Risk Level: {risk_level}")


# Save results to CSV
results_df = pd.DataFrame(results)

results_df.to_csv(
    "Module4_ML/results.csv",
    index=False
)

print("\nResults saved successfully!")
print("File created: Module4_ML/results.csv")