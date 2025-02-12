from ucimlrepo import fetch_ucirepo
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
import os

# Fetch dataset
phishing_websites = fetch_ucirepo(id=327)

# Data (as pandas dataframes)
X = phishing_websites.data.features
y = phishing_websites.data.targets

# Convert target to binary label (assuming -1 is phishing and 1 is legitimate)
y = y['result'].apply(lambda x: 1 if x == 1 else 0)

# Print column names to verify
print("Column names in X:", X.columns)

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the model
print("Training the model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
print("Model trained.")

# Predict on the test set
y_pred = model.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print(f'Model Accuracy: {accuracy}')

# Save the model
model_filename = 'phishing_detection_model.pkl'
print(f"Saving the model to {model_filename}...")
joblib.dump(model, model_filename)
print(f"Model saved successfully to {model_filename}")

# Verify the file was created
if os.path.exists(model_filename):
    print(f"The model file {model_filename} was created successfully.")
else:
    print(f"Failed to create the model file {model_filename}.")