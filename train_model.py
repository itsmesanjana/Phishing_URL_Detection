from ucimlrepo import fetch_ucirepo
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
from sklearn.model_selection import GridSearchCV

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

# ----------------- Hyperparameter Tuning for Random Forest -----------------
# Set the parameter grid for RandomForestClassifier
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [10, 20, 30, None],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4]
}

# Create a RandomForestClassifier and tune hyperparameters
rf = RandomForestClassifier(random_state=42)

# Apply GridSearchCV for hyperparameter optimization
grid_search = GridSearchCV(estimator=rf, param_grid=param_grid, cv=3, n_jobs=-1, verbose=2)
grid_search.fit(X_train, y_train)

# Get the best model from grid search
best_rf_model = grid_search.best_estimator_
print(f"Best model parameters: {grid_search.best_params_}")

# ----------------- Train the model -----------------
print("Training the best model...")
best_rf_model.fit(X_train, y_train)
print("Model trained.")

# ----------------- Model Evaluation -----------------
y_pred = best_rf_model.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print(f'Model Accuracy: {accuracy}')
print("Classification Report:\n", classification_report(y_test, y_pred))

# ----------------- Save the model -----------------
model_filename = 'phishing_detection_model.pkl'
print(f"Saving the model to {model_filename}...")
joblib.dump(best_rf_model, model_filename)
print(f"Model saved successfully to {model_filename}")

# Verify the file was created
if os.path.exists(model_filename):
    print(f"The model file {model_filename} was created successfully.")
else:
    print(f"Failed to create the model file {model_filename}.")

