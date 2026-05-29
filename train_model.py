import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
df = pd.read_csv("dataset/dataset.csv")
print(df.columns.tolist())

# Remove unnecessary column
df.drop("index", axis=1, inplace=True)

# Features (X)
X = df.drop("Result", axis=1)

# Labels (y)
y = df["Result"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Create model
model = RandomForestClassifier()

# Train model
model.fit(X_train, y_train)

# Predictions
predictions = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, predictions)

print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Save model
joblib.dump(model, "model/phishing_detector.pkl")

print("Model saved successfully!")