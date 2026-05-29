import joblib

model = joblib.load("model/phishing_detector.pkl")

print("MODEL FEATURES:")
for col in model.feature_names_in_:
    print(col)