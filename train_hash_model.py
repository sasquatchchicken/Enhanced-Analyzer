import joblib
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Simulated training data for classifying hashes
X = []
y = []  # Labels: 0 = Legit File, 1 = Malware Hash, 2 = Encryption Key

for _ in range(1000):
    length = random.choice([32, 40, 48, 64])  # hash lengths
    ascii_sum = random.randint(0, 255)
    category = random.choice([0, 1, 2]) 

    X.append([length, ascii_sum])
    y.append(category)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(f"Model Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")

joblib.dump(model, "hash_model.pkl")
print("Model saved as hash_model.pkl")
