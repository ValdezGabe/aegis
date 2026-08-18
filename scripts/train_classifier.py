# train_classifier.py
# Trains a prompt-injection detector (TF-IDF + Logistic Regression) on the
# public deepset/prompt-injections dataset, reports precision/recall on a
# held-out test set, and saves the model to models/classifier.joblib for the
# gateway.

from pathlib import Path

from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load
print("Loading dataset...")
dataset = load_dataset("deepset/prompt-injections")

X_train = dataset["train"]["text"]     
y_train = dataset["train"]["label"]    
X_test = dataset["test"]["text"]       
y_test = dataset["test"]["label"]      

print(f"Training examples: {len(X_train)} | Test examples: {len(X_test)}")

# Build Model
model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1)),
    ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
])

# Train
print("Training...")
model.fit(X_train, y_train)

# Measure on the data the model never saw
y_pred = model.predict(X_test)

print("\n================ RESULTS ================\n")
# classification_report prints precision, recall, and f1 for each class.
print(classification_report(y_test, y_pred, target_names=["safe (0)", "attack (1)"]))

# Confusion Matrix
print("Confusion matrix (rows = truth, columns = prediction):")
print(confusion_matrix(y_test, y_pred))
print("\n=========================================\n")

# Save trained model into models/ at the repo root, which is where the gateway
# loads it from at startup.
MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "classifier.joblib"
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(model, MODEL_PATH)
print(f"Saved trained model to {MODEL_PATH}")