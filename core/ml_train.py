"""
Trains a small, explainable text classifier to predict a command's risk
tier (LOW / MEDIUM / HIGH), using the dataset auto-labeled by our existing
hardcoded rules (see ml_dataset.py).

This model is NOT meant to replace the hardcoded rules — it's the fallback
for commands that don't match any hardcoded pattern, so "we don't recognize
this" can become an actual informed guess instead of a blind default.

Approach: TF-IDF (turns command text into numeric features based on which
words/patterns appear) + Logistic Regression (a simple, fast, and —
importantly — explainable classifier: you can inspect which words push a
prediction toward which risk tier, unlike a black-box deep model).
"""
import csv
import os
import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "storage", "training_data.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "storage", "risk_model.pkl")


def load_dataset():
    commands, labels = [], []
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            commands.append(row["command"])
            labels.append(row["risk_tier"])
    return commands, labels


def train_and_evaluate():
    commands, labels = load_dataset()
    print(f"Loaded {len(commands)} labeled examples.")

    # Hold out 20% of the data purely for honest evaluation — the model
    # never sees this during training, so accuracy on it reflects real
    # generalization, not memorization.
    X_train, X_test, y_train, y_test = train_test_split(
        commands, labels, test_size=0.2, random_state=42, stratify=labels
    )
    print(f"Training on {len(X_train)} examples, testing on {len(X_test)} held-out examples.")

    # TF-IDF with character n-grams (not just whole words) — this matters
    # for commands, since risk often hides in short substrings/flags
    # (e.g. "-f", "--force", "rm -rf") rather than whole dictionary words.
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=1)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = LogisticRegression(max_iter=1000, class_weight="balanced")
    model.fit(X_train_vec, y_train)

    predictions = model.predict(X_test_vec)
    accuracy = accuracy_score(y_test, predictions)

    print(f"\n=== Evaluation on held-out test set ===")
    print(f"Accuracy: {accuracy:.2%}")
    print("\nConfusion matrix (rows = actual, columns = predicted):")
    labels_order = ["LOW", "MEDIUM", "HIGH"]
    cm = confusion_matrix(y_test, predictions, labels=labels_order)
    print("           " + "  ".join(f"{l:>7}" for l in labels_order))
    for i, row in enumerate(cm):
        print(f"{labels_order[i]:>9}  " + "  ".join(f"{v:>7}" for v in row))

    print("\nPer-class breakdown:")
    print(classification_report(y_test, predictions, labels=labels_order, zero_division=0))

    # Save the trained model + vectorizer together so ml_classifier.py can
    # load both and make predictions on brand-new commands later.
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"vectorizer": vectorizer, "model": model}, f)
    print(f"Saved trained model -> {MODEL_PATH}")

    return accuracy


if __name__ == "__main__":
    train_and_evaluate()