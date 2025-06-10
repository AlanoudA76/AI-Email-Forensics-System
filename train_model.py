import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import joblib

# Dummy dataset (you can replace this with a larger dataset)
data = {
    "text": [
        "Urgent: Update your account now",
        "Important notice from your bank",
        "Win a free iPhone now!!!",
        "Hello, here is the report you requested",
        "Your invoice is attached",
        "Click to verify your account",
        "Meeting rescheduled to next week",
        "Confirm your email to win",
        "Let's catch up tomorrow",
        "Your PayPal account has been suspended"
    ],
    "label": [1, 1, 1, 0, 0, 1, 0, 1, 0, 1]  # 1 = phishing, 0 = legit
}

df = pd.DataFrame(data)

# Split and train
X_train, X_test, y_train, y_test = train_test_split(df['text'], df['label'], test_size=0.2, random_state=42)

model = Pipeline([
    ('vectorizer', CountVectorizer()),
    ('classifier', MultinomialNB())
])

model.fit(X_train, y_train)

# Save model
joblib.dump(model, 'phishing_model.pkl')

print("✅ Model trained and saved as phishing_model.pkl")
