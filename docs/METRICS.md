# Classifier Evaluation

Layer 3 of the inbound guard is a model trained here rather than bought or
called over the network. A classifier is a program that reads a message and
sorts it into one of two groups, safe or attack.

The method is TF-IDF with logistic regression. TF-IDF (Term Frequency, Inverse
Document Frequency) turns text into numbers by weighting each word by how often
it appears in this message against how rare that word is across all messages.
Logistic regression then scores that vector and returns both a label and a
confidence value. It is a well established text classification approach, fast
enough to run in process on every request.

Training used the public `deepset/prompt-injections` dataset. Evaluation used
116 examples the model never saw during training, which is what makes the
numbers honest rather than a measure of memorization.

## What the results mean

When this layer flags a message as an attack, it is right almost every time.
Out of 56 harmless messages it wrongly flagged only 1, so real users are rarely
interrupted by a false alarm.

It is less complete at catching every attack. Out of 60 attacks it caught 45 and
missed 15, so on its own it catches about three out of four.

That trade is deliberate. This layer runs behind two others, so most of what it
misses is already caught in front of it. No single check is perfect, so they
cover each other.

## The numbers

| Measure | Score | What it means |
|---|---|---|
| Precision | 98 percent | When it says attack, it is right 98 percent of the time |
| Recall | 75 percent | It catches 75 percent of real attacks by itself |
| Accuracy | 86 percent | Overall correct answers across all messages |

Precision answers: of all the messages it labeled as attacks, how many really
were attacks. High precision means few false alarms.

Recall answers: of all the real attacks that existed, how many it caught. High
recall means few attacks slip through.

Accuracy is the overall share of messages, safe and attack together, labeled
correctly.

## Full report

Standard output from the evaluation step. Support is the number of test examples
in each group. F1 score combines precision and recall into one number.

```
              precision    recall  f1-score   support

    safe (0)       0.79      0.98      0.87        56
  attack (1)       0.98      0.75      0.85        60

    accuracy                           0.86       116
   macro avg       0.88      0.87      0.86       116
weighted avg       0.89      0.86      0.86       116
```

Safe (0) and attack (1) are the two groups. The 0 and 1 are the numeric labels
the model uses internally.

## Confusion matrix

A confusion matrix is a grid showing what the model got right and wrong. Rows
are the truth, columns are the prediction.

|  | Predicted safe | Predicted attack |
|---|---|---|
| Actually safe | 55 | 1 |
| Actually attack | 15 | 45 |

Reading it: 55 safe messages were correctly called safe and 1 was wrongly called
an attack. 45 attacks were correctly caught and 15 were wrongly called safe.

## Reproducing this

```bash
python scripts/train_classifier.py
```

The script trains, prints the report and confusion matrix above, and writes the
model to `models/classifier.joblib`, which the gateway loads at startup.
