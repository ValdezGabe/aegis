# Classifier Evaluation

This part of the gateway is a model I trained myself to recognize attacks. It is
called a classifier, which simply means a program that looks at a message and
sorts it into one of two groups: safe or attack. I built it using a common method
called TF-IDF with logistic regression, which is a well established way to teach a
program to tell text apart based on the words it contains. I trained it on a free,
public collection of real attack and safe examples, and then tested it on 116
examples it had never seen before, to get an honest measure of how well it works.

## What this means

When it flags a message as an attack, it is right almost every time. Out of 56
harmless messages, it wrongly flagged only 1. That means real users are very
rarely interrupted by a false alarm.

It is more cautious about catching every single attack. Out of 60 attacks, it
caught 45 and missed 15. On its own it catches about three out of four.

That is on purpose, and it is why the gateway does not rely on this one check
alone. It runs behind two other checks, so the attacks this layer misses are
usually caught by the ones in front of it. No single check is perfect, so they
work together and cover each other.

## The numbers

| Measure | Score | What it means |
|---|---|---|
| Precision | 98 percent | When it says attack, it is right 98 percent of the time |
| Recall | 75 percent | It catches 75 percent of real attacks by itself |
| Accuracy | 86 percent | Overall correct answers across all messages |

These three terms have specific meanings:

Precision answers the question: of all the messages it labeled as attacks, how
many really were attacks. High precision means few false alarms.

Recall answers the question: of all the real attacks that existed, how many it
managed to catch. High recall means few attacks slip through.

Accuracy is the overall share of messages, both safe and attack, that it labeled
correctly.

## Full report

The table below is the standard output from the testing step. Support is simply
the number of test examples in each group. F1 score is a single number that
combines precision and recall into one overall grade.

```
              precision    recall  f1-score   support

    safe (0)       0.79      0.98      0.87        56
  attack (1)       0.98      0.75      0.85        60

    accuracy                           0.86       116
   macro avg       0.88      0.87      0.86       116
weighted avg       0.89      0.86      0.86       116
```

In that table, safe (0) and attack (1) are the two groups. The 0 and 1 are just
the labels the model uses for safe and attack.

## Confusion matrix

A confusion matrix is a simple grid that shows what the model got right and wrong.
The rows are the truth, and the columns are what the model predicted.

|  | Predicted safe | Predicted attack |
|---|---|---|
| Actually safe | 55 | 1 |
| Actually attack | 15 | 45 |

Reading it: 55 safe messages were correctly called safe, and 1 was wrongly called
an attack. 45 attacks were correctly caught, and 15 were wrongly called safe.