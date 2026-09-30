"""
Fine-tune a transformer token-classification model for PII / sensitive-data
detection, using a real-world open dataset.

WHY THIS SCRIPT ISN'T RUN INSIDE THE DEV SANDBOX
--------------------------------------------------
This project was scaffolded in an environment whose network access is
restricted to PyPI/GitHub/npm (for reproducible package installs). It
cannot reach huggingface.co to pull base-model weights or the training
dataset. That's fine -- fine-tuning is a one-time, offline step that
belongs on your own machine (ideally with a GPU) or in Google Colab, not
in the deployed backend. Run this script there, then copy the resulting
model directory into `models/shadow-ner-finetuned/` next to this repo and
flip `SAG_NER_BACKEND=transformer` in your .env.

RECOMMENDED DATASET
--------------------
ai4privacy/pii-masking-200k on the Hugging Face Hub: ~200k real-world-style
text samples across many PII categories (names, emails, SSNs, credit cards,
addresses, etc.) with token-level BIO labels -- exactly the shape this
script expects. It's actively used in industry PII-detection benchmarks.
Swap `DATASET_NAME` for any other token-classification PII/NER dataset
with the same schema (tokens + BIO tags) if you prefer.

USAGE (on a machine with internet + ideally a GPU)
----------------------------------------------------
    pip install transformers datasets seqeval torch accelerate evaluate
    python scripts/train_ner.py \
        --base_model distilbert-base-uncased \
        --output_dir ./models/shadow-ner-finetuned \
        --epochs 3

Then in your backend .env:
    SAG_NER_BACKEND=transformer
    SAG_TRANSFORMER_MODEL_PATH=./models/shadow-ner-finetuned
"""
from __future__ import annotations

import argparse

import numpy as np


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fine-tune a token-classification model for PII detection.")
    parser.add_argument("--dataset_name", default="ai4privacy/pii-masking-200k",
                         help="HF dataset with tokens + BIO tags (or a local JSON/CSV with the same schema).")
    parser.add_argument("--base_model", default="distilbert-base-uncased",
                         help="Base checkpoint to fine-tune. Smaller = faster to train/serve; "
                              "try 'microsoft/deberta-v3-base' for higher accuracy if you have GPU budget.")
    parser.add_argument("--output_dir", default="./models/shadow-ner-finetuned")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch_size", type=int, default=16)
    parser.add_argument("--learning_rate", type=float, default=5e-5)
    parser.add_argument("--max_length", type=int, default=256)
    parser.add_argument("--eval_split", default="validation")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Imports are local to main() so `python scripts/train_ner.py --help`
    # works even before you've installed the heavy training deps.
    import evaluate
    from datasets import load_dataset
    from transformers import (
        AutoModelForTokenClassification,
        AutoTokenizer,
        DataCollatorForTokenClassification,
        Trainer,
        TrainingArguments,
    )

    print(f"Loading dataset: {args.dataset_name} ...")
    raw = load_dataset(args.dataset_name)

    # ai4privacy/pii-masking-200k ships pre-tokenized text with a BIO tag
    # sequence per example under columns typically named 'tokens' /
    # 'ner_tags' (check `raw['train'].features` after loading -- dataset
    # schemas do shift between versions, adjust the two column names below
    # if `raw['train'].column_names` differs on the version you pull).
    label_list = raw["train"].features["ner_tags"].feature.names
    id2label = dict(enumerate(label_list))
    label2id = {v: k for k, v in id2label.items()}
    print(f"Found {len(label_list)} labels: {label_list}")

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)

    def tokenize_and_align_labels(examples):
        tokenized = tokenizer(
            examples["tokens"],
            truncation=True,
            is_split_into_words=True,
            max_length=args.max_length,
        )
        all_labels = []
        for i, labels in enumerate(examples["ner_tags"]):
            word_ids = tokenized.word_ids(batch_index=i)
            previous_word_idx = None
            label_ids = []
            for word_idx in word_ids:
                if word_idx is None:
                    label_ids.append(-100)  # ignored by the loss function
                elif word_idx != previous_word_idx:
                    label_ids.append(labels[word_idx])
                else:
                    label_ids.append(-100)  # only label the first sub-token of a word
                previous_word_idx = word_idx
            all_labels.append(label_ids)
        tokenized["labels"] = all_labels
        return tokenized

    print("Tokenizing + aligning labels ...")
    tokenized_ds = raw.map(tokenize_and_align_labels, batched=True)

    model = AutoModelForTokenClassification.from_pretrained(
        args.base_model, num_labels=len(label_list), id2label=id2label, label2id=label2id,
    )

    seqeval = evaluate.load("seqeval")

    def compute_metrics(eval_pred):
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=2)

        true_predictions = [
            [id2label[p] for p, l in zip(pred, label) if l != -100]
            for pred, label in zip(predictions, labels)
        ]
        true_labels = [
            [id2label[l] for p, l in zip(pred, label) if l != -100]
            for pred, label in zip(predictions, labels)
        ]
        results = seqeval.compute(predictions=true_predictions, references=true_labels)
        return {
            "precision": results["overall_precision"],
            "recall": results["overall_recall"],
            "f1": results["overall_f1"],
            "accuracy": results["overall_accuracy"],
        }

    data_collator = DataCollatorForTokenClassification(tokenizer=tokenizer)

    training_args = TrainingArguments(
        output_dir=args.output_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=args.learning_rate,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        num_train_epochs=args.epochs,
        weight_decay=0.01,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_steps=50,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_ds["train"],
        eval_dataset=tokenized_ds[args.eval_split],
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics,
    )

    print("Starting fine-tuning ...")
    trainer.train()

    print("Evaluating best checkpoint ...")
    metrics = trainer.evaluate()
    print(metrics)

    print(f"Saving model + tokenizer to {args.output_dir} ...")
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)

    print(
        "\nDone. Copy the output_dir into your backend deployment, then set:\n"
        "  SAG_NER_BACKEND=transformer\n"
        f"  SAG_TRANSFORMER_MODEL_PATH={args.output_dir}\n"
        "in your .env and restart the service."
    )


if __name__ == "__main__":
    main()
