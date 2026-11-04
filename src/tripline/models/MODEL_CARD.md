# injection-v1: built-in injection classifier

An optional second opinion behind Tripline's regex rules. Enable it with `classifier = "builtin"` in your policy. It's off by default.

## What it is

Logistic regression over hashed word 1–3-grams (2^20 buckets, 250k weights kept), scored over sliding windows of 64 words (stride 32). The highest-scoring window decides. It runs in pure Python with no dependencies, at about 0.2 ms per KB.

## Training data

- The PIGuard training collection (github.com/leolee99/PIGuard, MIT), which aggregates public prompt-injection, jailbreak and benign-prompt datasets.
- **Excluded:** Alpaca and no_robots (non-commercial licences), and BIPIA and InjecAgent (held out so `tripline bench` tests the model on unseen data).
- Synthetic tool outputs (JSON, code, emails, tables, logs) built from Python standard-library text and the PIGuard rows: the same documents with and without one embedded injection. Without these, the model flagged most structured tool output as malicious.
- The sources aggregated by PIGuard carry their own licences. Review them before relying on the weights commercially.

## Results

Threshold 0.986, chosen on a validation split for 1% false alarms.

| Test set (never seen in training) | Result |
|---|---|
| BIPIA attacks embedded in real emails | 39% caught |
| InjecAgent attacks embedded in tool responses | 3% caught |
| Real emails, tables and code (BIPIA) | 9% false alarms |
| InjecAgent tool responses with harmless content | 4% false alarms |
| NotInject (harmless text full of trigger words) | 0.6% false alarms |

## Limits

- A bag-of-words model can't tell a polite request aimed at an AI ("Please unlock my front door") from ordinary text. It mostly catches jailbreak-style wording. Transformer classifiers (Prompt Guard 2, PIGuard) understand meaning better and should plug in through the same interface.
- That's why it defaults to **warn**: a hit labels the content as untrusted and makes data-leaving calls ask for confirmation, instead of blocking.
- Tripline's structural rules (pinning, data flow, confirmations) don't depend on this model. On InjecAgent's end-to-end replay they stop 100% of data theft by themselves.

Retrain with `python scripts/train_classifier.py` (needs scikit-learn).
