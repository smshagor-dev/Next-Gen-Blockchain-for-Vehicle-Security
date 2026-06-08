# Adversarial Detection Evaluation

This runner computes detection metrics only from a provided labeled CSV. It does not fabricate adversarial datasets or results.

## Input Schema

- `label`: `0` for normal, `1` for attack.
- `score`: detector score between `0` and `1`.
- `attack_type`: attack family or scenario label.

## Metric Definitions

- `precision = TP / (TP + FP)`
- `recall = TP / (TP + FN)`
- `specificity = TN / (TN + FP)`
- `F1 = 2 * precision * recall / (precision + recall)`
- `accuracy = (TP + TN) / total`
- `false_positive_rate = FP / (FP + TN)`
- `false_negative_rate = FN / (FN + TP)`

## Summary

- `experiment`: `adversarial_detection`
- `status`: `dataset_required`
- `created_at`: `2026-06-05T14:12:43.247157+00:00`
- `input_csv`: ``
- `threshold`: `0.5`
- `label_column`: `label`
- `score_column`: `score`
- `attack_column`: `attack_type`
- `input_rows`: `0`
- `metrics`: `tp,fp,tn,fn,precision,recall,specificity,f1,accuracy,false_positive_rate,false_negative_rate`
- `measured_runtime_benchmark`: `False`
- `dataset_required`: `True`
- `statistical_significance`: `False`
- `seed`: `0`

No input CSV was provided, so no metric values were computed.
Provide `--input-csv` with the schema above to generate results.

## Results

| scope | attack_type | tp | fp | tn | fn | precision | recall | specificity | f1 | accuracy | false_positive_rate | false_negative_rate | sample_count | measured_runtime_benchmark | dataset_required | statistical_significance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| schema_example | TODO_ATTACK_TYPE |  |  |  |  |  |  |  |  |  |  |  |  | False | True | False |
