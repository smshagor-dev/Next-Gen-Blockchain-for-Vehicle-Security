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
- `status`: `computed_from_labeled_csv`
- `created_at`: `2026-06-05T14:13:08.769055+00:00`
- `input_csv`: `experiments\reports\adversarial_fixture_smoke\fixture.csv`
- `threshold`: `0.5`
- `label_column`: `label`
- `score_column`: `score`
- `attack_column`: `attack_type`
- `input_rows`: `4`
- `metrics`: `tp,fp,tn,fn,precision,recall,specificity,f1,accuracy,false_positive_rate,false_negative_rate`
- `measured_runtime_benchmark`: `False`
- `dataset_required`: `False`
- `statistical_significance`: `False`
- `seed`: `0`

## Results

| scope | attack_type | tp | fp | tn | fn | precision | recall | specificity | f1 | accuracy | false_positive_rate | false_negative_rate | sample_count | measured_runtime_benchmark | dataset_required | statistical_significance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| overall | overall | 1 | 1 | 1 | 1 | 0.5 | 0.5 | 0.5 | 0.5 | 0.5 | 0.5 | 0.5 | 4 | False | False | False |
| per_attack_type | normal | 0 | 1 | 1 | 0 | 0.0 | 0.0 | 0.5 | 0.0 | 0.5 | 0.5 | 0.0 | 2 | False | False | False |
| per_attack_type | replay | 1 | 0 | 0 | 1 | 1.0 | 0.5 | 0.0 | 0.666667 | 0.5 | 0.0 | 0.5 | 2 | False | False | False |
