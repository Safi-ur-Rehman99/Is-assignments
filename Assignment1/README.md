# CLO 4 IDS ML Solution (Assignment 1)

## Project Title
AI-Powered Intrusion Detection System Using Gradient Boosting Classification on CIC-IDS2017

## Objective
Build and evaluate a machine learning proof-of-concept that classifies network traffic as **Normal** or **Malicious** for SecureNet Corp, aligned with CLO 4:

Create solutions to real-life security scenarios using security-related tools.

## Repository Deliverables (Assignment1)
- `Assignment1_Solution.docx` (your report)
- `IDS_GBC_CIC2017.ipynb` (well-documented notebook with full workflow)
- `src/ids_pipeline.py` (reusable implementation)
- `tests/test_pipeline_smoke.py` (smoke test)
- `data/raw/` (place official CIC-IDS2017 CSV files here)
- `data/processed/` (generated metrics output)

## Dataset Setup Instructions (Official CIC-IDS2017)
1. Download CIC-IDS2017 data from the official source:
   https://www.unb.ca/cic/datasets/ids-2017.html
2. Extract CSV files.
3. Copy one or more CSV files into `Assignment1/data/raw/`.
4. Keep column `Label` in data (required for binary target mapping).

Notes:
- A small file `data/raw/synthetic_smoke_sample.csv` is included only for quick smoke validation.
- For final academic results, run with official CIC-IDS2017 raw files.

## Environment and Dependency Installation
Recommended Python: 3.10+

Install dependencies:

```bash
pip install pandas numpy scikit-learn matplotlib seaborn pytest jupyter
```

## How To Run The Code
From inside `Assignment1`:

### Option A: Jupyter Notebook (Primary Submission Path)
```bash
jupyter notebook IDS_GBC_CIC2017.ipynb
```
Run all cells from top to bottom.

### Option B: CLI Pipeline
```bash
python src/ids_pipeline.py --data-dir data/raw --output-json data/processed/metrics_summary.json
```
Optional row cap for faster runs:
```bash
python src/ids_pipeline.py --data-dir data/raw --max-rows 50000
```

## How To Run Tests
From `Assignment1`:

```bash
pytest -q
```

This executes a synthetic smoke test that verifies preprocessing, training, and evaluation functions.

## Methodology Summary
1. Data ingestion from CIC-IDS2017 CSV files.
2. Preprocessing:
   - Replace infinite values and handle missing data
   - Encode categorical features
   - Scale numerical features
   - Stratified train/test split
3. Model:
   - Gradient Boosting Classifier (scikit-learn)
4. Evaluation:
   - Accuracy
   - Precision and Recall (attack class focus)
   - Confusion Matrix
5. Security interpretation:
   - Discuss false negatives risk and operational implications.

## Brief Results Summary
- The notebook prints and stores key metrics including:
  - Overall Accuracy
  - Attack Precision
  - Attack Recall
  - Confusion Matrix
- It also visualizes class distribution and top feature importances.

## Viva/Presentation Talking Points
- Why CIC-IDS2017 fits realistic enterprise attack scenarios.
- Why Gradient Boosting was chosen over simpler models.
- Why high attack recall is crucial in intrusion detection.
- Operational limitations (drift, zero-day behavior) and improvements (retraining, anomaly layer).

## Suggested Public Repository Name
- `CLO4-IDS-ML-Solution`
- or `CLO4-IDS-GBC-Solution`
