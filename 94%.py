import pandas as pd
import numpy as np
import time
import matplotlib.pyplot as plt
import seaborn as sns
from mpl_toolkits.mplot3d import Axes3D
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                             f1_score, confusion_matrix, classification_report)

# --- [1] SETTINGS & LOAD ---
DATA_FILE = "UNSW_NB15_training-set.csv"
PCA_RETAINED_VAR = 0.95
SEED = 42

print("--- [SYSTEM] Initializing Intelligence Suite ---")
df = pd.read_csv(DATA_FILE)
X_raw = df.drop(columns=['id', 'attack_cat', 'label'])
y = df['label']

# --- [2] THE FAIL-SAFE PIPELINE (Imputes NaNs automatically) ---
cat_cols = X_raw.select_dtypes(include='object').columns.tolist()
num_cols = X_raw.select_dtypes(include=['float64', 'int64']).columns.tolist()

num_pipeline = Pipeline([
    ('imputer', SimpleImputer(strategy='median')),
    ('scaler', StandardScaler())
])

cat_pipeline = Pipeline([
    ('imputer', SimpleImputer(strategy='constant', fill_value='unknown')),
    ('encoder', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
])

preprocessor = ColumnTransformer([
    ('num', num_pipeline, num_cols),
    ('cat', cat_pipeline, cat_cols)
])

# PCA fitted to extract 95% variance
pca = PCA(n_components=PCA_RETAINED_VAR, random_state=SEED)

print("--- [SYSTEM] Processing Data & Transforming Dimensions ---")
X_processed = preprocessor.fit_transform(X_raw)
X_pca = pca.fit_transform(X_processed)

# --- [3] MODEL TRAINING & TESTING ---
X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
    X_pca, y, np.arange(X_pca.shape[0]), test_size=0.3, random_state=SEED, stratify=y
)

print(f"--- [INFO] PCA Components identified: {X_pca.shape[1]}")
print("--- [TRAINING] Running Random Forest Analytics ---")
rf = RandomForestClassifier(n_estimators=100, random_state=SEED, n_jobs=-1)
rf.fit(X_train, y_train)
y_pred = rf.predict(X_test)

# --- [4] METRICS CALCULATION ---
metrics = {
    "Accuracy": accuracy_score(y_test, y_pred),
    "Precision": precision_score(y_test, y_pred),
    "Recall": recall_score(y_test, y_pred),
    "F1-Score": f1_score(y_test, y_pred)
}

# --- [5] VISUALIZATION SUITE ---
plt.style.use('dark_background') # Aesthetic matching your dashboard

# Chart A: 3D Cluster Chart (PC1 vs PC2 vs PC3)
fig = plt.figure(figsize=(10, 8))
ax = fig.add_subplot(111, projection='3d')
scatter = ax.scatter(X_pca[:5000, 0], X_pca[:5000, 1], X_pca[:5000, 2], 
                     c=y[:5000], cmap='cool', alpha=0.6, s=10)
ax.set_title("3D Protocol Signature (PC1 vs PC2 vs PC3)", fontsize=14, pad=20)
ax.set_xlabel("Principal Component 1")
ax.set_ylabel("Principal Component 2")
ax.set_zlabel("Principal Component 3")
plt.colorbar(scatter, label='0=Normal, 1=Attack')
plt.savefig('pca_3d_cluster.png')
print("✅ Saved: PCA 3D Cluster Chart")

# Chart B: Metrics Comparison Bar
plt.figure(figsize=(8, 5))
plt.bar(metrics.keys(), metrics.values(), color=['#00f2ff', '#7000ff', '#ff0070', '#ffb800'])
plt.ylim(0.8, 1.05)
plt.title("Intelligence Performance Summary", fontsize=14)
for i, v in enumerate(metrics.values()):
    plt.text(i, v + 0.01, f"{v:.2%}", ha='center', fontweight='bold')
plt.savefig('model_metrics.png')
print("✅ Saved: Performance Metrics Bar Chart")

# Chart C: Confusion Matrix Heatmap
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(7, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False)
plt.title("Confusion Matrix (Attack vs Normal Detection)")
plt.xlabel("Predicted Threat Level")
plt.ylabel("Actual Threat Level")
plt.savefig('confusion_matrix.png')
print("✅ Saved: Confusion Matrix Heatmap")

# --- [6] FINAL EXPORT ---
audit_df = X_raw.iloc[idx_test].copy()
audit_df['ACTUAL_LABEL'] = y_test.values
audit_df['AI_PREDICTION'] = y_pred
audit_df['AI_CONFIDENCE'] = np.max(rf.predict_proba(X_test), axis=1)

# Include Top 3 PCA Components in CSV for reference
audit_df['PC1'] = X_test[:, 0]
audit_df['PC2'] = X_test[:, 1]
audit_df['PC3'] = X_test[:, 2]

audit_df.to_csv('SENTRY_MASTER_AUDIT.csv', index=False)

print("\n" + "="*40)
print(" FINAL PERFORMANCE SUMMARY")
print("="*40)
for k, v in metrics.items():
    print(f"{k:10}: {v:.4f}")
print("="*40)
print(f"REPORT SAVED: SENTRY_MASTER_AUDIT.csv")
print("VISUALS SAVED: pca_3d_cluster.png, model_metrics.png, confusion_matrix.png")
