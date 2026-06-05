# ===================== IMPORTS =====================
import pandas as pd
import numpy as np
import math

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.cluster import MiniBatchKMeans

# ===================== LOAD DATA =====================
df = pd.read_csv("cybercrime_forensic_dataset.csv")  # change name if needed

print("Dataset loaded")
print(df.head())

# ===================== PREPROCESSING =====================
# Timestamp
df['Timestamp'] = pd.to_datetime(df['Timestamp'])
df['Timestamp_num'] = df['Timestamp'].astype('int64') // 10**9

# Encode categorical columns
df['Activity_enc'] = LabelEncoder().fit_transform(df['Activity_Type'].astype(str))
df['Action_enc'] = LabelEncoder().fit_transform(df['Action'].astype(str))
df['Label_enc'] = LabelEncoder().fit_transform(df['Label'])

# ===================== FEATURE SELECTION =====================
features = [
    'Timestamp_num',
    'User_ID',
    'Activity_enc',
    'Action_enc',
    'File_Size'
]

# Ensure numeric + handle missing values
df[features] = df[features].apply(pd.to_numeric, errors='coerce')
df[features] = df[features].fillna(0)

# ===================== SCALING (CRITICAL) =====================
scaler = StandardScaler()
X = df[features]
X_scaled = scaler.fit_transform(X)

print("X_scaled created:", X_scaled.shape)

# ===================== CLUSTERING =====================
k = max(2, int(math.sqrt(len(X_scaled))))

model = MiniBatchKMeans(
    n_clusters=k,
    random_state=42,
    batch_size=256,
    n_init=10
)

df['Cluster'] = model.fit_predict(X_scaled)

# ===================== ANOMALY DETECTION =====================
distances = model.transform(X_scaled)
df['Anomaly_Score'] = distances.min(axis=1)

threshold = np.percentile(df['Anomaly_Score'], 95)
df['Threat_Flag'] = (df['Anomaly_Score'] > threshold).astype(int)

print("Clustering completed")
print(df[['Cluster', 'Anomaly_Score', 'Threat_Flag']].head())

# ===================== SAVE OUTPUT =====================
df.to_csv("final_output.csv", index=False)
print("Saved: final_output.csv")

# Display number of records in each cluster
print("Cluster distribution:")
print(df['Cluster'].value_counts())

# (Optional) Sorted for better readability
print("\nCluster distribution (sorted):")
print(df['Cluster'].value_counts().sort_index())

# ===================== CLUSTER VS LABEL ANALYSIS =====================
import pandas as pd

# Cross-tabulation of clusters and actual labels
result = pd.crosstab(df['Cluster'], df['Label'])
print("Cluster vs Label distribution:")
print(result)

# ===================== MANUAL WORKLOAD ESTIMATION =====================
total_events = len(df)
clusters = df['Cluster'].nunique()

# Estimate of manual workload reduction
reduction = (1 - clusters / total_events) * 100

print(f"\nManual workload reduced by approx {reduction:.2f}%")

df.to_csv("final_clustered_forensic_results.csv", index=False)

