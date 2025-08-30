from sklearn.ensemble import IsolationForest

def is_login_anomaly(df):
    df['timestamp'] = df['timestamp'].astype('int64') // 10**6
    X = df[['timestamp']]  # You can also include IP clustering, user frequency, etc.

    model = IsolationForest(contamination=0.1)
    model.fit(X)

    preds = model.predict(X)
    latest_pred = preds[-1]  # prediction for last login attempt

    return latest_pred == -1
