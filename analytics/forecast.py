import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db  # ✅ directly import the Flask app and db object
from models import Order, ForecastData  # adjust as per your model location

from prophet import Prophet
import pandas as pd

with app.app_context():
    # Load order data
    orders = Order.query.all()
    df = pd.DataFrame([{'ds': o.created_at, 'y': o.amount} for o in orders])
    
    if len(df) < 2:
        print("Not enough data to forecast.")
        exit()

    model = Prophet()
    model.fit(df)

    future = model.make_future_dataframe(periods=30)
    forecast = model.predict(future)

    # Clear old forecast data
    ForecastData.query.delete()
    db.session.commit()

    for _, row in forecast.iterrows():
       fd = ForecastData(
        date=row['ds'],
        prediction=row['yhat'],
        lower_bound=row['yhat_lower'],
        upper_bound=row['yhat_upper']
        )
       db.session.add(fd)

    db.session.commit()

    print("✅ Forecast updated.")
