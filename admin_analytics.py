from models import Click, db, ForecastData, Order
from flask import render_template, request
from app import app
from flask_login import current_user

@app.route('/admin/analytics/heatmaps')
def heatmap_view():
    clicks = Click.query.order_by(Click.timestamp.desc()).limit(100).all()
    return render_template("admin/analytics/heatmaps.html", clicks=clicks)

@app.route('/admin/analytics/forecast')
def forecast_view():
    data = ForecastData.query.order_by(ForecastData.date).all()
    return render_template('admin/analytics/forecast.html', data=data)

@app.route('/admin/analytics/segments')
def segment_view():
    segments = db.session.execute("""
        SELECT segment, COUNT(*) FROM user GROUP BY segment
    """).fetchall()
    return render_template("admin/analytics/segments.html", segments=segments)


@app.route('/api/track_click', methods=['POST'])
def track_click():
    data = request.json
    click = Click(user_id=current_user.id if current_user.is_authenticated else None,
                  page=data['page'], x=data['x'], y=data['y'])
    db.session.add(click)
    db.session.commit()
    return '', 204


@app.route('/click-report')
def click_report():
    clicks = Click.query.order_by(Click.timestamp.desc()).all()

    total_clicks = len(clicks)
    unique_users = len(set(c.user_id for c in clicks if c.user_id))
    unique_pages = len(set(c.page for c in clicks))

    return render_template(
        'admin/click_report.html',
        clicks=clicks,
        total_clicks=total_clicks,
        unique_users=unique_users,
        unique_pages=unique_pages
    )


@app.route('/forecast')
def admin_forecast():
    forecasts = ForecastData.query.order_by(ForecastData.date).all()
    if not forecasts:
        return render_template('admin/analytics/forecast.html', no_data=True)

    # Forecast data
    dates = [f.date.strftime('%Y-%m-%d') for f in forecasts]
    predictions = [f.prediction for f in forecasts]
    lower_bounds = [f.lower_bound for f in forecasts]
    upper_bounds = [f.upper_bound for f in forecasts]

    # Get actual sales per day from Orders
    sales_data = (
        db.session.query(
            db.func.date(Order.created_at).label('date'),
            db.func.sum(Order.amount).label('total')
        )
        .filter(Order.status == 'completed')  # Or use 'paid' depending on your logic
        .group_by(db.func.date(Order.created_at))
        .all()
    )

    actual_dates = [d.date.strftime('%Y-%m-%d') for d in sales_data]
    actual_sales = [float(d.total) for d in sales_data]

    # Optional: Check if future forecast is low
    threshold = 1000  # set based on your business logic
    alert = None
    if forecasts[-1].prediction < threshold:
        alert = "⚠️ Forecasted sales for next week are low. Consider boosting marketing or reducing stock."

    return render_template(
        'admin/analytics/forecast.html',
        dates=dates,
        predictions=predictions,
        lower_bounds=lower_bounds,
        upper_bounds=upper_bounds,
        actual_dates=actual_dates,
        actual_sales=actual_sales,
        alert=alert
    )