import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db
from models import User, Order  # Adjust import if models are elsewhere

from sklearn.cluster import KMeans
import numpy as np

with app.app_context():
    # Fetch users and aggregate their order counts and total spend
    users = User.query.all()
    user_data = []

    for user in users:
        orders = Order.query.filter_by(user_id=user.id).all()
        total_spent = sum(o.amount for o in orders)
        order_count = len(orders)
        user_data.append([order_count, total_spent])

    if len(user_data) < 2:
        print("Not enough user data to segment.")
        exit()

    X = np.array(user_data)

    # Choose number of clusters
    k = 4
    kmeans = KMeans(n_clusters=k)
    kmeans.fit(X)

    labels = kmeans.labels_

    # Save segment labels back to users
    for user, label in zip(users, labels):
        user.segment = int(label)  # Make sure User model has 'segment' field (Integer)
        db.session.add(user)

    db.session.commit()
    print("✅ User segmentation updated.")
