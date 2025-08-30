from flask import request
from flask_login import current_user
from app import app, db
from models import Click

@app.route('/api/track_click', methods=['POST'])
def track_click():
    data = request.json
    click = Click(
        user_id=current_user.id if current_user.is_authenticated else None,
        page=data.get('page'),
        x=data.get('x'),
        y=data.get('y'),
        screen_width=data.get('screen_width'),
        screen_height=data.get('screen_height')
    )
    db.session.add(click)
    db.session.commit()
    return '', 204
