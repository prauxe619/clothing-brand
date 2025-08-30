# seed_db.py
import os
from app import app, db
from models import Size, Color

# Your provided data
ALL_SIZES_DATA = [
    {'name': 'XS'}, {'name': 'S'}, {'name': 'M'},
    {'name': 'L'}, {'name': 'XL'}, {'name': 'XXL'}
]
ALL_COLORS_DATA = [
    {'name': 'Black', 'hex_code': '#000000'},
    {'name': 'White', 'hex_code': '#FFFFFF'},
    # Add all other colors from your list
]

def seed_database():
    with app.app_context():
        print("Starting database seeding...")
        try:
            # Seed sizes
            for size_data in ALL_SIZES_DATA:
                if not Size.query.filter_by(name=size_data['name']).first():
                    db.session.add(Size(name=size_data['name']))

            # Seed colors
            for color_data in ALL_COLORS_DATA:
                if not Color.query.filter_by(name=color_data['name']).first():
                    db.session.add(Color(name=color_data['name'], hex_code=color_data['hex_code']))

            db.session.commit()
            print("Database seeded successfully with sizes and colors.")
        except Exception as e:
            db.session.rollback()
            print(f"Failed to seed database: {e}")

if __name__ == '__main__':
    seed_database()