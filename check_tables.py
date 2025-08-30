from sqlalchemy import create_engine, inspect

engine = create_engine("sqlite:///site.db")  # Use your actual DB path
inspector = inspect(engine)

tables = inspector.get_table_names()
print("📦 Tables found in site.db:")
for table in tables:
    print("  -", table)
