from sqlalchemy import create_engine

DATABASE_URL = "postgresql://postgres:Alish%40123@localhost:5432/Intern"
engine = create_engine(DATABASE_URL)

try:
    with engine.connect() as connection:
        print("Database connected successfully!")
except Exception as e:
    print("Database connection failed:", e)
