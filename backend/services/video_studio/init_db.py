import os
os.environ.setdefault("DATABASE_URL", "sqlite:///./martial_arts.db")

from database import Base, engine, init_db
from db_models import DBProject, DBVideo, DBSkeletonData, DBTechnique, DBUser

def create_tables():
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully!")

    print("\nCreated tables:")
    for table in Base.metadata.sorted_tables:
        print(f"  - {table.name}")

if __name__ == "__main__":
    create_tables()
