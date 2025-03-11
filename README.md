**Documentation**

User authentication and authorization implementation.

**TechStack**

Backend (Python)

Database (PostgreSQL)

FAST Api

**ProjectStructure**

/SMTMINTERN/Task 4/

│

├── main.py

├──database.py

├──models.py

├── auth.py

└── .venv/

**Step-By-StepImplementation**



1.    _Set your Database in database.py_

  from sqlalchemy import create\_engine
  
  from sqlalchemy.ext.declarative importdeclarative\_base
  
  from sqlalchemy.orm import sessionmaker
  
  DATABASE\_URL="postgresql://postgres:******@localhost:5432/Intern"
  
  engine = create\_engine(DATABASE\_URL)
  
  SessionLocal = sessionmaker(autocommit=False,autoflush=False, bind=engine)
  
  Base = declarative\_base()
  
  def get\_db():
  
      db= SessionLocal()

     try:
  
         yield db
  
     finally:
  
          db.close()

        

2.     _Createmodels in models.py_

  from sqlalchemy import Column, String
  
  from database import Base
  
  class User(Base):
  
     \_\_tablename\_\_ = "users"
  
     username = Column(String, primary\_key=True, index=True)
  
     full\_name = Column(String)
  
     email = Column(String, unique=True, index = True)
  
     hashed\_password = Column(String)

     role = Column(String, default="user")

     

3.     _Createyour authentication in auth.py_

  from fastapi import Depends,HTTPException, status
  
  from fastapi.security importOAuth2PasswordBearer, OAuth2PasswordRequestForm
  
  from sqlalchemy.orm importSession
  
  from jose import JWTError, jwt
  
  from datetime import datetime,timedelta
  
  from passlib.context importCryptContext
  
  from database import SessionLocal
  
  from models import User
  
  SECRET\_KEY = 'mysecretkey'
  
  ALGORITHM = 'HS256'
  
  ACCESS\_TOKEN\_EXPIRE\_MINUTES = 30

  pwd\_context =CryptContext(schemes=\["bcrypt"\], deprecated="auto")
  
  oauth2\_scheme =OAuth2PasswordBearer(tokenUrl="token")
  
  def get\_db():
  
      db = SessionLocal()
  
      try:
  
          yield db
  
      finally:
  
          db.close()
  
  defverify\_password(plain\_password, hashed\_password):
  
      return pwd\_context.verify(plain\_password,hashed\_password)

  def create\_access\_token(data:dict, expires\_delta: timedelta = None):
  
      to\_encode = data.copy()
  
      expire = datetime.utcnow() + (expires\_deltaor timedelta(minutes=15))
  
      to\_encode.update({"exp": expire})
  
      return jwt.encode(to\_encode, SECRET\_KEY,algorithm=ALGORITHM)
  
  def authenticate\_user(username:str, password: str, db: Session):
  
      user = db.query(User).filter(User.username== username).first()
  
      if user and verify\_password(password,user.hashed\_password):
  
          return user
  
      return None

  def get\_current\_user(token: str =Depends(oauth2\_scheme), db: Session = Depends(get\_db)):
  
      credentials\_exception = HTTPException(
  
         status\_code=status.HTTP\_401\_UNAUTHORIZED,
  
          detail="Could not validatecredentials",
  
          headers={"WWW-Authenticate":"Bearer"},
  
      )
  
      try:
  
          payload = jwt.decode(token, SECRET\_KEY,algorithms=\[ALGORITHM\])
  
          username: str =payload.get("sub")
  
          if username is None:

              raise credentials\_exception
  
          user =db.query(User).filter(User.username == username).first()
  
          if user is None:
  
              raise credentials\_exception
  
          return User
  
      except JWTError:
  
          raise credentials\_exception
  
  def get\_current\_admin(user: User= Depends(get\_current\_user)):
  
          if user.role != "admin":
  
              raise HTTPException(status\_code=403,detail="Not enough permissions")

          return user

          

4.     _Authorizethe user in main.py_

  from fastapi import FastAPI, Depends,HTTPException
  
  from sqlalchemy.orm import Session
  
  from database import get\_db
  
  from models import User
  
  from auth import authenticate\_user,create\_access\_token, get\_current\_user, get\_current\_admin
  
  from fastapi.security importOAuth2PasswordRequestForm
  
  from pydantic import BaseModel, EmailStr
  
  from datetime import timedelta
  
  from passlib.context import CryptContext

  app = FastAPI()
  
  pwd\_context =CryptContext(schemes=\["bcrypt"\], deprecated="auto")
  
  class UserCreate(BaseModel):
  
     username: str
  
     email: EmailStr
  
     full\_name: str
  
     password: str
  
     role: str = "user"
  
  @app.get("/")
  
  def read\_root():

     return {"message": "Welcome to the FastAPI authenticationand authorization app!"}
  
  @app.post("/register")
  
  def register(user: UserCreate, db: Session =Depends(get\_db)):
  
     existing\_user = db.query(User).filter(User.username ==user.username).first()
  
      ifexisting\_user:
  
         raise HTTPException(status\_code=400, detail="Username alreadyregistered")
  
     hashed\_password = pwd\_context.hash(user.password)
  
     new\_user = User(
  
         username=user.username,
  
         email=user.email,

         full\_name=user.full\_name,
  
         hashed\_password=hashed\_password,
  
         role=user.role
  
      )
  
     db.add(new\_user)
  
     db.commit()
  
     db.refresh(new\_user)
  
     return {"message": "User created successfully"}
  
  @app.post("/token")
  
  def login\_for\_access\_token(form\_data:OAuth2PasswordRequestForm = Depends(), db:Session = Depends(get\_db)):

     user = authenticate\_user(form\_data.username, form\_data.password, db)
  
      ifnot user:
  
         raise HTTPException(status\_code=401, detail="Incorrect username orpassword")
  
     access\_token = create\_access\_token(data={"sub":user.username}, expires\_delta=timedelta(minutes=30))
  
     return {"access\_token": access\_token, "token\_type":"bearer"}
  
  @app.get("/users/me")
  
  def read\_users\_me(current\_user: User =Depends(get\_current\_user)):
  
     return {"username": current\_user.username, "role":current\_user.role}
  
  @app.get("/admin")
  
  def read\_admin\_data(admin: User =Depends(get\_current\_admin)):

     return {"message": "Welcome admin","user": admin.username}

     

5.     _Test thedatabase connection in test.db_

  from sqlalchemy import create\_engine
  
  DATABASE\_URL ="postgresql://postgres:Alish@123@localhost:5432/Intern"
  
  engine = create\_engine(DATABASE\_URL)
  
  try:
  
     with engine.connect() as connection:
  
         print("Database connected successfully!")
  
  except Exception as e:
  
     print("Database connection failed:", e)
  
  
  **Run theProject**
  
  .      .venv\\Scripts\\activate
  
  ·      Run server using uvicorn main:app –reload
  
  ·      Viewthe GET request in [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
  
  ·      Viewthe POST request in [http://127.0.0.1:8000/register](http://127.0.0.1:8000/register) 
          using Invoke-RestMethod -Method POST -Uri"http://127.0.0.1:8000/register" -ContentType"application/json" -Body 
    '{
  ·      >>     "username": "alish",
  
  ·      >>     "full\_name": "AlishDahal",
  
  ·      >>     "email":"alish@example.com",
  
  ·      >>     "password":"Password",
  
  ·      >>     "role": "admin"
  
  ·      >>}'

**Fetchingthe data**

  **SendingGET request for** [**http://127.0.0.1:8000/**](http://127.0.0.1:8000/)
  ![Image](https://github.com/user-attachments/assets/574828dd-5234-464e-86ce-f732ebd70788)

**SendingPOST request for** [**http://127.0.0.1:8000/request**](http://127.0.0.1:8000/request)
![Image](https://github.com/user-attachments/assets/fadc2774-a43f-48e0-b1f1-5db71d3a2587)

**Conclusion:**

  ThisFAST API helps in authenticating and authorizing user.
