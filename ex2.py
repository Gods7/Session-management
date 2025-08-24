from fastapi import FastAPI, Query
import jwt
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

app = FastAPI()

@app.get("/")
def home():
    return {"message": "JWT Example Running"}

@app.get("/get-token")
def get_token():
    payload = {"user": "godson"}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token}

@app.get("/decode-token")
def decode_token(token: str = Query(...)):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"decoded": decoded}
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}
