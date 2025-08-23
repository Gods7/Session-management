from fastapi import FastAPI, Response, Request, Cookie, HTTPException

app = FastAPI()

# Session storage (in-memory)
sessions = {}

@app.get("/")
def root():
    return {"message": "Welcome! Try /login or /profile"}

@app.get("/login")
def login(response: Response):
    # Create fake session
    sessions["abc123"] = {"user": "John"}  
    response.set_cookie(key="session_id", value="abc123")
    return {"message": "You are logged in"}

@app.get("/profile")
def profile(session_id: str = Cookie(None)):
    if session_id not in sessions:
        raise HTTPException(status_code=401, detail="Not logged in")
    return {"user": sessions[session_id]["user"]}


@app.get("/logout")
def logout(response: Response, session_id: str = Cookie(None)):
    if session_id in sessions:
        del sessions[session_id]   # delete from server
    response.delete_cookie("session_id")  # remove from client
    return {"message": "You are logged out"}
