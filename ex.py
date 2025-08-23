from fastapi import FastAPI, Response, Request

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Welcome! Try /set-cookie or /get-cookie"}


@app.get("/set-cookie")
def set_cookie(response: Response):
    response.set_cookie(key="my_cookie", value="hello_world")
    return {"message": "Cookie has been set!"}

@app.get("/get-cookie")
def get_cookie(request: Request):
    cookie_value = request.cookies.get("my_cookie")
    return {"my_cookie": cookie_value}