from fastapi import FastAPI, Form, Request, Response, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from starlette.status import HTTP_401_UNAUTHORIZED

app = FastAPI()
templates = Jinja2Templates(directory="templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBasic()

# This should be replaced with a proper user authentication system
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("secret")
    }
}


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, response: Response, credentials: HTTPBasicCredentials = Depends(security)):
    # Check if user is logged in
    credentials_exception = HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Not authenticated"
    )

    user = authenticate_user(credentials.username, credentials.password)
    if not user:
        response.headers['WWW-Authenticate'] = 'Basic'
        raise credentials_exception
    # If authenticated, show a different page
    return "Welcome!"


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(username, password)
    if not user:
        return "Invalid username or password!"
    response.set_cookie(key="username", value=username)  # Set a secure cookie
    return RedirectResponse(url="/", status_code=302)


@app.get("/logout")
async def logout(response: Response):
    response.delete_cookie(key="username")
    return RedirectResponse(url="/", status_code=302)
