from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel

import pymongo

mongo_client = pymongo.MongoClient("mongodb://test:test@localhost:27017/")

db = mongo_client["gatekeeper"]
users_table = db["users"]
sessions_table = db["sessions"]

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = [
    {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$argon2id$v=19$m=65536,t=3,p=4$wagCPXjifgvUFBzq4hqe3w$CYaIb8sB+wtD+Vu/P4uod1+Qof8h+1g7bbDlBID48Rc",
        "disabled": False,
    }
]


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


password_hash = PasswordHash.recommended()

DUMMY_HASH = password_hash.hash("dummypassword")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    "compare hashed password stored in db to one from user"
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    "hashed the password from the user"
    return password_hash.hash(password)


def get_user(username: str | None) -> UserInDB | None:
    "gets the user from the database based on the username"
    user = users_table.find_one({"username": username})
    if user:
        return UserInDB(**user)


def authenticate_user(username: str, password: str) -> User | bool:
    "check the creds from the user to those in the db"
    user = get_user(username)
    if not user:
        verify_password(password, DUMMY_HASH)
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    "creates the jwt token"
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    "gets the current user based on the jwt"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    session = sessions_table.find_one(
        {"token": token, "username": token_data.username, "type": "jwt"}
    )
    if session:
        user = get_user(username=token_data.username)
        if user is None:
            raise credentials_exception
        return user
    else:
        raise credentials_exception


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    "checks if current user is active"
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    "compare the creds in db to the ones from the user if a match create a jwt and create a copy in the db then respond with the new jwt"
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    created_at = datetime.now(timezone.utc)
    access_token = create_access_token(
        data={"sub": user.username, "created_at": str(created_at)},
        expires_delta=access_token_expires,
    )
    sessions_table.insert_one(
        {
            "token": access_token,
            "expires_at": str(datetime.now(timezone.utc) + access_token_expires),
            "type": "jwt",
            "username": user.username,
            "created_at": str(created_at),
        }
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    return current_user


@app.post("/register")
async def register(
    username: Annotated[str, Form()],
    full_name: Annotated[str, Form()],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> User:
    new_user = {
        "username": username,
        "full_name": full_name,
        "email": email,
        "hashed_password": get_password_hash(password),
        "disabled": False,
    }
    if users_table.find_one({"username": username}):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="user already exists",
        )
    users_table.insert_one(new_user)
    user = get_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="user creation failed",
        )
    user = user.model_dump()
    return User(**user)


if __name__ == "main":
    x = users_table.insert_many(fake_users_db)
