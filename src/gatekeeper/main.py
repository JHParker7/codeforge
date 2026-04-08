from datetime import datetime, timedelta, timezone
from typing import Annotated
import uuid
import logging


import jwt
from fastapi import Depends, FastAPI, HTTPException, status, Form, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel

import pymongo

mongo_client = pymongo.MongoClient("mongodb://test:test@localhost:27017/")

db = mongo_client["gatekeeper"]

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    """Oauth2 token."""

    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Data in the jwt token"""

    username: str | None = None


class User(BaseModel):
    """store user details"""

    user_id: str
    username: str
    email: str | None = None
    full_name: str | None = None
    role_id: str | None = None
    disabled: bool | None = None


class Role(BaseModel):
    """constains the permissions of the users or services"""

    role_id: str
    permissions: dict


class UserInDB(User):
    """used to add the hashed_password to the user"""

    hashed_password: str


password_hash = PasswordHash.recommended()

DUMMY_HASH = password_hash.hash("dummypassword")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """compares the password given by the client to the password in the database

    Args:
        plain_password (str): unhashed password from the user
        hashed_password (str): hashed password from the database

    Returns:
        bool: is true if the password matches
    """
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """hashes the password

    Args:
        password (str): plain text password

    Returns:
        str: hashed password
    """
    return password_hash.hash(password)


def get_user(username: str | None) -> UserInDB | None:
    """get the user from the database and returns it

    Args:
        username (str | None): the username of the user to get from the database
    Returns:
        UserInDB | None: the user as it is in the database with password hash
    """
    user = db["users"].find_one({"username": username})
    if user:
        return UserInDB(**user)


def authenticate_user(username: str, password: str) -> User | bool:
    """compare creds to those in the database

    Args:
        username (str): username of the user
        password (str): password to check against the database

    Returns:
        User | bool: confirms if the creds are correct
    """
    user = get_user(username)
    if not user:
        verify_password(password, DUMMY_HASH)
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """generates the access token

    Args:
        data (dict): data to encode into the jwt
        expires_delta (timedelta | None, optional): time for the jwt to expire. Defaults to None.

    Returns:
        str: the jwt
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    """_summary_

    Args:
        token (Annotated[str, Depends): _description_

    Raises:
        credentials_exception: _description_
        credentials_exception: _description_
        credentials_exception: _description_
        credentials_exception: _description_

    Returns:
        User: _description_
    """
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
    session = db["sessions"].find_one(
        {"token": token, "username": token_data.username, "type": "jwt"}
    )
    if session:
        user = get_user(username=token_data.username)
        if user is None:
            raise credentials_exception
        user = user.model_dump()
        del user["hashed_password"]
        return User(**user)
    else:
        raise credentials_exception


async def get_role(id: str) -> Role:
    """get the role from the database based on its id and puts it into a Role object

    Args:
        id (str): id of the role to get

    Returns:
        Role: a Role object that contains the permissions of a role
    """
    role = db["roles"].find_one({"role_id": id})
    return Role(**role)


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """checks if the user is currently active

    Args:
        current_user (Annotated[User, Depends): a user to check

    Raises:
        HTTPException: raised if the user is inactive

    Returns:
        User: a confirmed active user
    """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def check_role_for_access(token: str, action: str, resource: str) -> bool:
    """WIP"""
    user = await get_current_user(token)
    print(user)
    role = await get_role(user.role_id)
    print(role)


@app.middleware("/gatekeeper")
async def authenticate(request: Request, call_next):
    """WIP"""
    if "Authorization" not in request.headers or request.url.path == "/token":
        response = await call_next(request)
        return response
    logger.info(request.url.path)
    logger.info(request.method)
    user = await get_current_user(request.headers["Authorization"][7:])
    role = db["roles"].find_one({"role_id": user.role_id})
    print(role)
    print(str(request.url.path).split("/"))
    result = db["actions"].find(
        {
            "method": request.method,
            "endpoint": {"$in": str(request.url.path).split("/")},
        }
    )
    actions_needed = []
    for x in result:
        actions_needed.append(x["action"])
    actions_needed = set(actions_needed)
    print(actions_needed)

    response = await call_next(request)
    return response


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """checks password and username and returns a token if matches database creds

    Args:
        form_data (Annotated[OAuth2PasswordRequestForm, Depends): the user and password details to log in with

    Raises:
        HTTPException: raised if the username or password do not match the database

    Returns:
        Token: a new jwt token
    """
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
    db["sessions"].insert_one(
        {
            "token": access_token,
            "expires_at": str(datetime.now(timezone.utc) + access_token_expires),
            "type": "jwt",
            "username": user.username,
            "created_at": str(created_at),
        }
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """returns the details of the currently logged in user

    Args:
        current_user (Annotated[User, Depends): json of the current user details

    Returns:
        User: the currently log in users details
    """
    return User(**current_user)


@app.post("/register")
async def register(
    username: Annotated[str, Form()],
    full_name: Annotated[str, Form()],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> User:
    """post request to register a user

    Args:
        username (Annotated[str, Form): username of new user
        full_name (Annotated[str, Form): fullname of new user
        email (Annotated[str, Form): email of new user
        password (Annotated[str, Form): password of new user

    Raises:
        HTTPException: raised if user already exists
        HTTPException: the user creation failed

    Returns:
        User: new user details
    """
    user_id = str(uuid.uuid7())
    role_id = str(uuid.uuid7())
    new_user = {
        "user_id": user_id,
        "username": username,
        "full_name": full_name,
        "email": email,
        "hashed_password": get_password_hash(password),
        "role_id": role_id,
        "disabled": False,
    }
    new_role = {
        "role_id": role_id,
        "permissions": {
            "gatekeeper": {
                "services": [f"user/{username}", f"role/{role_id}"],
                "actions": [
                    "GetUser",
                    "DeleteUser",
                    "ListUsers",
                    "EditUser",
                    "GetRole",
                ],
            }
        },
    }
    if db["users"].find_one({"username": username}):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="user already exists",
        )
    db["users"].insert_one(new_user)
    db["roles"].insert_one(new_role)
    user = get_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="user creation failed",
        )
    user = user.model_dump()
    return User(**user)


@app.get("/gatekeeper/user")
def getUser(current_user: Annotated[User, Depends(get_current_active_user)]):
    return {}


# if __name__ == "main":
#     config = {
#         "actions_to_endpoint": [
#             {"action": "GetUser", "endpoint": "user", "method": "GET"},
#             {"action": "ListUsers", "endpoint": "users", "method": "GET"},
#             {"action": "DeleteUser", "endpoint": "user", "method": "DELETE"},
#             {"action": "EditUser", "endpoint": "user", "method": "PUT"},
#             {"action": "GetRole", "endpoint": "role", "method": "GET"},
#         ]
#     }
#     db["actions"].insert_many(config["actions_to_endpoint"])
