from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr


# ======================== CONFIGURACIÓN JWT ======================== #

SECRET_KEY = "cambia_este_secreto_por_algo_mas_largo_y_aleatorio"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# ======================== MODELOS Pydantic ======================== #

class UsuarioBase(BaseModel):
    username: str
    email: EmailStr


class UsuarioCreate(UsuarioBase):
    password: str


class UsuarioRead(UsuarioBase):
    disabled: bool = False


class UsuarioInDB(UsuarioBase):
    hashed_password: str
    disabled: bool = False


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None


# ======================== "BASE DE DATOS" EN MEMORIA ======================== #

usuarios_db: Dict[str, UsuarioInDB] = {}


# ======================== GESTIÓN DE PASSWORDS ======================== #

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verificar_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def get_usuario(username: str) -> Optional[UsuarioInDB]:
    return usuarios_db.get(username)


def autenticar_usuario(username: str, password: str) -> Optional[UsuarioInDB]:
    usuario = get_usuario(username)
    if not usuario:
        return None
    if not verificar_password(password, usuario.hashed_password):
        return None
    return usuario


# ======================== UTILIDADES JWT ======================== #

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def crear_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UsuarioInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    usuario = get_usuario(token_data.username)
    if usuario is None:
        raise credentials_exception
    return usuario


async def get_current_active_user(current_user: UsuarioInDB = Depends(get_current_user)) -> UsuarioInDB:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Usuario deshabilitado")
    return current_user


# ======================== APLICACIÓN FASTAPI ======================== #

app = FastAPI(title="Práctica 4 - API con Autenticación por Tokens")


# ---------------------- ENDPOINTS DE USUARIOS ---------------------- #

@app.post("/usuarios", response_model=UsuarioRead, status_code=status.HTTP_201_CREATED)
def crear_usuario(datos: UsuarioCreate) -> UsuarioRead:
    """
    Registra un nuevo usuario.
    - Comprueba que el username no exista.
    - Hashea la contraseña antes de guardarla.
    """
    if datos.username in usuarios_db:
        raise HTTPException(status_code=400, detail="El usuario ya existe")

    usuario_db = UsuarioInDB(
        username=datos.username,
        email=datos.email,
        hashed_password=hash_password(datos.password),
    )
    usuarios_db[datos.username] = usuario_db

    return UsuarioRead(
        username=usuario_db.username,
        email=usuario_db.email,
        disabled=usuario_db.disabled,
    )


@app.get("/usuarios", response_model=List[UsuarioRead])
def listar_usuarios(current_user: UsuarioInDB = Depends(get_current_active_user)) -> List[UsuarioRead]:
    """
    Lista todos los usuarios registrados.
    Endpoint PROTEGIDO con token.
    """
    return [
        UsuarioRead(username=u.username, email=u.email, disabled=u.disabled)
        for u in usuarios_db.values()
    ]


@app.get("/usuarios/me", response_model=UsuarioRead)
async def leer_usuario_actual(current_user: UsuarioInDB = Depends(get_current_active_user)) -> UsuarioRead:
    """
    Devuelve la información del usuario autenticado.
    Endpoint PROTEGIDO con token.
    """
    return UsuarioRead(
        username=current_user.username,
        email=current_user.email,
        disabled=current_user.disabled,
    )


# ---------------------- ENDPOINT LOGIN / TOKEN ---------------------- #

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    """
    Recibe username + password y devuelve un token JWT.
    """
    usuario = autenticar_usuario(form_data.username, form_data.password)
    if not usuario:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = crear_access_token(
        data={"sub": usuario.username},
        expires_delta=access_token_expires,
    )

    return Token(access_token=access_token, token_type="bearer")


# ---------------------- OTRO ENDPOINT PROTEGIDO ---------------------- #

@app.get("/datos-seguros")
async def datos_seguros(current_user: UsuarioInDB = Depends(get_current_active_user)):
    """
    Ejemplo de endpoint protegido que requiere token.
    """
    return {
        "mensaje": f"Hola {current_user.username}, este es un recurso protegido.",
        "email": current_user.email,
    }
