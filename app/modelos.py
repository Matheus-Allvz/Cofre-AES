from pydantic import BaseModel


class NovoCofre(BaseModel):
    nome: str
    senha_mestra: str


class NovoSegredo(BaseModel):
    titulo: str
    usuario: str | None = None
    url: str | None = None
    senha: str
