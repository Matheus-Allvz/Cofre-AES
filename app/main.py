import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app import banco, cripto
from app.modelos import NovoCofre, NovoSegredo

app = FastAPI(title="Cofre de Senhas")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://keep.matheus-alves.dev"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "X-Senha-Mestra"],
)


def _verificar_cofre(cofre_id: str, senha_mestra: str) -> bytes:
    cofre = banco.buscar_cofre(cofre_id)
    if cofre is None:
        raise HTTPException(status_code=404, detail="cofre não encontrado")
    sal = cripto.de_b64(cofre["kdf_sal"])
    chave = cripto.derivar_chave(senha_mestra, sal, cofre["kdf_iteracoes"])
    if not cripto.senha_mestra_correta(
        chave,
        cofre["verificador_nonce"],
        cofre["verificador_criptograma"],
        cofre["verificador_etiqueta"],
        cofre_id,
    ):
        raise HTTPException(status_code=401, detail="senha-mestra incorreta")
    return chave


def _buscar_segredo_do_cofre(cofre_id: str, segredo_id: str):
    segredo = banco.buscar_segredo(segredo_id)
    if segredo is None or segredo["cofre_id"] != cofre_id:
        raise HTTPException(status_code=404, detail="segredo não encontrado")
    return segredo


@app.post("/cofres", status_code=201)
def criar_cofre(novo: NovoCofre):
    cofre_id = str(uuid.uuid4())
    sal = cripto.gerar_sal()
    chave = cripto.derivar_chave(novo.senha_mestra, sal, cripto.ITERACOES_PADRAO)
    nonce, criptograma, etiqueta = cripto.criar_verificador(chave, cofre_id)
    banco.inserir_cofre(
        cofre_id,
        novo.nome,
        cripto.para_b64(sal),
        cripto.ITERACOES_PADRAO,
        nonce,
        criptograma,
        etiqueta,
    )
    return {"id": cofre_id}


@app.post("/cofres/{cofre_id}/abrir")
def abrir_cofre(cofre_id: str, x_senha_mestra: str = Header(...)):
    _verificar_cofre(cofre_id, x_senha_mestra)
    return {"detail": "senha-mestra correta"}


@app.post("/cofres/{cofre_id}/segredos", status_code=201)
def criar_segredo(cofre_id: str, novo: NovoSegredo, x_senha_mestra: str = Header(...)):
    chave = _verificar_cofre(cofre_id, x_senha_mestra)
    segredo_id = str(uuid.uuid4())
    aad = cripto.montar_aad_segredo(cofre_id, segredo_id)
    nonce, criptograma, etiqueta = cripto.cifrar(chave, novo.senha, aad)
    banco.inserir_segredo(
        segredo_id, cofre_id, novo.titulo, novo.usuario, novo.url,
        nonce, criptograma, etiqueta,
    )
    return {"id": segredo_id}


@app.get("/cofres/{cofre_id}/segredos")
def listar_segredos(cofre_id: str, x_senha_mestra: str = Header(...)):
    _verificar_cofre(cofre_id, x_senha_mestra)
    return banco.listar_segredos(cofre_id)


@app.get("/cofres/{cofre_id}/segredos/{segredo_id}")
def ler_segredo(cofre_id: str, segredo_id: str, x_senha_mestra: str = Header(...)):
    chave = _verificar_cofre(cofre_id, x_senha_mestra)
    segredo = _buscar_segredo_do_cofre(cofre_id, segredo_id)
    aad = cripto.montar_aad_segredo(cofre_id, segredo_id)
    try:
        senha = cripto.decifrar(
            chave, segredo["nonce"], segredo["criptograma"], segredo["etiqueta"], aad,
        )
    except ValueError:
        raise HTTPException(status_code=500, detail="registro adulterado")
    return {"senha": senha}


@app.put("/cofres/{cofre_id}/segredos/{segredo_id}")
def atualizar_segredo(
    cofre_id: str,
    segredo_id: str,
    novo: NovoSegredo,
    x_senha_mestra: str = Header(...),
):
    chave = _verificar_cofre(cofre_id, x_senha_mestra)
    _buscar_segredo_do_cofre(cofre_id, segredo_id)
    aad = cripto.montar_aad_segredo(cofre_id, segredo_id)
    nonce, criptograma, etiqueta = cripto.cifrar(chave, novo.senha, aad)
    banco.atualizar_segredo(
        segredo_id, nonce, criptograma, etiqueta,
        datetime.now(timezone.utc).isoformat(),
    )
    return {"detail": "segredo atualizado"}


@app.delete("/cofres/{cofre_id}/segredos/{segredo_id}")
def remover_segredo(cofre_id: str, segredo_id: str, x_senha_mestra: str = Header(...)):
    _verificar_cofre(cofre_id, x_senha_mestra)
    _buscar_segredo_do_cofre(cofre_id, segredo_id)
    banco.remover_segredo(segredo_id)
    return {"detail": "segredo removido"}
