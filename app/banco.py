import os

from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()
supabase: Client = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_KEY"],
)


def inserir_cofre(cofre_id, nome, kdf_sal, kdf_iteracoes,
                   verificador_nonce, verificador_criptograma, verificador_etiqueta):
    supabase.table("cofres").insert({
        "id": cofre_id,
        "nome": nome,
        "kdf_sal": kdf_sal,
        "kdf_iteracoes": kdf_iteracoes,
        "verificador_nonce": verificador_nonce,
        "verificador_criptograma": verificador_criptograma,
        "verificador_etiqueta": verificador_etiqueta,
    }).execute()


def buscar_cofre(cofre_id):
    consulta = supabase.table("cofres").select("*").eq("id", cofre_id)
    resposta = consulta.execute()
    registros = resposta.data
    return registros[0] if registros else None


def inserir_segredo(segredo_id, cofre_id, titulo, usuario, url, nonce, criptograma, etiqueta):
    supabase.table("segredos").insert({
        "id": segredo_id,
        "cofre_id": cofre_id,
        "titulo": titulo,
        "usuario": usuario,
        "url": url,
        "nonce": nonce,
        "criptograma": criptograma,
        "etiqueta": etiqueta,
    }).execute()


def listar_segredos(cofre_id):
    resposta = supabase.table("segredos").select(
        "id, titulo, usuario, url, criado_em"
    ).eq("cofre_id", cofre_id).execute()
    return resposta.data


def buscar_segredo(segredo_id):
    consulta = supabase.table("segredos").select("*").eq("id", segredo_id)
    resposta = consulta.execute()
    registros = resposta.data
    return registros[0] if registros else None


def atualizar_segredo(segredo_id, nonce, criptograma, etiqueta, atualizado_em):
    supabase.table("segredos").update({
        "nonce": nonce,
        "criptograma": criptograma,
        "etiqueta": etiqueta,
        "atualizado_em": atualizado_em,
    }).eq("id", segredo_id).execute()


def remover_segredo(segredo_id):
    supabase.table("segredos").delete().eq("id", segredo_id).execute()
