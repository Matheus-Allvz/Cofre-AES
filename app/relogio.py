from datetime import UTC, datetime


def agora() -> datetime:
    """Única fonte de "agora" das regras de sessão/limite: os testes trocam esta função."""
    return datetime.now(UTC)
