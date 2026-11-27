import base64
import ipaddress
import re

REDE = ipaddress.IPv4Network("10.78.24.0/24")
HUB = str(REDE.network_address + 1)
PORTA = 51820
TUNEL = "turmavpn"
TUNEL_HOST_WINDOWS = "turmahost"

def chave(valor):
    if not isinstance(valor, str) or len(valor) != 44:
        raise ValueError("Chave WireGuard inválida.")
    dados = base64.b64decode(valor, validate=True)
    if len(dados) != 32 or not any(dados) or base64.b64encode(dados).decode() != valor:
        raise ValueError("Chave WireGuard inválida.")
    return valor

def destino(valor):
    if not isinstance(valor, str) or len(valor) > 253:
        raise ValueError("Use um IPv4 ou nome DNS do servidor.")
    if re.fullmatch(r"[\d.]+", valor):
        return str(ipaddress.IPv4Address(valor))
    if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", parte)
               for parte in valor.split(".")):
        raise ValueError("Nome DNS inválido.")
    return valor

def nome_valido(valor):
    if not isinstance(valor, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", valor):
        raise ValueError("Use um nome com 1 a 32 letras sem acento, números, _ ou -.")
    return valor

def perfil(convite, privada, publica):
    if not isinstance(convite, dict) or convite.get("formato") != "TurmaVPN-1":
        raise ValueError("Selecione um convite .turma válido.")
    if chave(convite["membro"]) != publica:
        raise ValueError("Este convite pertence a outra chave. Envie sua chave ao dono da rede.")
    ip = ipaddress.IPv4Address(convite["ip"])
    if ip not in REDE or not REDE.network_address + 2 <= ip < REDE.broadcast_address:
        raise ValueError("IP fora da faixa da turma.")
    host = destino(convite["servidor"])
    return (f"[Interface]\nPrivateKey = {chave(privada)}\nAddress = {ip}/32\n\n"
            f"[Peer]\nPublicKey = {chave(convite['hub'])}\nEndpoint = {host}:{PORTA}\n"
            f"AllowedIPs = {REDE}\nPersistentKeepalive = 25\n")
