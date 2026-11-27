#!/usr/bin/env python3
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from rede import HUB, PORTA, REDE, TUNEL, chave, destino, nome_valido

WINDOWS = sys.platform == "win32"
if WINDOWS:
    import host_windows
    from rede import TUNEL_HOST_WINDOWS
    PASTA = host_windows.programas() / "TurmaVPN-Servidor"
    CONF = PASTA / f"{TUNEL_HOST_WINDOWS}.conf"
    INTERFACE = TUNEL_HOST_WINDOWS
    WG = host_windows.programas() / "WireGuard/wg.exe"
else:
    PASTA = Path("/etc/turmavpn")
    CONF = Path("/etc/wireguard") / f"{TUNEL}.conf"
    INTERFACE = TUNEL
    WG = "wg"
ESTADO = PASTA / "rede.json"
MARCA = "# Gerado por TurmaVPN v1"

def comando(*args, entrada=None):
    return subprocess.run(args, input=entrada, text=True, stdout=subprocess.PIPE,
                          check=True).stdout.strip()

def gravar(path, conteudo):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as arq:
        temp = Path(arq.name)
        try:
            arq.write(conteudo)
            arq.flush()
            os.fsync(arq.fileno())
        except BaseException:
            temp.unlink(missing_ok=True)
            raise
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)

def aplicar(rede):
    if CONF.exists() and CONF.read_text().splitlines()[:1] != [MARCA]:
        raise ValueError(f"Já existe outra configuração em {CONF}.")
    wg = f"[Interface]\nPrivateKey = {rede['privada']}\nListenPort = {PORTA}\n"
    pares = "".join(f"\n[Peer]\nPublicKey = {p['chave']}\nAllowedIPs = {p['ip']}/32\n"
                    for p in rede["membros"].values())
    if WINDOWS:
        existe = host_windows.verificar(CONF)
        gravar(CONF, f"{MARCA}\n" + wg + f"Address = {HUB}/{REDE.prefixlen}\n" + pares)
        host_windows.aplicar(CONF, wg + pares, existe)
        return
    # Só encaminha pacotes que entram e saem pelo túnel da turma.
    regras = [f"-i %i ! -o %i -j DROP", f"-i %i -o %i -s {REDE} -d {REDE} -j ACCEPT"]
    extras = f"Address = {HUB}/{REDE.prefixlen}\n"
    for regra in regras:
        extras += f"PostUp = iptables -w -I FORWARD 1 {regra}\n"
        extras += f"PostDown = iptables -w -D FORWARD {regra}\n"
    extras += "PostUp = sysctl -q -w net.ipv4.conf.%i.forwarding=1\n"
    gravar(CONF, f"{MARCA}\n" + wg + extras + pares)
    unidade = f"wg-quick@{TUNEL}"
    comando("systemctl", "enable", "--now", unidade)
    comando("wg", "syncconf", TUNEL, "/dev/stdin", entrada=wg + pares)

def convite(rede, nome):
    p = rede["membros"][nome]
    return {"formato": "TurmaVPN-1", "nome": nome, "ip": p["ip"], "membro": p["chave"],
            "servidor": rede["servidor"], "hub": rede["publica"]}

def cadastrar(rede, nome, publica):
    membros = rede["membros"]
    if nome in membros:
        if membros[nome]["chave"] != publica:
            raise ValueError("Esse nome já tem outra chave.")
        return
    if publica == rede["publica"] or any(m["chave"] == publica for m in membros.values()):
        raise ValueError("Essa chave já está em uso.")
    ocupados = {p["ip"] for p in membros.values()}
    livre = next((str(ip) for ip in REDE.hosts() if str(ip) != HUB and str(ip) not in ocupados), None)
    if not livre:
        raise ValueError("Rede cheia.")
    membros[nome] = {"chave": publica, "ip": livre}

def executar(args):
    arquivo = getattr(args, "arquivo", None)
    if arquivo and Path(arquivo).suffix.lower() != ".turma":
        raise ValueError("Use a extensão .turma no arquivo de convite.")
    if args.acao == "parar":
        if not ESTADO.exists():
            raise ValueError("Nenhuma rede criada neste servidor.")
        if WINDOWS:
            host_windows.parar(CONF)
        else:
            comando("systemctl", "disable", "--now", f"wg-quick@{TUNEL}")
        print("Hospedagem parada. Para voltar, use aplicar.")
        return
    if args.acao == "criar" and not ESTADO.exists():
        if CONF.exists():
            raise ValueError(f"O nome {TUNEL} já está em uso em {CONF}.")
        privada = comando(WG, "genkey")
        publica = comando(WG, "pubkey", entrada=privada + "\n")
        rede = {"servidor": destino(args.host), "privada": chave(privada),
                "publica": chave(publica), "membros": {}}
    else:
        if not ESTADO.exists():
            raise ValueError("Primeiro crie a rede com o comando criar.")
        rede = json.loads(ESTADO.read_text())
    if args.acao == "criar" and rede["servidor"] != destino(args.host):
        raise ValueError("Já existe uma rede com outro endereço de servidor.")
    if args.acao == "listar":
        contatos = dict(linha.split() for linha in comando(WG, "show", INTERFACE, "latest-handshakes").splitlines())
        for nome, p in rede["membros"].items():
            ultimo = int(contatos.get(p["chave"], 0))
            info = f"último contato há {max(0, int(time.time())-ultimo)} s" if ultimo else "sem contato"
            print(f"{nome:32} {p['ip']:15} {info}")
        return
    if args.acao == "convidar":
        cadastrar(rede, nome_valido(args.nome), chave(args.chave))
    if args.acao == "remover":
        rede["membros"].pop(nome_valido(args.nome), None)
    gravar(ESTADO, json.dumps(rede, indent=2))
    aplicar(rede)
    if args.acao == "convidar":
        texto = json.dumps(convite(rede, args.nome), indent=2)
        if arquivo:
            gravar(Path(arquivo), texto)
            print(f"Convite salvo em {Path(arquivo).resolve()}")
        else:
            print(texto)
    else:
        print("Rede atualizada.")

@contextmanager
def trava():
    with (PASTA / "lock").open("a+b") as lock:
        if WINDOWS:
            import msvcrt
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX)
        yield

def menu():
    print(f"TurmaVPN | IP deste computador na rede: {HUB}")
    opcoes = {"1": "criar", "2": "convidar", "3": "listar", "4": "remover", "5": "parar", "6": "aplicar"}
    while True:
        print("\n1 Criar rede   2 Convidar amigo   3 Listar amigos   4 Remover amigo")
        print("5 Parar hospedagem   6 Retomar hospedagem   0 Fechar menu")
        opcao = input("Escolha: ").strip()
        if opcao == "0":
            return
        if opcao not in opcoes:
            continue
        args = argparse.Namespace(acao=opcoes[opcao])
        try:
            if args.acao == "criar":
                args.host = input("IPv4 público ou DNS deste servidor: ").strip()
            if args.acao in ("convidar", "remover"):
                args.nome = nome_valido(input("Nome do amigo: ").strip())
            if args.acao == "convidar":
                args.chave = input("Chave pública do amigo: ").strip()
                args.arquivo = args.nome + ".turma"
            with trava():
                executar(args)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as erro:
            print(f"Erro: {erro}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="Servidor da TurmaVPN")
    sub = parser.add_subparsers(dest="acao", required=True)
    sub.add_parser("criar").add_argument("host")
    convidar = sub.add_parser("convidar")
    convidar.add_argument("nome")
    convidar.add_argument("chave")
    convidar.add_argument("--arquivo", help="salvar o convite em um arquivo .turma")
    sub.add_parser("menu")
    sub.add_parser("parar")
    sub.add_parser("remover").add_argument("nome")
    sub.add_parser("listar")
    sub.add_parser("aplicar")
    args = parser.parse_args()
    if WINDOWS:
        host_windows.preparar(PASTA)
    elif sys.platform.startswith("linux"):
        if os.geteuid() != 0:
            sys.exit("Execute com sudo no servidor.")
        os.umask(0o077)
        PASTA.mkdir(mode=0o700, exist_ok=True)
    else:
        sys.exit("A hospedagem requer Windows ou Linux.")
    if args.acao == "menu":
        menu()
    else:
        with trava():
            executar(args)

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as erro:
        sys.exit(f"Erro: {erro}. Se a aplicação da rede falhou, corrija a causa e execute aplicar.")
