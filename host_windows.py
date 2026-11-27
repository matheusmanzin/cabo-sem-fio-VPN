"""Hospedagem nativa com WireGuard para Windows e Windows PowerShell 5.1."""
import ctypes
import os
from pathlib import Path
import subprocess
import tempfile

from rede import HUB, PORTA, TUNEL, TUNEL_HOST_WINDOWS

SERVICO = "WireGuardTunnel$" + TUNEL_HOST_WINDOWS
REGRA = "TurmaVPN-Host-UDP"

def programas():
    return Path(os.environ.get("ProgramW6432") or os.environ["ProgramFiles"])

def sistema():
    return Path(os.environ["SystemRoot"]) / "System32"

def executar(*args):
    resultado = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=90)
    if resultado.returncode:
        raise RuntimeError((resultado.stderr or resultado.stdout).strip()
                           or f"{Path(args[0]).name} retornou {resultado.returncode}.")
    return resultado.stdout.strip()

def powershell(script):
    return executar(sistema() / "WindowsPowerShell/v1.0/powershell.exe",
                    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                    "$ErrorActionPreference='Stop'; " + script)

def preparar(pasta):
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Execute como administrador para hospedar no Windows.")
    for nome in ("wireguard.exe", "wg.exe"):
        if not (programas() / "WireGuard" / nome).is_file():
            raise ValueError("Instale o WireGuard oficial para Windows.")
    pasta.mkdir(exist_ok=True)
    executar(sistema() / "icacls.exe", pasta, "/inheritance:r", "/grant:r",
             "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")

def instalado(conf):
    # O ImagePath do WireGuard contém o executável, /tunnelservice e o perfil.
    import winreg
    try:
        chave = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               rf"SYSTEM\CurrentControlSet\Services\{SERVICO}")
    except FileNotFoundError:
        return False
    with chave:
        linha = winreg.QueryValueEx(chave, "ImagePath")[0]
    import ctypes.wintypes as wt
    shell = ctypes.windll.shell32
    shell.CommandLineToArgvW.argtypes = [wt.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(wt.LPWSTR)
    total = ctypes.c_int()
    itens = shell.CommandLineToArgvW(linha, ctypes.byref(total))
    if not itens:
        raise OSError("Falha ao identificar o serviço do WireGuard.")
    try:
        args = itens[:total.value]
    finally:
        ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        ctypes.windll.kernel32.LocalFree(itens)
    motor = programas() / "WireGuard" / "wireguard.exe"
    if (len(args) != 3 or Path(args[0]) != motor or args[1].lower() != "/tunnelservice"
            or Path(args[2]) != conf):
        raise ValueError(f"O serviço {SERVICO} pertence a outra configuração.")
    return True

def aplicar(conf, bruto, existe):
    motor = programas() / "WireGuard"
    if not existe:
        executar(motor / "wireguard.exe", "/installtunnelservice", conf)
    # Início manual: cada sessão habilita o roteamento no adaptador recém-criado.
    powershell(f"Set-Service -Name '{SERVICO}' -StartupType Manual; "
               f"Start-Service -Name '{SERVICO}'; "
               f"$limite=(Get-Date).AddSeconds(25); "
               f"while (-not (Get-NetIPAddress -InterfaceAlias '{TUNEL_HOST_WINDOWS}' "
               f"-IPAddress '{HUB}' -ErrorAction SilentlyContinue)) {{ "
               "if ((Get-Date) -gt $limite) { throw 'O adaptador da TurmaVPN nao iniciou.' }; "
               "Start-Sleep -Milliseconds 250 }")
    # wg.exe no Windows lê uma configuração pura do disco, sem as opções do adaptador.
    with tempfile.NamedTemporaryFile(mode="w", dir=conf.parent, encoding="ascii",
                                     delete=False) as arq:
        caminho = Path(arq.name)
        arq.write(bruto)
    try:
        executar(motor / "wg.exe", "syncconf", TUNEL_HOST_WINDOWS, caminho)
    finally:
        caminho.unlink(missing_ok=True)

    powershell(f"Set-NetIPInterface -InterfaceAlias '{TUNEL_HOST_WINDOWS}' "
               "-AddressFamily IPv4 -PolicyStore ActiveStore -Forwarding Enabled; "
               f"if (-not (Get-NetFirewallRule -Name '{REGRA}' -ErrorAction SilentlyContinue)) {{ "
               f"New-NetFirewallRule -Name '{REGRA}' -DisplayName 'TurmaVPN (UDP {PORTA})' "
               f"-Direction Inbound -Action Allow -Protocol UDP -LocalPort {PORTA} "
               "-Profile Any | Out-Null } else { "
               f"Enable-NetFirewallRule -Name '{REGRA}' }}")

def verificar(conf):
    existe = instalado(conf)
    ativos = executar(programas() / "WireGuard/wg.exe", "show", "interfaces").lower().split()
    if TUNEL in ativos:
        raise ValueError("Desconecte o cliente TurmaVPN deste PC antes de hospedar.")
    if TUNEL_HOST_WINDOWS in ativos and not existe:
        raise ValueError("O adaptador de hospedagem já está em uso.")
    return existe

def parar(conf):
    if instalado(conf):
        powershell(f"Set-Service -Name '{SERVICO}' -StartupType Manual; "
                   f"Stop-Service -Name '{SERVICO}'")
    powershell(f"Get-NetFirewallRule -Name '{REGRA}' -ErrorAction SilentlyContinue "
               "| Remove-NetFirewallRule")
