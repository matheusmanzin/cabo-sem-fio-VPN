import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from rede import TUNEL, TUNEL_HOST_WINDOWS, chave, nome_valido, perfil

def rodar(*args, entrada=None):
    resultado = subprocess.run(args, input=entrada, capture_output=True, text=True,
                               errors="replace", timeout=25, creationflags=subprocess.CREATE_NO_WINDOW)
    if resultado.returncode:
        raise RuntimeError((resultado.stderr or resultado.stdout).strip()
                           or f"{Path(args[0]).name} retornou erro {resultado.returncode}.")
    return resultado.stdout.strip()

def gravar(path, texto):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False,
                                     encoding="utf-8") as arquivo:
        temporario = Path(arquivo.name)
        arquivo.write(texto)
    try:
        os.replace(temporario, path)
    finally:
        temporario.unlink(missing_ok=True)

class Cliente:
    def __init__(self, janela):
        self.janela = janela
        programas = Path(os.environ.get("ProgramW6432") or os.environ["ProgramFiles"])
        self.wg = programas / "WireGuard" / "wg.exe"
        self.motor = self.wg.with_name("wireguard.exe")
        if not (self.wg.is_file() and self.motor.is_file()):
            raise ValueError("Instale o WireGuard para Windows e abra a TurmaVPN novamente.")
        self.pasta = programas / "TurmaVPN"
        self.pasta.mkdir(exist_ok=True)
        # Administradores e SYSTEM precisam ler a configuração mesmo após reiniciar.
        rodar(Path(os.environ["SystemRoot"]) / "System32/icacls.exe", self.pasta,
              "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
        identidade = self.pasta / "identidade.key"
        if not identidade.exists():
            gravar(identidade, chave(rodar(self.wg, "genkey")))
        self.privada = chave(identidade.read_text().strip())
        self.publica = chave(rodar(self.wg, "pubkey", entrada=self.privada + "\n"))
        self.arquivo = self.pasta / "convite.turma"
        self.conf = self.pasta / (TUNEL + ".conf")
        self.convite = None
        self.info = tk.StringVar(value="Aguardando seu convite")
        self.status = tk.StringVar(value="Verificando o túnel…")
        if self.arquivo.exists():
            self.selecionar(json.loads(self.arquivo.read_text(encoding="utf-8")))
        area = ttk.Frame(janela, padding=22)
        area.pack(fill="both", expand=True)
        ttk.Label(area, text="TurmaVPN", font=("Segoe UI", 20)).pack(anchor="w")
        ttk.Label(area, text="Envie sua chave pública para quem criou a rede.").pack(anchor="w", pady=(14,4))
        ttk.Button(area, text="Copiar minha chave pública", command=self.copiar).pack(anchor="w")
        ttk.Label(area, textvariable=self.info).pack(anchor="w", pady=(18,4))
        ttk.Button(area, text="Abrir convite .turma", command=lambda: self.acao(self.importar)).pack(anchor="w")
        linha = ttk.Frame(area)
        linha.pack(anchor="w", pady=(18,6))
        ttk.Button(linha, text="Conectar", command=lambda: self.acao(self.conectar)).pack(side="left")
        ttk.Button(linha, text="Desconectar", command=lambda: self.acao(self.desconectar)).pack(side="left", padx=8)
        ttk.Label(area, textvariable=self.status, wraplength=420).pack(anchor="w")
        self.atualizar()

    def copiar(self):
        self.janela.clipboard_clear()
        self.janela.clipboard_append(self.publica)
        messagebox.showinfo("TurmaVPN", "Chave pública copiada.")

    def selecionar(self, dados):
        perfil(dados, self.privada, self.publica)
        nome = nome_valido(dados["nome"])
        self.convite = dados
        self.info.set(f"{nome}   •   Seu IP na turma: {dados['ip']}")

    def importar(self):
        if self.ativo():
            raise ValueError("Desconecte antes de trocar o convite.")
        caminho = filedialog.askopenfilename(filetypes=[("Convite TurmaVPN", "*.turma")])
        if caminho:
            with open(caminho, "rb") as arq:
                dados = json.loads(arq.read(8193))
            self.selecionar(dados)
            gravar(self.arquivo, json.dumps(dados))

    def ativo(self):
        return TUNEL in rodar(self.wg, "show", "interfaces").split()

    def conectar(self):
        if self.convite is None:
            raise ValueError("Abra o convite enviado pelo dono da rede.")
        ativos = rodar(self.wg, "show", "interfaces").lower().split()
        if TUNEL_HOST_WINDOWS in ativos:
            raise ValueError("Este PC já hospeda a turma. Use o IP 10.78.24.1 para jogar.")
        if TUNEL in ativos:
            return
        gravar(self.conf, perfil(self.convite, self.privada, self.publica))
        rodar(self.motor, "/installtunnelservice", self.conf)

    def desconectar(self):
        if self.conf.exists():
            rodar(self.motor, "/uninstalltunnelservice", TUNEL)
            self.conf.unlink(missing_ok=True)

    def acao(self, tarefa):
        try:
            tarefa()
        except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as erro:
            messagebox.showerror("TurmaVPN", str(erro))
        self.estado()

    def estado(self):
        try:
            texto = "Desconectado"
            if self.ativo():
                dados = rodar(self.wg, "show", TUNEL, "latest-handshakes").split()
                ultimo = int(dados[-1]) if dados else 0
                if ultimo:
                    segundos = max(0, int(time.time()) - ultimo)
                    texto = f"Último contato com o servidor há {segundos} s."
                else:
                    texto = "Túnel ligado. Aguardando o primeiro contato com o servidor."
            self.status.set(texto)
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as erro:
            self.status.set(f"Falha ao consultar o túnel: {erro}")

    def atualizar(self):
        self.estado()
        self.janela.after(5000, self.atualizar)

if __name__ == "__main__":
    janela = tk.Tk()
    janela.title("TurmaVPN")
    janela.withdraw()
    try:
        if sys.platform != "win32" or not ctypes.windll.shell32.IsUserAnAdmin():
            raise ValueError("Abra o cliente em um terminal do Windows como administrador.")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateMutexW.restype = ctypes.c_void_p
        trava = kernel.CreateMutexW(None, False, "Global\\TurmaVPN-Cliente-V1")
        if not trava or ctypes.get_last_error() == 183:
            raise ValueError("Feche a outra janela da TurmaVPN antes de abrir o cliente.")
        app = Cliente(janela)
        janela.deiconify()
        janela.mainloop()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as erro:
        messagebox.showerror("TurmaVPN", str(erro))
        janela.destroy()
