import subprocess
import sys
import os

# Garante que o GitHub CLI (gh) esteja no PATH caso esteja instalado nos locais padrao
GH_PATHS = [
    r"C:\Program Files\GitHub CLI",
    r"C:\Program Files (x86)\GitHub CLI",
    os.path.expanduser(r"~\AppData\Local\Programs\GitHub CLI\bin"),
    os.path.expanduser(r"~\scoop\shims"),
]
for path_dir in GH_PATHS:
    if os.path.exists(path_dir) and path_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = path_dir + os.pathsep + os.environ.get("PATH", "")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

def safe_print(text):
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        print(text.encode(encoding, errors="replace").decode(encoding))

# Caminho para o executavel Python no .venv local ou do sistema para rodar commitizen
def get_cz_command():
    venv_python = os.path.join(os.path.dirname(__file__), ".venv", "Scripts", "python.exe")
    if os.path.exists(venv_python):
        return f'"{venv_python}" -m commitizen'
    return f'"{sys.executable}" -m commitizen'

def run_command(command, description):
    safe_print(f"\n[>] Executando: {description}...")
    try:
        # Executa no PowerShell se for Windows
        shell = True if os.name == 'nt' else False
        result = subprocess.run(command, shell=shell, check=True, text=True, capture_output=True, encoding='utf-8', errors="replace")
        if result.stdout:
            safe_print(result.stdout.strip())
        safe_print(f"[+] Sucesso: {description}")
    except subprocess.CalledProcessError as e:
        safe_print(f"[-] Erro em '{description}':")
        error_msg = e.stderr.strip() if e.stderr else str(e)
        safe_print(error_msg)
        sys.exit(1)

def pre_merge():
    print("=== PRE-MERGE CHECKS ===")
    # tudo que precisar ser checado antes do merge vai aqui.
    
    # 1. Verifica se existem arquivos modificados e pendentes de commit
    run_command("git status -s", "Verificando status do repositório")
    
    # 2. Testes automatizados (Django)
    run_command("python manage.py test", "Executando testes automatizados do Django")

def create_pr(flag="--fill"):
    print("\n=== CREATING PULL REQUEST ===")
    # depois do pre_merge, solicitamos o pull request.
    # o pr deve ser resolvido na web pelo revisor

    run_command(f"gh pr create {flag}", f"Criando Pull Request com GitHub CLI ({flag})")

def cleanup_git():
    print("\n=== LIMPANDO E ATUALIZANDO O REPOSITÓRIO ===")
    # depois do pr fechado, pode facilitar o processo de limpar o repo
    # local com esse comando. ele retorna para a main, puxa atualizaçoes e deleta a branch atual 
    # CUIDADO PARA NÃO USAR NA BRANCH ERRADA

    try:
        branch = subprocess.run("git branch --show-current", shell=True, text=True, capture_output=True, encoding='utf-8', errors="replace").stdout.strip()
    except Exception:
        branch = None
        
    run_command("git checkout main", "Retornando para a branch main")
    run_command("git pull origin main", "Puxando atualizações recentes da main")
    
    if branch and branch != 'main':
        # Tenta deletar a branch mesclada. Usamos -d (safe delete) para evitar apagar coisas não mescladas por engano
        run_command(f'git branch -d "{branch}"', f"Deletando a branch local '{branch}' já mesclada")

    print("\n=== GERANDO RELEASE NA MAIN ===")
    cz_bin = get_cz_command()
    run_command(f"{cz_bin} bump --changelog --yes", "Gerando nova versão (bump), atualizando CHANGELOG e criando tag")
    run_command("git push origin main --tags", "Enviando nova versão e tags para o repositório remoto")

def sync_main():
    print("\n=== SINCRONIZANDO COM A MAIN ===")
    # se necessario resolver conflitos com a main, esse comando
    # facilita o processo

    run_command("git fetch origin", "Buscando atualizações do repositório remoto")
    run_command("git merge origin/main", "Mesclando origin/main na branch atual para resolver conflitos")

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ["pre", "pr", "sync", "clean"]:
        print("Uso: python run_commands.py [pre|pr|sync|clean] [--web]")
        print("  pre   - Executa testes automatizados do Django e checa status do repositório")
        print("  pr    - Cria um Pull Request no GitHub de forma automática com os commits (use --web para abrir no navegador)")
        print("  clean - Volta para a main, atualiza e deleta a branch local mesclada")
        print("  sync  - Busca atualizações da main e tenta mesclar localmente para resolver conflitos")
        sys.exit(1)
        
    action = sys.argv[1]
    if action == "pre":
        pre_merge()
    elif action == "pr":
        flag = "--web" if len(sys.argv) > 2 and sys.argv[2] == "--web" else "--fill"
        create_pr(flag)
    elif action == "sync":
        sync_main()
    elif action == "clean":
        cleanup_git()