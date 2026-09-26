import subprocess
import sys
import os
import json

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
    venv_win = os.path.join(os.path.dirname(__file__), ".venv", "Scripts", "python.exe")
    if os.path.exists(venv_win):
        return f'"{venv_win}" -m commitizen'
    venv_unix = os.path.join(os.path.dirname(__file__), ".venv", "bin", "python")
    if os.path.exists(venv_unix):
        return f'"{venv_unix}" -m commitizen'
    return f'"{sys.executable}" -m commitizen'

def run_command(command, description):
    safe_print(f"\n[>] Executando: {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True, encoding='utf-8', errors="replace")
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
    run_command(f'"{sys.executable}" manage.py test', "Executando testes automatizados do Django")

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

def fetch_pr_comments(pr_target=None, save_to_file=False):
    print("\n=== OBTENDO COMENTÁRIOS E REVISÕES DO PULL REQUEST ===")

    target_arg = f'"{pr_target}"' if pr_target and not pr_target.startswith("--") else ""

    safe_print("[>] Buscando detalhes e comentários gerais com o GitHub CLI...")
    cmd_view = f"gh pr view {target_arg} --comments"
    res_view = subprocess.run(cmd_view, shell=True, text=True, capture_output=True, encoding='utf-8', errors="replace")

    if res_view.returncode != 0:
        safe_print("[-] Não foi possível obter os dados do PR via GitHub CLI.")
        safe_print("    Certifique-se de que o gh está autenticado (`gh auth login`) e que existe um PR aberto para a branch atual.")
        if res_view.stderr:
            safe_print(f"    Detalhes: {res_view.stderr.strip()}")
        return

    # Tenta obter comentários de revisão inline (code review por linha de código)
    cmd_info = f"gh pr view {target_arg} --json number,title,url"
    res_info = subprocess.run(cmd_info, shell=True, text=True, capture_output=True, encoding='utf-8', errors="replace")
    
    review_comments_section = ""
    pr_title = ""
    pr_url = ""

    if res_info.returncode == 0:
        try:
            info = json.loads(res_info.stdout)
            pr_num = info.get("number")
            pr_title = info.get("title", "")
            pr_url = info.get("url", "")

            if pr_num:
                cmd_reviews = f"gh api repos/:owner/:repo/pulls/{pr_num}/comments"
                res_reviews = subprocess.run(cmd_reviews, shell=True, text=True, capture_output=True, encoding='utf-8', errors="replace")
                if res_reviews.returncode == 0 and res_reviews.stdout.strip():
                    reviews = json.loads(res_reviews.stdout)
                    if reviews:
                        review_comments_section += f"\n{'='*60}\n"
                        review_comments_section += f"=== COMENTÁRIOS DE CODE REVIEW INLINE ({len(reviews)}) ===\n"
                        for r in reviews:
                            path = r.get("path", "arquivo")
                            line = r.get("line") or r.get("original_line") or "?"
                            author = r.get("user", {}).get("login", "desconhecido")
                            body = r.get("body", "").strip()
                            review_comments_section += f"\n📁 {path}:{line} — @{author}:\n   {body.replace(chr(10), chr(10) + '   ')}\n"
        except Exception:
            pass

    full_output = res_view.stdout.strip()
    if review_comments_section:
        full_output += "\n" + review_comments_section

    safe_print("\n" + full_output)

    if save_to_file:
        filename = "PR_COMMENTS.md"
        with open(filename, "w", encoding="utf-8") as f:
            header = f"# PR Comments: {pr_title}\nURL: {pr_url}\n\n" if pr_title else ""
            f.write(header + full_output + "\n")
        safe_print(f"\n[+] Comentários exportados com sucesso para o arquivo '{filename}'!")

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ["pre", "pr", "sync", "clean", "comments"]:
        print("Uso: python run_commands.py [pre|pr|sync|clean|comments] [opcoes]")
        print("  pre      - Executa testes automatizados do Django e checa status do repositório")
        print("  pr       - Cria um Pull Request no GitHub de forma automática com os commits (use --web para abrir no navegador)")
        print("  clean    - Volta para a main, atualiza e deleta a branch local mesclada")
        print("  sync     - Busca atualizações da main e tenta mesclar localmente para resolver conflitos")
        print("  comments - Puxa e exibe comentários e revisões de código do PR via GitHub CLI (use [numero_pr] e/ou --save)")
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
    elif action == "comments":
        save_file = "--save" in sys.argv
        target = None
        for arg in sys.argv[2:]:
            if not arg.startswith("--"):
                target = arg
                break
        fetch_pr_comments(pr_target=target, save_to_file=save_file)