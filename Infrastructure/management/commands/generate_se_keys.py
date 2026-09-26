import base64
import json
import os
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.core.management.base import BaseCommand

from Infrastructure.services.seCryptoService import SECryptoService


class Command(BaseCommand):
    help = 'Gera 2 chaves privadas no Secure Element (TPM) e salva as chaves públicas em um JSON'

    def add_arguments(self, parser):
        parser.add_argument(
            '--output',
            type=str,
            default='se_keys_info.json',
            help='Caminho do arquivo JSON de saída',
        )

    def generate_key_in_se(self, key_name):
        # Usamos o PowerShell para acessar as classes .NET de criptografia (CNG)
        # O 'Microsoft Platform Crypto Provider' interage diretamente com o TPM / Secure Element no Windows.
        # Definimos ExportPolicy = None para garantir que a chave privada não possa ser exportada de forma alguma.
        #
        # IMPORTANTE: A chave deve ser gerada com permissão de exportação (CNGExportPolicies::AllowExport).
        # Caso contrário, o TPM bloqueará o carregamento da chave pelo .NET.
        # A chave privada NÃO será vazada, pois ela não pode ser extraída do TPM sem a chave de autenticação do fabricante.
        ps_script = f"""
        try {{
            $provider = [System.Security.Cryptography.CngProvider]::new('Microsoft Platform Crypto Provider')
            $cp = [System.Security.Cryptography.CngKeyCreationParameters]::new()
            $cp.Provider = $provider
            $cp.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::OverwriteExistingKey
            $cp.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
            
            # Gera uma chave RSA (o tamanho padrão geralmente é 2048, suportado por todos os TPMs)
            $key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, '{key_name}', $cp)
            
            # Exporta APENAS a chave pública (a privada fica presa no hardware)
            $pub = $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)
            
            $base64Pub = [Convert]::ToBase64String($pub)
            
            $result = @{{
                KeyName = '{key_name}'
                PublicKeyBase64 = $base64Pub
                Algorithm = 'RSA'
                Provider = 'Microsoft Platform Crypto Provider'
            }}
            
            $result | ConvertTo-Json -Compress
        }} catch {{
            Write-Error $_.Exception.Message
            exit 1
        }}
        """
        
        result = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True)
        if result.returncode != 0:
            self.stderr.write(f"Erro ao gerar a chave {key_name}: {result.stderr}")
            return None
        
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            self.stderr.write(f"Erro ao decodificar resposta JSON para a chave {key_name}: {result.stdout}")
            return None

    def generate_key_in_linux_tpm(self, key_name: str):
        """Gera chave RSA 2048-bit diretamente no chip de hardware TPM 2.0 no Linux usando tpm2-tools."""
        base_dir = Path(getattr(settings, 'BASE_DIR', Path.cwd()))
        tpm_dir = base_dir / '.tpm_keys'
        tpm_dir.mkdir(parents=True, exist_ok=True)

        primary_ctx = tpm_dir / 'primary.ctx'
        key_pub = tpm_dir / f"{key_name}.pub"
        key_priv = tpm_dir / f"{key_name}.priv"
        key_ctx = tpm_dir / f"{key_name}.ctx"
        key_pem = tpm_dir / f"{key_name}_pub.pem"

        # 1. Cria Primary Key (Storage Root Key - SRK) na hierarquia Owner se não existir
        if not primary_ctx.exists():
            cmd_primary = [
                "tpm2_createprimary",
                "-C", "o",
                "-g", "sha256",
                "-G", "rsa",
                "-c", str(primary_ctx)
            ]
            res = subprocess.run(cmd_primary, capture_output=True, text=True)
            if res.returncode != 0:
                self.stderr.write(f"Erro ao criar Primary Key no TPM: {res.stderr.strip()}")
                self.stderr.write("Dica: Certifique-se de que 'tpm2-tools' está instalado e que você tem permissão em /dev/tpmrm0 (sudo chmod 666 /dev/tpmrm0 ou sudo usermod -aG tss $USER).")
                return None

        # 2. Gera a chave RSA 2048 no hardware TPM com atributos de descriptografia e assinatura
        cmd_create = [
            "tpm2_create",
            "-C", str(primary_ctx),
            "-g", "sha256",
            "-G", "rsa2048:null",
            "-u", str(key_pub),
            "-r", str(key_priv),
            "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign"
        ]
        res = subprocess.run(cmd_create, capture_output=True, text=True)
        if res.returncode != 0:
            self.stderr.write(f"Erro ao gerar chave {key_name} no TPM: {res.stderr.strip()}")
            return None

        # 3. Carrega a chave para o contexto do TPM
        cmd_load = [
            "tpm2_load",
            "-C", str(primary_ctx),
            "-u", str(key_pub),
            "-r", str(key_priv),
            "-c", str(key_ctx)
        ]
        res = subprocess.run(cmd_load, capture_output=True, text=True)
        if res.returncode != 0:
            self.stderr.write(f"Erro ao carregar contexto da chave {key_name} no TPM: {res.stderr.strip()}")
            return None

        # 4. Lê a chave pública do TPM em formato PEM
        cmd_readpub = [
            "tpm2_readpublic",
            "-c", str(key_ctx),
            "-f", "pem",
            "-o", str(key_pem)
        ]
        res = subprocess.run(cmd_readpub, capture_output=True, text=True)
        if res.returncode != 0:
            self.stderr.write(f"Erro ao ler chave pública do TPM: {res.stderr.strip()}")
            return None

        # 5. Converte a chave pública para formato BCRYPT_RSAKEY_BLOB da Microsoft CNG (RSA1)
        with open(key_pem, 'rb') as f:
            pub_key_obj = serialization.load_pem_public_key(f.read())

        pub_blob = SECryptoService.export_cng_public_blob(pub_key_obj)
        pub_b64 = base64.b64encode(pub_blob).decode('utf-8')

        return {
            "KeyName": key_name,
            "PublicKeyBase64": pub_b64,
            "Algorithm": "RSA",
            "Provider": "Linux TPM 2.0 (tpm2-tools)"
        }

    def handle(self, *args, **options):
        output_file = options['output']
        self.stdout.write("Iniciando geração de 2 chaves no Secure Element (TPM)...")

        keys_info = []

        for i in range(1, 3):
            key_name = f"VotaAI_SecureKey_{i}"
            self.stdout.write(f"Gerando chave: {key_name}...")

            if sys.platform == "win32":
                key_data = self.generate_key_in_se(key_name)
            else:
                key_data = self.generate_key_in_linux_tpm(key_name)

            if key_data:
                keys_info.append(key_data)
                self.stdout.write(self.style.SUCCESS(f"Chave {key_name} gerada com sucesso! (Chave privada mantida segura no hardware)"))
            else:
                self.stdout.write(self.style.ERROR(f"Falha ao gerar a chave {key_name}."))
                return

        if keys_info:
            base_dir = Path(getattr(settings, 'BASE_DIR', Path.cwd()))
            output_path = base_dir / output_file if not os.path.isabs(output_file) else Path(output_file)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(keys_info, f, indent=4)

            self.stdout.write(self.style.SUCCESS(f"Informações das chaves (incluindo as públicas) salvas com sucesso em: {output_path}"))
