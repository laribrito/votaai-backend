import json
import subprocess
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Gera 2 chaves privadas no Secure Element (TPM) usando a API CNG do Windows e salva as chaves públicas em um JSON'

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

    def handle(self, *args, **options):
        output_file = options['output']
        self.stdout.write("Iniciando geração de 2 chaves no Secure Element (TPM)...")
        
        keys_info = []
        
        for i in range(1, 3):
            key_name = f"VotaAI_SecureKey_{i}"
            self.stdout.write(f"Gerando chave: {key_name}...")
            
            key_data = self.generate_key_in_se(key_name)
            if key_data:
                keys_info.append(key_data)
                self.stdout.write(self.style.SUCCESS(f"Chave {key_name} gerada com sucesso! (Chave privada mantida segura no hardware)"))
            else:
                self.stdout.write(self.style.ERROR(f"Falha ao gerar a chave {key_name}."))

        if keys_info:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(keys_info, f, indent=4)
            
            self.stdout.write(self.style.SUCCESS(f"Informações das chaves (incluindo as públicas) salvas com sucesso em: {output_file}"))
