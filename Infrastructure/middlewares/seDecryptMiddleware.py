import json
import base64
import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Infrastructure.services.seCryptoService import SECryptoService

logger = logging.getLogger(__name__)

class SEDecryptMiddleware(MiddlewareMixin):
    """
    Middleware que intercepta requisições e respostas:
    1. Descriptografa os dados de entrada usando as chaves privadas do TPM/Secure Element.
    2. Registra e salva a chave pública do cliente Desktop/Mobile enviada na requisição.
    3. Criptografa os dados de retorno (response) usando a chave pública do cliente.
    """

    # Rotas de infraestrutura e documentação que não passam por criptografia de hardware
    EXEMPT_ROUTES = (
        '/admin',
        '/api/docs',
        '/api/schema',
        '/api/redoc',
        '/static',
        '/media',
    )

    # Prefixos de rotas para Desktop usando a chave 1
    DESKTOP_ROUTES = (
        '/api/admin',              # pré-cadastro do admin
        '/api/election/create',    # cadastrar eleição
        '/api/election/start',     # iniciar eleição
        '/api/election/list',      # listar eleições
        '/api/election/close',     # Fechar eleição
        '/api/election/tally',     # apurar eleição
        '/api/ping-desktop',       # Rota de teste
        '/api/auth',               # autenticação desktop
        '/api/users',              # gerenciamento de usuários
        '/api/roles',              # listagem de roles
        '/api/groups',             # grupos
        '/api/permissions',        # permissões
        '/api/password',           # reset/gestão de senha
    )

    # Prefixos de rotas para Mobile usando a chave 2
    MOBILE_ROUTES = (
        '/api/vote',               # solicitação de voto e votar
        '/api/election/track',     # acompanhar eleição
    )

    def process_request(self, request):
        path = request.path

        # Rotas isentas passam direto
        if path.startswith(self.EXEMPT_ROUTES):
            return None

        # Determina qual dispositivo e chave usar com base na rota
        key_name = None
        device_type = None
        if path.startswith(self.DESKTOP_ROUTES):
            key_name = 'VotaAI_SecureKey_1'
            device_type = 'desktop'
        elif path.startswith(self.MOBILE_ROUTES):
            key_name = 'VotaAI_SecureKey_2'
            device_type = 'mobile'

        # Todas as rotas da aplicação precisam pertencer a um dispositivo
        if not key_name or not device_type:
            return JsonResponse({
                'error': f'Rota {path} não mapeada para nenhum dispositivo (Desktop ou Mobile). Acesso restrito.'
            }, status=400)

        # Marca no request o tipo de dispositivo para uso no process_response
        request._device_type = device_type

        # Apenas requisições que enviam dados (POST, PUT, PATCH) são criptografadas no body
        if request.method not in ['POST', 'PUT', 'PATCH']:
            return None

        # Se houver corpo na requisição
        if request.body:
            try:
                # O cliente envia um JSON contendo a string base64 criptografada
                # Formato esperado: {"encrypted_payload": "...", "encrypted_aes_key": "...", ...}
                body_data = json.loads(request.body)
                encrypted_payload = body_data.get('encrypted_payload')
                encrypted_aes_key = body_data.get('encrypted_aes_key')
                iv = body_data.get('iv')
                tag = body_data.get('tag')
                client_public_key = body_data.get('client_public_key')

                # Se a chave pública do cliente veio dentro do envelope JSON da requisição, salva
                if client_public_key and device_type:
                    try:
                        SECryptoService.save_client_public_key(device_type, client_public_key)
                    except Exception as e:
                        logger.warning(f"Não foi possível salvar chave pública enviada no body: {e}")

                if not encrypted_payload:
                    return JsonResponse({'error': 'Payload criptografado não encontrado. Envie no campo "encrypted_payload".'}, status=400)

                if not encrypted_aes_key or not iv or not tag:
                    return JsonResponse({'error': 'Faltam campos "encrypted_aes_key", "iv" ou "tag" para criptografia AES-GCM + RSA.'}, status=400)

                # 1. Descriptografa a chave AES usando o hardware TPM
                aes_key_bytes = SECryptoService.decrypt_with_tpm(key_name, encrypted_aes_key)
                
                # AESGCM pede chave de 16, 24 ou 32 bytes.
                aesgcm = AESGCM(aes_key_bytes[:32]) # Pega os primeiros 32 bytes
                
                iv_bytes = base64.b64decode(iv)
                tag_bytes = base64.b64decode(tag)
                payload_bytes = base64.b64decode(encrypted_payload)
                
                # No Python AESGCM, a tag é concatenada ao final do ciphertext
                ciphertext = payload_bytes + tag_bytes
                
                decrypted_json_bytes = aesgcm.decrypt(iv_bytes, ciphertext, None)
                decrypted_json_str = decrypted_json_bytes.decode('utf-8')
                
                # Valida se o texto devolvido pelo TPM é um JSON válido
                json.loads(decrypted_json_str)
                
                # Sobrescreve o corpo da requisição com os dados em texto claro.
                # Dessa forma, as Views (Controllers) não precisam saber de criptografia.
                request._body = decrypted_json_str.encode('utf-8')
                
                # Forçamos o Content-Type para json para evitar problemas nos parsers do Django
                request.META['CONTENT_TYPE'] = 'application/json'

            except json.JSONDecodeError:
                return JsonResponse({'error': 'Corpo da requisição original, ou o corpo descriptografado, não é um JSON válido.'}, status=400)
            except ValueError as ve:
                logger.error(f"Erro na descriptografia (Secure Element): {str(ve)}")
                return JsonResponse({'error': 'Falha na descriptografia. Verifique sua chave pública e criptografia.'}, status=403)
            except Exception as e:
                logger.error(f"Erro interno de descriptografia: {str(e)}")
                return JsonResponse({'error': 'Erro de processamento criptográfico interno.'}, status=500)

        return None

    def process_response(self, request, response):
        """
        Criptografa o corpo da resposta antes de enviá-la de volta ao cliente,
        usando a chave pública do Desktop/Mobile registrada.
        """
        path = request.path

        # Rotas isentas (admin, docs, static) não são criptografadas
        if path.startswith(self.EXEMPT_ROUTES):
            return response

        device_type = getattr(request, '_device_type', None)
        if not device_type:
            if path.startswith(self.DESKTOP_ROUTES):
                device_type = 'desktop'
            elif path.startswith(self.MOBILE_ROUTES):
                device_type = 'mobile'

        # Se não conseguir inferir o dispositivo para qualquer rota da API, retorna erro
        if not device_type:
            return JsonResponse({
                'error': f'Não foi possível inferir o tipo de dispositivo (desktop/mobile) para a rota {path}.'
            }, status=400)

        # Se não há conteúdo ou se a resposta for streaming, mantém inalterada
        if getattr(response, 'streaming', False) or not response.content:
            return response

        try:
            client_pub_key = SECryptoService.get_client_public_key(device_type)
            if not client_pub_key:
                return JsonResponse({
                    'error': f'Chave pública do cliente ({device_type}) não encontrada. Envie sua chave pública no campo "client_public_key".'
                }, status=400)

            # Criptografa o conteúdo da resposta com criptografia híbrida AES-GCM + RSA
            encrypted_data = SECryptoService.encrypt_response_hybrid(client_pub_key, response.content)
            
            encrypted_json_bytes = json.dumps(encrypted_data).encode('utf-8')
            response.content = encrypted_json_bytes
            response['Content-Type'] = 'application/json'
            response['Content-Length'] = str(len(encrypted_json_bytes))

        except Exception as e:
            logger.error(f"Erro ao criptografar resposta para {device_type}: {e}")
            return JsonResponse({'error': f'Erro ao processar criptografia de resposta: {str(e)}'}, status=500)

        return response
