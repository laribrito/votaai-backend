from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

class PingDesktopView(APIView):
    """
    Rota de teste para validar a Criptografia de Hardware do Desktop.
    Como o SEDecryptMiddleware roda antes desta View, o request.data 
    já deve chegar aqui totalmente descriptografado e em texto claro.
    """
    permission_classes = [AllowAny] # Permite acesso sem token apenas para testar a criptografia

    def post(self, request, *args, **kwargs):
        # request.data conterá o JSON limpo!
        decrypted_payload = request.data
        
        return Response({
            "message": "Sucesso! A requisição passou pelo Secure Element (TPM), a chave AES foi decodificada e o payload foi extraído corretamente.",
            "data_recebida": decrypted_payload
        })
