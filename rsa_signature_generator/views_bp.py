from django.shortcuts import render
from django.http import JsonResponse
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import hashlib
import binascii
from django.views.decorators.csrf import csrf_exempt

def index(request):
    print("VIEW INDEX")
    return render(request, 'rsa_signature_generator/index.html')

@csrf_exempt
def generate_rsa_key(request):
    print("GEN RSA_KEY")
    if request.method == 'POST':
        key_size = int(request.POST.get('key_size'))
        key = RSA.generate(key_size)
        public_key = key.publickey().export_key().decode()
        private_key = key.export_key().decode()
        return JsonResponse({'public_key': public_key, 'private_key': private_key})
    return JsonResponse({'error': 'Method not allowed'})

@csrf_exempt
def calculate_hash_and_sign(request):
    if request.method == 'POST':
        file_sender = request.FILES.get('file_sender')
        private_key = request.POST.get('private_key')

        if not private_key:
            return JsonResponse({'error': 'Không tìm thấy khóa bí mật'})

        file_content = file_sender.read()
        hash_sha1 = hashlib.sha1(file_content).hexdigest()

        try:
            key = RSA.import_key(private_key)
            signer = PKCS1_v1_5.new(key)
            hash_obj = SHA256.new(hash_sha1.encode())
            signature = signer.sign(hash_obj)
            print("========= signature: ", key)
            return JsonResponse({'hash_sha1': hash_sha1, 'signature': binascii.hexlify(signature).decode()})
        except ValueError:
            return JsonResponse({'error': 'Khóa bí mật không hợp lệ'})
        except Exception as e:
            return JsonResponse({'error': str(e)})
    return JsonResponse({'error': 'Method not allowed'})


@csrf_exempt
def verify_signature(request):
    if request.method == 'POST':
        received_public_key = request.POST.get('received_public_key')
        file_to_verify = request.FILES.get('file_to_verify')
        received_signature = request.POST.get('received_signature')

        if not (received_public_key and file_to_verify and received_signature):
            return JsonResponse({'error': 'Thiếu dữ liệu'})

        file_content = file_to_verify.read()
        hash_sha1 = hashlib.sha1(file_content).hexdigest()

        try:
            received_signature = binascii.unhexlify(received_signature)
        except Exception as e:
            return JsonResponse({'result': 'Chữ ký không hợp lệ','hash_sha1': hash_sha1})

        try:
            key = RSA.import_key(received_public_key)
            verifier = PKCS1_v1_5.new(key)
            hash_obj = SHA256.new(hash_sha1.encode())
            if verifier.verify(hash_obj, received_signature):
                return JsonResponse({'hash_sha1': hash_sha1,'result': 'Chữ ký hợp lệ'})
            else:
                return JsonResponse({'hash_sha1': hash_sha1,'result': 'Chữ ký không hợp lệ'})
        except ValueError:
            return JsonResponse({'result': 'Khóa công khai không hợp lệ'})
        except Exception as e:
            return JsonResponse({'error': str(e)})
    return JsonResponse({'error': 'Method not allowed'})
