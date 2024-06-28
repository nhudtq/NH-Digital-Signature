from django.shortcuts import render
from django.http import JsonResponse
import random
import hashlib

from django.views.decorators.csrf import csrf_exempt


def index(request):
    return render(request, 'rsa_signature_generator/index.html')

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    for _ in range(k):
        a = random.randint(2, n - 1)
        if gcd(n, a) != 1:
            return False
        if pow(a, n - 1, n) != 1:
            return False
    return True

def generate_prime(bits):
    while True:
        p = random.randint(2**(bits-1), 2**bits)
        if is_prime(p):
            return p

def generate_keypair(bits):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def sign(file_hash, d, n):
    signature = pow(file_hash, d, n)
    return signature

def verify(signature, e, n):
    hash_from_signature = pow(signature, e, n)
    return hash_from_signature

def key_to_string(key):
    return ",".join(map(str, key))

def string_to_key(s):
    parts = s.split(",")
    return (int(parts[0]), int(parts[1]))



@csrf_exempt
def generate_rsa_key(request):
    if request.method == 'POST':
        key_size = int(request.POST.get('key_size'))
        private_key, public_key = generate_keypair(key_size)
        private_key_str = key_to_string(private_key)
        public_key_str = key_to_string(public_key)
        return JsonResponse({'public_key': public_key_str, 'private_key': private_key_str})
    return JsonResponse({'error': 'Method not allowed'})

@csrf_exempt
def calculate_hash_and_sign(request):
    if request.method == 'POST':
        file_sender = request.FILES.get('file_sender')
        private_key = request.POST.get('private_key')

        if not private_key:
            return JsonResponse({'error': 'Không tìm thấy khóa bí mật'})

        file_content = file_sender.read()
        file_hash = int.from_bytes(hashlib.sha1(file_content).digest(), byteorder='big')
        private_key_tuple = string_to_key(private_key)
        signature = sign(file_hash, private_key_tuple[0], private_key_tuple[1])
        print(signature)
        return JsonResponse({'hash_sha1': str(file_hash), 'signature': str(signature)})

@csrf_exempt
def verify_signature(request):
    if request.method == 'POST':
        received_public_key = request.POST.get('received_public_key')
        file_to_verify = request.FILES.get('file_to_verify')
        received_signature = request.POST.get('received_signature')

        if not (received_public_key and file_to_verify and received_signature):
            return JsonResponse({'error': 'Thiếu dữ liệu'})

        file_content = file_to_verify.read()
        file_hash = int.from_bytes(hashlib.sha1(file_content).digest(), byteorder='big')
        try:
            signature = int(received_signature)
            print(signature)
            print(file_hash)
            public_key_tuple = string_to_key(received_public_key)
            decode = verify(signature, public_key_tuple[0], public_key_tuple[1])
            if file_hash == decode:
                return JsonResponse({'hash_sha1': str(file_hash),'decode_signature':str(decode), 'result': 'Chữ ký hợp lệ'})
            else:
                return JsonResponse({'hash_sha1': str(file_hash),'decode_signature':str(decode), 'result': 'Chữ ký không hợp lệ'})
        except Exception as e:
            return JsonResponse({'hash_sha1': str(file_hash),'decode_signature':'', 'result': 'Chữ ký không hợp lệ'})
