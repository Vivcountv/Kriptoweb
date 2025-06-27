import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Util import number
from PIL import Image
import random
import math

def generate_rsa_custom():
    """Generate RSA dengan p, q 16-bit sesuai ketentuan soal"""
    print("🔑 Generating RSA parameters...")
    
    # Generate p dan q 16-bit
    p = number.getPrime(16)
    q = number.getPrime(16)
    while p == q:  # Pastikan p != q
        q = number.getPrime(16)
    
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    
    # Pastikan gcd(e, phi) = 1
    while number.GCD(e, phi) != 1:
        p = number.getPrime(16)
        q = number.getPrime(16)
        n = p * q
        phi = (p - 1) * (q - 1)
    
    # Hitung d
    d = number.inverse(e, phi)
    
    print(f"   p = {p} (16-bit)")
    print(f"   q = {q} (16-bit)")
    print(f"   n = {n} ({n.bit_length()}-bit)")
    print(f"   phi(n) = {phi}")
    print(f"   e = {e}")
    print(f"   d = {d}")
    print(f"   gcd(e, phi) = {number.GCD(e, phi)} ✓")
    
    return RSA.construct((n, e, d, p, q))

# ======================================================================
# RSA Enkripsi/Dekripsi dengan Padding untuk Handle Byte-per-Byte
# ======================================================================
def rsa_encrypt_with_padding(key, message_bytes):
    """Enkripsi RSA dengan padding untuk menangani data > modulus"""
    n = key.n
    e = key.e
    max_bytes = (n.bit_length() - 1) // 8 
    
    encrypted_blocks = []
    for i in range(0, len(message_bytes), max_bytes):
        block = message_bytes[i:i+max_bytes]
        # Konversi ke integer
        m = number.bytes_to_long(block)
        if m >= n:
            raise ValueError(f"Message block too large for modulus")
        # Enkripsi
        c = pow(m, e, n)
        encrypted_blocks.append(c)
    
    return encrypted_blocks

def rsa_decrypt_with_padding(key, encrypted_blocks):
    """Dekripsi RSA dengan padding"""
    n = key.n
    d = key.d
    max_bytes = (n.bit_length() - 1) // 8
    
    decrypted_bytes = b''
    for c in encrypted_blocks:
        # Dekripsi
        m = pow(c, d, n)
        # Konversi kembali ke bytes
        block_bytes = number.long_to_bytes(m)
        decrypted_bytes += block_bytes
    
    return decrypted_bytes

# ======================================================================
# FUNGSI UTILITAS KRIPTOGRAFI
# ======================================================================
def generate_message_fingerprint(message):
    """Generate fingerprint dari pesan menggunakan SHA256 (4 digit pertama)"""
    sha256_hash = hashlib.sha256(message.encode()).hexdigest()
    four_digits_hex = sha256_hash[:4]
    return int(four_digits_hex, 16)

def is_prime(n, k=10):
    """Miller-Rabin primality test"""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    
    # Tulis n-1 sebagai d * 2^s
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    
    # Test k kali
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits):
    """Generate bilangan prima dengan bit length tertentu"""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1  # Set MSB dan LSB
        if is_prime(p):
            return p

def aes_encrypt(message, key):
    """Enkripsi AES-128 CBC"""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def aes_decrypt(ciphertext, key):
    """Dekripsi AES-128 CBC"""
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# ======================================================================
# SCHNORR DIGITAL SIGNATURE
# ======================================================================
def generate_schnorr_params():
    """Generate parameter Schnorr sesuai spesifikasi (p = 32-bit)"""
    print("🔏 Generating Schnorr parameters...")
    
    # Generate q (subgroup order) - 16 bit
    q = generate_large_prime(16)
    
    # Generate p = kq + 1 dimana p adalah 32-bit prima
    max_attempts = 1000
    for _ in range(max_attempts):
        # Hitung k sehingga p = kq + 1 sekitar 32-bit
        target_p_bits = 32
        k_bits = target_p_bits - q.bit_length()
        k = random.getrandbits(k_bits)
        if k == 0:
            k = 1
        
        p = k * q + 1
        
        # Pastikan p adalah 32-bit dan prima
        if p.bit_length() == 32 and is_prime(p):
            break
    else:
        raise ValueError("Failed to generate suitable Schnorr parameters")
    
    # Generate generator g
    # g = h^k mod p dimana h adalah random, g != 1
    h = random.randint(2, p - 2)
    g = pow(h, k, p)
    while g == 1:
        h = random.randint(2, p - 2)
        g = pow(h, k, p)
    
    # Generate private key x (random < q)
    x = random.randint(1, q - 1)
    
    # Generate public key y = g^x mod p
    y = pow(g, x, p)
    
    print(f"   q = {q} (16-bit)")
    print(f"   k = {k}")
    print(f"   p = {p} (32-bit)")
    print(f"   g = {g}")
    print(f"   x = {x} (private key)")
    print(f"   y = {y} (public key)")
    print(f"   Verification: g^x mod p = {pow(g, x, p)} = y ✓")
    
    return p, q, g, x, y

def schnorr_sign(p, q, g, x, message):
    """Schnorr digital signature"""
    # Generate random k
    k = random.randint(1, q - 1)
    
    # Compute r = g^k mod p
    r = pow(g, k, p)
    
    # Compute e = H(r || message) mod q
    e = int(hashlib.sha256((str(r) + message).encode()).hexdigest(), 16) % q
    
    # Compute s = (k + xe) mod q
    s = (k + x * e) % q
    
    return (e, s)

def schnorr_verify(p, q, g, y, message, signature):
    """Schnorr signature verification"""
    e, s = signature
    
    # Compute r' = g^s * y^(-e) mod p
    y_inv_e = pow(y, -e, p)  # y^(-e) mod p
    r_prime = (pow(g, s, p) * y_inv_e) % p
    
    # Compute e' = H(r' || message) mod q
    e_prime = int(hashlib.sha256((str(r_prime) + message).encode()).hexdigest(), 16) % q
    
    # Verify e' == e
    return e_prime == e

# ======================================================================
# STEGANOGRAFI LSB
# ======================================================================
def lsb_encode_image(source_image, data_to_embed, output_path=None):
    """Embed data ke dalam gambar menggunakan LSB"""
    try:
        if isinstance(source_image, str):
            img = Image.open(source_image)
        elif isinstance(source_image, Image.Image):
            img = source_image
        else:
            raise TypeError("Unsupported source_image type.")
        
        img = img.convert("RGB")
        
        # Konversi data ke binary
        binary_data = ''.join([format(byte, '08b') for byte in data_to_embed])
        
        # Cek apakah gambar cukup besar
        if len(binary_data) > img.width * img.height * 3:
            raise ValueError("Data is too large to embed in this image.")
        
        pixels = list(img.getdata())
        index = 0
        
        # Embed data
        for i in range(len(pixels)):
            pixel = list(pixels[i])
            for j in range(3):  # RGB
                if index < len(binary_data):
                    # Ubah LSB
                    pixel[j] = (pixel[j] & ~1) | int(binary_data[index])
                    index += 1
            pixels[i] = tuple(pixel)
        
        # Buat gambar baru
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(pixels)
        
        if output_path:
            new_img.save(output_path)
        
        return new_img, len(data_to_embed)
    
    except Exception as e:
        print(f"Error during LSB encoding: {e}")
        return None, 0

def lsb_decode_image(source_image, data_length):
    """Extract data dari gambar menggunakan LSB"""
    try:
        if isinstance(source_image, str):
            img = Image.open(source_image)
        elif isinstance(source_image, Image.Image):
            img = source_image
        else:
            raise TypeError("Unsupported source_image type.")
        
        img = img.convert("RGB")
        pixels = list(img.getdata())
        
        binary_data = []
        index = 0
        bits_to_read = data_length * 8
        
        # Extract LSB
        for pixel in pixels:
            for value in pixel[:3]:  # RGB
                if index < bits_to_read:
                    binary_data.append(str(value & 1))
                    index += 1
                else:
                    break
            if index >= bits_to_read:
                break
        
        # Konversi binary ke bytes
        binary_str = ''.join(binary_data)
        return bytes([int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8)])
    
    except Exception as e:
        print(f"Error during LSB decoding: {e}")
        return b''

# ======================================================================
# FUNGSI UTAMA PENGIRIM DAN PENERIMA
# ======================================================================
def sender():
    print("🚀 === PENGIRIM ===")
    
    # Input pesan dan kunci AES
    message = input("Masukkan pesan (NIM dan Nama, max 16 karakter): ")[:16].ljust(16)
    print(f"Pesan (16 karakter): '{message}'")
    
    while True:
        aes_key_str = input("Masukkan kunci AES (tepat 16 karakter): ")
        if len(aes_key_str) == 16:
            aes_key = aes_key_str.encode('utf-8')
            break
        else:
            print("Error: Kunci AES harus tepat 16 karakter.")
    
    print(f"Kunci AES: '{aes_key_str}'")
    
    # Generate semua parameter otomatis
    print("\n" + "="*60)
    
    # Generate RSA parameters
    rsa_key = generate_rsa_custom()
    public_key = rsa_key.publickey()
    
    print("\n" + "="*60)
    
    # Generate Schnorr parameters
    p_schnorr, q_schnorr, g_schnorr, x_schnorr, y_schnorr = generate_schnorr_params()
    
    # Buat gambar default jika tidak ada
    image_path = "sample_image.png"
    if not os.path.exists(image_path):
        print(f"\n📸 Creating default image: {image_path}")
        # Buat gambar 100x100 dengan warna random
        default_img = Image.new('RGB', (100, 100), 
                              (random.randint(50, 200), random.randint(50, 200), random.randint(50, 200)))
        default_img.save(image_path)
    
    print(f"📸 Using image: {image_path}")
    
    print("\n" + "="*60)
    print("🔐 PROSES ENKRIPSI, FINGERPRINTING, DAN SIGNING")
    
    # 1. Enkripsi pesan dengan AES
    ciphertext = aes_encrypt(message, aes_key)
    print(f"✅ Pesan dienkripsi dengan AES-128 ({len(ciphertext)} bytes)")
    
    # 2. Enkripsi kunci AES dengan RSA
    encrypted_key_blocks = rsa_encrypt_with_padding(public_key, aes_key)
    print(f"✅ Kunci AES dienkripsi dengan RSA ({len(encrypted_key_blocks)} blocks)")
    
    # 3. Generate fingerprint
    fingerprint = generate_message_fingerprint(message)
    print(f"✅ Sidik Jari Pesan: {fingerprint} (hex: {fingerprint:04x})")
    
    # 4. Generate digital signature
    signature = schnorr_sign(p_schnorr, q_schnorr, g_schnorr, x_schnorr, message)
    print(f"✅ Tanda tangan digital: e={signature[0]}, s={signature[1]}")
    
    # 5. Buat paket data
    print("\n📦 MEMBUAT PAKET DATA")
    
    # Serialize encrypted key blocks
    encrypted_key_data = b''
    for block in encrypted_key_blocks:
        # Gunakan 4 bytes untuk setiap block (32-bit)
        encrypted_key_data += block.to_bytes(4, 'big')
    
    # Format paket
    fingerprint_bytes = fingerprint.to_bytes(2, 'big')
    len_ciphertext_bytes = len(ciphertext).to_bytes(2, 'big')
    
    # Signature bytes
    q_bytes_len = (q_schnorr.bit_length() + 7) // 8
    signature_e_bytes = signature[0].to_bytes(q_bytes_len, 'big')
    signature_s_bytes = signature[1].to_bytes(q_bytes_len, 'big')
    
    # Paket lengkap
    package = (
        len(encrypted_key_blocks).to_bytes(1, 'big') +  # Jumlah block
        encrypted_key_data +                            # Encrypted key blocks
        fingerprint_bytes +                             # Fingerprint
        len_ciphertext_bytes +                          # Length ciphertext
        ciphertext +                                    # Ciphertext
        signature_e_bytes +                             # Signature e
        signature_s_bytes                               # Signature s
    )
    
    print(f"   Jumlah block kunci: {len(encrypted_key_blocks)}")
    print(f"   Encrypted key: {len(encrypted_key_data)} bytes")
    print(f"   Fingerprint: {len(fingerprint_bytes)} bytes")
    print(f"   Ciphertext: {len(ciphertext)} bytes")
    print(f"   Signature: {len(signature_e_bytes + signature_s_bytes)} bytes")
    print(f"   Total package: {len(package)} bytes")
    
    # 6. Steganografi LSB
    output_path = "stego_image.png"
    _, data_length = lsb_encode_image(image_path, package, output_path)
    
    if data_length > 0:
        print(f"\n✅ Paket data berhasil disembunyikan dalam gambar")
        print(f"   Gambar steganografi: {output_path}")
        print(f"   Data tersembunyi: {data_length} bytes")
    else:
        print("❌ Gagal menyimpan data ke gambar!")
        return None
    
    return {
        'private_key': rsa_key,
        'p_schnorr': p_schnorr,
        'q_schnorr': q_schnorr,
        'g_schnorr': g_schnorr,
        'y_schnorr': y_schnorr,
        'output_image': output_path,
        'data_length': data_length,
        'num_key_blocks': len(encrypted_key_blocks),
        'q_bytes_len': q_bytes_len
    }

def receiver(sender_data):
    print("\n🎯 === PENERIMA ===")
    
    # Ambil parameter dari pengirim
    private_key = sender_data['private_key']
    p_schnorr = sender_data['p_schnorr']
    q_schnorr = sender_data['q_schnorr']
    g_schnorr = sender_data['g_schnorr']
    y_schnorr = sender_data['y_schnorr']
    stego_image = sender_data['output_image']
    data_length = sender_data['data_length']
    num_key_blocks = sender_data['num_key_blocks']
    q_bytes_len = sender_data['q_bytes_len']
    
    print("📤 Mengekstrak data dari gambar steganografi...")
    extracted_data = lsb_decode_image(stego_image, data_length)
    
    if not extracted_data:
        print("❌ Error: Gagal mengekstrak data!")
        return
    
    print("📦 Membongkar paket data...")
    try:
        cursor = 0
        
        # Baca jumlah block kunci
        num_blocks = int.from_bytes(extracted_data[cursor:cursor+1], 'big')
        cursor += 1
        
        # Baca encrypted key blocks
        encrypted_key_blocks = []
        for _ in range(num_blocks):
            block = int.from_bytes(extracted_data[cursor:cursor+4], 'big')
            encrypted_key_blocks.append(block)
            cursor += 4
        
        # Baca fingerprint
        fingerprint_received = int.from_bytes(extracted_data[cursor:cursor+2], 'big')
        cursor += 2
        
        # Baca panjang ciphertext
        len_ciphertext = int.from_bytes(extracted_data[cursor:cursor+2], 'big')
        cursor += 2
        
        # Baca ciphertext
        ciphertext = extracted_data[cursor:cursor+len_ciphertext]
        cursor += len_ciphertext
        
        # Baca signature
        e = int.from_bytes(extracted_data[cursor:cursor+q_bytes_len], 'big')
        cursor += q_bytes_len
        s = int.from_bytes(extracted_data[cursor:cursor+q_bytes_len], 'big')
        signature = (e, s)
        
        print(f"✅ Paket berhasil dibongkar:")
        print(f"   Jumlah block kunci: {num_blocks}")
        print(f"   Fingerprint: {fingerprint_received}")
        print(f"   Panjang ciphertext: {len_ciphertext}")
        print(f"   Signature: e={e}, s={s}")
        
    except Exception as e_parse:
        print(f"❌ Error: Gagal membongkar paket data. Detail: {e_parse}")
        return
    
    print("\n🔓 PROSES DEKRIPSI DAN VERIFIKASI")
    
    try:
        # Dekripsi kunci AES dengan RSA
        aes_key = rsa_decrypt_with_padding(private_key, encrypted_key_blocks)
        print(f"✅ Kunci AES berhasil didekripsi: '{aes_key.decode()}'")
        
        # Dekripsi pesan dengan AES
        message = aes_decrypt(ciphertext, aes_key)
        print(f"✅ Pesan berhasil didekripsi: '{message}'")
        
    except Exception as ex:
        print(f"❌ Error saat dekripsi: {ex}")
        return
    
    # Verifikasi fingerprint
    fingerprint_calculated = generate_message_fingerprint(message)
    print(f"\n🔍 VERIFIKASI FINGERPRINT:")
    print(f"   Fingerprint diterima: {fingerprint_received} (hex: {fingerprint_received:04x})")
    print(f"   Fingerprint dihitung: {fingerprint_calculated} (hex: {fingerprint_calculated:04x})")
    
    is_fingerprint_valid = (fingerprint_received == fingerprint_calculated)
    print(f"   Status: {'✅ VALID' if is_fingerprint_valid else '❌ TIDAK VALID'}")
    
    # Verifikasi tanda tangan digital
    print(f"\n🔏 VERIFIKASI TANDA TANGAN DIGITAL:")
    is_signature_valid = schnorr_verify(p_schnorr, q_schnorr, g_schnorr, y_schnorr, message, signature)
    print(f"   Status: {'✅ VALID' if is_signature_valid else '❌ TIDAK VALID'}")
    
    # Kesimpulan akhir
    print("\n" + "="*60)
    print("🎯 === KESIMPULAN AKHIR ===")
    
    if is_fingerprint_valid and is_signature_valid:
        print("🎉 Pesan yang diterima adalah ASLI, OTENTIK, DAN TIDAK BERUBAH")
        print("   ✅ Integritas pesan terjaga")
        print("   ✅ Autentikasi pengirim valid")
        print("   ✅ Non-repudiation terpenuhi")
    else:
        print("⚠️  Pesan yang diterima PALSU ATAU TELAH DIMODIFIKASI!")
        if not is_fingerprint_valid:
            print("   ❌ Integritas pesan tidak terjaga")
        if not is_signature_valid:
            print("   ❌ Autentikasi pengirim tidak valid")

def main():
    print("🔐 === IMPLEMENTASI KRIPTOGRAFI HIBRIDA ===")
    print("📋 Spesifikasi:")
    print("   • AES-128 untuk enkripsi pesan")
    print("   • RSA (p,q 16-bit) untuk enkripsi kunci")
    print("   • SHA-256 untuk fingerprint (4 digit pertama)")
    print("   • Schnorr (p 32-bit) untuk tanda tangan digital")
    print("   • LSB Steganografi untuk menyembunyikan data")
    print("="*60)
    
    sender_data = sender()
    
    if sender_data:
        print("\n" + "="*60)
        input("⏳ Tekan Enter untuk melanjutkan ke proses Penerima...")
        receiver(sender_data)
    else:
        print("❌ Program dihentikan karena error pada pengirim.")

if __name__ == "__main__":
    main()
