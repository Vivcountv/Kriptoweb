import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image
import random
import math

# Fungsi untuk menghasilkan bilangan prima
def is_prime(n, k=5):
    """
    Checks if a number n is prime using the Miller-Rabin primality test.
    k is the number of iterations for the test.
    """
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False

    # Write n as d*2^s + 1
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    # Miller-Rabin test
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Fungsi untuk menghasilkan bilangan prima besar dengan bit tertentu
def generate_large_prime(bits):
    """Generates a large prime number with a specified number of bits."""
    while True:
        p = random.getrandbits(bits)
        # Ensure the number has the exact bit length by setting the most significant bit
        # and ensuring it's odd
        p |= (1 << (bits - 1)) | 1
        if is_prime(p):
            return p

# Fungsi untuk enkripsi AES (Advanced Encryption Standard)
def aes_encrypt(message, key):
    """
    Encrypts a message using AES in CBC mode.
    The IV is prepended to the ciphertext.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    # Pad the message to be a multiple of the block size (16 bytes for AES)
    # If message is 16 bytes, PKCS7 padding adds a full block of 16 bytes.
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

# Fungsi untuk dekripsi AES
def aes_decrypt(ciphertext, key):
    """
    Decrypts an AES ciphertext.
    The IV is expected to be the first AES.block_size bytes of the ciphertext.
    """
    if len(ciphertext) < AES.block_size:
        raise ValueError("Incorrect IV length")
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Unpad the decrypted message
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# Fungsi untuk enkripsi RSA
def rsa_encrypt(key, message):
    """Encrypts a message using RSA with PKCS1_OAEP padding."""
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)

# Fungsi untuk dekripsi RSA
def rsa_decrypt(key, ciphertext):
    """Decrypts an RSA ciphertext using PKCS1_OAEP padding."""
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)

# Fungsi untuk menghasilkan sidik jari (fingerprint) SHA256 4 digit pertama
def generate_fingerprint(message):
    """
    Generates a SHA256 hash of the message and returns the
    decimal value of its first 4 hexadecimal digits.
    """
    hash_obj = hashlib.sha256(message.encode())
    hex_dig = hash_obj.hexdigest()
    first_4 = hex_dig[:4]
    decimal = int(first_4, 16)
    return decimal

# Fungsi untuk tanda tangan Schnorr
def schnorr_sign(p, q, g, x, message):
    """
    Generates a Schnorr signature (e, s) for a given message.
    p, q, g are public parameters, x is the private key.
    """
    k = random.randint(1, q - 1)  # Ephemeral random key
    r = pow(g, k, p)              # Compute r = g^k mod p
    # Compute challenge e = H(r || message) mod q
    e = int(hashlib.sha256((str(r) + message).encode()).hexdigest(), 16) % q
    s = (k + x * e) % q           # Compute s = (k + x*e) mod q
    return (e, s)

# Fungsi untuk verifikasi tanda tangan Schnorr
def schnorr_verify(p, q, g, y, message, signature):
    """
    Verifies a Schnorr signature (e, s) for a given message.
    p, q, g, y are public parameters, where y = g^x mod p.
    """
    e, s = signature
    # Compute r' = (g^s * y^-e) mod p
    # Note: pow(y, -e, p) is modular multiplicative inverse of y^e mod p
    rv = (pow(g, s, p) * pow(y, -e, p)) % p
    # Recompute challenge e' = H(r' || message) mod q
    ev = int(hashlib.sha256((str(rv) + message).encode()).hexdigest(), 16) % q
    return ev == e  # Signature is valid if e' == e

# Fungsi untuk steganografi LSB (Least Significant Bit)
def lsb_encode_image(img_obj, data):
    """
    Menyembunyikan data ke dalam objek gambar dan mengembalikan objek gambar baru.
    TIDAK memerlukan 'output_path'.
    """
    img = img_obj.convert("RGB")
    binary_data = ''.join([format(byte, '08b') for byte in data])
    if len(binary_data) > img.width * img.height * 3:
        raise ValueError("Data terlalu besar untuk gambar ini")
    
    pixels = list(img.getdata())
    index = 0
    for i in range(len(pixels)):
        pixel = list(pixels[i])
        for j in range(3): # Loop untuk channel R, G, B
            if index < len(binary_data):
                pixel[j] = pixel[j] & ~1 | int(binary_data[index])
                index += 1
        pixels[i] = tuple(pixel)
    
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(pixels)
    
    # Mengembalikan objek gambar baru dan panjang data, BUKAN menyimpan file.
    return new_img, len(data)

# def lsb_encode_image(image_path, data, output_path):
#     """
#     Embeds binary data into the least significant bit of each color channel
#     of an image.
#     """
#     try:
#         img = Image.open(image_path)
#         img = img.convert("RGB") # Ensure image is in RGB mode
#         # Convert bytes data to a binary string
#         binary_data = ''.join([format(byte, '08b') for byte in data])

#         # Check if data fits into the image
#         if len(binary_data) > img.width * img.height * 3: # 3 channels (R, G, B) per pixel
#             raise ValueError("Data too large for image")

#         pixels = list(img.getdata())
#         index = 0

#         # Iterate through each pixel and each color channel (R, G, B)
#         for i in range(len(pixels)):
#             pixel = list(pixels[i]) # Convert tuple to list to modify
#             for j in range(3):      # R, G, B channels
#                 if index < len(binary_data):
#                     # Clear the least significant bit (pixel[j] & ~1)
#                     # Set the new bit ( | int(binary_data[index]))
#                     pixel[j] = pixel[j] & ~1 | int(binary_data[index])
#                     index += 1
#             pixels[i] = tuple(pixel) # Convert list back to tuple

#         new_img = Image.new(img.mode, img.size)
#         new_img.putdata(pixels)
#         new_img.save(output_path)
#         return new_img, len(data) # Return the new image object and original data length
#     except Exception as e:
#         print(f"Error in LSB encoding: {e}")
#         return None, 0

def lsb_decode_image(img_obj, data_length):
    """
    Mengekstrak data dari objek gambar.
    """
    img = img_obj.convert("RGB")
    pixels = list(img.getdata())
    binary_data = []
    index = 0
    bits_to_read = data_length * 8

    for pixel in pixels:
        for value in pixel[:3]: # Loop untuk R, G, B
            if index < bits_to_read:
                binary_data.append(str(value & 1))
                index += 1
            else:
                break
        if index >= bits_to_read:
            break
            
    binary_str = ''.join(binary_data)
    # Mengembalikan data dalam bentuk bytes
    return bytes([int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8)])


# def lsb_decode(image_path, data_length):
#     """
#     Extracts binary data from the least significant bit of each color channel
#     of an image.
#     """
#     try:
#         img = Image.open(image_path)
#         img = img.convert("RGB") # Ensure image is in RGB mode for consistency
#         pixels = list(img.getdata())

#         binary_data = []
#         index = 0
#         bits_to_read = data_length * 8

#         # Iterate through pixels and extract LSB
#         for pixel in pixels:
#             for value in pixel[:3]: # R, G, B channels
#                 if index < bits_to_read:
#                     binary_data.append(str(value & 1)) # Extract the LSB
#                     index += 1
#                 else:
#                     break
#             if index >= bits_to_read:
#                 break

#         binary_str = ''.join(binary_data)
#         # Convert binary string back to bytes
#         bytes_data = [int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8)]
#         return bytes(bytes_data)
#     except Exception as e:
#         print(f"Error in LSB decoding: {e}")
#         return b''

# Fungsi untuk generate kunci AES secara otomatis (16 bytes = 128 bits)
def generate_aes_key():
    """Generates a random 16-byte (128-bit) AES key."""
    return get_random_bytes(16)

def generate_schnorr_params(q_bits=16, p_bits=32):
    """
    Generates valid and secure Schnorr parameters (p, q, g, x) efficiently.
    q (16-bit prime), p (32-bit prime of the form k*q+1), 
    g (generator), x (private key).
    """
    print("Generating Schnorr parameters (this should be fast now)...")
    
    q = generate_large_prime(q_bits)

    while True:
        k_bits = p_bits - q_bits
        k = random.getrandbits(k_bits)
        p = k * q + 1
        
        if not (1 << (p_bits - 1)) <= p < (1 << p_bits):
            continue

        if is_prime(p):
            break
            
    while True:
        h = random.randint(2, p - 2)
        g = pow(h, k, p)
        if g != 1:
            break

    x = random.randint(1, q - 1)

    return p, q, g, x

# Fungsi utama untuk pengirim
def sender():
    """
    Handles the sender's role: message input, key generation (AES, RSA, Schnorr),
    encryption, signing, and steganography.
    """
    print("=== PENGIRIM ===")
    
    # 1. Input pesan (16 karakter)
    message = input("Masukkan pesan (NIM dan Nama, 16 karakter): ")[:16]
    message = message.ljust(16)
    print(f"Pesan: '{message}'")

    # 2. Kunci AES
    aes_key = generate_aes_key()
    print(f"Kunci AES (generated): {aes_key.hex()}")

    # 3. Parameter RSA
    print("\n" + "="*50)
    print("PARAMETER RSA")

    e = 65537 # Standar public exponent
    print("Generating 2048-bit RSA key...")
    rsa_key = RSA.generate(2048, e=e)
    public_key = rsa_key.publickey()
    print("RSA key generated successfully.")
    
    # 4. Parameter Schnorr
    print("\n" + "="*50)
    print("PARAMETER SCHNORR")
    p_schnorr, q_schnorr, g_schnorr, x_schnorr = generate_schnorr_params()
    y_schnorr = pow(g_schnorr, x_schnorr, p_schnorr)
    print(f"p (generated): {p_schnorr}")
    print(f"q (generated): {q_schnorr}")
    print(f"g (generated): {g_schnorr}")
    print(f"x (private, generated): {x_schnorr}")
    print(f"y (public, generated): {y_schnorr}")

    # 5. Input gambar untuk steganografi
    print("\n" + "="*50)
    print("STEGANOGRAFI")
    image_path = input("Masukkan path gambar untuk steganografi (contoh: sample.png): ")
    while not os.path.exists(image_path):
        print("File tidak ditemukan! Coba lagi.")
        image_path = input("Masukkan path gambar untuk steganografi: ")

    print("\n" + "="*50)
    print("PROSES ENKRIPSI DAN SIGNING")

    # Enkripsi pesan dengan AES
    ciphertext = aes_encrypt(message, aes_key)
    print(f"\nCiphertext AES (IV + data): {ciphertext.hex()}")

    # Enkripsi kunci AES dengan RSA
    encrypted_key = rsa_encrypt(public_key, aes_key)
    print(f"Encrypted AES Key (RSA): {encrypted_key.hex()}")

    # Tanda tangan digital Schnorr
    signature = schnorr_sign(p_schnorr, q_schnorr, g_schnorr, x_schnorr, message)
    print(f"Signature (e, s): {signature}")

    # ======================================================================
    # STRUKTUR PAKET DATA YANG ROBUST
    # Format: [Encrypted Key][Len CT (2B)][Ciphertext][Sig E][Sig S]
    # ======================================================================
    q_bytes_len = (q_schnorr.bit_length() + 7) // 8
    signature_e_bytes = signature[0].to_bytes(q_bytes_len, 'big')
    signature_s_bytes = signature[1].to_bytes(q_bytes_len, 'big')

    len_ciphertext_bytes = len(ciphertext).to_bytes(2, 'big') # Gunakan 2 bytes untuk panjang ciphertext

    package = encrypted_key + len_ciphertext_bytes + ciphertext + signature_e_bytes + signature_s_bytes
    
    print(f"\nPackage to be hidden (hex): {package.hex()}")
    print(f"Package length: {len(package)} bytes")

    # Masukkan package ke dalam gambar dengan LSB
    output_path = "stego_image.png"
    _, data_length = lsb_encode_image(image_path, package, output_path)

    if data_length > 0:
        print(f"✅ Gambar dengan data tersembunyi disimpan sebagai: {output_path}")
        print(f"✅ Data length embedded: {data_length} bytes")
        print(f"✅ Proses pengirim selesai!")
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
        'data_length': data_length
    }

# Fungsi utama untuk penerima
def receiver(sender_data):
    """
    Handles the receiver's role: extracting data from stego image,
    decryption, and signature verification.
    """
    print("\n=== PENERIMA ===")

    private_key = sender_data['private_key']
    public_key = private_key.publickey()
    p_schnorr = sender_data['p_schnorr']
    q_schnorr = sender_data['q_schnorr']
    g_schnorr = sender_data['g_schnorr']
    y_schnorr = sender_data['y_schnorr']
    stego_image = sender_data['output_image']
    data_length = sender_data['data_length']

    print("Mengekstrak data dari gambar...")
    extracted_data = lsb_decode(stego_image, data_length)

    if not extracted_data or len(extracted_data) < data_length:
        print("Error: Data yang diekstrak tidak lengkap atau korup!")
        return False

    # ======================================================================
    # PARSING DATA DENGAN KURSOR (LEBIH ROBUST)
    # Format: [Encrypted Key][Len CT (2B)][Ciphertext][Sig E][Sig S]
    # ======================================================================
    try:
        cursor = 0
        
        # 1. Ekstrak Kunci RSA Terenkripsi
        key_size = public_key.size_in_bytes()
        encrypted_key = extracted_data[cursor:key_size]
        cursor += key_size

        # 2. Ekstrak Panjang Ciphertext
        len_ciphertext = int.from_bytes(extracted_data[cursor:cursor+2], 'big')
        cursor += 2

        # 3. Ekstrak Ciphertext
        ciphertext = extracted_data[cursor:cursor+len_ciphertext]
        cursor += len_ciphertext
        
        # 4. Ekstrak Tanda Tangan Schnorr
        q_bytes_len = (q_schnorr.bit_length() + 7) // 8
        signature_e_bytes = extracted_data[cursor:cursor+q_bytes_len]
        cursor += q_bytes_len
        signature_s_bytes = extracted_data[cursor:cursor+q_bytes_len]
        
        e = int.from_bytes(signature_e_bytes, 'big')
        s = int.from_bytes(signature_s_bytes, 'big')
        signature = (e, s)

    except (IndexError, ValueError) as e_parse:
        print(f"❌ Error: Gagal mem-parsing data dari gambar. Data korup. Detail: {e_parse}")
        return False

    print(f"Extracted Encrypted Key: {encrypted_key.hex()}")
    print(f"Extracted Ciphertext: {ciphertext.hex()}")
    print(f"Extracted Signature: {signature}")

    # Dekripsi kunci AES dengan RSA
    try:
        aes_key = rsa_decrypt(private_key, encrypted_key)
        print(f"\nDecrypted AES Key: {aes_key.hex()}")
    except Exception as ex:
        print(f"❌ Error decrypting AES key: {ex}")
        return False

    # Dekripsi pesan dengan AES
    try:
        message = aes_decrypt(ciphertext, aes_key)
        print(f"Decrypted Message: '{message}'")
    except Exception as ex:
        print(f"❌ Error decrypting message: {ex}")
        return False

    # Verifikasi tanda tangan Schnorr
    is_valid = schnorr_verify(p_schnorr, q_schnorr, g_schnorr, y_schnorr, message, signature)
    print(f"\nVerifikasi Tanda Tangan: {'✅ VALID' if is_valid else '❌ TIDAK VALID'}")

    return is_valid

# Program utama
def main():
    """Main function to run the hybrid cryptography application."""
    print("🔐 === IMPLEMENTASI KRIPTOGRAFI HIBRIDA === 🔐")
    print("1. Jalankan Demo Lengkap (Pengirim -> Penerima)")
    print("2. Jalankan Penerima Saja (membutuhkan 'sender_data.txt')")
    choice = input("Pilih mode (1/2): ")

    if choice == '1':
        print("\n🚀 === DEMO LENGKAP DIMULAI ===")
        sender_data = sender()
        if sender_data:
            # ======================================================================
            # KUNCI PERBAIKAN: Menyimpan kunci dalam format PEM yang benar
            # ======================================================================
            with open('sender_data.txt', 'w') as f:
                f.write(f"Private Key:\n{sender_data['private_key'].export_key('PEM').decode('ascii')}\n")
                f.write(f"Schnorr p: {sender_data['p_schnorr']}\n")
                f.write(f"Schnorr q: {sender_data['q_schnorr']}\n")
                f.write(f"Schnorr g: {sender_data['g_schnorr']}\n")
                f.write(f"Schnorr y: {sender_data['y_schnorr']}\n")
                f.write(f"Stego Image: {sender_data['output_image']}\n")
                f.write(f"Data Length: {sender_data['data_length']}\n")
            print("\n✅ Data pengirim (kunci privat RSA, dll) disimpan ke sender_data.txt")
            
            print("\n" + "="*60)
            is_valid = receiver(sender_data)
            print("\n🎯 === HASIL AKHIR VERIFIKASI ===")
            print("Pesan yang diterima adalah", "✅ ASLI DAN VALID" if is_valid else "❌ PALSU ATAU KORUP")

    elif choice == '2':
        # ======================================================================
        # KUNCI PERBAIKAN: Membaca kunci dalam format PEM dengan benar
        # ======================================================================
        try:
            with open('sender_data.txt', 'r') as f:
                sender_data = {}
                key_data = ""
                in_key = False
                for line in f:
                    if '-----BEGIN RSA PRIVATE KEY-----' in line:
                        in_key = True
                    if in_key:
                        key_data += line
                    if '-----END RSA PRIVATE KEY-----' in line:
                        in_key = False
                        # Once the key is fully read, break from adding more lines to it
                        continue # continue to parse other lines
                    
                    if not in_key and ':' in line:
                        key, value = line.strip().split(': ', 1)
                        if key == 'Schnorr p':
                            sender_data['p_schnorr'] = int(value)
                        elif key == 'Schnorr q':
                            sender_data['q_schnorr'] = int(value)
                        elif key == 'Schnorr g':
                            sender_data['g_schnorr'] = int(value)
                        elif key == 'Schnorr y':
                            sender_data['y_schnorr'] = int(value)
                        elif key == 'Stego Image':
                            sender_data['output_image'] = value
                        elif key == 'Data Length':
                            sender_data['data_length'] = int(value)
            
            sender_data['private_key'] = RSA.import_key(key_data)

            is_valid = receiver(sender_data)
            print("\n🎯 === HASIL AKHIR VERIFIKASI ===")
            print("Pesan yang diterima adalah", "✅ ASLI DAN VALID" if is_valid else "❌ PALSU ATAU KORUP")

        except FileNotFoundError:
            print("❌ File sender_data.txt tidak ditemukan!")
            print("Silakan jalankan Demo Lengkap (pilihan 1) terlebih dahulu.")
        except Exception as ex:
            print(f"❌ Error saat membaca atau memproses sender_data.txt: {ex}")
            
    else:
        print("Pilihan tidak valid.")

if __name__ == "__main__":
    main()
