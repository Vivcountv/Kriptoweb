import base64
import io
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
from Crypto.PublicKey import RSA

# Mengimpor semua fungsi dari file HibridaCrypto.py kita
# Kita memberinya alias 'crypto' agar pemanggilan lebih rapi
import HibridaCrypto as crypto

# ======================================================================
# INISIALISASI FLASK DAN CORS
# ======================================================================
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ======================================================================
# ENDPOINT API UNTUK ENKRIPSI (MENGHASILKAN KUNCI UNIVERSAL)
# ======================================================================
@app.route('/api/encrypt', methods=['POST'])
def encrypt_route():
    try:
        # Memastikan pesan dipotong/diisi menjadi tepat 16 karakter.
        message_raw = request.form['message']
        message = message_raw[:16].ljust(16)
        
        print(f"--- DEBUG ENCRYPT: Pesan diterima: '{message_raw}' ---")
        print(f"--- DEBUG ENCRYPT: Pesan setelah format (16 char): '{message}' ---")

        cover_image_file = request.files['image']

        # 1. Panggil fungsi dari modul 'crypto'
        aes_key = crypto.generate_aes_key()
        rsa_key = RSA.generate(2048, e=65537)
        public_key = rsa_key.publickey()
        p, q, g, x = crypto.generate_schnorr_params()
        y = pow(g, x, p)

        # 2. Enkripsi dan tanda tangan menggunakan pesan yang sudah diformat
        ciphertext_aes = crypto.aes_encrypt(message, aes_key)
        encrypted_aes_key = crypto.rsa_encrypt(public_key, aes_key)
        signature = crypto.schnorr_sign(p, q, g, x, message)

        # 3. Susun paket data
        q_bytes_len = (q.bit_length() + 7) // 8
        signature_e_bytes = signature[0].to_bytes(q_bytes_len, 'big')
        signature_s_bytes = signature[1].to_bytes(q_bytes_len, 'big')
        len_ciphertext_bytes = len(ciphertext_aes).to_bytes(2, 'big')
        package = encrypted_aes_key + len_ciphertext_bytes + ciphertext_aes + signature_e_bytes + signature_s_bytes
        
        # 4. Sembunyikan paket data
        cover_image = Image.open(cover_image_file.stream)
        stego_image, data_length = crypto.lsb_encode_image(cover_image, package)
        print(f"--- DEBUG ENCRYPT: Data disembunyikan: {data_length} bytes ---")

        # 5. Konversi gambar hasil ke Base64 data URL
        buffer = io.BytesIO()
        stego_image.save(buffer, format="PNG")
        stego_image_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        data_url = f"data:image/png;base64,{stego_image_b64}"

        # --- PERUBAHAN UTAMA: Gabungkan semua ke dalam satu kunci ---
        # 6. Kemas semua data (kunci DAN gambar) ke dalam satu dictionary
        receiver_universal_key_data = {
            'rsa_private_pem': rsa_key.export_key('PEM').decode('utf-8'),
            'p': p, 'q': q, 'g': g, 'y': y,
            'data_length': data_length,
            'stegoImageB64': data_url  # <-- Gambar disertakan di sini
        }
        # Encode dictionary ini menjadi satu string Base64
        receiver_key_str = json.dumps(receiver_universal_key_data)
        receiver_key_b64 = base64.b64encode(receiver_key_str.encode('utf-8')).decode('utf-8')

        # Kembalikan HANYA satu kunci universal ini
        return jsonify({
            'receiverKey': receiver_key_b64
        })

    except Exception as e:
        print(f"Error di /api/encrypt: {e}")
        return jsonify({"error": f"Terjadi kesalahan di server: {str(e)}"}), 500

# ======================================================================
# ENDPOINT API UNTUK DEKRIPSI (HANYA MENERIMA KUNCI UNIVERSAL)
# ======================================================================
@app.route('/api/decrypt', methods=['POST'])
def decrypt_route():
    try:
        # Hapus input file, sekarang hanya menerima satu kunci dari form
        receiver_key_b64 = request.form['key']

        print("\n--- DEBUG DECRYPT: Memulai proses dekripsi dari Kunci Universal ---")

        # 1. Buka kemasan kunci universal
        receiver_key_str = base64.b64decode(receiver_key_b64).decode('utf-8')
        keys = json.loads(receiver_key_str)
        
        # Ekstrak semua data dari dictionary
        rsa_private_key = RSA.import_key(keys['rsa_private_pem'])
        p, q, g, y = keys['p'], keys['q'], keys['g'], keys['y']
        data_length = keys['data_length']
        stego_image_b64 = keys['stegoImageB64'] # <-- Ekstrak data gambar
        
        print(f"--- DEBUG DECRYPT: Panjang data dari kunci: {data_length} bytes ---")

        # 2. Ekstrak data dari gambar yang ada di dalam kunci
        # Konversi data URL Base64 menjadi objek gambar di memori
        image_data_string = stego_image_b64.split(',')[1]
        image_data_bytes = base64.b64decode(image_data_string)
        stego_image = Image.open(io.BytesIO(image_data_bytes))
        
        extracted_data = crypto.lsb_decode_image(stego_image, data_length)
        if not extracted_data: raise ValueError("Gagal mengekstrak data dari gambar.")
        print(f"--- DEBUG DECRYPT: Panjang data diekstrak dari gambar: {len(extracted_data)} bytes ---")
        
        # 3. Parsing paket data (logika tetap sama)
        cursor = 0
        key_size = rsa_private_key.publickey().size_in_bytes()
        encrypted_aes_key = extracted_data[cursor:key_size]; cursor += key_size
        len_ciphertext = int.from_bytes(extracted_data[cursor:cursor+2], 'big'); cursor += 2
        ciphertext_aes = extracted_data[cursor:cursor+len_ciphertext]; cursor += len_ciphertext
        q_bytes_len = (q.bit_length() + 7) // 8
        e = int.from_bytes(extracted_data[cursor:cursor+q_bytes_len], 'big'); cursor += q_bytes_len
        s = int.from_bytes(extracted_data[cursor:cursor+q_bytes_len], 'big')
        signature = (e, s)

        # 4. Dekripsi dan verifikasi
        aes_key = crypto.rsa_decrypt(rsa_private_key, encrypted_aes_key)
        print(f"--- DEBUG DECRYPT: Kunci AES didekripsi (hex): {aes_key.hex()} ---")
        
        decrypted_message = crypto.aes_decrypt(ciphertext_aes, aes_key)
        print(f"--- DEBUG DECRYPT: Pesan didekripsi: '{decrypted_message}' ---")
        
        is_valid = crypto.schnorr_verify(p, q, g, y, decrypted_message, signature)
        print(f"--- DEBUG DECRYPT: Hasil verifikasi Schnorr: {is_valid} ---")
        
        # Siapkan respons JSON yang akan dikirim kembali ke frontend
        response_data = {
            "isValid": is_valid,
            "message": decrypted_message,
            "stegoImageB64": stego_image_b64 # Kembalikan gambar agar bisa ditampilkan
        }
        if not is_valid:
            response_data["message"] = f"Pesan Diterima: '{decrypted_message}' (TANDA TANGAN TIDAK VALID!)"

        return jsonify(response_data)

    except Exception as e:
        print(f"Error di /api/decrypt: {e}")
        return jsonify({
            "isValid": False, 
            "message": f"Proses dekripsi gagal. Kunci salah atau data korup. ({str(e)})",
            "stegoImageB64": None
        }), 500

if __name__ == '__main__':
    print("🚀 Server Flask (Universal Key) telah dimulai...")
    app.run(host='127.0.0.1', port=5000, debug=True)
