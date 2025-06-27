import base64
import io
import json
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
from Crypto.PublicKey import RSA

# Impor semua fungsi dari file HibridaCrypto.py Anda
import HibridaCrypto as crypto

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.route('/')
def index():
    return jsonify({
        "status": "online",
        "message": "Selamat Datang di API Kriptografi Hibrida",
        "version": "1.1.0"
    })

@app.route('/api/encrypt', methods=['POST'])
def encrypt_route():
    try:
        # --- Menangkap input dari form ---
        if 'message' not in request.form or 'aes_key' not in request.form or 'image' not in request.files:
            return jsonify({
                "success": False,
                "error": { "code": 400, "message": "Input tidak lengkap. Pastikan 'message', 'aes_key', dan 'image' terkirim."}
            }), 400
            
        message_raw = request.form['message']
        aes_key_str = request.form['aes_key']
        cover_image_file = request.files['image']

        message = message_raw[:16].ljust(16)
        if len(aes_key_str) != 16:
            return jsonify({
                "success": False,
                "error": { "code": 400, "message": "Kunci AES harus tepat 16 karakter."}
            }), 400
        aes_key = aes_key_str.encode('utf-8')
        
        # --- Generate parameter dan tangkap detailnya ---
        rsa_key = crypto.generate_rsa_custom()
        public_key = rsa_key.publickey()
        p_schnorr, q_schnorr, g_schnorr, x_schnorr, y_schnorr = crypto.generate_schnorr_params()

        # --- Proses Enkripsi, Fingerprinting, dan Signing ---
        ciphertext_aes = crypto.aes_encrypt(message, aes_key)
        encrypted_aes_key_blocks = crypto.rsa_encrypt_with_padding(public_key, aes_key)
        fingerprint = crypto.generate_message_fingerprint(message)
        signature = crypto.schnorr_sign(p_schnorr, q_schnorr, g_schnorr, x_schnorr, message)

        # --- Susun paket data ---
        num_key_blocks = len(encrypted_aes_key_blocks)
        n_bytes_len = (rsa_key.n.bit_length() + 7) // 8
        encrypted_key_data = b''.join([block.to_bytes(n_bytes_len, 'big') for block in encrypted_aes_key_blocks])
        
        q_bytes_len = (q_schnorr.bit_length() + 7) // 8
        package = (
            num_key_blocks.to_bytes(1, 'big') + encrypted_key_data +
            fingerprint.to_bytes(2, 'big') + len(ciphertext_aes).to_bytes(2, 'big') +
            ciphertext_aes + signature[0].to_bytes(q_bytes_len, 'big') +
            signature[1].to_bytes(q_bytes_len, 'big')
        )
        
        # --- Steganografi ---
        cover_image = Image.open(cover_image_file.stream)
        stego_image, data_length = crypto.lsb_encode_image(cover_image, package)
        if not stego_image:
            raise ValueError("Gagal menyembunyikan data ke dalam gambar.")

        buffer = io.BytesIO()
        stego_image.save(buffer, format="PNG")
        data_url = f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode('utf-8')}"

        # --- Kemas Kunci Universal ---
        receiver_universal_key_data = {
            'rsa_private_pem': rsa_key.export_key('PEM').decode('utf-8'),
            'p': p_schnorr, 'q': q_schnorr, 'g': g_schnorr, 'y': y_schnorr,
            'data_length': data_length, 'num_key_blocks': num_key_blocks,
            'q_bytes_len': q_bytes_len, 'n_bytes_len': n_bytes_len
        }
        universal_decryption_key = base64.b64encode(json.dumps(receiver_universal_key_data).encode('utf-8')).decode('utf-8')
        
        # --- Kumpulkan detail generasi untuk ditampilkan di UI ---
        generation_details = {
            "rsa": { "n": rsa_key.n, "e": rsa_key.e, "d": rsa_key.d, "p": rsa_key.p, "q": rsa_key.q },
            "schnorr": { "p": p_schnorr, "q": q_schnorr, "g": g_schnorr, "x": x_schnorr, "y": y_schnorr }
        }

        # --- Siapkan respons JSON yang lengkap ---
        return jsonify({
            "success": True,
            "message": "Enkripsi dan steganografi berhasil!",
            "stegoImage": { "dataURL": data_url },
            "keys": { "universalDecryptionKey": universal_decryption_key },
            "generationDetails": generation_details
        })

    except Exception as e:
        error_details = traceback.format_exc()
        print(f"Error di /api/encrypt: {e}\n{error_details}")
        return jsonify({
            "success": False, "error": { "code": 500, "message": "Terjadi kesalahan internal pada server saat enkripsi.", "details": str(e) }
        }), 500


@app.route('/api/decrypt', methods=['POST'])
def decrypt_route():
    try:
        if 'key' not in request.form or 'image' not in request.files:
            return jsonify({
                "success": False,
                "error": { "code": 400, "message": "Input tidak lengkap. Pastikan 'key' dan 'image' (gambar stego) terkirim."}
            }), 400

        receiver_key_b64 = request.form['key']
        stego_image_file = request.files['image']

        # --- Buka kemasan kunci universal ---
        receiver_key_str = base64.b64decode(receiver_key_b64).decode('utf-8')
        keys = json.loads(receiver_key_str)
        
        rsa_private_key = RSA.import_key(keys['rsa_private_pem'])
        p, q, g, y = keys['p'], keys['q'], keys['g'], keys['y']
        
        # --- Ekstrak data dari gambar yang di-upload ---
        stego_image = Image.open(stego_image_file.stream)
        extracted_data = crypto.lsb_decode_image(stego_image, keys['data_length'])
        if not extracted_data:
            raise ValueError("Gagal mengekstrak data dari gambar. Gambar mungkin bukan gambar stego yang benar.")
        
        # --- Parsing paket data ---
        cursor = 0
        num_blocks_read = int.from_bytes(extracted_data[cursor:cursor+1], 'big'); cursor += 1
        
        encrypted_key_blocks = []
        for _ in range(num_blocks_read):
            block = int.from_bytes(extracted_data[cursor:cursor+keys['n_bytes_len']], 'big')
            encrypted_key_blocks.append(block)
            cursor += keys['n_bytes_len']
        
        fingerprint_received = int.from_bytes(extracted_data[cursor:cursor+2], 'big'); cursor += 2
        len_ciphertext = int.from_bytes(extracted_data[cursor:cursor+2], 'big'); cursor += 2
        ciphertext_aes = extracted_data[cursor:cursor+len_ciphertext]; cursor += len_ciphertext
        
        e = int.from_bytes(extracted_data[cursor:cursor+keys['q_bytes_len']], 'big'); cursor += keys['q_bytes_len']
        s = int.from_bytes(extracted_data[cursor:cursor+keys['q_bytes_len']], 'big')
        signature = (e, s)

        # --- Proses Dekripsi dan Verifikasi ---
        aes_key = crypto.rsa_decrypt_with_padding(rsa_private_key, encrypted_key_blocks)
        decrypted_message = crypto.aes_decrypt(ciphertext_aes, aes_key)
        
        fingerprint_calculated = crypto.generate_message_fingerprint(decrypted_message)
        is_fingerprint_valid = (fingerprint_received == fingerprint_calculated)
        is_signature_valid = crypto.schnorr_verify(p, q, g, y, decrypted_message, signature)
        
        # --- Siapkan ringkasan hasil untuk UI ---
        summary_text = "Status tidak diketahui"
        if is_fingerprint_valid and is_signature_valid:
            summary_text = "Pesan ASLI dan TERJAGA. Verifikasi sidik jari dan tanda tangan digital BERHASIL."
        elif not is_fingerprint_valid and not is_signature_valid:
            summary_text = "Pesan PALSU. Verifikasi sidik jari dan tanda tangan digital GAGAL."
        elif not is_fingerprint_valid:
            summary_text = "INTEGRITAS PESAN GAGAL. Pesan mungkin telah diubah. Verifikasi sidik jari GAGAL."
        else:
            summary_text = "AUTENTIKASI PENGIRIM GAGAL. Verifikasi tanda tangan digital GAGAL."
        
        # Konversi gambar yang diupload ke data URL untuk ditampilkan kembali
        stego_image_file.seek(0)
        img_b64 = base64.b64encode(stego_image_file.read()).decode('utf-8')
        data_url = f"data:image/png;base64,{img_b64}"

        return jsonify({
            "success": True,
            "verification": {
                "summary": summary_text,
                "signature": {"isValid": is_signature_valid, "statusText": "VALID" if is_signature_valid else "TIDAK VALID"},
                "fingerprint": {
                    "isValid": is_fingerprint_valid, "statusText": "COCOK" if is_fingerprint_valid else "TIDAK COCOK",
                    "received": f"{fingerprint_received:04x}", "calculated": f"{fingerprint_calculated:04x}"
                }
            },
            "data": { "decryptedMessage": decrypted_message, "decryptedAesKey": aes_key.decode('utf-8', 'ignore')},
            "stegoImage": { "dataURL": data_url } 
        })

    except Exception as e:
        error_details = traceback.format_exc()
        print(f"Error di /api/decrypt: {e}\n{error_details}")
        return jsonify({
            "success": False, "error": { "code": 500, "message": "Proses dekripsi gagal. Pastikan kunci dan gambar stego benar.", "details": str(e) }
        }), 500

if __name__ == '__main__':
    print("🚀 Server Flask (UI/UX Focused) telah dimulai...")
    app.run(host='127.0.0.1', port=5000, debug=True)
