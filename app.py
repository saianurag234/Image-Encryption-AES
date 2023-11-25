from fastapi import FastAPI, UploadFile, HTTPException, Depends, Request, Form
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.responses import RedirectResponse, FileResponse
from fastapi.responses import JSONResponse
from user_encrypter import alice_encrypts
from user_decrypter import alice_decrypts
from encrypt import AES_encryption
from decrypt import AES_decryption
from RSA.prime_generator import *
from RSA.rsa_utils import *
from RSA.rsa import *
from RSA.rsa_constant import e, KEY_SIZE
from RSA.encrypt import *
from RSA.decrypt import *
from RSA.rsa_signature import *
from ECC.curve import *
from key_generator import KeyGenerator

import numpy as np
import cv2
from pathlib import Path
from dataclasses import dataclass
import uuid
import pickle
import uvicorn

app = FastAPI()


def generate_keys_ecc():
    curve = Secp521r1()
    alice = Curve(curve)
    bob = Curve(curve)

    alice.get_prikey()
    bob.get_prikey()

    alice.get_pubkey()
    bob.get_pubkey()

    return alice, bob


def generate_keys_rsa():
    p = generate_prime(KEY_SIZE)
    q = generate_prime(KEY_SIZE)

    n = get_n_value(p, q)

    phi = euler_phi(p, q)

    d = get_d_val(e=e, phi=phi)

    public_keys = public_key(e, n)

    private_keys = private_key(d, n)

    return public_keys, private_keys


@dataclass
class send_encrypted_data_ecc:
    ciphertext: bytes
    tag: str
    signature: tuple
    metadata: dataclass
    encrypted_image: np.array
    encryption_scheme: str


@dataclass
class send_encrypted_data_rsa:
    ciphertext: bytes
    key_hash: str
    signature: tuple
    metadata: dataclass
    encrypted_image: np.array
    encryption_scheme: str


download_counts = {}  # Dictionary to keep track of download counts
MAX_DOWNLOADS = 5     # Set the maximum number of allowed downloads

alice, bob = generate_keys_ecc()
public_keys, private_keys = generate_keys_rsa()


@app.get("/")
def index():
    return RedirectResponse(url="/docs")


@app.post("/encrypt/")
async def encrypt_image(image: UploadFile, Public_Encryption_Scheme: str = Form(...)):
    if not (image.filename.endswith(".jpg") or image.filename.endswith(".png") or image.filename.endswith(".jpeg")):
        return {"error": "The uploaded file should be in .jpg, .png, or .jpeg format"}

    image_data = image.file.read()
    image_np_array = np.frombuffer(image_data, np.uint8)
    image = cv2.imdecode(image_np_array, -1)

    masterkey_generator = KeyGenerator()
    key = masterkey_generator.generate_key()
    master_key = np.frombuffer(key, dtype=np.uint8)
    encrypt_master_key = list(master_key)

    master_key = master_key.reshape((4, 8))

    aes_cipher = AES_encryption(image, master_key)
    encrypted_image, metadata = aes_cipher.aes_encryption()

    if Public_Encryption_Scheme.lower() == "ecc":
        ciphertext, tag, signature = alice_encrypts(
            encrypt_master_key, alice, bob)

        encrypted_data = send_encrypted_data_ecc(
            ciphertext, tag, signature, metadata, encrypted_image, Public_Encryption_Scheme.lower())

    if Public_Encryption_Scheme.lower() == "rsa":
        encrypted_list = rsa_encryption(encrypt_master_key, public_keys)
        sign, key_hash = generate_signature(encrypt_master_key, private_keys)
        encrypted_data = send_encrypted_data_rsa(
            encrypted_list, key_hash, sign, metadata, encrypted_image, Public_Encryption_Scheme.lower())

    uid = str(uuid.uuid4())
    filename = f"{uid}.pkl"
    download_counts[uid] = 0

    with open(filename, "wb") as f:
        pickle.dump(encrypted_data, f)

    output_path = f"{uid}.jpg"
    cv2.imwrite(output_path, encrypted_image)

    return {"uid": uid,
            "message": "File generated successfully!"
            # "encrypted_image": FileResponse(output_path, media_type="image/jpeg", filename="encrypted_image.jpg")
            }


@app.get("/decrypt/{encrypted_uid}")
async def download_file(uid: str):

    if uid not in download_counts:
        raise HTTPException(
            status_code=404, detail="File not found or download limit reached")

    if download_counts[uid] >= MAX_DOWNLOADS:
        raise HTTPException(
            status_code=403, detail="Download limit reached for this file")

    file_path = Path(f"{uid}.pkl")

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    with file_path.open("rb") as f:
        pickled_object = pickle.load(f)

    download_counts[uid] += 1

    if download_counts[uid] >= MAX_DOWNLOADS:
        file_path.unlink()
        del download_counts[uid]

    if pickled_object.encryption_scheme == "ecc":

        master_key, verify_tag, verify_sign, recovered_a_pubk = alice_decrypts(
            ciphertext=pickled_object.ciphertext,
            tag=pickled_object.tag,
            signature=pickled_object.signature,
            alice=alice,
            bob=bob
        )

        if not verify_tag and verify_sign:
            raise HTTPException(
                status_code=400, detail="The Signature is Corrupted")

    if pickled_object.encryption_scheme == "rsa":
        verify = is_signature_valid(
            pickled_object.key_hash, pickled_object.signature, public_keys)
        if verify:
            master_key = rsa_decryption(
                pickled_object.ciphertext, private_keys)

    master_key = np.array(master_key).reshape((4, 8))

    aes_final = AES_decryption(
        pickled_object.encrypted_image, master_key, pickled_object.metadata)
    decrypt = aes_final.aes_decryption()

    output_path = "decrypted_image.jpg"
    cv2.imwrite(output_path, decrypt)
    return FileResponse(output_path, media_type="image/jpeg", filename="decrypted_image.jpg")


@app.exception_handler(ConnectionResetError)
async def handle_connection_reset_error(request: Request, exc: ConnectionResetError):
    return {"detail": "Connection was reset. Please try again."}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)
