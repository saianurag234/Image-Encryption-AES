from fastapi import FastAPI, UploadFile, HTTPException, Depends, Request
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.responses import RedirectResponse, FileResponse
from user_encrypter import alice_encrypts
from user_decrypter import alice_decrypts
from encrypt import AES_encryption
from decrypt import AES_decryption
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
def generate_keys():
    curve = Secp521r1()
    alice = Curve(curve)
    bob = Curve(curve)

    alice.get_prikey(5848086670634336295179241537947744107056560678941168314791178081878633088455617469991013034321652554105110886298371233598544051928031241656197349434021052)
    bob.get_prikey(65215690354676615037081482303758947066186667230878659726538709580154848544607330564152279281874441250878379865736772667630609470695976953483213929929888987)

    alice.get_pubkey()
    bob.get_pubkey()

    return alice,bob

@dataclass
class send_encrypted_data:
    ciphertext: bytes
    tag: str
    signature: tuple
    metadata: dataclass
    encrypted_image: np.array

download_counts = {}  # Dictionary to keep track of download counts
MAX_DOWNLOADS = 5     # Set the maximum number of allowed downloads

alice, bob = generate_keys()

@app.get("/")
def index():
    return RedirectResponse(url="/docs")

@app.post("/encrypt/")
async def encrypt_image(image: UploadFile):
    if not (image.filename.endswith(".jpg") or image.filename.endswith(".png") or image.filename.endswith(".jpeg")):
        return {"error": "The uploaded file should be in .jpg, .png, or .jpeg format"}

    image_data = image.file.read()
    image_np_array = np.frombuffer(image_data, np.uint8)
    image = cv2.imdecode(image_np_array, -1)

    masterkey_generator = KeyGenerator()
    key = masterkey_generator.generate_key()
    master_key = np.frombuffer(key, dtype=np.uint8)
    encrypt_master_key = list(master_key)

    ciphertext, tag, signature = alice_encrypts(encrypt_master_key, alice, bob)
    master_key = master_key.reshape((4, 8))

    aes_cipher = AES_encryption(image, master_key)
    encrypted_image, metadata = aes_cipher.aes_encryption()

    encrypted_data = send_encrypted_data(ciphertext, tag, signature, metadata, encrypted_image)

    uid = str(uuid.uuid4())
    filename = f"{uid}.pkl"
    download_counts[uid] = 0

    with open(filename, "wb") as f:
        pickle.dump(encrypted_data, f)

    headers = {"uid": uid, "message": "File generated successfully!"}

    output_path = "encrypted_image.jpg"
    cv2.imwrite(output_path, encrypted_image)
    
    return FileResponse(output_path, media_type="image/jpeg", filename="encrypted_image.jpg", headers=headers)

@app.get("/decrypt/{encrypted_uid}")
async def download_file(uid: str):

    if uid not in download_counts:
        raise HTTPException(status_code=404, detail="File not found or download limit reached")

    if download_counts[uid] >= MAX_DOWNLOADS:
        raise HTTPException(status_code=403, detail="Download limit reached for this file")

    file_path = Path(f"{uid}.pkl")

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    with file_path.open("rb") as f:
        pickled_object = pickle.load(f)

    download_counts[uid] += 1

    if download_counts[uid] >= MAX_DOWNLOADS:
        file_path.unlink()
        del download_counts[uid]

    master_key, verify_tag, verify_sign, recovered_a_pubk = alice_decrypts(
        ciphertext=pickled_object.ciphertext,
        tag=pickled_object.tag,
        signature=pickled_object.signature,
        alice=alice,
        bob=bob
    )

    master_key = np.array(master_key).reshape((4, 8))

    if not verify_tag and verify_sign:
        raise HTTPException(status_code=400, detail="The Signature is Corrupted")
    
    aes_final = AES_decryption(pickled_object.encrypted_image, master_key, pickled_object.metadata)
    decrypt = aes_final.aes_decryption()
    
    output_path = "decrypted_image.jpg"
    cv2.imwrite(output_path, decrypt)
    return FileResponse(output_path, media_type="image/jpeg", filename="decrypted_image.jpg")

@app.exception_handler(ConnectionResetError)
async def handle_connection_reset_error(request: Request, exc: ConnectionResetError):
    return {"detail": "Connection was reset. Please try again."}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)