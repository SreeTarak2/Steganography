import io
import numpy as np
import wave
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from pydub import AudioSegment


def convert_to_wave(filename):
    # """Convert the input audio file (e.g., mp3) to WAV format.""" 
    try:
        sound = AudioSegment.from_file(filename)  # Supports multiple formats
        wave_data = io.BytesIO()
        sound.export(wave_data, format='wav')
        return wave_data.getvalue()
    except Exception as e:
        print(f"Error converting {filename} to WAV: {e}")
        return None

def generate_key(password, salt):
    return PBKDF2(password.encode(), salt, dkLen=32, count=1000000)

def read_file_as_bytes(filename):
    # """Reads any file as bytes."""
    with open(filename, 'rb') as file:
        file_data = file.read()
    return file_data

def encrypt_compress(data, key):
    # """Encrypt and compress the data."""
    compressed_data = zlib.compress(data)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(compressed_data, AES.block_size))
    return encrypted_data, iv

def decrypt_decompress(encrypted_data, key, iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        decompressed_data = zlib.decompress(decrypted_data)
        return decompressed_data
    except Exception as e:
        print("Incorrect password")
        print(f'Decryption failed: exiting.....')
        print(f'Error : {e}')
        return None
def download_hiddenFile(message, ext):
    file_extension = "hidden_file." + ext
    with open(file_extension, 'wb') as f:
        f.write(message)
    print(f"Hidden file saved at: {file_extension}")


def embed_bits(samples, bits):
    # """Embed a bit into the least significant bit (LSB) of a sample."""
    samples = int(samples)
    if bits == 0:
        return samples & ~1
    else:
        return samples | 1

def embed_audio_data(filename, file_to_embed, outputfile='stego.wav', key=None):
    # """Embed any file into an audio file."""
    # Convert the input audio to WAV format (if not already in WAV)
    wav_data = convert_to_wave(filename)
    if not wav_data:
        print("Error: Could not convert the file to WAV format.")
        return None
    
    audio_data = io.BytesIO(wav_data)
    with wave.open(audio_data, 'rb') as audio:
        params = audio.getparams()
        frames = audio.readframes(audio.getnframes())
    
    audio_samples = np.frombuffer(frames, dtype=np.int16)
    
    # Read the file to be hidden as bytes
    file_data = read_file_as_bytes(file_to_embed)
    if not file_data:
        print(f"Error: Could not read the file {file_to_embed}.")
        return None
    
    # Encrypt and compress the file data to embed
    encrypted_data, iv = encrypt_compress(file_data, key)
    encrypted_data += b"$END" + iv
    message_bits = ''.join(format(byte, '08b') for byte in encrypted_data)
    
    # Ensure there is enough space in the audio file to embed the message
    if len(message_bits) > len(audio_samples):
        print(f"Error: The audio file is too small to hide the message. Required space: {len(message_bits)} bits, available space: {len(audio_samples)} bits.")
        return None
    
    # Embed the bits into the audio file
    modified_audio_samples = audio_samples.copy()
    for i in range(len(modified_audio_samples)):
        if i < len(message_bits):
            modified_audio_samples[i] = embed_bits(modified_audio_samples[i], int(message_bits[i]))

    modified_data = modified_audio_samples.tobytes()

    # Save the new stego file
    with wave.open(outputfile, 'wb') as output:
        output.setparams(params)
        output.writeframes(modified_data)
    
    print(f"Stego file saved at: {outputfile}")
    return outputfile
def extract_audio_from_stego(stego_audio_file, key):
    """Extract the hidden file from the stego audio file."""
    try:
        with wave.open(stego_audio_file, 'rb') as audio:
            frames = audio.readframes(audio.getnframes())
        
        audio_samples = np.frombuffer(frames, dtype=np.int16)
        
        # Extract bits from audio samples (LSB extraction)
        msg_bits = [audio_samples[i] & 1 for i in range(len(audio_samples))]
        msg_bytes = []
        
        # Convert extracted bits into bytes
        for i in range(0, len(msg_bits), 8):
            byte = msg_bits[i:i + 8]
            if len(byte) == 8:
                msg_bytes.append(int(''.join(map(str, byte)), 2))
        
        msg_bytes = bytes(msg_bytes)
        
        # Split the message at the '$END' marker and get the IV
        msg, _, iv_msg = msg_bytes.partition(b'$END')
        
        # Check if IV is correct size (16 bytes)
        iv = iv_msg[:16]  # Ensure IV is exactly 16 bytes
        
        if len(iv) != 16:
            print(f"Error: IV is not 16 bytes. IV length is {len(iv)} bytes.")
            return None
        
        # Decrypt and decompress the message
        hidden_file_data = decrypt_decompress(msg, key, iv)
        return hidden_file_data
    except Exception as e:
        print(f"Exception during decryption: {e}")
        return None
def main():
    salt = get_random_bytes(16)
    while True:
        print("\nChoose an option:")
        print("1. Embed data into audio")
        print("2. Extract data from audio")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == '1':
            filename = input("Enter the audio file path: ")
            file_to_embed = input("Enter the file path to embed (can be .txt, .py, .mp3 etc.): ")
            extfilename = file_to_embed.split('\\')[-1]
            extension = extfilename.split('.')[-1]
            outputfile = input("Enter the output stego audio file (default: stego.wav): ") or 'stego.wav'
            password = input("Enter the password : ")
            key = generate_key(password, salt)
            print(f'Salt is: {salt.hex()}')
            embed_audio_data(filename, file_to_embed, outputfile, key)
        
        elif choice == '2':
            stego_audio_file = input("Enter the stego audio file path: ")
            salt = input("Enter the salt key: ")
            saltUser = bytes.fromhex(salt)
            password = input("Enter the password : ")
            key = generate_key(password, saltUser)
            message = extract_audio_from_stego(stego_audio_file, key)
            if message:
                    try:
                        print('\n----------------------------------------------------------------')
                        print('Message hidden in the audio file : \n')
                        print(f"Extracted message: \n{message.decode()}")
                        # newfile = "hiddenfile."+extension
                        download_hiddenFile(message, extension)
                    except UnicodeDecodeError:
                        print("Extracted data is not text. Saving as binary file...")
                        download_hiddenFile(message, extension)

        elif choice == '3':
            exit()

if __name__ == '__main__':
    main()
