import argparse
from pydub import AudioSegment
import io
import numpy as np
import wave
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import pprint


print("""    _             _ _         ____  _                               
   / \\  _   _  __| (_) ___   / ___|| |_ ___  __ _  ___  _ __  _   _ 
  / _ \\| | | |/ _` | |/ _ \\  \\___ \\| __/ _ \\/ _` |/ _ \\| '_ \\| | | |
 / ___ \\ |_| | (_| | | (_) |  ___) | ||  __/ (_| | (_) | |_) | |_| |
/_/   \\_\\__,_|\\__,_|_|\\___/  |____/ \\__\\___|\\__, |\\___/| .__/ \\__, |
                                            |___/      |_|    |___/  """)

def convert_to_wave(filename):
    print('Audio file is converting........')
    print('****************************************************************')
    try:
        sound = AudioSegment.from_mp3(filename)
        wave_data = io.BytesIO()
        sound.export(wave_data, format='wav')
        return wave_data.getvalue()
    except Exception as e:
        print(f'Error while converting file: {filename}....-{e}')
        return None

def download_hiddenFile(data, filetype):
    with open(f'{filetype}', 'wb') as file:
        file.write(data)
    return "File is saved successfully"

def generate_key(password, salt):
    return PBKDF2(password.encode(), salt, dkLen=32, count=1000000)

def encrypt_compress(filename, key):
    try:
        with open(filename, 'rb') as f:
            file_data = f.read()
        compressed_data = zlib.compress(file_data)
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted_data = cipher.encrypt(pad(compressed_data, AES.block_size))
        return encrypted_data, cipher.iv
    except Exception as e:
        print(f'Error while encrypting and compressing file: {filename} - {e}')
        return None, None

def decrypt_decompress(encrypted_data, key, iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        decompressed_data = zlib.decompress(decrypted_data)
        return decompressed_data
    except Exception as e:
        print(f'Error while decrypting and decompressing: {e}')
        return None

def embed_bits(samples, bits):
    samples = int(samples)
    if bits == 0:
        return samples & ~1
    else:
        return samples | 1

def embed_data(filename, textfilename=None, output_path='stego.wav', key=None):
    wav_data = convert_to_wave(filename)

    audio_data = io.BytesIO(wav_data)
    with wave.open(audio_data, 'rb') as audio:
        params = audio.getparams()
        frames = audio.readframes(audio.getnframes())
    audio_samples = np.frombuffer(frames, dtype=np.int16)

    encrypted_data, iv = encrypt_compress(textfilename, key)

    if encrypted_data is None:
        print("No data to embed.")
        return None, None

    encrypted_data += b'$END'
    message_bits = ''.join(format(byte, '08b') for byte in encrypted_data)

    modify_audio_samples = audio_samples.copy()

    for i in range(len(modify_audio_samples)):
        if i < len(message_bits):
            modify_audio_samples[i] = embed_bits(modify_audio_samples[i], int(message_bits[i]))

    modified_data = modify_audio_samples.tobytes()

    with wave.open(output_path, 'wb') as output:
        output.setparams(params)
        output.writeframes(modified_data)
    return output_path, iv

def decrypt_from_audio(outputfile, key, iv):
    try:
        with wave.open(outputfile, 'rb') as audio:
            frames = audio.readframes(audio.getnframes())

        audio_samples = np.frombuffer(frames, dtype=np.int16)
        msg_bits = [audio_samples[i] & 1 for i in range(len(audio_samples))]
        msg_bytes = []

        for i in range(0, len(msg_bits), 8):
            byte = msg_bits[i:i + 8]
            if len(byte) == 8:
                msg_bytes.append(int(''.join(map(str, byte)), 2))

        # Convert the byte array to bytes
        msg_bytes = bytes(msg_bytes)

        # Split the message at the end marker
        msg, _, _ = msg_bytes.partition(b'$END')  # Correctly unpacking into three parts

        # Decrypt the actual message
        message = decrypt_decompress(msg, key, iv)
        return message
    except Exception as e:
        print(f"Exception during decryption: {e}")
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-e', '--encode', action='store_true', help='Encoding message into audio')
    parser.add_argument('-d', '--decode', action='store_true', help='Decoding message from audio')
    parser.add_argument('-a', '--audiofile', type=str, required=True, help='Path of the audio file')
    parser.add_argument('-o', '--outputfile', type=str, help='Specify the output file to save the encoded data')
    parser.add_argument('-m', '--text', type=str, help='Message to embed into the audio')
    parser.add_argument('-f', '--filetype', type=str, help='Path to the file (e.g., .txt, .py, .cpp) to embed')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-p', '--password', type=str, required=True, help='Password to encode and decode the hidden message')

    args = parser.parse_args()
    password = args.password
    salt = get_random_bytes(16)
    key = generate_key(password, salt)
    filetype = args.filetype
    print(f'Generating encryption key...{key.hex()}')

    if args.encode:
        if args.filetype:
            output_file, iv = embed_data(args.audiofile, textfilename=args.filetype, output_path=args.outputfile, key=key)
            if output_file:
                print(f'Audio file has been successfully embedded with the message. Output saved as {output_file}')
        else:
            print('Error: Filetype not provided. Please provide a valid filetype.')
    elif args.decode:
        print('Decoding audio file...')
        print('****************************************************************')
        message = decrypt_from_audio(args.outputfile, key, iv)
        if message:
            if args.verbose:
                pprint.pprint(f'Decoded message: \n{message.encode()}')
            else:
                print(f"Hidden file is saved .....")
                download_hiddenFile(message.encode(), filetype)

if __name__ == '__main__':
    main()
