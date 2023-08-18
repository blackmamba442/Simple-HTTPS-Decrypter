import pyshark
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key_path = ''
pcap_file = ''

def decrypt_traffic(packet):
    if 'tls' in packet:
        tls_payload = packet['tls'].payload
        key = open(key_path, 'rb').read()
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(bytes.fromhex(tls_payload[:32])), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_payload = decryptor.update(bytes.fromhex(tls_payload[32:])) + decryptor.finalize()
        packet['tls'].payload = decrypted_payload.hex()

capture = pyshark.LiveCapture(interface='eth0', display_filter='ssl')

with open(pcap_file, 'wb') as pcap:
    pcap.write(pyshark.pcap.global_header())
