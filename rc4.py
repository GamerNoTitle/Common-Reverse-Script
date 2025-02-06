import sys
import argparse
import ast

# RC4 解密脚本

# 初始化向量，默认为填充0~255
def init_vector():
    return [i for i in range(256)]

# 生成密钥流
def generate_key_stream(S, length):
    i = 0
    j = 0
    key_stream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        key_stream.append(S[t])
    return key_stream

# 解密函数
def rc4_decrypt(ciphertext, key, rounds=256, xor_value=0, vector=None):
    if vector is None:
        vector = init_vector()

    # 初始化 S 盒
    S = list(range(256))
    T = []
    for i in range(256):
        T.append(ord(key[i % len(key)]))

    j = 0
    for i in range(rounds):
        j = (j + S[i] + T[i]) % 256
        S[i], S[j] = S[j], S[i]

    # 生成密钥流
    key_stream = generate_key_stream(S, len(ciphertext))

    # 解密
    plaintext = []
    for i in range(len(ciphertext)):
        decrypted_byte = ciphertext[i] ^ key_stream[i] ^ xor_value
        plaintext.append(decrypted_byte)

    return bytes(plaintext)

description = r"""+=======================================================================+
|                                                                       |
|  ____   ____ _  _      ___                       _           _     _  |
| |  _ \ / ___| || |    / _ \ _ __   ___       ___| |__   ___ | |_  | | |
| | |_) | |   | || |_  | | | | '_ \ / _ \_____/ __| '_ \ / _ \| __| | | |
| |  _ <| |___|__   _| | |_| | | | |  __/_____\__ \ | | | (_) | |_  |_| |
| |_| \_\\____|  |_|    \___/|_| |_|\___|     |___/_| |_|\___/ \__| (_) |
|                                                                       |
|                                                   -- GamerNoTitle     |
+=======================================================================+

如果你在逆向的时候看到了很多的 256 轮加密，则此加密很可能是 RC4 加密，你可以尝试使用本程序进行解密。
若你不确定如何开始，你可以尝试运行一下命令：
$ python rc4.py GamerNoTitle 4c3e191cde4b84d78d7211f1800e
这里的 `GamerNoTitle` 是密钥，`4c3e191cde4b84d78d7211f1800e` 是密文，你可以尝试解密一下。
"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('key', help='RC4 加密的密钥')
    parser.add_argument('ciphertext', help='RC4 加密后的密文，格式应该为 \\x00\\x01... 或者 000102...')
    parser.add_argument('--rounds', type=int, default=256, help='RC4 轮次（默认为 256）')
    parser.add_argument('--xor', type=int, default=0, help='最终异或值（默认为 0，即不进行异或）')
    parser.add_argument('--vector', type=str, default=None, help='手动初始化向量，应该为 [0,1,2,...,255] 或者 0~255 的格式')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    
    key = args.key
    # 将转义字符转换成对应的字节
    if args.ciphertext.startswith('\\x'):
        ciphertext = args.ciphertext.encode('latin-1').decode('unicode_escape').encode('latin-1')
    else:
        ciphertext = bytes.fromhex(args.ciphertext)
    rounds = args.rounds
    xor_value = args.xor
    vector = None
    if args.vector:
        try:
            if '~' in args.vector:
                start, end = map(int, args.vector.split('~'))
                vector = list(range(start, end + 1))
            else:
                vector = ast.literal_eval(args.vector)
        except (ValueError, SyntaxError):
            print("非法的向量格式！正确格式应该为 [0,1,2,...,255] 或者 0~255")
            sys.exit(1)

    decrypted_data = rc4_decrypt(ciphertext, key, rounds, xor_value, vector)
    print("解密后的内容为: ", decrypted_data.decode())