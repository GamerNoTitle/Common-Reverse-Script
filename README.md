# Common-Reverse-Script

因为在学习逆向补基础，所以顺带就写了用于解密的脚本，文件名对应了算法的名字

## 清单

- RC4

## 用法

### rc4

#### 调用基本格式

```bash
$ python rc4.py [-h] [--rounds ROUNDS] [--xor XOR] [--vector VECTOR] key ciphertext
```

#### 参数说明

| 参数名     | 说明                                                         | 默认值 | 必须 |
| ---------- | ------------------------------------------------------------ | ------ | ---- |
| key        | RC4 加密用到的 key                                           | 无     | √    |
| ciphertext | RC4 加密过后的密文，可以为纯十六进制数据流，也可以为`\x`开头的数据 | 无     | √    |
| round      | 使用 `--rounds` 指定 RC4 加密的轮次数                        | 256    | ×    |
| xor        | 使用 `--xor` 指定 RC4 加密后密文异或的值（此设定是为了应对变种 RC4） | 0      | ×    |
| vector     | 使用 `--vector` 指定 RC4 加密过程的初始向量，格式应该为 [0,1,2,...,255] 或者 0~255 | 0~255  | ×    |

#### 用例

```bash
$ python rc4.py GamerNoTitle 4c3e191cde4b84d78d7211f1800e
解密后的内容为:  Hello CTFer!!!
```

