import random
import string

RUSSIAN = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
ALLOWED = ' .,!?—:;«»()'

try:
    with open('Wolf.txt', 'r', encoding='utf-8') as f:
        text = f.read().lower()
except FileNotFoundError:
    print("Файл Wolf.txt не найден")
    exit(1)

letters = list(RUSSIAN)
random.shuffle(letters)
cipher_alphabet = ''.join(letters)

trans_dict = str.maketrans(RUSSIAN, cipher_alphabet)

encrypted = text.translate(trans_dict)

key = RUSSIAN + ' → ' + cipher_alphabet
print("Ключ шифрования:")
print(key)

with open('cipher_key.txt', 'w', encoding='utf-8') as f:
    f.write(key)

print("Ключ сохранён в файл: cipher_key.txt")

with open('encrypted.txt', 'w', encoding='utf-8') as f:
    f.write(encrypted)

print("Зашифрованный текст сохранён в файл: encrypted.txt")
print(encrypted)