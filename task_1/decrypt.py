
key_line = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя;маньбъящоукфычцхплэюжвйитдршёсгез"

original, _, encrypted_alph = key_line.partition(';')
original = original.strip()
encrypted_alph = encrypted_alph.strip()

if len(original) != len(encrypted_alph):
    print("Ошибка в ключе: разная длина алфавитов!")
    exit(1)

trans_dict = str.maketrans(encrypted_alph, original)

try:
    with open('encrypted.txt', 'r', encoding='utf-8') as f:
        encrypted_text = f.read()
except FileNotFoundError:
    print("Файл encrypted.txt не найден")
    exit(1)

decrypted = encrypted_text.translate(trans_dict)

with open('decrypted_1.txt', 'w', encoding='utf-8') as f:
    f.write(decrypted)

print("Расшифрованный текст сохранён в файл: decrypted_1.txt")
print(decrypted)