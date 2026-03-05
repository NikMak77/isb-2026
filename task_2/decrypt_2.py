import os
from collections import Counter

INPUT_CIPHER_FILE = "cod16.txt"
OUTPUT_DECODED = "decoded.txt"
OUTPUT_KEY = "key.txt"
OUTPUT_FREQ = "frequency.txt"


def read_ciphertext(file_path: str) -> str:
    """
    Читает шифротекст из указанного файла.
    
    Args:
        file_path: путь к файлу с зашифрованным текстом
        
    Returns:
        строка с содержимым файла
        
    Raises:
        FileNotFoundError, если файл не найден
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Файл шифротекста не найден: {file_path}")
    
    with open(file_path, encoding="utf-8") as f:
        return f.read()


def prepare_ciphertext(raw_text: str) -> str:
    """
    Подготавливает шифротекст: приводит к верхнему регистру и убирает переносы строк.
    """
    return raw_text.upper().replace('\n', ' ')


def count_symbol_frequencies(text: str) -> Counter:
    """
    Подсчитывает частоту появления каждого символа в тексте.
    """
    return Counter(text)


def create_initial_mapping(freq_counter: Counter) -> dict:
    """
    Создаёт начальное отображение, предполагая, что самый частый символ — это пробел.
    """
    if not freq_counter:
        return {}
    most_common = freq_counter.most_common(1)[0][0]
    return {most_common: ' '}


def apply_mapping(cipher_text: str, mapping: dict) -> str:
    """
    Применяет текущую таблицу замен к шифротексту.
    """
    return ''.join(mapping.get(c, c) for c in cipher_text)


def clear_screen() -> None:
    """Очищает консоль """
    os.system('cls' if os.name == 'nt' else 'clear')


def display_progress(cipher_text: str, mapping: dict, freq: Counter) -> None:
    """
    Выводит текущий расшифрованный текст и статистику частот с заменами.
    """
    clear_screen()
    decoded = apply_mapping(cipher_text, mapping)
    
    print("Текущий расшифрованный текст:\n")
    print("-" * 100)
    print(decoded)
    print("-" * 100)
    print("\nЧастота символов и текущие замены:\n")
    
    total = len(cipher_text)
    for char, count in freq.most_common(33):
        percent = count / total * 100
        replacement = mapping.get(char, '?')
        print(f" {char:3} {count:5} {percent:5.1f}% → {replacement}")
    
    print(f"\nВсего символов: {total}\n |  Известно замен: {len(mapping)}")


def print_help() -> None:
    """Выводит справку по доступным командам."""
    print("\nКоманды:")
    print("  J о       — заменить J → о")
    print("  3 .       — убрать замену (оставить символ как есть)")
    print("  clear     — обновить экран")
    print("  help      — показать эту справку")
    print("  q         — выход + сохранение всех файлов")
    print()


def save_results(cipher_text: str, mapping: dict, freq: Counter) -> None:
    """
    Сохраняет результаты расшифровки в три файла.
    """
    decoded = apply_mapping(cipher_text, mapping)

    with open(OUTPUT_DECODED, "w", encoding="utf-8") as f:
        f.write(decoded)

    with open(OUTPUT_KEY, "w", encoding="utf-8") as f:
        f.write("Таблица замен (шифр → открытый текст):\n")
        f.write("-" * 40 + "\n")
        for cipher_char in sorted(mapping):
            plain = mapping[cipher_char]
            f.write(f"{cipher_char:3} → {plain}\n")
        f.write("\n")

    with open(OUTPUT_FREQ, "w", encoding="utf-8") as f:
        f.write("Символ | Кол-во | Процент\n")
        f.write("-" * 35 + "\n")
        total = len(cipher_text)
        for char, count in freq.most_common():
            percent = count / total * 100
            f.write(f"{char:6} | {count:6} | {percent:6.2f}%\n")
        f.write(f"\nВсего символов: {total}\n")

    print("\nСохранено в файлы:")
    print(f"  {OUTPUT_DECODED:<15} — расшифрованный текст")
    print(f"  {OUTPUT_KEY:<15} — таблица замен")
    print(f"  {OUTPUT_FREQ:<15} — частотный анализ\n")


def main() -> None:
    """Основная функция — интерактивная расшифровка методом подстановки."""
    print("Интерактивная расшифровка текста (частотный анализ + ручные замены)\n")
    print(f"Читаем шифротекст из файла: {INPUT_CIPHER_FILE}\n")

    try:
        raw_cipher = read_ciphertext(INPUT_CIPHER_FILE)
        clean_cipher = prepare_ciphertext(raw_cipher)
        frequencies = count_symbol_frequencies(clean_cipher)
        current_mapping = create_initial_mapping(frequencies)

        display_progress(clean_cipher, current_mapping, frequencies)
        print_help()

        while True:
            command = input(" ").strip()

            if command.lower() in ('q'):
                save_results(clean_cipher, current_mapping, frequencies)
                clear_screen()
                print("Результаты сохранены. До свидания.")
                break

            if command.lower() == 'clear':
                display_progress(clean_cipher, current_mapping, frequencies)
                continue

            if command.lower() in ('help'):
                print_help()
                continue

            parts = command.split(maxsplit=1)
            if len(parts) != 2:
                print("Формат: <символ> <замена>    пример:  J о")
                continue

            cipher_sym, replacement = parts
            if len(cipher_sym) != 1:
                print("Левый аргумент должен быть одним символом")
                continue

            if replacement in ('.', 'как есть', 'оригинал', '-', 'удалить', 'убрать'):
                current_mapping.pop(cipher_sym, None)
            else:
                current_mapping[cipher_sym] = replacement

            display_progress(clean_cipher, current_mapping, frequencies)

    except FileNotFoundError as e:
        print(e)
    except KeyboardInterrupt:
        print("\nCtrl+C → сохранение и выход")
        save_results(clean_cipher, current_mapping, frequencies)
    except Exception as e:
        print(f"Произошла ошибка: {e}")


if __name__ == '__main__':
    main()