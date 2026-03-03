import os
from collections import Counter

raw_ciphertext = """=J3-dJxMLJtGIQ
dMRGJ!Mt3IBP-MItGP$Pd3ndP-GtFMQ-=-B-$KM=PC=->-$$USML-xtGdnxMtMJQ=-L-3-$$U!nMn$YJ=!PVnJ$$U!nM=-tI=tP!nMAMAJGJ=U!MQJ3IBP-GMLJtGIQMQJ3KCJdPG-3KMn3nMO=IQQPMQJ3KCJdPG-3-x
Q=nMGPAJ!MQJLSJL-MCPMJt$JdIM9-=-GtFMLJ3h$JtGKMQJ3KCJdPG-3FMn3nM-OJMQ=n$PL3-h$JtGKMAMJQ=-L-3-$$J!IMQJL=PCL-3-$n8
$PQ=n!-=M9ISOP3G-=M9IL-GMn!-GKMLJtGIQMAMYn$P$tJdJxMnMAPL=JdJxMn$YJ=!PVnnMt!Jh-GMt!JG=-GKMnMnC!-$FGKM-E
=P9JG$nAMQ=JnCdJLtGd-$$JOJMJGL-3PM9IL-GMn!-GKMLJtGIQMAMG-S$nB-tAJxMnMn$h-$-=$JxMn$YJ=!PVnnMQ=JdJLnGKMJQ=-L-3-$$U-ML-xtGdnFMtM$n!n
!P$LPG$UxMLJtGIQ
dMRGJ!Mt3IBP-MItGP$Pd3ndP-GtFMO=PLPVnFMn$YJ=!PVnnM$PMI=Jd$nMtJO3Pt$JMAJ$YnL-$VnP3K$JtGnMV-$$JtGnMLP$$US
tJJGd-GtGd-$$JMBGJ9UMQJ3IBnGKMLJtGIQMAMGJ!IMn3nMn$J!IMI=Jd$8MLJtGIQPM$Ih$JMJ93PLPGKMQJLSJLFZn!ML3FMRGJOJMtGPGItJ!MAJGJ=UxMItGP$Pd3ndP-GtFMdMtntG-!-
GPAPFM!JL-3KMPdGJ=nCPVnnM$Pn9J3--MSP=PAG-=$PML3FMOJtIB=-hL-$nxM=P9JGP8ZnSMtMOJtILP=tGd-$$JxMGPx$JxMnML=IOn!nMdnLP!nMAJ$YnL-$VnP3K$JxMn$YJ=!PVnn
--MQ=n$VnQnP3K$U!MJG3nBn-!MJGML=IOnSM!JL-3-xMFd3F-GtFMGJGMYPAGMBGJMQJ3KCJdPG-3KM$-M!Jh-GM$nAPAMnC!-$nGKMCPLP$$UxMI=Jd-$KMLJtGIQ$JtGnMn$YJ=!PVnn"""

ciphertext = raw_ciphertext.upper()
clean = ciphertext.replace('\n', '')
freq = Counter(clean)
most_common_char = freq.most_common(1)[0][0]
mapping = {most_common_char: ' '}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_decoded_and_freq():
    decoded = ''.join(mapping.get(c, c) for c in ciphertext)
    
    clear_screen()
    print("Текущий расшифрованный текст:\n")
    print("-" * 100)
    print(decoded)
    print("-" * 100)
    print("\nЧастота символов и текущие замены:\n")
    
    total = len(clean)
    for char, count in freq.most_common():
        percent = count / total * 100
        repl = mapping.get(char, '?')
        print(f" {char:3} {count:4} {percent:5.1f}% → {repl}")
    
    print(f"\nВсего символов: {total}\n")

def save_results():
    decoded = ''.join(mapping.get(c, c) for c in ciphertext)

    with open("decoded.txt", "w", encoding="utf-8") as f:
        f.write(decoded)

    with open("key.txt", "w", encoding="utf-8") as f:
        f.write("Таблица замен (шифр → открытый текст):\n")
        f.write("-" * 40 + "\n")
        for cipher_char in sorted(mapping):
            plain = mapping[cipher_char]
            f.write(f"{cipher_char:3} → {plain}\n")
        f.write("\n")

    with open("frequency.txt", "w", encoding="utf-8") as f:
        f.write("Символ | Кол-во | Процент\n")
        f.write("-" * 35 + "\n")
        total = len(clean)
        for char, count in freq.most_common():
            percent = count / total * 100
            f.write(f"{char:6} | {count:6} | {percent:6.2f}%\n")
        f.write(f"\nВсего символов: {total}\n")
    
    print("\nСохранено в файлы:")
    print("  decoded.txt     — расшифрованный текст")
    print("  key.txt         — ключ")
    print("  frequency.txt   — частоты символов шифрованного текста\n")

def show_help():
    print("\nКоманды:")
    print("  J о       — заменить J → о")
    print("  3 .       — убрать замену (показывать символ как есть)")
    print("  clear     — обновить экран")
    print("  exit / q  — выход + сохранение всех файлов")
    print()

def main():
    show_decoded_and_freq()
    show_help()

    while True:
        try:
            cmd = input("→ ").strip()

            if cmd.lower() in ('q'):
                save_results()
                clear_screen()
                print("Результаты сохранены в decoded.txt, key.txt и frequency.txt")
                break

            if cmd.lower() == 'clear':
                show_decoded_and_freq()
                continue

            parts = cmd.split(maxsplit=1)
            if len(parts) != 2:
                print("символ → замена ")

                show_decoded_and_freq()
                continue

            sym, repl = parts
            if len(sym) != 1:
                print("Символ должен быть один")
                show_decoded_and_freq()
                continue

            if repl in ('.', 'как есть', 'оригинал', 'удалить', '-'):
                mapping.pop(sym, None)
            else:
                mapping[sym] = repl

            show_decoded_and_freq()

        except KeyboardInterrupt:
            print("\nCtrl+C → сохранение и выход")
            save_results()
            clear_screen()
            print("Результаты сохранены.")
            break

if __name__ == '__main__':
    main()