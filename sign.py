# Скрипт для создания цифровой подписи
from ecdsa import *

print("Крива: {}".format(curve.name))

inp = str(input("Введіть ваше повідомлення "))

msg = bytes(inp, encoding='utf-8')


if len(msg) == 0:
    print("Ви нічого не ввели!")
else:
    private, public = make_keypair()
    print("Приватний ключ (необхідно знати тільки Вам для підпису повідомлення):", hex(private))
    print("Публічний: (0x{:x}, 0x{:x})".format(*public))

    signature = sign_message(private, msg)

    print('\nПовідомлення:', msg.decode('utf-8'))
    print('Підпис: (0x{:x}, 0x{:x})'.format(*signature))
