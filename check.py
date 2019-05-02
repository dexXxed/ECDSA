# Скрипт для проверки Цифровой подписи
from ecdsa import *

inp = str(input("Введіть ваше повідомлення "))

msg = bytes(inp, encoding="utf-8")

if len(msg) == 0:
    print("Ви нічого не ввели!")
else:
    print("Ваше повідомлення: {}".format(msg.decode("utf-8")))
    inp = str(input("Введіть публічний ключ, вводячи 2 числа через кому ")).split(", ")
    inp_signature = str(input("Введіть сам електронний підпис, вводячи 2 числа через кому ")).split(", ")
    if len(inp) <= 1 or len(inp_signature) <= 1:
        print("Некоректне введення")
        exit()
    else:
        keys = [int(i, 16) for i in inp]
        keys = tuple(keys)
        signature = [int(i, 16) for i in inp_signature]
        signature = tuple(signature)
        print(verify_signature(keys, msg, inp_signature))
