from ecdsa import *

print('Використана еліптична крива: {}'.format(curve.name))

private, public = make_keypair()
print("Приватний ключ:", hex(private))
print("Публічний: (0x{:x}, 0x{:x})".format(*public))

msg = b'Hello!'
signature = sign_message(private, msg)

print('\nПовідомлення:', msg)
print('Підпис: (0x{:x}, 0x{:x})'.format(*signature))
print('Перевірка:', verify_signature(public, msg, signature))

msg = b'H!'
print('\nПовідомлення:', msg)
print('Перевірка:', verify_signature(public, msg, signature))

private, public = make_keypair()

msg = b'Hello!'
print('\nПовідомлення:', msg)
print("Публічний ключ: (0x{:x}, 0x{:x})".format(*public))
print('Перевірка:', verify_signature(public, msg, signature))
