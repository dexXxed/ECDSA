#!/usr/bin/env python3
# Основная логика для подписей
import collections
import hashlib
import random

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

# Выбрана кривая secp256k1 группы SECG («Standards for Efficient Cryptography Group», основанной Certicom)
# Та же самая кривая используется в Bitcoin для цифровых подписей
# Числа взяты из исходного кода OpenSSL

curve = EllipticCurve(
    'secp256k1',
    # Характеристика поля
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Коефіцієнти кривої
    a=0,
    b=7,
    # Базова точка
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Порядок підгрупи
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Кофактор підгруппи
    h=1,
)


# Модульна арифметика

def inverse_mod(k, p):
    """
        Повертає інверсію k за модулем p

        Ця функція повертає єдине ціле число x таке, що (x * k) % p == 1

        k має бути ненульовим, а p - простим
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Розширенний алгоритм Евкліда
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Функції, які працюють з точками ЕК


def is_on_curve(point):
    """
        Повертає True, якщо точка лежить на ЕК
    """
    if point is None:
        # Ніхто не представляє точку на нескінченності
        return True

    x, y = point

    return (y ** 2 - x ** 3 - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """
        Повертає -point.
    """
    assert is_on_curve(point)

    if point is None:
        # -0 == 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def point_add(point1, point2):
    """
        Повертає результат point1 + point2 згідно группового закону
    """
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # якщо point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # якщо point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """
        Повертає k * point за допомогою подвоєння і додавання точки
    """
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Додавання
            result = point_add(result, addend)

        # Подвоєння
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


# Генерування ключів та сам ECDSA

def make_keypair():
    """
        Генерує реально "рандомну" ключову пару (приватний та публічний ключі)
    """
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key


def hash_message(message):
    """
        Повертає скорочений хеш SHA521 повідомлення
    """
    message_hash = hashlib.sha512(message).digest()
    e = int.from_bytes(message_hash, 'big')

    # FIPS 180 стверджує, що, коли необхідно обрізати хеш, необхідно відкинути крайній правий біт
    z = e >> (e.bit_length() - curve.n.bit_length())

    assert z.bit_length() <= curve.n.bit_length()

    return z


def sign_message(private_key, message):
    """
        Сам алгоритм підпису ECDSA
    """
    z = hash_message(message)

    r = 0
    s = 0
    t = tuple()

    while not r or not s:
        k = random.randrange(1, curve.n)
        x, y = scalar_mult(k, curve.g)

        r = x % curve.n
        s = ((z + r * private_key) * inverse_mod(k, curve.n)) % curve.n

        t = (r, s)
    return t


def verify_signature(public_key, message, signature):
    """
        Алгоритм перевірки підпису ECDSA
    """
    z = hash_message(message)

    r, s = signature

    w = inverse_mod(int(str(s), 16), curve.n)
    u1 = (z * w) % curve.n
    u2 = (int(str(r), 16) * w) % curve.n

    x, y = point_add(scalar_mult(u1, curve.g),
                     scalar_mult(u2, public_key))

    if (int(str(r), 16) % curve.n) == (x % curve.n):
        return 'Підпис співпадає'
    else:
        return 'Підпис не співпадає (можлива підробка підпису)'
