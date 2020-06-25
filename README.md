# ECDSA

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/e295e925461e48128eb07225ce330728)](https://app.codacy.com/manual/dexXxed/ECDSA?utm_source=github.com&utm_medium=referral&utm_content=dexXxed/ECDSA&utm_campaign=Badge_Grade_Dashboard)

*ECDSA (Elliptic Curve Digital Signature Algorithm)* — це алгоритм з
відкритим ключем для створення цифрового підпису, аналогічний за своєю
будовою DSA, але визначений, на відміну від нього, не над полем цілих
чисел, а в групі точок еліптичної кривої.

Стійкість цього алгоритму ґрунтується на проблемі дискретного
логарифмування в групі точок еліптичної кривої. На відміну від проблеми
простого дискретного логарифма і проблеми факторизації цілого числа, не
існує суб-експоненціального алгоритму для проблеми дискретного логарифма
в групі точок еліптичної кривої. З цієї причини «сила на один біт ключа»
набагато вище в алгоритмі з еліптичними кривими.

Для генерування та перевірки підписів були написані скрипти на мові
Python 3. Результат роботи скриптів представлений на скриншотах нижче.

`script.py`
![](./screenshots/script.JPG)

`sign.py`
![](./screenshots/sign.JPG)

`check.py`
![](screenshots/check_ok.JPG)

![](screenshots/check_not_ok.JPG)
