from passlib.hash import sha256_crypt


def isspecial(string):
    s = '.,:;!@#$%^&_()*+=-?~[]{}<>/\|`'
    for char in string:
        if char in s:
            return True
        else:
            return False


def encrypt(password):
    return sha256_crypt.hash(password)


def check_passwords(password, crypt_password):
    return sha256_crypt.verify(password, crypt_password)
