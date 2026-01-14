import string


class CaesarCipherDescriptor:
    def __init__(self, shift):
        self.shift = shift % 26
        self.rus_shift = shift % 32

    def __get__(self, instance, owner):
        return self

    def __set__(self, instance, value):
        raise AttributeError

    def _apply_ascii_shift(self, char, direction):
        if not char.isalnum():
            current_code = ord(char)
            delta = self.shift if direction else -self.shift

            shifted_code = current_code + delta
            while shifted_code > 126 or shifted_code < 32:
                if shifted_code > 126:
                    shifted_code -= 95
                elif shifted_code < 32:
                    shifted_code += 95

            return chr(shifted_code)
        return None

    def encrypt(self, text):
        result = []
        for char in text:
            if char.isalpha():
                if char.isascii():
                    offset = ord('a') if char.islower() else ord('A')
                    new_char = chr((ord(char) - offset + self.shift) % 26 + offset)
                else:
                    lower_bound = ord('а') if char.islower() else ord('А')
                    new_char = chr((ord(char) - lower_bound + self.rus_shift) % 32 + lower_bound)
                result.append(new_char)
            else:
                special_char = self._apply_ascii_shift(char, True)
                result.append(special_char if special_char is not None else char)
        return ''.join(result)

    def decrypt(self, text):
        result = []
        for char in text:
            if char.isalpha():
                if char.isascii():
                    offset = ord('a') if char.islower() else ord('A')
                    new_char = chr((ord(char) - offset - self.shift) % 26 + offset)
                else:
                    lower_bound = ord('а') if char.islower() else ord('А')
                    new_char = chr((ord(char) - lower_bound - self.rus_shift) % 32 + lower_bound)
                result.append(new_char)
            else:
                special_char = self._apply_ascii_shift(char, False)
                result.append(special_char if special_char is not None else char)
        return ''.join(result)


class AtbashCipherDescriptor:
    def __init__(self):
        self.lat_alphabet = 'abcdefghijklmnopqrstuvwxyz'
        self.rus_alphabet = 'абвгдежзийклмнопрстуфхцчшщъыьэюя'
        self.rev_lat_alphabet = self.lat_alphabet[::-1].upper()
        self.rev_rus_alphabet = self.rus_alphabet[::-1].upper()
        self.special_chars = list(string.punctuation + string.digits)
        self.reverse_special_chars = self.special_chars[::-1]

    def __get__(self, instance, owner):
        return self

    def __set__(self, instance, value):
        raise AttributeError

    def encrypt(self, text):
        result = []
        for char in text:
            if char.isalpha():
                if char.isascii():
                    index = self.lat_alphabet.find(char.lower())
                    enc_char = self.rev_lat_alphabet[index] if char.isupper() else self.rev_lat_alphabet[index].lower()
                else:
                    index = self.rus_alphabet.find(char.lower())
                    enc_char = self.rev_rus_alphabet[index] if char.isupper() else self.rev_rus_alphabet[index].lower()
            elif char in self.special_chars:
                index = self.special_chars.index(char)
                enc_char = self.reverse_special_chars[index]
            else:
                enc_char = char
            result.append(enc_char)
        return ''.join(result)

    def decrypt(self, text):
        return self.encrypt(text)


class CipherManager:
    caesar_cipher = CaesarCipherDescriptor(shift=1)
    atbash_cipher = AtbashCipherDescriptor()


if __name__ == "__main__":
    cipher_manager = CipherManager()
    user_input = input("Введите ваше сообщение: ")
    caesar_encrypted = cipher_manager.caesar_cipher.encrypt(user_input)
    caesar_decrypted = cipher_manager.caesar_cipher.decrypt(caesar_encrypted)
    atbash_encrypted = cipher_manager.atbash_cipher.encrypt(user_input)
    atbash_decrypted = cipher_manager.atbash_cipher.decrypt(atbash_encrypted)
    print(f'Шифрование Цезаря: {caesar_encrypted}')
    print(f'Шифрование Атбаша: {atbash_encrypted}')
    print(f'Расшифровка Цезаря: {caesar_decrypted}')
    print(f'Расшифровка Атбаша: {atbash_decrypted}')