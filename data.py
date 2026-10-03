"""Small built-in lists. For real use, drop a bigger list into data/common_passwords.txt
(one entry per line, e.g. a top-10k list from the public SecLists project)."""
import os

COMMON_PASSWORDS = set("""
password password1 password123 passw0rd p@ssw0rd p@ssword admin admin123 administrator
welcome welcome1 welcome123 login letmein letmein1 qwerty qwerty123 qwertyuiop asdfgh asdfghjkl
zxcvbnm abc123 abcd1234 iloveyou monkey dragon master sunshine princess football baseball
superman batman trustno1 shadow michael jennifer hunter freedom whatever secret changeme
default guest root toor test test123 testing temp temp123 user hello hello123 hello1
111111 123123 12345 123456 1234567 12345678 123456789 1234567890 000000 654321 666666 121212
1q2w3e4r 1q2w3e 1qaz2wsx qazwsx zaq12wsx google facebook linkedin computer internet
secret123 summer winter spring autumn cricket soccer starwars pokemon naruto
correcthorsebatterystaple mustang access flower hottie loveme ashley bailey passw0rd1
""".split())

COMMON_WORDS = set("""
about above after again alpha angel apple april august autumn baby beach bear beauty black blue
bridge brother brown build cake canada castle chair charlie cheese cherry child circle city clever
cloud coffee color cookie correct cool dance dark daughter december diamond doctor dog dollar
dream earth eagle east eight electric family father february fire fish flower forest friday friend
garden ghost gold green guitar hammer happy heart horse house hunter india jacket january jungle
july june junior king kitchen knight lemon light lion london love magic mango march market may
monday money monkey moon morning mother mountain music night ninja north ocean orange panda paris
pepper phone pink planet purple queen rabbit rain river rocket saturday school secret server
shadow silver sister sleep smile snow spring staple star storm summer sunday sunshine super
tiger thunder thursday tomato tuesday turtle united valley victory violet water wednesday
west white window winter wolf yellow zebra battery stable office login network system
security cyber hacker hacking admin user email account bank password
""".split())

KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsxedcrfv"]

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
                      "@": "a", "$": "s", "!": "i", "|": "l", "+": "t"})


def load_extra_common(path=None):
    """Optionally extend the built-in list from a local text file."""
    path = path or os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "common_passwords.txt")
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="ignore") as fh:
            COMMON_PASSWORDS.update(l.strip().lower() for l in fh if l.strip())


load_extra_common()
