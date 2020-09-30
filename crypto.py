import math
import random as ran

alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

# Caesar Cipher
# Arguments: string, integer
# Returns: string
def encrypt_caesar(plaintext, offset):
    encrypted = ''
    if (len(plaintext) > 0):
        for x in plaintext:
            if x in alphabet:
                encrypted += shiftLetter(x, offset)
            else:
                encrypted += x
    return encrypted

# Arguments: string, integer
# Returns: string
def decrypt_caesar(ciphertext, offset):
    return encrypt_caesar(ciphertext, -offset)

def shiftLetter(letter, offset):
    # print("shiftletter was called")
    if ((ord(letter) + offset) > ord('Z')):
        # print(ord(letter) + offset - ord('z'))
        letter = chr(ord(letter) + offset - ord('Z') + ord('A') - 1)
    elif((ord(letter) + offset) < ord('A')):
        letter = chr(ord('Z')-(ord('A') - (ord(letter) + offset)) + 1)
    else:
        letter = (chr(ord(letter) + offset))
    return letter

# Vigenere Cipher
# Arguments: string, string
# Returns: string
def encrypt_vigenere(plaintext, keyword):
     if len(plaintext) < len(keyword):
         keyword = keyword[:len(plaintext)]
     elif len(plaintext) > len(keyword):

         remainder = len(plaintext)-len(keyword)
         key_length = len(keyword)

         while(remainder > key_length):
             keyword += keyword
             remainder -= key_length
         keyword += keyword[:remainder]
     encrypted = ''
     for x in range(len(plaintext)):
        encrypted += shiftLetter(plaintext[x],getShift(keyword[x]))
     return(encrypted)

# Arguments: string, string
# Returns: string
def decrypt_vigenere(ciphertext, keyword):
    if len(ciphertext) < len(keyword):
         keyword = keyword[:len(ciphertext)]
    elif len(ciphertext) > len(keyword):
         remainder = len(ciphertext)-len(keyword)
         key_length = len(keyword)

         while(remainder > key_length):
             keyword += keyword
             remainder -= key_length
         keyword += keyword[:remainder]
    decrypted = ''
    for x in range(len(ciphertext)):
         decrypted += shiftLetter(ciphertext[x],-getShift(keyword[x]))
    return(decrypted)

#returns the position of letter in alphabet for vigenere
def getShift(letter):
    return alphabet.index(letter)

# Merkle-Hellman Knapsack Cryptosystem
# Arguments: integer
# Returns: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
def generate_private_key(n=8):
    w = [ran.randint()]
    for i in range(n-1):
        w.append(ran.randomint(sum(w) + 1, sum(w) * 2))
    q = w.pop(-1)
    w = tuple(w)
    r = generateCoprime(q)

    return (w,q,r)

#returns a number coprime to num
def generateCoprime(num):
    coprime = num
    while math.gcd(num,coprime) != 1:
        coprime = ran.randomint(2, num - 1)
    return coprime

# Arguments: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
# Returns: B - a length-n tuple of integers
def create_public_key(private_key):
    w = private_key[0]
    q = private_key[1]
    r = private_key[2]
    b = []
    for i in range(len(w)):
        b.append(r * w[i] % q)
    return tuple(b)


# Arguments: string, tuple B
# Returns: list of integers
def encrypt_mhkc(plaintext, public_key):
    list_of_c = []
    for char in plaintext:
        bin_str = getBinary(ord(char))
        bin_list = list(bin_str)
        bin_list = [int(x) for x in bin_list]
        c = sum([bin_list[i] * public_key[i] for i in range(len(public_key))])
        list_of_c.append(c)

    return list_of_c

#converts decimal to binary
def getBinary(x, n=8):
    return format(x,'b').zfill(n)

#converts binary to decimal
def getDecimal(n):
    return int(n,2)

# Arguments: list of integers, private key (W, Q, R) with W a tuple.
# Returns: bytearray or str of plaintext
def decrypt_mhkc(ciphertext, private_key):
    w = list(private_key[0])
    q = private_key[1]
    r = private_key[2]
    s = generateS(r,q)

    w.reverse()

    decrypted_str = []
    for c in ciphertext:
        c_prime = (c * s) % q
        bin_list = []
        for j in w:
            if j <= c_prime:
                c_prime -= j
                bin_list.append(1)
            else:
                bin_list.append(0)

        bin_list.reverse()
        # del bin_list[8:]
        bin_list_str = ''.join([str(x) for x in bin_list])
        decrypted_str.append(chr(getDecimal(bin_list_str)))

    return ''.join(decrypted_str)

#returns an S value given r and q
def generateS(r,q):
    for s in range(2,q):
        if ((r * s) % q == 1):
            return s

#contains testing
def main():
   print('Caesar Cipher')
   print(encrypt_caesar('0DD !T$', 3))
   print(decrypt_caesar('IIJJKKHH', 8))

   print('\nVigenere Cipher')
   print(encrypt_vigenere('IMHIT','H'))
   print(decrypt_vigenere('PTOPA','H'))

   print('\nMHKC')
   private_key = ((10, 14, 35, 115, 248, 677, 1413, 3644), 10242, 5)
   public_key = create_public_key(private_key)
   public_key_correct = (50, 70, 175, 575, 1240, 3385, 7065, 7978)
   print("key creation is working: " + str(public_key == public_key_correct))
   encrypted = encrypt_mhkc("FOREACHEPSILONGREATERTHANDELTA", public_key)
   encrypted_correct = [10520, 19738, 7710, 11433, 8048, 15113, 1310, 11433, 645, 15688, 9288, 4695, 19738, 11760, 18498, 7710, 11433, 8048, 4030, 11433, 7710, 4030, 1310, 8048, 11760, 3455, 11433, 4695, 4030, 8048]
   print(encrypted)
   print(encrypted_correct)
   print("encryption is working " + str(encrypted == encrypted_correct))
   decrypted = decrypt_mhkc(encrypted_correct, private_key)
   # print(decrypted)
   # print("FOREACHEPSILONGREATERTHANDELTA")
   print("decryption is working " + str(decrypted == "FOREACHEPSILONGREATERTHANDELTA"))

   print('--end--')


if __name__ == "__main__":
    main()

