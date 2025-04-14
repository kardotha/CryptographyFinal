import socket
import json
import threading
import select
import time

class RNG:
    def __init__(self, seed):
        self.state = seed
    
    def getRNG(self):
        x = self.state
        self.state += 1
        return x
  
    def __init__(self, seed):
        self.state = seed if seed is not None else self.entropy()
        self.counter = 0
    
    def entropy(self):
        return self.hash(str(self.hash(str(id(self)) + str(time.time()))))

    #https://www.cs.hmc.edu/~geoff/classes/hmc.cs070.200101/homework10/hashfuncs.html
    #pjw hash
    def hash(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        x = 0
        for byte in data:
            x = (x << 4) + byte
            y = x + 0xF0000000
            if y != 0:
                x ^= (y >> 24)
                x ^= y
        return x & 0xFFFFFFFF
   
    def update(self):
        self.state = self.hash(str(self.hash(str(id(self)) + str(time.time()))))
        self.counter += 1
        
    #num in blocks of 32
    def get_bits(self, num):
        output = 0
        for i in range(num // 32):
            self.update()
            output = (output << 32) | self.state & 0xFFFFFFFF
        return output
    
    def rand(self):
        return self.get_bits(32) / (1 << 32)
    
    def randint(self, a, b):
        x = b - a + 1
        y = x.bit_length()
        
        while True:
            z = self.get_bits(y)
            if z < x:
                return a + z

class ECC:
    def __init__(self, seed):
        self.state = seed
    def getKeys(self):
        return 1, 2
    
class DES:
    def __init__(self):
        self.val = 0
        
#ECC
#https://en.wikipedia.org/wiki/Elliptic-curve_cryptography
#https://martin.kleppmann.com/papers/curve25519.pdf
    #use bitcoin elliptic curve
    #https://security.stackexchange.com/questions/78621/which-elliptic-curve-should-i-use
class SimplifiedECC:
    def __init__(self, a, b, p, g, n):
        #y² ≡ x³ + ax + b (mod p)
        #g: base point (x, y) tuple
        #n: order of g
        self.a = a
        self.b = b
        self.p = p
        self.g = g
        self.n = n
        
    #Function to compute the modular inverse
    #https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    def mod_inverse(self, x, p):
        return pow(x, p - 2, p)
    
    #https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    def egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.egcd(b % a, a)
            return (g, x - (b // a) * y, y)
    
    #https://stackoverflow.com/questions/75089523/elliptic-curve-point-verify-point-is-on-the-curve
    def is_point_on_curve(self, point):
        x, y = point
        #y^2 - x^3 - ax - b % p
        if ((y * y - x * x * x - self.a * x - self.b) % self.p == 0):
            return True
        return False
        
    #https://crypto.stackexchange.com/questions/11744/scalar-multiplication-on-elliptic-curves
    #Function to multiply a point by a scalar (using double-and-add algorithm)
    def scalar_mult(self, k, p):
        result = None  #straight line
        addend = p
        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result

    #Function to add two points on the elliptic curve
    def point_add(self, P, Q):
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and y1 != y2:
            return None  #POINT IS VERTICAL LINE XDDDDD
        if P == Q:
            lam = (3 * x1 * x1 + self.a) * self.mod_inverse(2 * y1, self.p) % self.p
        else:
            lam = (y2 - y1) * self.mod_inverse(x2 - x1, self.p) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)
    
    #gen priv and pub key
    def keypair(self, prng):
        #forward coding (PRNG OBJECT NEEDS TO HAVE .RANDINT FUNCTION !!!)
        priv = prng.randint(1, self.n - 1)
        pub = self.scalar_mult(priv, self.g)
        
        return priv, pub
    
    #https://cryptobook.nakov.com/asymmetric-key-ciphers/ecc-encryption-decryption
    def encrypt(self, pub, plaintext, prng):
        plaintext = plaintext.encode()
        m = int.from_bytes(plaintext, 'big') % self.p
        point = (m, (m**3 + self.a*m + self.b) % self.p)
        
        k = prng.randint(1, self.n-1)
        c1 = self.scalar_mult(k, self.g)
        c2 = self.point_add(point, self.scalar_mult(k, pub))
        return c1, c2
    
    def decrypt(self, priv, c):
        c1, c2 = c
        s = self.scalar_mult(priv, c1)
        
        invs = (s[0], (-s[1]) % self.p)
        point = self.point_add(c2, invs)
        
        return point[0].to_bytes((point[0].bit_length() + 7) // 8, 'big')
   
#DES
class SimplifiedDES:
   #https://en.wikipedia.org/wiki/DES_supplementary_material
   #https://ziaullahrajpoot.medium.com/data-encryption-standard-des-dc8610aafdb3
   #Initial and final permutation for plaintext/ciphertext
   IP = [
      58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7
   ]

   #Final Permutation Table
   IP_INV = [
      40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25
   ]
    
   E = [
      32, 1, 2, 3, 4, 5,
      4, 5, 6, 7, 8, 9,
      8, 9, 10, 11, 12, 13,
      12, 13, 14, 15, 16, 17,
      16, 17, 18, 19, 20, 21,
      20, 21, 22, 23, 24, 25,
      24, 25, 26, 27, 28, 29,
      28, 29, 30, 31, 32, 1
   ]
    
    #P-box permutation
   P = [
      16, 7, 20, 21,
      29, 12, 28, 17,
      1, 15, 23, 26,
      5, 18, 31, 10,
      2, 8, 24, 14,
      32, 27, 3, 9,
      19, 13, 30, 6,
      22, 11, 4, 25
   ]
    
   #PC-1 permutation table (key permutation)
   PC1 = [
      57, 49, 41, 33, 25, 17, 9,
      1, 58, 50, 42, 34, 26, 18,
      10, 2, 59, 51, 43, 35, 27,
      19, 11, 3, 60, 52, 44, 36,
      63, 55, 47, 39, 31, 23, 15,
      7, 62, 54, 46, 38, 30, 22,
      14, 6, 61, 53, 45, 37, 29,
      21, 13, 5, 28, 20, 12, 4
   ]

   #PC-2 permutation table (compression permutation)
   PC2 = [
      14, 17, 11, 24, 1, 5,
      3, 28, 15, 6, 21, 10,
      23, 19, 12, 4, 26, 8,
      16, 7, 27, 20, 13, 2,
      41, 52, 31, 37, 47, 55,
      30, 40, 51, 45, 33, 48,
      44, 49, 39, 56, 34, 53,
      46, 42, 50, 36, 29, 32
   ]
    
   #S-boxes
   S = [
      #S1
      [
         [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
      ],
      #S2
      [
         [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
      ],
      #S3
      [
         [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
      ],
      #S4
      [
         [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
      ],
      #S5
      [
         [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
      ],
      #S6
      [
         [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
      ],
      #S7
      [
         [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
      ],
      #S8
      [
         [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
      ]
   ]

   def __init__(self, key):
      self.key = key
      self.subkeys = self.subkey_gen()
        
   def bytes_bits(self, data):
      bits = []
      for bit in data:
         for i in range(7, -1, -1):
            bits.append((bit >> i) & i)
      return bits
    
   def bits_bytes(self, data):
      bits = []
      for i in range(0, len(data), 8):
         bit = 0
         for j in range(8):
            if i + j < len(data):
               bit |= bits[i+j] << (7 - j)
         bits.append(bit)
      return bytes(bits)
        
   def permute(self, input_bits, permutation_table):
      return [input_bits[i-1] for i in permutation_table]

   def shift_left(self, bits, n):
      return bits[n:] + bits[:n] #circular

   def subkey_gen(self):
      #how you represent l or r
      shift_schema = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
       
      key_bits = self.bytes_bits(self.key)
      perm_key = [key_bits[i-1] for i in self.PC1]
        
      #56 / 2 = 28
      #l = first half, r = second half
      l = perm_key[:28]
      r = perm_key[28:]
        
      subkeys = []
      for shift in shift_schema:
         l = l[shift:] + l[:shift]
         r = r[shift:] + r[:shift]
            
         lr = l + r
         subkey = [lr[i-1] for i in self.PC2]
         subkeys.append(subkey)

   def feistel(self, data, subkey):
      #https://en.wikipedia.org/wiki/Data_Encryption_Standard
      #Expansion: expand 4 bits to 8 bits
      expanded = [data[i-1] for i in self.E]
       
      #XOR with subkey
      xored = [expanded[i] ^ subkey[i] for i in range(48)]
        
      sbox_output = []
      #S-box substitution
      for i in range(8):
         block = xored[i * 6 : (i+1) * 6]
         r = (block[0] << 1) + block[5]
         c = (block[1] << 3) + (block[2] << 2) + (block[3] << 1) + block[4]
         x = self.S[i][r][c]
         sbox_output += [(x >> (3-j)) & 1 for j in range(4)]
        
      #p-box black magic
      permuted = [sbox_output[i-1] for i in self.P]
      return permuted

   def encrypt_block(self, plaintext):
      #plaintext MUST BE 64 BITS
      bits = self.bytes_bits(plaintext)
      permuted = [bits[i-1] for i in self.IP]
        
      left = permuted[:32]
      right = permuted[32:]
        
      #16 rounds here, deprecating old one_round func
      for i in range(16):
         l = right.copy()
         r = self.feistel(right, self.subkeys[i])
            
         r = [left[j] ^ r[j] for j in range(32)]
         left, right = l, r
        
      lr = left + right
      c = [lr[i-1] for i in self.IP]
      return self.bits_bytes(c)

   def decrypt_block(self, ciphertext):
      #plaintext MUST BE 64 BITS
      bits = self.bytes_bits(ciphertext)
      permuted = [bits[i-1] for i in self.IP]
      
      left = permuted[:32]
      right = permuted[32:]
        
      #16 rounds here, deprecating old one_round func
      #copied from ENCRYPT so is in reverse order!
      for i in range(15, -1, -1):
         r = left.copy()
         l = self.feistel(left, self.subkeys[i])
            
         l = [right[j] ^ l[j] for j in range(32)]
         left, right = l, r
        
      rl = right + left
      p = [rl[i-1] for i in self.IP_INV]
      return self.bits_bytes(p)
    
   def xor(self, a, b):
      return [x^y for x, y in zip(a, b)]
    
   #mac stuff goes here ig?
   #wtf how do i impl this
   #https://gist.github.com/TomCorwine/88090a64dc62c2610ce6d55d832766b0
   #https://www.naukri.com/code360/library/cbc-mac-in-cryptography
   def get_mac(self, payload):
      iv = [0] * 64
        
      before = iv
      message = message.encode()
        
      len_pad = 8 - (len(message) % 8)
      message += bytes([len_pad] * len_pad)
      blocks = [message[payload[i:i+8]] for i in range(0, len(message), 8)]
        
      for block in blocks:
         bits = []
         for bit in block:
            bits.extend([int(b) for b in f"{bit:08b}"])
                
         xor = self.xor(bits, before)
         enc = self.encrypt_block(xor)
         before = enc
            
      mac = bytes(int(''.join(map(str, before[i:i+8])), 2) for i in range(0, 64, 8))
      return mac
      
class HMAC:
   def __init__(self):
      self.val = 0








class ATMClient:
   def __init__(self, host='localhost', port=12345):
      self.host = host
      self.port = port
      self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.connected = False
      self.authenticated = False
      self.account_num = None

      self.rng = RNG.getRNG()

      self.private_key, self.public_key = SimplifiedECC.keypair(self.rng)

      #self.DES = SimplifiedDES(self.private_key)
    
   def connect(self):
   
      #Step 1: Send client's public key to server
      self.socket.sendall(repr(self.public_key).encode('utf-8'))
            
      #Step 2: Receive encrypted session key
      encrypted_session_key = eval(self.socket.recv(1024).decode('utf-8'))
            
      #Step 3: Decrypt session key with client's private key
      session_key_bytes = SimplifiedECC.decrypt(self.private_key, encrypted_session_key)
      #session_key = int.from_bytes(session_key_bytes, 'big')
            
      #Initialize DES with session key
      self.des = SimplifiedDES(session_key_bytes[:8])  #Use first 8 bytes as DES key
            
      #Initialize HMAC with session key
      self.hmac = HMAC(session_key_bytes)
            
      #Start interactive session
      try:
         self.socket.connect((self.host, self.port))
         self.connected = True
         print("Connected to bank server")
         return True
      except Exception as e:
         print(f"Failed to connect to bank server: {e}")
         return False
    
   def send_request(self, data):
      try:
         self.socket.send(json.dumps(data).encode('utf-8'))
         response = self.socket.recv(1024).decode('utf-8')
         return json.loads(response)
      except Exception as e:
         print(f"Communication error: {e}")
         return {"status": "error", "message": "Communication failed"}
    
   def authenticate(self):
      if not self.connected:
         print("Not connected to server")
         return False
      
      #defaults, can be changed if future implementation needed
      self.account_num = "123456"
      self.authenticated = True
      return True
      
   def check_balance(self):
      #shouldnt ever throw this error
      if not self.authenticated:
         print("Please authenticate first")
         return
      return {
         "action": "check_balance",
         "account_num": self.account_num
      }
    
   def deposit(self):
      #shouldnt ever throw this error
      if not self.authenticated:
         print("Please authenticate first")
         return
        
      try:
         amount = int(input("Enter amount to deposit: "))
         if amount <= 0:
            print("Amount must be greater than 0")
            return
      except ValueError:
         print("Invalid amount. Minimum denomination is one dollar.")
         return
      return {
         "action": "deposit",
         "account_num": self.account_num,
         "amount": amount
      }

   def withdraw(self):
      #shouldnt ever throw this error
      if not self.authenticated:
         print("Please authenticate first")
         return
        
      try:
         amount = int(input("Enter amount to withdraw: "))
         if amount <= 0:
            print("Amount must be greater than 0")
            return
      except ValueError:
         print("Invalid amount. Minimum denomination is one dollar.")
         return
        
      return {
         "action": "withdraw",
         "account_num": self.account_num,
         "amount": amount
      }
    
   def show_menu(self):
      validRequest = True
      while True: #only exit on user exit
         print("\nATM Menu:\n" \
         "1. Check Balance\n" \
         "2. Deposit Money\n" \
         "3. Withdraw Money\n" \
         "4. Exit")
            
         choice = input("Enter your choice (1-4): ")
         
         if choice == "1":
            request = self.check_balance()
            validRequest = True
         elif choice == "2":
            request = self.deposit()
            validRequest = True
         elif choice == "3":
            request = self.withdraw()
            validRequest = True
         elif choice == "4":
            print("Thank you for using our ATM. Goodbye!")
            break
         else:
            print("Invalid choice. Please try again.")
            validRequest = False
         
         if(validRequest):
            #Generate MAC for request
            mac = self.hmac.generate(request.encode('utf-8'))
            full_request = request.encode('utf-8') + mac
            
            #Encrypt and send request
            encrypted_request = self.des.encrypt(full_request)
            self.socket.sendall(encrypted_request)
            
            #Receive and process response
            encrypted_response = self.socket.recv(1024)
            decrypted_response = self.des.decrypt(encrypted_response)
            
            #Split response and MAC
            response = decrypted_response[:-32]  #Assuming SHA-256 (32 bytes)
            received_mac = decrypted_response[-32:]
            
            #Verify MAC
            computed_mac = self.hmac.generate(response)
            if received_mac != computed_mac:
               print("MAC verification failed for response!")
               continue

            if response.get("status") == "success":
               if choice == "1":
                  print(f"Your current balance is: ${response['balance']}")
               elif choice == "2":
                  print(f"Deposit successful. New balance: ${response['balance']}")
               elif choice == "3":
                  print(f"Withdrawal successful. New balance: ${response['balance']}")
            else:
               print(f"Error: {response.get('message', 'Unknown error')}")
      
    
   def run(self):
      if not self.connect():
         return
        
      if self.authenticate():
         self.show_menu()
        
      self.socket.close()







class BankServer:
   def __init__(self, host='localhost', port=12345):
      self.host = host
      self.port = port
      self.accounts = {"123456": {"balance": 1000}}
      self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      self.lock = threading.Lock() #prevent DOS
      self.running = False #server control loop flag

      self.rng = RNG.getRNG()

      self.private_key, self.public_key = SimplifiedECC.keypair()

        
   def handle_client(self, client_socket, address):

      print(f"Connection established with {address}")
      #Step 1: Receive client's public key
      #ATM sends request, need to have an initial send of pub key
      client_pub_key_data = client_socket.recv(1024)
      client_pub_key = SimplifiedECC(eval(client_pub_key_data))
      
      #Step 2: Generate session key
      session_key = self.rng(1, 2**128-1)
      session_key_bytes = session_key.to_bytes(16, 'big')
      
      #Step 3: Encrypt session key with client's public key
      encrypted_session_key = SimplifiedECC.encrypt(client_pub_key, session_key_bytes, self.rng)
      client_socket.sendall(repr(encrypted_session_key).encode('utf-8'))
      
      #Initialize DES with session key
      DES = SimplifiedDES(session_key_bytes[:8])  #Use first 8 bytes as DES key
      
      #Initialize HMAC with session key
      hmac = HMAC(session_key_bytes)

      try:
         while True:
            encrypted_request = client_socket.recv(1024).decode('utf-8')
            #request = client_socket.recv(1024).decode('utf-8')
            #if not request:
            #   break
            decrypted_request = SimplifiedDES.decrypt(encrypted_request)
            request = decrypted_request[:-32] #32 might be incorrect
            request_mac = decrypted_request[:32]
            computed_mac = HMAC.generate(request) #might need to be request_mac instead of request
            if request_mac != computed_mac:
               print("MAC verification failed!")
               client_socket.sendall(DES.encrypt(b"ERROR: MAC verification failed"))
               continue
            #response = self.process_request(request)
            try:
               data = json.loads(request)
               response = self.process_request(data)
            except json.JSONDecodeError:
               response = {"status": "error", "message": "Invalid request format"}

            response_mac = HMAC.generate(response)
            full_response = response + response_mac
            encrypted_response = SimplifiedDES.encrypt(full_response)
            client_socket.sendall(encrypted_response)

            #client_socket.send(json.dumps(response).encode('utf-8'))
      except Exception as e:
         print(f"Error with client {address}: {e}")
      finally:
         client_socket.close()
         print(f"Connection closed with {address}")
    
   def process_request(self, data):
      action = data.get("action")
      account_num = data.get("account_num")
       
      if action == "check_balance":
         return self.check_balance(account_num)
      elif action == "deposit":
         return self.deposit(account_num, data.get("amount"))
      elif action == "withdraw":
         return self.withdraw(account_num, data.get("amount"))
      else:
         return {"status": "error", "message": "Invalid action"}
    
   
   def check_balance(self, account_num):
      with self.lock:
         balance = self.accounts[account_num]["balance"]
         return {"status": "success", "balance": balance}
    
   def deposit(self, account_num, amount):
      try:
         amount = int(amount)
         if amount <= 0:
            return {"status": "error", "message": "Amount must be positive"}
            
         with self.lock:
            self.accounts[account_num]["balance"] += amount
            return {"status": "success", "balance": self.accounts[account_num]["balance"]}
      except ValueError:
         return {"status": "error", "message": "Invalid amount"}
    
   def withdraw(self, account_num, amount):
      try:
         amount = int(amount)
         if amount <= 0:
            return {"status": "error", "message": "Amount must be positive"}
            
         with self.lock:
            if self.accounts[account_num]["balance"] < amount:
               return {"status": "error", "message": "Insufficient funds"}
                
            self.accounts[account_num]["balance"] -= amount
            return {"status": "success", "balance": self.accounts[account_num]["balance"]}
      except ValueError:
         return {"status": "error", "message": "Invalid amount"}
    
   def start(self):
      self.server_socket.bind((self.host, self.port))
      self.server_socket.listen(5) #5 pendings max
      self.server_socket.settimeout(1)  #Make socket.accept() non-blocking with a timeout
      print(f"Bank server started on {self.host}:{self.port}")
      self.running = True
      try:	
         while self.running:
               try:
                  #select checks if the socket is readable (has incoming connections)
                  readable, _, _ = select.select([self.server_socket], [], [], 1)
                  if readable: #act as normal
                     client_socket, address = self.server_socket.accept()
                     client_thread = threading.Thread(
                        target=self.handle_client, args=(client_socket, address), daemon=True
                     )
                     client_thread.start()
               except socket.timeout: #lets keyboard interupts be red
                  continue  
               except OSError as e: #error checking (shouldnt get run unless something catastrophic happens)
                  if self.running:
                     print(f"Socket error: {e}")
                  break	
      except KeyboardInterrupt:
         print("Shutting down server...")
      finally:
         self.server_socket.close()


if __name__ == "__main__":
   import sys
   if len(sys.argv) > 1 and sys.argv[1] == "server":
      #if running server command, host bank
      bank_server = BankServer()
      bank_server.start()
   else:
      #otherwise, host atm
      atm_socket = ATMClient()
      atm_socket.run()