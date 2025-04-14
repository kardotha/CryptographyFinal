import socket
import json
import threading
import select
import time

class RNG:
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
    
    def randrange(self, a, b):
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

        self.private_key, self.public_key = ECC.getKeys(self.rng)
     
    def connect(self):
        #with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Step 1: Send client's public key to server
            #s.sendall(repr(self.public_key).encode('utf-8'))
                    
            # Step 2: Receive encrypted session key
            #encrypted_session_key = eval(s.recv(1024).decode('utf-8'))
                    
            # Step 3: Decrypt session key with client's private key
            #session_key_bytes = ecc.decrypt(self.private_key, encrypted_session_key)
            #session_key = int.from_bytes(session_key_bytes, 'big')
                    
            # Initialize DES with session key
            #self.des = DES(session_key_bytes[:8])  # Use first 8 bytes as DES key
                    
            # Initialize HMAC with session key
            #self.hmac = HMAC(session_key_bytes)
                    
        # Start interactive session
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
          
        response = self.send_request({
            "action": "check_balance",
            "account_num": self.account_num
        })
          
        if response.get("status") == "success":
            print(f"Your current balance is: ${response['balance']}")
        else:
            print(f"Error: {response.get('message', 'Unknown error')}")
     
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
          

        response = self.send_request({
            "action": "deposit",
            "account_num": self.account_num,
            "amount": amount
        })
          
        if response.get("status") == "success":
            print(f"Deposit successful. New balance: ${response['balance']}")
        else:
            print(f"Error: {response.get('message', 'Unknown error')}")
     
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
          

        response = self.send_request({
            "action": "withdraw",
            "account_num": self.account_num,
            "amount": amount
        })
          
        if response.get("status") == "success":
            print(f"Withdrawal successful. New balance: ${response['balance']}")
        else:
            print(f"Error: {response.get('message', 'Unknown error')}")
     
    def show_menu(self):

        while True: #only exit on user exit
            print("\nATM Menu:\n" \
            "1. Check Balance\n" \
            "2. Deposit Money\n" \
            "3. Withdraw Money\n" \
            "4. Exit")
                
            choice = input("Enter your choice (1-4): ")
                
            if choice == "1":
                self.check_balance()
            elif choice == "2":
                self.deposit()
            elif choice == "3":
                self.withdraw()
            elif choice == "4":
                print("Thank you for using our ATM. Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")

            #instead of going to functions, selection should change request var
            #Generate MAC for request
            #mac = self.HMAC.generate(request.encode('utf-8'))
            #full_request = request.encode('utf-8') + mac
            
            #Encrypt and send request
            #encrypted_request = self.DES.encrypt(full_request)
            #sock.sendall(encrypted_request)
            
            #Receive and process response
            #encrypted_response = sock.recv(1024)
            #decrypted_response = self.DES.decrypt(encrypted_response)
            
            #Split response and MAC
            #response = decrypted_response[:-32]  # Assuming SHA-256 (32 bytes)
            #received_mac = decrypted_response[-32:]
            
            #Verify MAC
            #computed_mac = self.HMAC.generate(response)
            #if received_mac != computed_mac:
            #	print("MAC verification failed for response!")
            #	continue
     
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

        self.private_key, self.public_key = ECC.getKeys()
          
    def handle_client(self, client_socket, address):
        print(f"Connection established with {address}")
        # Step 1: Receive client's public key
        #ATM sends request, need to have an initial send of pub key
        client_pub_key_data = client_socket.recv(1024)
        client_pub_key = ECC.Point._make(eval(client_pub_key_data))
        
        # Step 2: Generate session key
        session_key = self.rng.randint(1, 2**128-1)
        session_key_bytes = session_key.to_bytes(16, 'big')
        
        # Step 3: Encrypt session key with client's public key
        encrypted_session_key = ECC.encrypt(client_pub_key, session_key_bytes, self.rng)
        client_socket.sendall(repr(encrypted_session_key).encode('utf-8'))
        
        # Initialize DES with session key
        des = DES(session_key_bytes[:8])  # Use first 8 bytes as DES key
        
        # Initialize HMAC with session key
        hmac = HMAC(session_key_bytes)

        try:
            while True:
                #encrypted_request = client_socket.recv(1024).decode('utf-8')
                request = client_socket.recv(1024).decode('utf-8')
                if not request:
                    break
                #decrypted_request = DES.decrypt(encrypted_request)
                #request = decrypted_request[:-32] orwhatever this ends up being
                #request_mac = descrypted_request[:32]
                #computed_mac = HMAC.generate(request_msg)
                #if received_mac != computed_mac:
               #print("MAC verification failed!")
               #client_socket.sendall(DES.encrypt(b"ERROR: MAC verification failed"))
               #continue
                #response = self.process_request(msg)
                #response_mac = HMAC.generate(response)
            #full_response = response + response_mac
                #encrypted_response = DES.encrypt(full_response)
            #client_socket.sendall(encrypted_response)
                try:
                    data = json.loads(request)
                    response = self.process_request(data)
                except json.JSONDecodeError:
                    response = {"status": "error", "message": "Invalid request format"}
                     
                client_socket.send(json.dumps(response).encode('utf-8'))
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
        self.server_socket.settimeout(1)  # Make socket.accept() non-blocking with a timeout
        print(f"Bank server started on {self.host}:{self.port}")
        self.running = True
        try:	
            while self.running:
                    try:
                        #select checks if the socket is readable (has incoming connections)
                        readable, temp1, temp2 = select.select([self.server_socket], [], [], 1)
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
        bank_server = BankServer()
        bank_server.start()
    else:
        #run atm client
        #client = atm()
        #client.connect()
        atm_socket = ATMClient()
        atm_socket.run()