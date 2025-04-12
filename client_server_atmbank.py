import socket
import json
import threading
import select


class RNG:
	def __init__(self, seed):
		self.state = seed
	 
	def getRNG(self):
		x = self.state
		self.state += 1
		return x

class ATMClient:
	def __init__(self, host='localhost', port=12345):
		self.host = host
		self.port = port
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connected = False
		self.authenticated = False
		self.account_num = None
	 
	def connect(self):
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
		  
	def handle_client(self, client_socket, address):
		print(f"Connection established with {address}")
		try:
			while True:
				request = client_socket.recv(1024).decode('utf-8')
				if not request:
					break
					 
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