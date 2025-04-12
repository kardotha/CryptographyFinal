class RNG:
    def __init__(self, seed):
        self.state = seed
    
    def getRNG(self):
        x = self.state
        self.state += 1
        return x
    



if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        #server = bank()
        #server.start()
        exit
    else:
        #client = atm()
        #client.connect()
        exit