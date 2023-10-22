import hashlib
import time
import numpy as np

class KeyGenerator:

    def __init__(self):
        self.state = str(time.time()).encode()

    def feed_entropy(self, source):
        self.state = hashlib.sha256(self.state + source).digest()

    def generate_key(self, size=32):
        while True:
            self.state = hashlib.sha256(self.state).digest()
            self.feed_entropy(str(time.time()).encode())
            if len(self.state) >= size:
                return self.state[:size]

