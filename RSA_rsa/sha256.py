def r_rotate(lst, i):
    return lst[-i:] + lst[:-i]


def XOR(x, y, z):
    y = int(x, 2) ^ int(y, 2) ^ int(z, 2)
    return bin(y)[2:].zfill(len(x))  # zfill to 32


def r_shift(a, RShft_n):
    b_rightshiftedVal = bin(int(a) >> RShft_n)[2:].zfill(32)
    return b_rightshiftedVal


def b32(val):
    """ convert to 32 bit binary """
    return bin(val)[2:].zfill(32)


class sha256:
    H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
         0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    def transform(self, W):
        def Ch(x, y, z): return bin(int(x, 2) & int(y, 2)
                                    ^ (~int(x, 2)) & int(z, 2))[2:].zfill(32)

        def Maj(x, y, z): return bin(int(x, 2) & int(y, 2) ^ int(x, 2) & int(z, 2) ^ int(y, 2)
                                     & int(z, 2))[2:].zfill(32)

        for zIndex in range(16, 64):
            s0 = XOR(r_rotate(W[zIndex-15], 7), r_rotate(W[zIndex
                                                           - 15], 18),
                     r_shift(int(W[zIndex-15], 2), 3))

            s1 = XOR(r_rotate(W[zIndex-2], 17),
                     r_rotate(W[zIndex-2], 19), r_shift(int(W[zIndex-2],
                                                            2), 10))
            W[zIndex] = format((int(W[zIndex-16], 2) + int(s0, 2) +
                                int(W[zIndex-7], 2) + int(s1, 2)) % 2**32, '08b').zfill(32)

        V = []
        for i in range(8):
            V.append(b32(self.H[i]))

        for i in range(64):
            S1 = XOR(r_rotate(V[4], 6), r_rotate(V[4], 11), r_rotate(V[4], 25))
            T1 = format((int(V[7], 2) + int(S1, 2) + int(Ch(V[4], V[5], V[6]), 2) +
                         self.K[i] + int(W[i], 2)) % 2**32, '08b').zfill(32)

            S0 = XOR(r_rotate(V[0], 2), r_rotate(V[0], 13), r_rotate(V[0], 22))

            T2 = bin(
                (int(S0, 2) + int(Maj(V[0], V[1], V[2]), 2)) % 2**32)[2:].zfill(32)

            V[7] = V[6]
            V[6] = V[5]
            V[5] = V[4]
            V[4] = bin((int(V[3], 2) + int(T1, 2)) % 2**32)[2:].zfill(32)
            V[3] = V[2]
            V[2] = V[1]
            V[1] = V[0]
            V[0] = bin((int(T1, 2) + int(T2, 2)) % 2**32)[2:].zfill(32)

        for i in range(8):
            self.H[i] = (self.H[i] + int(V[i], 2)) % 2**32
        return self.H

    """ default class initializer """

    def __init__(self, msg):
        self.convertToBytes = ''.join(format(ord(char), '08b') for char in msg)
        self.add1 = self.convertToBytes + '1'
        self.zFill = None
        padding = (512 - len(self.add1) - 64) % 512

        self.zFill = self.add1 + ''.zfill(padding)

        self.addlen = self.zFill + \
            format(len(self.convertToBytes), '08b').zfill(64)[0:64]
        self.W = [self.addlen[i:i+32] 
                  for i in range(0, len(self.addlen), 32)]
        
        def digest(hVal): return str(hex(hVal))[2:].zfill(8)
        TMP = []
        for i in range(64):
            TMP.append("0"*32)

        for i in range(0, int((padding+len(self.add1)+64)/512)):
            for j in range(0, 16):
                TMP[j] = self.W[j+16*i]
            self.transform(TMP)

        self.hexdigest = digest(self.H[0]) + digest(self.H[1]) + \
            digest(self.H[2]) + digest(self.H[3]) + \
            digest(self.H[4]) + digest(self.H[5]) + \
            digest(self.H[6]) + digest(self.H[7])

    def to_bytes(self):
        """ Convert the hash values to bytes format """
        hash_bytes = bytearray()
        for h in self.H:
            hash_bytes.extend(h.to_bytes(4, 'big'))
        return bytes(hash_bytes)
