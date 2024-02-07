from enum import Enum
from datetime import datetime
import struct
import ctypes


class ProductNames(Enum):
    CandyCaneMachine2000 = 0
    CandyCaneMachine = 1
    
    
class ProductTypes(Enum):
    Standard = 0
    Advanced = 1
    Premium = 2

class CandyCaneBlock(ctypes.Structure):
    _fields_ = [
        ("Expiration", ctypes.c_uint),
        ("Generation", ctypes.c_uint),
        ("Product", ctypes.c_byte),
        ("Flags", ctypes.c_byte),
        ("Count", ctypes.c_ushort),
        ("Random", ctypes.c_ushort),
        ("Type", ctypes.c_byte),
        ("Shuffle", ctypes.c_byte)
    ]
    def __init__(self, expiration, generation, product, flags, count, random, ptype, shuffle):
        self.candyMap = [255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,0,1,2,3,4,5,6,7,255,255,255,255,255,255,255,8,9,10,11,12,13,14,15,255,16,17,18,19,20,255,21,22,23,24,25,26,27,28,29,30,31,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255]
        self.candyMixVertical00 = [23,9,22,21,11,15,13,16,17,4,10,3,19,7,18,1,5,6,20,12,2,0,14,8]
        self.candyMixVertical01 = [10,13,9,18,12,7,2,22,16,0,23,17,4,19,15,6,8,20,1,5,14,21,11,3]
        self.candyMixVertical02 = [21,6,19,15,5,0,17,18,3,22,7,16,8,14,1,23,9,10,11,12,13,4,2,20]
        self.candyMixVertical03 = [22,8,15,7,1,14,2,16,3,12,21,4,19,20,10,5,18,11,17,0,6,9,23,13]
        self.candyMixVertical04 = [18,19,1,2,6,20,5,14,23,22,21,17,8,4,10,11,3,9,0,7,16,12,13,15]
        self.candyMixVertical05 = [22,15,23,12,7,1,11,2,17,10,3,16,14,0,21,8,13,5,6,9,19,4,18,20]
        self.candyMixVertical06 = [11,18,21,8,20,23,17,3,2,22,7,10,0,4,1,19,13,9,12,5,16,6,15,14]
        self.candyMixVertical07 = [7,2,6,15,12,11,10,21,8,18,19,23,17,20,0,9,4,13,1,22,5,14,16,3]
        self.candyMixVertical08 = [16,4,20,15,1,8,0,2,17,5,3,12,10,18,7,21,23,6,9,13,22,19,14,11]
        self.candyMixVertical09 = [12,4,22,2,10,14,6,20,3,16,1,9,18,0,15,5,11,13,19,17,23,7,8,21]
        self.candyMixVertical0A = [0,16,6,13,7,15,17,23,21,22,4,19,1,9,11,20,8,3,12,2,14,5,10,18]
        self.candyMixVertical0B = [10,21,6,16,8,4,5,0,3,9,7,2,13,12,11,20,1,18,17,19,22,14,23,15]
        self.candyMixVertical0C = [19,6,17,13,8,1,4,21,2,11,7,9,5,16,14,10,0,12,20,23,3,22,15,18]
        self.candyMixVertical0D = [22,1,8,4,11,2,18,13,10,7,14,0,19,23,20,9,16,15,17,3,21,6,5,12]
        self.candyMixVertical0E = [20,18,3,19,4,6,0,15,13,17,16,22,9,23,14,2,12,1,10,8,7,11,21,5]
        self.candyMixVertical0F = [15,13,9,12,1,16,3,0,23,21,17,6,19,8,22,11,14,5,20,2,18,10,4,7]
        self.candyMixVertical10 = [13,18,4,14,9,19,2,5,16,17,10,3,7,15,21,20,8,22,11,23,1,6,0,12]
        self.candyMixVertical11 = [21,14,10,11,13,0,3,23,17,7,15,5,12,19,22,6,9,1,2,8,18,16,20,4]
        self.candyMixVertical12 = [17,22,0,20,8,12,15,13,10,2,9,14,11,4,5,18,19,16,23,1,21,6,7,3]
        self.candyMixVertical13 = [5,15,17,2,13,1,11,23,10,22,4,20,8,6,16,18,9,0,14,12,7,3,21,19]
        self.candyMixVertical14 = [1,6,22,14,3,21,4,17,2,0,9,13,10,11,23,16,15,7,19,18,8,12,5,20]
        self.candyMixVertical15 = [21,7,6,17,9,11,14,16,2,10,5,8,22,19,15,23,4,20,18,12,1,13,0,3]
        self.candyMixVertical16 = [11,18,9,12,17,13,10,22,0,1,20,16,7,19,15,3,5,8,14,21,2,23,6,4]
        self.candyMixVertical17 = [15,12,5,22,23,4,8,18,16,11,0,14,7,6,20,17,2,19,21,10,1,9,13,3]
        self.candyMixVertical18 = [16,22,2,14,11,8,7,1,17,4,13,23,12,5,21,10,9,15,0,6,3,19,20,18]
        self.candyMixVertical19 = [20,14,5,10,12,1,8,7,13,2,6,16,22,23,4,11,9,3,15,17,19,18,0,21]
        self.candyMixVertical1A = [5,14,0,23,18,16,11,1,20,2,8,10,15,6,22,19,9,4,21,17,3,7,13,12]
        self.candyMixVertical1B = [13,7,17,18,14,0,22,21,10,12,3,5,8,23,6,20,15,4,9,19,1,16,2,11]
        self.candyMixVertical1C = [6,11,4,2,20,7,22,13,3,18,14,15,5,10,17,16,21,1,0,12,19,8,9,23]
        self.candyMixVertical1D = [7,4,10,2,8,23,19,12,6,5,9,13,0,22,11,16,21,1,14,3,17,20,15,18]
        self.candyMixVertical1E = [14,22,21,16,10,4,17,15,13,12,9,0,20,11,5,7,2,19,3,18,23,8,1,6]
        self.candyMixVertical1F = [18,21,4,13,17,15,1,11,10,6,20,9,7,5,19,0,2,3,12,23,14,8,22,16]
        self.candyMixVerticals = [
        self.candyMixVertical00,
        self.candyMixVertical01,
        self.candyMixVertical02,
        self.candyMixVertical03,
        self.candyMixVertical04,
        self.candyMixVertical05,
        self.candyMixVertical06,
        self.candyMixVertical07,
        self.candyMixVertical08,
        self.candyMixVertical09,
        self.candyMixVertical0A,
        self.candyMixVertical0B,
        self.candyMixVertical0C,
        self.candyMixVertical0D,
        self.candyMixVertical0E,
        self.candyMixVertical0F,
        self.candyMixVertical10,
        self.candyMixVertical11,
        self.candyMixVertical12,
        self.candyMixVertical13,
        self.candyMixVertical14,
        self.candyMixVertical15,
        self.candyMixVertical16,
        self.candyMixVertical17,
        self.candyMixVertical18,
        self.candyMixVertical19,
        self.candyMixVertical1A,
        self.candyMixVertical1B,
        self.candyMixVertical1C,
        self.candyMixVertical1D,
        self.candyMixVertical1E,
        self.candyMixVertical1F]
        self.shuffler = [26,1,5,20,15,2,21,25,27,3,13,31,20,27,27,11,18,27,26,11,0,23,3,26]
        self.candyMixHorizontal00 = [26,27,6,4,31,15,20,2,28,12,0,23,24,18,5,8,10,25,3,21,7,9,22,13,14,1,16,30,17,19,29,11]
        self.candyMixHorizontal01 = [9,6,30,22,20,28,5,31,0,24,21,2,4,27,16,12,29,18,25,17,11,26,1,19,10,8,3,14,15,13,7,23]
        self.candyMixHorizontal02 = [6,8,19,7,16,23,20,12,28,21,1,5,14,3,13,29,9,11,10,31,27,26,4,30,18,17,15,24,22,25,0,2]
        self.candyMixHorizontal03 = [10,23,5,15,21,18,25,11,31,19,16,20,12,22,8,26,17,24,4,30,0,14,6,13,2,9,28,27,1,29,7,3]
        self.candyMixHorizontal04 = [26,14,11,18,24,8,17,6,31,23,28,9,3,1,7,16,15,19,13,2,29,10,22,27,30,0,12,25,5,4,21,20]
        self.candyMixHorizontal05 = [30,16,3,0,6,24,18,14,22,26,29,27,8,10,1,31,25,13,12,7,15,23,5,20,17,19,11,21,2,4,28,9]
        self.candyMixHorizontal06 = [1,31,17,27,16,4,5,10,15,20,14,2,22,21,23,25,0,12,13,28,6,3,11,29,9,18,24,30,26,7,8,19]
        self.candyMixHorizontal07 = [15,31,18,25,1,21,3,29,6,2,27,11,24,28,0,30,4,19,20,23,7,12,22,14,16,9,26,10,5,17,13,8]
        self.candyMixHorizontal08 = [19,2,17,9,31,11,4,30,29,13,0,25,15,23,26,1,21,20,6,22,27,16,7,24,10,18,28,14,8,5,3,12]
        self.candyMixHorizontal09 = [28,24,4,13,18,12,23,7,5,30,19,3,2,17,27,15,16,25,21,14,31,10,8,22,11,1,20,29,0,9,6,26]
        self.candyMixHorizontal0A = [8,13,14,31,21,11,16,25,28,5,2,1,22,24,17,15,10,23,7,9,19,29,20,18,4,30,27,6,0,3,26,12]
        self.candyMixHorizontal0B = [24,27,29,31,21,30,18,12,13,0,9,26,2,6,19,23,16,11,28,5,1,14,7,15,10,4,25,20,3,22,17,8]
        self.candyMixHorizontal0C = [15,9,19,27,6,30,22,17,24,14,31,10,25,16,18,12,29,20,4,7,3,8,1,26,11,0,23,28,5,21,13,2]
        self.candyMixHorizontal0D = [5,13,1,23,31,18,27,12,20,15,14,8,7,29,24,11,30,3,26,17,19,25,21,22,0,10,4,28,2,16,6,9]
        self.candyMixHorizontal0E = [29,27,15,12,30,0,4,9,14,7,22,19,5,31,8,18,6,11,23,24,2,17,3,26,21,16,1,10,20,25,13,28]
        self.candyMixHorizontal0F = [27,1,10,15,3,21,11,9,2,25,12,30,31,29,22,28,6,17,20,7,8,5,19,13,0,16,14,4,18,23,24,26]
        self.candyMixHorizontal10 = [27,26,5,20,17,25,15,10,9,28,21,7,2,8,0,23,6,24,31,3,4,11,22,13,1,12,16,30,19,14,18,29]
        self.candyMixHorizontal11 = [6,14,27,13,29,22,11,19,18,4,21,16,30,17,8,26,0,25,12,7,28,3,10,20,9,24,2,23,5,15,1,31]
        self.candyMixHorizontal12 = [1,29,9,0,20,5,18,4,27,6,24,30,15,2,25,13,7,14,19,8,17,3,11,21,12,31,23,10,22,28,26,16]
        self.candyMixHorizontal13 = [16,30,24,5,28,1,27,29,11,21,14,26,8,4,13,3,2,6,9,25,23,7,10,20,0,17,22,18,12,15,19,31]
        self.candyMixHorizontal14 = [0,28,15,30,31,3,24,16,23,17,1,11,4,2,7,13,19,12,25,27,20,10,18,8,14,6,21,29,26,22,5,9]
        self.candyMixHorizontal15 = [24,0,19,15,22,11,14,28,12,8,25,17,26,23,3,31,18,13,5,7,30,4,27,1,16,2,21,10,9,20,29,6]
        self.candyMixHorizontal16 = [14,25,1,15,28,26,27,10,13,22,19,9,3,18,23,2,21,0,6,16,4,12,8,24,29,17,11,30,20,31,5,7]
        self.candyMixHorizontal17 = [16,12,31,17,13,28,9,4,1,10,27,30,5,26,21,6,15,7,24,11,8,14,29,22,19,20,0,3,2,25,18,23]
        self.candyMixHorizontal18 = [18,19,30,15,29,11,16,26,1,25,8,9,31,3,13,20,6,23,4,28,12,10,21,5,17,14,24,22,2,27,0,7]
        self.candyMixHorizontal19 = [26,15,13,22,21,0,16,17,28,8,29,20,4,14,27,3,19,24,23,30,9,5,25,10,6,31,18,11,2,7,1,12]
        self.candyMixHorizontal1A = [10,4,11,25,1,12,14,21,16,26,31,27,20,5,24,17,19,0,28,15,7,8,29,23,3,2,22,30,9,18,13,6]
        self.candyMixHorizontal1B = [13,12,29,0,1,28,30,20,5,27,8,7,19,18,16,17,10,2,15,22,21,31,4,6,23,9,11,14,24,3,26,25]
        self.candyMixHorizontal1C = [21,23,19,28,1,10,6,17,9,16,13,8,3,29,26,2,7,0,27,22,15,5,14,12,20,25,18,24,4,31,30,11]
        self.candyMixHorizontal1D = [26,15,18,21,0,22,6,11,24,29,14,2,31,23,1,30,25,3,5,12,13,17,19,28,4,7,16,9,8,27,10,20]
        self.candyMixHorizontal1E = [14,25,27,8,24,17,2,11,1,12,19,16,0,30,29,6,22,3,21,15,13,18,20,28,7,31,26,5,9,4,23,10]
        self.candyMixHorizontal1F = [12,10,11,20,19,8,18,6,0,28,29,26,15,23,27,31,1,5,30,13,25,16,7,2,4,17,14,22,24,9,21,3]
        self.candyMixHorizontals = [
        self.candyMixHorizontal00,
        self.candyMixHorizontal01,
        self.candyMixHorizontal02,
        self.candyMixHorizontal03,
        self.candyMixHorizontal04,
        self.candyMixHorizontal05,
        self.candyMixHorizontal06,
        self.candyMixHorizontal07,
        self.candyMixHorizontal08,
        self.candyMixHorizontal09,
        self.candyMixHorizontal0A,
        self.candyMixHorizontal0B,
        self.candyMixHorizontal0C,
        self.candyMixHorizontal0D,
        self.candyMixHorizontal0E,
        self.candyMixHorizontal0F,
        self.candyMixHorizontal10,
        self.candyMixHorizontal11,
        self.candyMixHorizontal12,
        self.candyMixHorizontal13,
        self.candyMixHorizontal14,
        self.candyMixHorizontal15,
        self.candyMixHorizontal16,
        self.candyMixHorizontal17,
        self.candyMixHorizontal18,
        self.candyMixHorizontal19,
        self.candyMixHorizontal1A,
        self.candyMixHorizontal1B,
        self.candyMixHorizontal1C,
        self.candyMixHorizontal1D,
        self.candyMixHorizontal1E,
        self.candyMixHorizontal1F]

        self.Expiration = expiration
        self.Generation = generation
        self.Product = product
        self.Flags = flags
        self.Count = count
        self.Random = random
        self.Type = ptype
        self.Shuffle = shuffle
        self.binary = self.to_bytes()
        self.array = self.binary_to_array()
        self.unshuffledarray = self.unshuffle_array()
        self.key = self.array_to_string()

    def to_bytes(self):
        print(f"[+] to_bytes: {bytes(self)}")
        return bytes(self)

    def binary_to_array(self):
        arr = [0] * 25
        
        def process_chunk(b, i, s):
            num = (int(b[i]) << 32) | \
                  (int(b[i + 1]) << 24) | \
                  (int(b[i + 2]) << 16) | \
                  (int(b[i + 3]) << 8) | \
                  int(b[i + 4])
            
            for j in range(8):
                arr[s + j] = (num >> (35 - (5 * j))) & 0x1F

            return i + 5, s + 8

        i, s = 0, 0
        for _ in range(3):
            i, s = process_chunk(self.binary, i, s)
        print(f"[+] Binary to array: {arr}")
        return arr

    def unshuffle_array(self):
        # now lets find a valid shuffle
        for shuffle in range(32):
            arr = [0]*25

            for i in range(24):
                arr[self.candyMixVerticals[shuffle].index(i)] = self.candyMixHorizontals[self.array[24]].index(self.array[i])

            if shuffle == (sum(arr) + sum(self.shuffler)) % 32:
                print(f"[+] shuffle: {shuffle}")
                print(f"[+] shuffle_array: {arr}")
                return arr
        return None

    def array_to_string(self):
        output_str = ''.join(chr(self.candyMap.index(self.unshuffledarray[i])) for i in range(25))
        out = '-'.join(output_str[i:i+5] for i in range(0, len(output_str), 5))
        print(f"[+] arr_to_license: {out}\n")
        return out

now = int(datetime.now().timestamp())+10000
now2 = now
ccb = CandyCaneBlock(now,
                     now2, 
                     ProductNames.CandyCaneMachine.value, 
                     0, 
                     0, 
                     0, 
                     ProductTypes.Premium.value, 
                     0)
