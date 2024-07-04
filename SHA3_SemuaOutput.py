class Sha3:
    @staticmethod
    def hash224(pesan):
        opsi = {'padding': 'sha-3', 'msgFormat': 'string', 'outFormat': 'hex'}
        return Sha3.keccak1600(1152, 448, pesan, opsi)
    
    @staticmethod
    def hash256(pesan):
        opsi = {'padding': 'sha-3', 'msgFormat': 'string', 'outFormat': 'hex'}
        return Sha3.keccak1600(1088, 512, pesan, opsi)
    
    @staticmethod
    def hash384(pesan):
        opsi = {'padding': 'sha-3', 'msgFormat': 'string', 'outFormat': 'hex'}
        return Sha3.keccak1600(832, 768, pesan, opsi)
    
    @staticmethod
    def hash512(pesan):
        opsi = {'padding': 'sha-3', 'msgFormat': 'string', 'outFormat': 'hex'}
        return Sha3.keccak1600(576, 1024, pesan, opsi)

    @staticmethod
    def keccak1600(r, c, pesan, opsi):
        defaults = {'padding': 'sha-3', 'msgFormat': 'string', 'outFormat': 'hex'}
        opt = {**defaults, **opsi}

        panjang_output_bit = c // 2

        msg = Sha3.hex_bytes_to_string(pesan) if opt['msgFormat'] == 'hex-bytes' else Sha3.utf8_encode(pesan)

        state = [[0 for _ in range(5)] for _ in range(5)]

        q = (r // 8) - len(msg) % (r // 8)
        msg += chr(0x01 if opt['padding'] == 'keccak' else 0x06) + chr(0x00) * (q - 2) + chr(0x80)

        ukuran_blok = r // 64 * 8
        for i in range(0, len(msg), ukuran_blok):
            for j in range(r // 64):
                x = j % 5
                y = j // 5
                lane = int.from_bytes(msg[i + j * 8:i + j * 8 + 8].encode('latin-1'), 'little')
                state[x][y] ^= lane
            Sha3.keccak_f1600(state)

        # Step 4: Transposisi state
        transposed_state = Sha3.transpose(state)

        # Step 5: Squeezing fase (dengan debugging)
        hash_val = ''.join([''.join([format(lane, '016x')[i:i+2] for i in range(0, 16, 2)][::-1]) for plane in transposed_state for lane in plane])
        hash_val = hash_val[:panjang_output_bit // 4]

        if opt['outFormat'] == 'hex-b':
            hash_val = ' '.join(hash_val[i:i+2] for i in range(0, len(hash_val), 2))
        elif opt['outFormat'] == 'hex-w':
            hash_val = ' '.join(hash_val[i:i+8] for i in range(0, len(hash_val), 8))

        return hash_val

    @staticmethod
    def keccak_f1600(state):
        konstanta_putaran = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
            0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
        ]

        for round in range(24):
            C = [0] * 5
            for x in range(5):
                for y in range(5):
                    C[x] ^= state[x][y]

            D = [0] * 5
            for x in range(5):
                D[x] = C[(x + 4) % 5] ^ Sha3.rotate_left(C[(x + 1) % 5], 1)
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= D[x]

            x, y = 1, 0
            current = state[x][y]
            for t in range(24):
                X, Y = y, (2 * x + 3 * y) % 5
                temp = state[X][Y]
                state[X][Y] = Sha3.rotate_left(current, ((t + 1) * (t + 2) // 2) % 64)
                current = temp
                x, y = X, Y

            for y in range(5):
                C = [row[y] for row in state]
                for x in range(5):
                    state[x][y] = C[x] ^ (~C[(x + 1) % 5] & C[(x + 2) % 5])

            state[0][0] ^= konstanta_putaran[round]

    @staticmethod
    def rotate_left(value, shift):
        return ((value << shift) & ((1 << 64) - 1)) | (value >> (64 - shift))

    @staticmethod
    def transpose(matrix):
        # Transpose the matrix to match JavaScript's implementation
        transposed = [[matrix[y][x] for y in range(5)] for x in range(5)]
        return transposed

    @staticmethod
    def utf8_encode(string):
        return ''.join([chr(byte) for byte in string.encode('utf-8')])

    @staticmethod
    def hex_bytes_to_string(hex_str):
        return bytes.fromhex(hex_str).decode('latin-1')

# # Contoh fungsi untuk menghitung hash dari string "hello" menggunakan SHA-3 256
# def main_hash():
#     pesan = "hello" #input yang bisa dirubah sesuai masukan user
#     hash_val_custom = Sha3.hash224(pesan)
#     print("Hash dari 'hello' (Perhitungan Manual SHA-3 224):", hash_val_custom)

#     hash_val_custom = Sha3.hash256(pesan)
#     print("Hash dari 'hello' (Perhitungan Manual SHA-3 256):", hash_val_custom)

#     hash_val_custom = Sha3.hash384(pesan)
#     print("Hash dari 'hello' (Perhitungan Manual SHA-3 384):", hash_val_custom)

#     hash_val_custom = Sha3.hash512(pesan)
#     print("Hash dari 'hello' (Perhitungan Manual SHA-3 512):", hash_val_custom)
    
# # Menjalankan contoh fungsi
# main_hash()
