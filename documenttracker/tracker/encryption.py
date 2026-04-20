"""
IDEA (International Data Encryption Algorithm) Implementation
This is a custom implementation of IDEA for educational purposes.
IDEA uses 64-bit blocks and 128-bit keys.
"""

import struct
from typing import Tuple


class IDEA:
    """
    International Data Encryption Algorithm (IDEA) implementation.
    
    IDEA is a 64-bit block cipher with a 128-bit key.
    It supports encryption and decryption of 64-bit blocks.
    """
    
    # IDEA constants
    BLOCK_SIZE = 8  # 64 bits / 8 bytes
    KEY_SIZE = 16   # 128 bits / 16 bytes
    
    def __init__(self, key: bytes):
        """
        Initialize IDEA with a 128-bit (16-byte) key.
        
        Args:
            key: 16-byte key for IDEA encryption
            
        Raises:
            ValueError: If key length is not 16 bytes
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")
        
        self.key = key
        # Generate encryption and decryption subkeys
        self.enc_keys = self._expand_key_encryption()
        self.dec_keys = self._expand_key_decryption()
    
    @staticmethod
    def _mod_inverse(x: int, m: int = 65537) -> int:
        """
        Calculate modular multiplicative inverse of x modulo m.
        Uses extended Euclidean algorithm.
        
        Args:
            x: Number to find inverse of
            m: Modulo value (default: 65537, which is 2^16 + 1)
            
        Returns:
            Modular multiplicative inverse
        """
        if x == 0:
            return 0
        
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        _, x_inv, _ = extended_gcd(x % m, m)
        return (x_inv % m + m) % m
    
    @staticmethod
    def _mul(x: int, y: int) -> int:
        """
        Multiply two 16-bit numbers modulo (2^16 + 1).
        This is used in IDEA's multiplication operations.
        
        Args:
            x: First number (16-bit)
            y: Second number (16-bit)
            
        Returns:
            Result of x * y mod (2^16 + 1)
        """
        # Convert 0 to 65536 for multiplication
        x = 0x10001 if x == 0 else x
        y = 0x10001 if y == 0 else y
        
        result = (x * y) % 0x10001
        return 0 if result == 0x10001 else result
    
    @staticmethod
    def _add(x: int, y: int) -> int:
        """
        Add two 16-bit numbers modulo 2^16.
        
        Args:
            x: First number (16-bit)
            y: Second number (16-bit)
            
        Returns:
            (x + y) mod 2^16
        """
        return (x + y) & 0xFFFF
    
    def _expand_key_encryption(self) -> list:
        """
        Expand the 128-bit key into 52 16-bit subkeys for encryption.
        IDEA uses 8 rounds, each requiring 6 subkeys, plus 4 for the output.
        
        Returns:
            List of 52 16-bit encryption subkeys
        """
        # Convert key bytes to 8 16-bit words
        key_words = struct.unpack('>8H', self.key)
        
        subkeys = []
        key_idx = 0
        
        # Generate 52 subkeys total (8 rounds * 6 + 4)
        for round_num in range(9):  # 8 rounds + output transformation
            for _ in range(6 if round_num < 8 else 4):
                subkeys.append(key_words[key_idx % 8])
                key_idx = (key_idx + 1) % 8
        
        return subkeys
    
    def _expand_key_decryption(self) -> list:
        """
        Generate decryption subkeys from encryption subkeys.
        
        Returns:
            List of 52 16-bit decryption subkeys
        """
        enc = self.enc_keys
        dec = []
        
        # Reverse the key schedule for decryption
        for round_num in range(8, -1, -1):
            if round_num == 8:
                # Output transformation keys stay the same (inversed)
                dec.append(self._mod_inverse(enc[round_num * 6]))
                dec.append(self._add(0, self._mod_inverse(enc[round_num * 6 + 1])))
                dec.append(self._add(0, self._mod_inverse(enc[round_num * 6 + 2])))
                dec.append(self._mod_inverse(enc[round_num * 6 + 3]))
            else:
                # Standard round keys
                dec.append(self._mod_inverse(enc[round_num * 6]))
                dec.append(self._add(0, self._mod_inverse(enc[round_num * 6 + 1])))
                dec.append(self._add(0, self._mod_inverse(enc[round_num * 6 + 2])))
                dec.append(self._mod_inverse(enc[round_num * 6 + 3]))
                dec.append(enc[round_num * 6 + 4])
                dec.append(enc[round_num * 6 + 5])
        
        return dec
    
    def _encrypt_block(self, plaintext: bytes) -> bytes:
        """
        Encrypt a single 64-bit block.
        
        Args:
            plaintext: 8-byte plaintext block
            
        Returns:
            8-byte ciphertext block
        """
        if len(plaintext) != self.BLOCK_SIZE:
            raise ValueError(f"Block must be {self.BLOCK_SIZE} bytes")
        
        # Convert plaintext to 4 16-bit words
        x = list(struct.unpack('>4H', plaintext))
        
        # 8 encryption rounds
        for round_num in range(8):
            key_offset = round_num * 6
            k = self.enc_keys[key_offset:key_offset + 6]
            
            # IDEA round function
            t0 = self._mul(x[0], k[0])
            t1 = self._add(x[1], k[1])
            t2 = self._add(x[2], k[2])
            t3 = self._mul(x[3], k[3])
            
            t4 = self._mul(self._add(t0, t2), k[4])
            t5 = self._mul(self._add(t1, t3), k[5])
            t6 = self._add(t4, t5)
            
            x[0] = self._add(t0, t5)
            x[1] = self._add(t2, t4)
            x[2] = self._add(t1, t6)
            x[3] = self._add(t3, t6)
        
        # Output transformation
        k = self.enc_keys[48:52]
        y = [
            self._mul(x[0], k[0]),
            self._add(x[1], k[1]),
            self._add(x[2], k[2]),
            self._mul(x[3], k[3])
        ]
        
        return struct.pack('>4H', *y)
    
    def _decrypt_block(self, ciphertext: bytes) -> bytes:
        """
        Decrypt a single 64-bit block.
        
        Args:
            ciphertext: 8-byte ciphertext block
            
        Returns:
            8-byte plaintext block
        """
        if len(ciphertext) != self.BLOCK_SIZE:
            raise ValueError(f"Block must be {self.BLOCK_SIZE} bytes")
        
        # Convert ciphertext to 4 16-bit words
        x = list(struct.unpack('>4H', ciphertext))
        
        # 8 decryption rounds
        for round_num in range(8):
            key_offset = round_num * 6
            k = self.dec_keys[key_offset:key_offset + 6]
            
            # IDEA round function for decryption
            t0 = self._mul(x[0], k[0])
            t1 = self._add(x[1], k[1])
            t2 = self._add(x[2], k[2])
            t3 = self._mul(x[3], k[3])
            
            t4 = self._mul(self._add(t0, t2), k[4])
            t5 = self._mul(self._add(t1, t3), k[5])
            t6 = self._add(t4, t5)
            
            x[0] = self._add(t0, t5)
            x[1] = self._add(t2, t4)
            x[2] = self._add(t1, t6)
            x[3] = self._add(t3, t6)
        
        # Output transformation for decryption
        k = self.dec_keys[48:52]
        y = [
            self._mul(x[0], k[0]),
            self._add(x[1], k[1]),
            self._add(x[2], k[2]),
            self._mul(x[3], k[3])
        ]
        
        return struct.pack('>4H', *y)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using ECB mode (pad to multiple of 8 bytes).
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Encrypted data
        """
        # PKCS7 padding
        padding_len = self.BLOCK_SIZE - (len(plaintext) % self.BLOCK_SIZE)
        padded = plaintext + bytes([padding_len] * padding_len)
        
        ciphertext = b''
        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            ciphertext += self._encrypt_block(block)
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using ECB mode.
        
        Args:
            ciphertext: Data to decrypt
            
        Returns:
            Decrypted data (unpadded)
        """
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError(f"Ciphertext length must be multiple of {self.BLOCK_SIZE}")
        
        plaintext = b''
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]
            plaintext += self._decrypt_block(block)
        
        # Remove PKCS7 padding
        padding_len = plaintext[-1]
        if padding_len > self.BLOCK_SIZE or padding_len == 0:
            raise ValueError("Invalid padding")
        
        return plaintext[:-padding_len]


def generate_idea_key() -> bytes:
    """
    Generate a random 128-bit (16-byte) IDEA key.
    
    Returns:
        Random 16-byte key
    """
    import os
    return os.urandom(16)


def encrypt_data(data: str, key: bytes) -> str:
    """
    Encrypt data using IDEA and return as hex string.
    
    Args:
        data: String to encrypt
        key: 16-byte IDEA key
        
    Returns:
        Hex-encoded encrypted data
    """
    idea = IDEA(key)
    plaintext = data.encode('utf-8')
    ciphertext = idea.encrypt(plaintext)
    return ciphertext.hex()


def decrypt_data(encrypted_hex: str, key: bytes) -> str:
    """
    Decrypt IDEA-encrypted hex data.
    
    Args:
        encrypted_hex: Hex-encoded encrypted data
        key: 16-byte IDEA key
        
    Returns:
        Decrypted string
    """
    idea = IDEA(key)
    ciphertext = bytes.fromhex(encrypted_hex)
    plaintext = idea.decrypt(ciphertext)
    return plaintext.decode('utf-8')
