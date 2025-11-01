"""
Advanced FXAP Decryptor
Enhanced version with multiple decryption strategies and better format support
"""

import struct
import hashlib
import base64
import zlib
import logging
import re

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

_ZLIB_SIGNATURES = (b"\x78\x01", b"\x78\x9c", b"\x78\xda")
_GZIP_SIGNATURE = b"\x1f\x8b"
_MAX_RESOURCE_SCAN_BYTES = 200_000
_MAX_LUA_VALIDATION_BYTES = 200_000
_MAX_DECOMPRESSED_BYTES = 5_000_000
_MAX_KEY_ATTEMPTS = 32
_LUA_PATTERN_STRINGS = [
    r"\bfunction\s+\w+",
    r"\blocal\s+\w+",
    r"\bend\b",
    r"\bif\s+.+\bthen\b",
    r"\bfor\s+\w+",
    r"\bwhile\s+.+\bdo\b",
    r"\breturn\b",
    r"\brequire\s*\(",
    r"CreateThread\s*\(",
    r"Citizen\.",
    r"ESX\.",
    r"QBCore\.",
    r"RegisterNetEvent",
    r"AddEventHandler",
    r"--.*",
]
_LUA_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in _LUA_PATTERN_STRINGS]
_RESOURCE_PATTERN_STRINGS = [
    r"resource_manifest_version\s+[\'"](.*?)[\'"]",
    r"fx_version\s+[\'"](.*?)[\'"]",
    r"name\s+[\'"](.*?)[\'"]",
    r"@([a-zA-Z0-9_-]+)",
    r"resource[_-]([a-zA-Z0-9_-]+)",
]
_RESOURCE_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in _RESOURCE_PATTERN_STRINGS]
_PRINTABLE_WHITESPACE = {"\n", "\r", "\t"}
_CHACHA_OFFSETS = (0, 12, 16, 20)

class AdvancedFXAPDecryptor:
    def __init__(self, server_key=None):
        """
        Advanced FXAP decryptor with multiple strategies
        
        Args:
            server_key (str): FiveM server key for keymaster API access
        """
        self.server_key = server_key
        self.backend = default_backend()
        
        # Known FXAP signatures and magic bytes
        self.FXAP_SIGNATURES = [
            b'FXAP',
            b'FXP2',
            b'FXAP\x01\x00\x00\x00',
            b'FXAP\x02\x00\x00\x00',
            b'\x1b\x4c\x75\x61',  # Lua bytecode header
        ]
        
        # Common FiveM encryption keys (for educational purposes)
        self.COMMON_KEYS = [
            b'fivem_default_key_2023',
            b'cfx_encryption_key_v2',
            b'fxserver_protection_key',
        ]

    def is_fxap_encrypted(self, file_data: bytes) -> bool:
        """Return True if the payload appears to be FXAP protected."""
        if not file_data:
            return False
        return any(file_data.startswith(signature) for signature in self.FXAP_SIGNATURES)
    
    def detect_encryption_type(self, file_data):
        """
        Detect the type of encryption used
        
        Args:
            file_data (bytes): Raw file data
            
        Returns:
            str: Encryption type ('fxap', 'lua_bytecode', 'xor', 'unknown')
        """
        if len(file_data) < 4:
            return 'unknown'
        
        # Check for FXAP signatures
        if self.is_fxap_encrypted(file_data):
            return 'fxap'
        
        # Check for Lua bytecode
        if file_data.startswith(b'\x1b\x4c\x75\x61'):
            return 'lua_bytecode'
        
        # Check for base64 encoding
        try:
            decoded = base64.b64decode(file_data[:100])
            if any(sig in decoded for sig in self.FXAP_SIGNATURES):
                return 'base64_fxap'
        except:
            pass
        
        # Check for simple XOR patterns
        if self.detect_xor_pattern(file_data):
            return 'xor'
        
        return 'unknown'
    
    def detect_xor_pattern(self, data):
        """
        Detect if data might be XOR encrypted by looking for patterns
        
        Args:
            data (bytes): File data
            
        Returns:
            bool: True if XOR pattern detected
        """
        if len(data) < 100:
            return False
        
        # Look for repeating patterns that might indicate XOR
        sample = data[:100]
        
        # Check for high entropy (might indicate encryption)
        unique_bytes = len(set(sample))
        if unique_bytes > 80:  # High entropy
            return True
        
        # Check for null byte patterns
        null_count = sample.count(0)
        if null_count > len(sample) * 0.3:  # Too many nulls
            return False
        
        return False
    
    def try_chacha20_decrypt(self, data, key, nonce=None):
        """
        Attempt ChaCha20 decryption with various nonce strategies
        
        Args:
            data (bytes): Encrypted data
            key (bytes): Decryption key
            nonce (bytes): Nonce (if None, will try to extract or generate)
            
        Returns:
            bytes: Decrypted data or None
        """
        if len(key) != 32:
            key = hashlib.sha256(key).digest()
        
        nonces_to_try = []

        if nonce:
            nonces_to_try.append(nonce[:12])

        if len(data) >= 12:
            nonces_to_try.extend([data[:12], data[-12:]])

        nonces_to_try.extend([
            b'\x00' * 12,
            b'\x01' * 12,
            hashlib.sha256(key).digest()[:12],
        ])

        unique_nonces = []
        seen_nonces = set()
        for candidate in nonces_to_try:
            if not candidate or len(candidate) != 12:
                continue
            if candidate in seen_nonces:
                continue
            seen_nonces.add(candidate)
            unique_nonces.append(candidate)

        for test_nonce in unique_nonces:
            try:
                cipher = Cipher(algorithms.ChaCha20(key, test_nonce), mode=None, backend=self.backend)
                for offset in _CHACHA_OFFSETS:
                    if len(data) <= offset:
                        continue

                    decryptor = cipher.decryptor()
                    test_data = data[offset:]
                    try:
                        result = decryptor.update(test_data) + decryptor.finalize()
                    except Exception:
                        continue

                    if self.is_valid_lua_content(result):
                        return result
            except Exception as e:
                logger.debug(f"ChaCha20 attempt failed: {e}")
                continue
        
        return None
    
    def try_aes_decrypt(self, data, key):
        """
        Attempt AES decryption with various modes
        
        Args:
            data (bytes): Encrypted data
            key (bytes): Decryption key
            
        Returns:
            bytes: Decrypted data or None
        """
        if len(key) != 32:
            key = hashlib.sha256(key).digest()
        
        # Try different AES modes
        modes_to_try = [
            ('ECB', None),
            ('CBC', data[:16] if len(data) >= 16 else b'\x00' * 16),
            ('CTR', data[:16] if len(data) >= 16 else b'\x00' * 16),
        ]
        
        for mode_name, iv in modes_to_try:
            try:
                if mode_name == 'ECB':
                    mode = modes.ECB()
                    test_data = data
                elif mode_name == 'CBC':
                    mode = modes.CBC(iv)
                    test_data = data[16:] if len(data) > 16 else data
                elif mode_name == 'CTR':
                    mode = modes.CTR(iv)
                    test_data = data[16:] if len(data) > 16 else data
                
                cipher = Cipher(algorithms.AES(key), mode, backend=self.backend)
                decryptor = cipher.decryptor()
                
                result = decryptor.update(test_data) + decryptor.finalize()
                
                # Remove PKCS7 padding if present
                if mode_name in ['CBC', 'ECB']:
                    try:
                        pad_len = result[-1]
                        if pad_len <= 16 and all(b == pad_len for b in result[-pad_len:]):
                            result = result[:-pad_len]
                    except:
                        pass
                
                if self.is_valid_lua_content(result):
                    return result
                    
            except Exception as e:
                logger.debug(f"AES {mode_name} attempt failed: {e}")
                continue
        
        return None
    
    def try_xor_decrypt(self, data, keys=None):
        """
        Attempt XOR decryption with various keys
        
        Args:
            data (bytes): Encrypted data
            keys (list): List of keys to try (if None, uses common keys)
            
        Returns:
            bytes: Decrypted data or None
        """
        if keys is None:
            keys = self.COMMON_KEYS + [
                data[:16] if len(data) >= 16 else b'default_key',
                hashlib.md5(data[:32]).digest() if len(data) >= 32 else b'fallback_key',
            ]
        
        for key in keys:
            try:
                if not key:
                    continue

                key_bytes = bytes(key)
                key_len = len(key_bytes)
                if key_len == 0:
                    continue

                result = bytearray()
                
                for i, byte in enumerate(data):
                    result.append(byte ^ key_bytes[i % key_len])
                
                result_bytes = bytes(result)
                if self.is_valid_lua_content(result_bytes):
                    return result_bytes
                    
            except Exception as e:
                logger.debug(f"XOR attempt failed: {e}")
                continue
        
        return None
    
    def try_base64_decode(self, data):
        """
        Attempt to decode base64 encoded data
        
        Args:
            data (bytes): Potentially base64 encoded data
            
        Returns:
            bytes: Decoded data or None
        """
        try:
            # Try direct base64 decode
            decoded = base64.b64decode(data)
            return decoded
        except:
            pass
        
        try:
            # Try with padding
            padded = data + b'=' * (4 - len(data) % 4)
            decoded = base64.b64decode(padded)
            return decoded
        except:
            pass
        
        return None
    
    def try_compression_decompress(self, data):
        """
        Attempt to decompress data using various algorithms
        
        Args:
            data (bytes): Potentially compressed data
            
        Returns:
            bytes: Decompressed data or None
        """
        if len(data) < 2:
            return None

        if data[:2] in _ZLIB_SIGNATURES:
            try:
                decompressed = zlib.decompress(data, max_length=_MAX_DECOMPRESSED_BYTES)
                return decompressed
            except Exception:
                pass

        if data.startswith(_GZIP_SIGNATURE):
            try:
                import gzip

                decompressed = gzip.decompress(data)
                if len(decompressed) > _MAX_DECOMPRESSED_BYTES:
                    return decompressed[:_MAX_DECOMPRESSED_BYTES]
                return decompressed
            except Exception:
                pass

        return None
    
    def is_valid_lua_content(self, data):
        """
        Enhanced validation for Lua content
        
        Args:
            data (bytes): Data to validate
            
        Returns:
            bool: True if content appears to be valid Lua
        """
        if len(data) > _MAX_LUA_VALIDATION_BYTES:
            data = data[:_MAX_LUA_VALIDATION_BYTES]

        try:
            content = data.decode('utf-8', errors='ignore')
        except Exception:
            return False

        if len(content.strip()) < 10:
            return False

        sample_content = content if len(content) <= _MAX_LUA_VALIDATION_BYTES else content[:_MAX_LUA_VALIDATION_BYTES]
        pattern_matches = sum(1 for pattern in _LUA_PATTERNS if pattern.search(sample_content))

        if pattern_matches >= 3 and sample_content:
            printable_chars = sum(1 for c in sample_content if c.isprintable() or c in _PRINTABLE_WHITESPACE)
            printable_ratio = printable_chars / len(sample_content)
            return printable_ratio > 0.8

        return False
    
    def decrypt_file_advanced(self, file_data):
        """
        Advanced decryption with multiple strategies
        
        Args:
            file_data (bytes): Raw encrypted file data
            
        Returns:
            tuple: (success: bool, decrypted_content: str, method_used: str, error_message: str)
        """
        try:
            logger.info("Starting advanced FXAP decryption")
            
            # Detect encryption type
            encryption_type = self.detect_encryption_type(file_data)
            logger.info(f"Detected encryption type: {encryption_type}")
            
            # Strategy 1: Handle base64 encoded files
            if encryption_type == 'base64_fxap':
                decoded_data = self.try_base64_decode(file_data)
                if decoded_data:
                    success, content, method, error = self.decrypt_file_advanced(decoded_data)
                    if success:
                        return True, content, f"base64+{method}", error
            
            # Strategy 2: Handle compressed files
            decompressed = self.try_compression_decompress(file_data)
            if decompressed and decompressed != file_data:
                success, content, method, error = self.decrypt_file_advanced(decompressed)
                if success:
                    return True, content, f"compressed+{method}", error
            
            # Strategy 3: Direct Lua bytecode
            if encryption_type == 'lua_bytecode':
                try:
                    # Try to decode Lua bytecode directly
                    content = file_data.decode('utf-8', errors='ignore')
                    if self.is_valid_lua_content(file_data):
                        return True, content, "lua_bytecode", ""
                except:
                    pass
            
            # Strategy 4: FXAP decryption
            if encryption_type in ['fxap', 'unknown']:
                # Extract resource ID if possible
                resource_id = self.extract_resource_id_advanced(file_data)
                
                # Generate multiple keys to try
                keys_to_try = []
                
                if resource_id:
                    # Generate keys based on resource ID
                    keys_to_try.extend([
                        hashlib.sha256(f"fxap_{resource_id}".encode()).digest(),
                        hashlib.sha256(f"{resource_id}_key".encode()).digest(),
                        hashlib.md5(resource_id.encode()).digest() * 2,  # Extend to 32 bytes
                    ])
                
                # Add common keys
                keys_to_try.extend([
                    hashlib.sha256(key).digest() for key in self.COMMON_KEYS
                ])
                
                # Add keys derived from file content
                keys_to_try.extend([
                    hashlib.sha256(file_data[:32]).digest(),
                    hashlib.sha256(file_data[-32:]).digest(),
                ])
                
                normalized_keys = []
                seen_keys = set()
                for candidate in keys_to_try:
                    if not candidate:
                        continue
                    normalized = candidate if len(candidate) == 32 else hashlib.sha256(candidate).digest()
                    if normalized in seen_keys:
                        continue
                    seen_keys.add(normalized)
                    normalized_keys.append(normalized)
                    if len(normalized_keys) >= _MAX_KEY_ATTEMPTS:
                        break
                
                total_keys = len(normalized_keys)
                for i, key in enumerate(normalized_keys):
                    logger.debug(f"Trying key {i+1}/{total_keys}")
                    
                    # Method 1: ChaCha20
                    result = self.try_chacha20_decrypt(file_data, key)
                    if result:
                        try:
                            content = result.decode('utf-8')
                            return True, content, "chacha20", ""
                        except UnicodeDecodeError:
                            pass
                    
                    # Method 2: AES
                    result = self.try_aes_decrypt(file_data, key)
                    if result:
                        try:
                            content = result.decode('utf-8')
                            return True, content, "aes", ""
                        except UnicodeDecodeError:
                            pass
                    
                    # Method 3: XOR
                    result = self.try_xor_decrypt(file_data, [key])
                    if result:
                        try:
                            content = result.decode('utf-8')
                            return True, content, "xor", ""
                        except UnicodeDecodeError:
                            pass
            
            # Strategy 5: Brute force with common patterns
            return self.brute_force_decrypt(file_data)
            
        except Exception as e:
            logger.error(f"Advanced decryption error: {e}")
            return False, "", "", f"Decryption failed: {str(e)}"
    
    def extract_resource_id_advanced(self, file_data):
        """
        Advanced resource ID extraction with multiple strategies
        
        Args:
            file_data (bytes): Raw file data
            
        Returns:
            str: Resource ID if found, None otherwise
        """
        try:
            # Strategy 1: Standard FXAP format
            if file_data.startswith(b'FXAP'):
                offset = 8  # Skip magic and version
                if len(file_data) >= offset + 4:
                    id_length = struct.unpack('<I', file_data[offset:offset+4])[0]
                    if 0 < id_length < 256 and len(file_data) >= offset + 4 + id_length:
                        resource_id = file_data[offset+4:offset+4+id_length].decode('utf-8', errors='ignore')
                        if resource_id.isalnum() or '_' in resource_id:
                            return resource_id
            
            # Strategy 2: Search for embedded resource IDs
            sample_bytes = file_data[:_MAX_RESOURCE_SCAN_BYTES]
            text_data = sample_bytes.decode('utf-8', errors='ignore')
            
            for pattern in _RESOURCE_PATTERNS:
                match = pattern.search(text_data)
                if not match:
                    continue
                candidate = match.group(1) if match.lastindex else match.group(0)
                candidate = candidate.strip()
                if candidate:
                    return candidate
            
            # Strategy 3: Extract from filename-like strings
            for word in re.findall(r'[a-zA-Z0-9_-]{3,20}', text_data)[:20]:
                if len(word) >= 5 and not word.isdigit():
                    return word
            
        except Exception as e:
            logger.debug(f"Resource ID extraction error: {e}")
        
        return None
    
    def brute_force_decrypt(self, file_data):
        """
        Last resort brute force decryption attempts
        
        Args:
            file_data (bytes): Encrypted file data
            
        Returns:
            tuple: (success: bool, content: str, method: str, error: str)
        """
        logger.info("Attempting brute force decryption")
        
        # Try simple byte operations
        operations = [
            lambda x: bytes(b ^ 0xFF for b in x),  # Flip all bits
            lambda x: bytes(b ^ 0xAA for b in x),  # XOR with 0xAA
            lambda x: bytes(b ^ 0x55 for b in x),  # XOR with 0x55
            lambda x: x[::-1],  # Reverse bytes
            lambda x: bytes((b + 1) % 256 for b in x),  # Add 1 to each byte
            lambda x: bytes((b - 1) % 256 for b in x),  # Subtract 1 from each byte
        ]
        
        for i, operation in enumerate(operations):
            try:
                result = operation(file_data)
                if self.is_valid_lua_content(result):
                    content = result.decode('utf-8')
                    return True, content, f"brute_force_{i}", ""
            except:
                continue
        
        return False, "", "", "All decryption methods failed"

# Backward compatibility
class FXAPDecryptor(AdvancedFXAPDecryptor):
    """Backward compatible wrapper"""
    
    def decrypt_file(self, file_data):
        """
        Main decryption function (backward compatible)
        
        Args:
            file_data (bytes): Raw encrypted file data
            
        Returns:
            tuple: (success: bool, decrypted_content: str, error_message: str)
        """
        success, content, method, error = self.decrypt_file_advanced(file_data)
        if success:
            logger.info(f"Decryption successful using method: {method}")
        return success, content, error
    
    def is_valid_lua(self, content):
        """Backward compatible validation"""
        return self.is_valid_lua_content(content.encode('utf-8') if isinstance(content, str) else content)