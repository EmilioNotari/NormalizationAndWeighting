import tenseal as ts
import numpy as np
from typing import Optional

class Hospital:
    def __init__(self, id: int):
        self.id = id
        self.context = None
        self.public_context = None
        self.secret_key = None
    
    def generate_keys(self):
        """Genera par de claves para el hospital"""
        self.context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree = 16384,
            coeff_mod_bit_sizes = [40, 20, 20, 40]
        )
        self.context.global_scale = 2**75
        self.secret_key = self.context.secret_key()
        
        # Contexto público para compartir
        self.public_context = self.context.copy()
        self.public_context.make_context_public()
        
        return self.public_context.serialize()
    
    def encrypt(self, data: np.ndarray, previous_encrypted: Optional[ts.CKKSVector] = None) -> ts.CKKSVector:
        """Encripta datos, opcionalmente sobre una encriptación previa"""
        if previous_encrypted is None:
            return ts.ckks_vector(self.context, data.tolist())
        else:
            # Creamos un nuevo vector cifrado con el mismo contexto
            re_encrypted = ts.ckks_vector_from(self.context, previous_encrypted.serialize())
            return re_encrypted
    
    def decrypt_layer(self, encrypted_data: ts.CKKSVector): # -> np.ndarray:
        """Descifra una capa de encriptación"""
        #encrypted_data.link_context(self.context)
        return np.array(encrypted_data.decrypt())

class ChainEncryptionSystem:
    def __init__(self, num_hospitals: int):
        self.num_hospitals = num_hospitals
        self.hospitals = [Hospital(i) for i in range(num_hospitals)]
        self.chain_encrypted_data = None
        self.encryption_order = []
    
    def setup(self):
        """Configuración inicial: generación de claves"""
        print("Configurando hospitales...")
        for hospital in self.hospitals:
            hospital.generate_keys()
            print(f"Hospital {hospital.id} ha generado sus claves")
    
    def chain_encrypt(self, plain_data: np.ndarray) -> ts.CKKSVector:
        """Encriptación en cadena por todos los hospitales"""    
        current_encrypted = None
        self.encryption_order = []
        
        print("\nIniciando encriptación en cadena:")
        for i, hospital in enumerate(self.hospitals):
            current_encrypted = hospital.encrypt(
                plain_data if i == 0 else None, 
                previous_encrypted=current_encrypted
            )
            self.encryption_order.append(hospital.id)
            print(f"Capa {i+1} añadida por Hospital {hospital.id}")
        
        self.chain_encrypted_data = current_encrypted
        return current_encrypted
    
    def chain_decrypt(self, encrypted_data: ts.CKKSVector) -> np.ndarray:
        """Descifrado en cadena en orden inverso (sin recifrar innecesario)"""
        current_data = encrypted_data

        print("\nIniciando descifrado en cadena:")
        for i, hospital in enumerate(reversed(self.hospitals)):
            if isinstance(current_data, ts.CKKSVector):
                current_data.link_context(hospital.context)
                decrypted = hospital.decrypt_layer(current_data)
            else:
                decrypted = current_data 
            
            print(f"Capa {len(self.hospitals)-i} descifrada por Hospital {hospital.id}")
            current_data = decrypted

        return np.array(current_data)



if __name__ == "__main__":
    NUM_HOSPITALS = 3
    SAMPLE_DATA = np.array([1.0, 2.0, 3.0])  
    
    # 1. Inicializar sistema
    print("=== Sistema de Encriptación en Cadena ===")
    ces = ChainEncryptionSystem(NUM_HOSPITALS)
    ces.setup()
    
    # 2. Encriptar en cadena
    encrypted = ces.chain_encrypt(SAMPLE_DATA)
    print("\nDatos originales:", SAMPLE_DATA)
    
    # 3. Descifrar en cadena inversa
    decrypted = ces.chain_decrypt(encrypted)
    print("\nDatos descifrados:", decrypted)
    
    # 4. Verificar precisión
    error = np.max(np.abs(SAMPLE_DATA - decrypted))
    print(f"\nError máximo: {error:.10f}")