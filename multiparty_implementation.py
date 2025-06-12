import tenseal as ts
import numpy as np
from typing import List, Tuple, Dict
import hashlib
import random

class Hospital:
    def __init__(self, id: int):
        self.id = id
        self.context = None
        self.secret_key_share = None
        self.public_context = None
        self.peer_contexts = {}
        self.zkp_commitments = {}  # {hospital_id: commitment}
        self.zkp_nonces = {}       # {hospital_id: nonce}
    
    def generate_key_share(self):
        """Genera la parte de la clave del hospital y devuelve su contexto público y compromiso ZKP"""
        self.context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree= 8192,
            coeff_mod_bit_sizes= [60, 40, 40, 60]
        )
        self.context.global_scale = 2**20
        self.secret_key_share = self.context.secret_key()
        
        self.public_context = self.context.copy()
        self.public_context.make_context_public()
        
        commitment, nonce = ZKPProtocol.create_commitment(self.id, self.public_context)
        self.zkp_commitments[self.id] = commitment
        self.zkp_nonces[self.id] = nonce
        
        return self.public_context.serialize(), commitment, nonce
    
    def receive_peer_commitment(self, hospital_id: int, commitment: bytes, nonce: int):
        """Almacena el compromiso ZKP de otro hospital"""
        if hospital_id != self.id:
            self.zkp_commitments[hospital_id] = commitment
            self.zkp_nonces[hospital_id] = nonce
    
    def verify_peer_key_share(self, hospital_id: int, serialized_context: bytes):
        """Verifica el compromiso ZKP de otro hospital"""
        if hospital_id == self.id:
            return True  # No necesitamos verificar nuestro propio compromiso
        
        if hospital_id not in self.zkp_commitments:
            raise ValueError(f"No se encontró compromiso para el hospital {hospital_id}")
        if hospital_id not in self.zkp_nonces:
            raise ValueError(f"No se encontró nonce para el hospital {hospital_id}")
        
        peer_context = ts.context_from(serialized_context)
        commitment = self.zkp_commitments[hospital_id]
        nonce = self.zkp_nonces[hospital_id]
        
        if not ZKPProtocol.verify_commitment(hospital_id, peer_context, nonce, commitment):
            raise ValueError(f"Fallo en la verificación ZKP para hospital {hospital_id}")
        
        self.peer_contexts[hospital_id] = peer_context
        return True
    
    def combine_public_keys(self):
        """Combina las claves públicas de todos los hospitales verificados"""
        if not self.peer_contexts:
            raise ValueError("No hay contextos de pares verificados para combinar")
        
        combined_context = ts.context_from(self.public_context.serialize())
        
        for hospital_id, context in self.peer_contexts.items():
            combined_context.add_public_key(context.public_key())
        
        return combined_context

class ZKPProtocol:
    @staticmethod
    def create_commitment(hospital_id: int, context_with_pk: ts.Context) -> Tuple[bytes, int]:
        """Crea un compromiso ZKP para verificación posterior"""
        context_serialized = context_with_pk.serialize(save_public_key=True)
        nonce = random.getrandbits(256)
        data_to_hash = (
            f"{hospital_id}".encode() + 
            context_serialized + 
            str(nonce).encode()
        )
        commitment = hashlib.sha3_256(data_to_hash).digest()
        return commitment, nonce

    @staticmethod
    def verify_commitment(hospital_id: int, context_with_pk: ts.Context, nonce: int, commitment: bytes) -> bool:
        """Verifica un compromiso ZKP"""
        context_serialized = context_with_pk.serialize(save_public_key=True)
        data_to_hash = (
            f"{hospital_id}".encode() + 
            context_serialized + 
            str(nonce).encode()
        )
        computed = hashlib.sha3_256(data_to_hash).digest()
        return computed == commitment

class FederatedLearningSystem:
    def __init__(self, num_hospitals: int, threshold: int = None):
        self.num_hospitals = num_hospitals
        self.threshold = threshold if threshold else (num_hospitals // 2 + 1)
        self.hospitals = [Hospital(i) for i in range(num_hospitals)]
        self.combined_context = None
        self.phase = "setup"  # setup, key_sharing, verification, ready
    
    def setup_mpc_environment(self):
        """Fase 1: Cada hospital genera su parte de la clave"""
        print("Iniciando configuración del entorno MPC...")
        self.key_shares = []
        
        # Paso 1: Todos generan sus partes y compromisos
        for hospital in self.hospitals:
            serialized_context, commitment, nonce = hospital.generate_key_share()
            self.key_shares.append((hospital.id, serialized_context, commitment, nonce))
            print(f"Hospital {hospital.id} ha generado su parte de la clave")
        
        # Paso 2: Distribuir los compromisos a todos los hospitales
        for hospital in self.hospitals:
            for h_id, _, commitment, nonce in self.key_shares:
                if h_id != hospital.id:
                    hospital.receive_peer_commitment(h_id, commitment, nonce)
        
        self.phase = "key_sharing"
        print("Fase de compartición de claves completada")
    
    def verify_key_shares(self):
        """Fase 2: Verificación mutua de las claves compartidas"""
        if self.phase != "key_sharing":
            raise RuntimeError("No en fase de compartición de claves")
        
        print("\nIniciando verificación de claves compartidas...")
        for hospital in self.hospitals:
            for h_id, serialized_ctx, _, _ in self.key_shares:
                try:
                    if h_id != hospital.id:
                        hospital.verify_peer_key_share(h_id, serialized_ctx)
                        print(f"Hospital {hospital.id} verificó con éxito la clave del hospital {h_id}")
                except ValueError as e:
                    print(f"Error en verificación: {str(e)}")
                    raise
        
        self.phase = "verification"
        print("Verificación de claves completada")
    
    def combine_keys(self):
        """Fase 3: Combinación de claves públicas"""
        if self.phase != "verification":
            raise RuntimeError("No en fase de verificación")
        
        print("\nCombinando claves públicas...")
        valid_contexts = []
        for hospital in self.hospitals:
            try:
                combined = hospital.combine_public_keys()
                valid_contexts.append(combined)
                print(f"Claves combinadas para hospital {hospital.id}")
            except Exception as e:
                print(f"Error combinando claves para hospital {hospital.id}: {str(e)}")
                continue
        
        if len(valid_contexts) < self.threshold:
            raise RuntimeError(f"No hay suficientes hospitales ({len(valid_contexts)}) para alcanzar el umbral ({self.threshold})")
        
        self.combined_context = valid_contexts[0]
        self.phase = "ready"
        print("Contexto combinado listo para uso")
    
    def encrypt_data(self, data: np.ndarray) -> ts.CKKSVector:
        """Cifra datos usando el contexto público combinado"""
        if self.phase != "ready":
            raise RuntimeError("Sistema no está listo para cifrar")
        return ts.ckks_vector(self.combined_context, data.tolist())
    
    def decrypt_data(self, encrypted_data: ts.CKKSVector, hospital_ids: List[int]) -> np.ndarray:
        """Descifrado colaborativo (simplificado)"""
        if len(hospital_ids) < self.threshold:
            raise PermissionError(f"Se necesitan al menos {self.threshold} hospitales para descifrar")
        
        encrypted_data.link_context(self.combined_context)
        return encrypted_data.decrypt()

if __name__ == "__main__":
    # Configuración reducida para prueba
    NUM_HOSPITALS = 3
    THRESHOLD = 2  # Mínimo de hospitales para descifrar
    
    # Inicializar sistema
    print("=== Inicializando sistema federado ===")
    fl_system = FederatedLearningSystem(NUM_HOSPITALS, THRESHOLD)
    
    # 1. Configurar entorno MPC
    fl_system.setup_mpc_environment()
    
    # 2. Verificar claves compartidas
    fl_system.verify_key_shares()
    
    # 3. Combinar claves públicas
    fl_system.combine_keys()
    
    # Generar datos de prueba
    num_rows, num_cols = 2, 2  # Matriz pequeña para prueba
    data_samples = [np.random.rand(num_rows, num_cols) for _ in range(NUM_HOSPITALS)]
    
    # Cada hospital cifra sus datos
    print("\n=== Cifrado de datos ===")
    encrypted_data = []
    for hospital, data in zip(fl_system.hospitals, data_samples):
        encrypted_matrix = []
        for row in data:
            encrypted_row = fl_system.encrypt_data(row)
            encrypted_matrix.append(encrypted_row)
        encrypted_data.append(encrypted_matrix)
        print(f"Datos del hospital {hospital.id} cifrados correctamente")
    
    # Ejemplo de descifrado colaborativo
    print("\n=== Intento de descifrado ===")
    try:
        # Intentar descifrar con el umbral requerido de hospitales
        decrypted_sample = fl_system.decrypt_data(encrypted_data[0][0], [0, 1])
        print("Descifrado exitoso con 2 hospitales:")
        print(decrypted_sample)
        
        # Verificar contra el valor original
        print("\nValor original:", data_samples[0][0])
        error = np.max(np.abs(decrypted_sample - data_samples[0][0]))
        print(f"Error máximo: {error:.8f}")
    except PermissionError as e:
        print("Error de descifrado:", str(e))