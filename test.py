import time
import pickle
import numpy as np
import tenseal as ts
from copy import deepcopy  

NUM_HOSPITALS = 5

# Cargar el fichero
fichero = open("/home/enotari/Escritorio/data.pkl", "rb")
normalized_list = pickle.load(fichero)

########## SIMULACIÓN CLIENTE ##########

# Crear contexto CKKS para cifrado homomórfico
context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[40, 20, 20, 20, 40]
)
context.generate_galois_keys()
context.generate_relin_keys()
context.global_scale = 2**20

# Medir tiempos
total_start = time.time()

# Encriptación
encrypt_start = time.time()
encrypted_data = []

#normalized_list = [[[1., 2., 3.], [4., 5., 6.]], [[7., 8., 9.], [10., 11., 12.]]]
#print(f"Normalized List: {normalized_list[:NUM_HOSPITALS]}")

for matrix in normalized_list[:NUM_HOSPITALS]:
    encrypted_matrix = []
    for row in matrix:
        row = np.asarray(row).flatten().astype(np.float64)
        #print(f"[Encrypt]: {row}")
        encrypted_row = ts.ckks_vector(context, row.tolist())
        encrypted_matrix.append(encrypted_row)
    encrypted_data.append(encrypted_matrix)
encrypt_end = time.time()

# Desencriptación
decrypt_start = time.time()
decrypted_data = []

for encrypted_matrix in encrypted_data:
    decrypted_matriz = []
    for enc_row in encrypted_matrix:
        decrypted_row = enc_row.decrypt()
        #print(f"[Decrypt]: {decrypted_row}")
        decrypted_matriz.append(decrypted_row)
    decrypted_data.append(decrypted_matriz)
decrypt_end = time.time()

total_end = time.time()

# Mostrar resultados
print(f"\nTiempo de encriptación : {encrypt_end - encrypt_start:.4f} segundos")
print(f"Tiempo de desencriptación : {decrypt_end - decrypt_start:.4f} segundos")
print(f"Tiempo total : {total_end - total_start:.4f} segundos")

########## SIMULACIÓN SERVIDOR ##########

encrypted_subset = encrypted_data[:NUM_HOSPITALS]

num_rows_per_matrix = len(encrypted_subset[0])
#print(f"\nNum matrix = {num_rows_per_matrix}")

ponderation_start = time.time()

# Inicializar suma ponderada con la primera matriz
encrypted_sum = [
    vec * (1 / NUM_HOSPITALS) for vec in deepcopy(encrypted_subset[0])
]

# Acumular el resto de las matrices ponderadas
for matrix in encrypted_subset[1:]:
    for i, vec in enumerate(matrix):
        encrypted_sum[i] += vec * (1 / NUM_HOSPITALS)

ponderation_end = time.time()

# Desencriptar resultados
decrypted = [vec.decrypt() for vec in encrypted_sum]
decrypted_weighted = decrypted  # Alias para claridad


print("\nMatriz ponderada (desencriptada para comprobación):")
for row in decrypted_weighted:
    print(row)
    
print(f"\nTiempo total ponderación : {ponderation_end - ponderation_start:.4f} segundos")
