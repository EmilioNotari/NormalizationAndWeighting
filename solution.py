import time
import numpy as np
import tenseal as ts
from copy import deepcopy

# Número de hospitales
NUM_HOSPITALS = 150

# Vector de ponderaciones aleatorias de 2 decimales y suma ≈ 1
weights = np.random.dirichlet(np.ones(NUM_HOSPITALS))


# Crear contexto CKKS
context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[40, 20, 20, 20, 40]
)
context.generate_galois_keys()
context.generate_relin_keys()
context.global_scale = 2**20

# Simular matrices normalizadas con valores aleatorios entre 0 y 1
num_rows = 8
num_cols = 8
normalized_list = [
    np.random.rand(num_rows, num_cols).tolist()
    for _ in range(NUM_HOSPITALS)
]

# ======= TIEMPO TOTAL CIFRADO (ponderación + cifrado + suma) =======
total_start = time.time()

# ======= PONDERACIÓN EN CLARO =======
plain_sum_start = time.time()
plain_sum = np.zeros((num_rows, num_cols))
for h, matrix in enumerate(normalized_list):
    plain_sum += np.array(matrix) * weights[h]
plain_sum_end = time.time()

# ======= Cifrado de matrices ya ponderadas =======
encrypt_start = time.time()
encrypted_data = []
for h, matrix in enumerate(normalized_list):
    encrypted_matrix = []
    for row in matrix:
        weighted_row = [val * weights[h] for val in row]
        vec = ts.ckks_vector(context, weighted_row)
        encrypted_matrix.append(vec)
    encrypted_data.append(encrypted_matrix)
encrypt_end = time.time()

# ======= Suma de matrices cifradas ponderadas =======
encrypted_sum_start = time.time()
encrypted_sum = deepcopy(encrypted_data[0])
for matrix in encrypted_data[1:]:
    for i in range(num_rows):
        encrypted_sum[i] += matrix[i]
encrypted_sum_end = time.time()

total_end = time.time()

# ======= Desencriptar resultado cifrado =======
decrypted_result = [vec.decrypt() for vec in encrypted_sum]
decrypted_result_np = np.array(decrypted_result)

# ======= Comparar resultados =======
max_error = np.max(np.abs(decrypted_result_np - plain_sum))
mean_error = np.mean(np.abs(decrypted_result_np - plain_sum))

# ======= Reporte =======
print("\n########## RESULTADOS (Ponderar ➜ Cifrar ➜ Sumar) ##########")
print(f"TIEMPO TOTAL:                    {total_end - total_start:.4f} s")
print(f"Tiempo cifrado (ponderado):      {encrypt_end - encrypt_start:.4f} s")
print(f"Tiempo suma cifrada:             {encrypted_sum_end - encrypted_sum_start:.4f} s")
print(f"Tiempo sin cifrar:               {plain_sum_end - plain_sum_start:.8f} s")

print(f"\nMáximo error absoluto:           {max_error:.8f}")
print(f"Error medio absoluto:            {mean_error:.8f}")

#####======================================================================================#####

# ======= TIEMPO TOTAL CIFRADO (Cifrar ➜ Ponderar ➜ Sumar) =======
total_start = time.time()

# ======= Cifrado de matrices (sin ponderar aún) =======
encrypt_start = time.time()
encrypted_data = []

for matrix in normalized_list:
    encrypted_matrix = []
    for row in matrix:
        vec = ts.ckks_vector(context, row)
        encrypted_matrix.append(vec)
    encrypted_data.append(encrypted_matrix)
encrypt_end = time.time()

# ======= Ponderar matrices cifradas =======
ponder_start = time.time()
for h, matrix in enumerate(encrypted_data):
    for i in range(num_rows):
        matrix[i] *= weights[h]
ponder_end = time.time()

# ======= Sumar matrices cifradas ponderadas =======
sum_start = time.time()
encrypted_sum = deepcopy(encrypted_data[0])
for matrix in encrypted_data[1:]:
    for i in range(num_rows):
        encrypted_sum[i] += matrix[i]
sum_end = time.time()

total_end = time.time()

# ======= Desencriptar resultado cifrado =======
decrypted_result = [vec.decrypt() for vec in encrypted_sum]
decrypted_result_np = np.array(decrypted_result)

# ======= Comparar con versión sin cifrado =======
plain_sum_start = time.time()
plain_sum = np.zeros((num_rows, num_cols))
for h, matrix in enumerate(normalized_list):
    plain_sum += np.array(matrix) * weights[h]
plain_sum_end = time.time()

# ======= Métricas de error =======
max_error = np.max(np.abs(decrypted_result_np - plain_sum))
mean_error = np.mean(np.abs(decrypted_result_np - plain_sum))

# ======= Reporte =======
print("\n########## RESULTADOS (Cifrar ➜ Ponderar ➜ Sumar) ##########")
print(f"TIEMPO TOTAL:                   {total_end - total_start:.4f} s")
print(f"Tiempo cifrado:                 {encrypt_end - encrypt_start:.4f} s")
print(f"Tiempo ponderación cifrada:     {ponder_end - ponder_start:.4f} s")
print(f"Tiempo suma cifrada:            {sum_end - sum_start:.4f} s")
print(f"Tiempo sin cifrar:              {plain_sum_end - plain_sum_start:.8f} s")

print(f"\nMáximo error absoluto:          {max_error:.8f}")
print(f"Error medio absoluto:           {mean_error:.8f}")
