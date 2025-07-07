import time
import numpy as np
import tenseal as ts

# ======= Configuración inicial =======
NUM_HOSPITALS =2
num_rows = 448
num_cols = 448

# ======= Ponderaciones =======
weights = np.random.dirichlet(np.ones(NUM_HOSPITALS))
print(f"WEIGHTS {weights}")

# ======= Contexto común =======
context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[40, 20, 20, 20, 40]
)
context.global_scale = 2**20
context.generate_galois_keys()
context.generate_relin_keys()

public_context = context.copy()
public_context.make_context_public()

# ======= Matrices normalizadas =======
normalized_list = [
    np.random.rand(num_rows, num_cols).tolist()
    for _ in range(NUM_HOSPITALS)
]
#print(f"NORMALIZED LIST {normalized_list}")

# ======= TIEMPO TOTAL CIFRADO (ponderación - cifrado - suma) =======
total_start = time.time()

# ======= Ponderación en claro =======
plain_sum_start = time.time()
plain_sum = np.zeros((num_rows, num_cols))
for h, matrix in enumerate(normalized_list):
    plain_sum += np.array(matrix) * weights[h]
plain_sum_end = time.time()

#print(f"PLAIN_SUM {plain_sum}")

# ======= Cifrado de matrices ya ponderadas =======
encrypt_start = time.time()
encrypted_data = []
for h, matrix in enumerate(normalized_list):
    encrypted_matrix = []
    for row in matrix:
        weighted_row = [val * weights[h] for val in row]
        vec = ts.ckks_tensor(public_context, weighted_row)
        encrypted_matrix.append(vec)
    encrypted_data.append(encrypted_matrix)
encrypt_end = time.time()

# ======= Suma de matrices cifradas ponderadas =======
encrypted_sum_start = time.time()
encrypted_sum = [vec.copy() for vec in encrypted_data[0]]  
for matrix in encrypted_data[1:]:
    for i in range(num_rows):
        encrypted_sum[i] += matrix[i]
encrypted_sum_end = time.time()

total_end = time.time()

# ======= Desencriptar resultado =======
for vec in encrypted_sum:
    vec.link_context(context)  # Asegura que tenga acceso a claves secretas

decrypted_rows = []
for vec in encrypted_sum:
    row = vec.decrypt().tolist()  # Devuelve lista de floats (1D)
    decrypted_rows.append(row)

# Convertir a NumPy 2D
decrypted_result_np = np.array(decrypted_rows)

#print(f"MATRIZ RESULTANTE \n{decrypted_result_np}")

# ======= Comparación con resultado en claro =======
max_error = np.max(np.abs(decrypted_result_np - plain_sum))
mean_error = np.mean(np.abs(decrypted_result_np - plain_sum))

print("\n########## RESULTADOS (Ponderar - Cifrar - Sumar) ##########")
print(f"Tiempo ponderación (en claro):   {plain_sum_end - plain_sum_start:.8f} s")
print(f"Tiempo cifrado (ya ponderado):   {encrypt_end - encrypt_start:.4f} s")
print(f"Tiempo suma cifrada:             {encrypted_sum_end - encrypted_sum_start:.4f} s")
print(f"Tiempo total:                    {total_end - total_start:.4f} s")

print(f"\nMáximo error absoluto:           {max_error:.8f}")
print(f"Error medio absoluto:            {mean_error:.8f}")

