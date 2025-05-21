import tenseal as ts

# Crear contexto CKKS
context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[40, 20, 20, 20, 40]
)
context.generate_galois_keys()
context.global_scale = 2**20

# Vector original
plain_vector = [1.0, 2.0, 3.0]
scalar = 0.5

# Cifrar el vector
encrypted_vector = ts.ckks_vector(context, plain_vector)

# Multiplicar el vector cifrado por el escalar
encrypted_vector *= scalar

# Desencriptar para verificar
decrypted_result = encrypted_vector.decrypt()

print(f"Resultado desencriptado: {decrypted_result}")
