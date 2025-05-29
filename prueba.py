import pickle

file_path = open("/home/enotari/Escritorio/data.pkl", "rb")

normalized_list = pickle.load(file_path)

for elem in normalized_list[:15]:
    print(elem)
    print("-------------------")
