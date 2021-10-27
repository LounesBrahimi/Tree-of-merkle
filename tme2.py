import hashlib

def encode_entier_b(entier):
	return '{:032b}'.format(entier)

def hash_id(nom, prenom):
	m = hashlib.blake2b(digest_size=32)
	s = nom+":"+prenom
	m.update(str(s).encode('utf-8'))
	return m.hexdigest()

def hash_blake2(s):
	m = hashlib.blake2b(digest_size=32)
	m.update(str(s).encode('utf-8'))
	return m.hexdigest()	
	
	
def encode_entier(entier):
	return '0x{0:08X}'.format(entier)
	
def hash_value(hash_ident, entier):
	m = hashlib.blake2b(digest_size=32)
	s = hash_ident+encode_entier_b(entier)
	m.update(str(s).encode('utf-8'))
	return m.hexdigest()
	
############################################################

def count_zero_prefix(data):
	cpt = 0
	for x in range(len(data)):
		if  data[x] == "0":
			cpt = cpt + 1
		else:
			break
	return cpt

def bin_format(integer, length):
    return f'{integer:0>{length}b}'

def encode_entier_256(entier):
	return bin_format(int(entier, 16), 256)
	
def is_valid(identite, nonce, n):
	hash = hash_value(identite, nonce)
	return count_zero_prefix(encode_entier_256(hash)) >= n
	
def mine(identite, n):
	nonce = 0
	for x in range(100000000):
		hash = hash_value(identite, x)
		if is_valid(identite, x, n):
			n = x
			break
		else:
			continue
	return n

	

#print(count_zero_prefix(encode_entier_b(123)))

#print(is_valid(hash_id("nakamoto", "satoshi"), 14460, 5))

#print(mine(hash_id("nakamoto", "satoshi"), 11))

#############################################################################

etat = [("1dc653a1447946592fe2871eeb01d8fd6ae353bf04ab789199e38777da3fd0c7", 1003),
		 ("ad415c298389574a24f009671697dd58a717ec04aaa79bd39a130b1ae7a4b2a9", 8532),
		  ("b6a46ab620ab41132a7e062bee0bd7ef6af99d5c25b9021edcb949f2cd6c2bbc", 100),
		  ("d91340a0a4fc7283117fb7871a95e983455275347662345ffaaa75d674def6ec", 943),
		  ("ff9f179535d17c8f29d7eb8ad3432eb8b16ce684b48527b12a1a71f10d3e63ec", 755)]

def splite_string_128(s):
	chunks = [s[i:i+128] for i in range(0, len(s), 128)]
	return chunks

def encode_montant(decimale):
	s = '0x{0:08X}'.format(decimale)
	s1 =s[:0] + s[(1):]
	s2 = s1[:0] + s1[(1):]
	return s2
	
def encode_char(char):
	s = hex(ord(char))
	s1 =s[:0] + s[(1):]
	s2 = s1[:0] + s1[(1):]
	return s2
	
def encode_compte(hash_ident, montant):
	montant = encode_montant(montant)
	s = ""
	for x in range(len(hash_ident)):
		s = s + encode_char(hash_ident[x])
	return s + montant

def decode_compte(code):
	list = splite_string_128(code)
	hash_id = bytes.fromhex(list[0]).decode('utf-8')
	montant = int(list[1], 16)
	return hash_id
	
def decode_compte_tuples(code):
	list = splite_string_128(code)
	hash_id = bytes.fromhex(list[0]).decode('utf-8')
	montant = int(list[1], 16)
	return (hash_id, montant)

def encode_etat(etat):
	nombre = len(etat)
	code = ""
	max_length = 0
	for x in range(nombre):
		code1 = encode_compte(etat[x][0], etat[x][1])
		code = code + code1
	return str('{:08d}'.format(nombre))+ code

def nombre_etats(s):
	chunks = [s[i:i+8] for i in range(0, len(s), 8)]
	return chunks[0]

def code_sans_nombre_etats(s):
	chunks = [s[i:i+8] for i in range(0, len(s), 8)]
	chunks.remove(chunks[0])
	str = ""
	for s1 in chunks:
		str = str + s1
	return str

def splite_by_nombre_etats(s, n):
	chunks = [s[i:i+n] for i in range(0, len(s), n)]
	return chunks

def decode_etat(code):
	nombre = int(nombre_etats(code))
	code = code_sans_nombre_etats(code)
	comptes = splite_by_nombre_etats(code, int(len(code)/nombre))
	
	original_comptes = []
	for x in range(nombre):
		original_comptes.append(decode_compte_tuples(comptes[x]))
		
	
	return original_comptes
	
#print(decode_etat(encode_etat(etat)))	

#print(decode_compte(encode_compte("ad415c298389574a24f009671697dd58a717ec04aaa79bd39a130b1ae7a4b2a9,", 8532)))

#print(decode_etat(encode_etat(etat)))

#print(decode_etat("0000002c18afef0f788ac5f95e523d6913fa667e34587bfb6d8577e0ea78a6c16c2024d30002bfd6f3de0449778e32f7232ef608634f1a56219117fff0c08ec5660a2037df79d07c0002c0d72f6b079c5d5edca6972601f7837076d6ffaa5f842797aa1b7cb75e7d975e82b9000e67e84f605a854cef0e11104c0fa39c667c4340a9c72d6a4ee414a3b79302a8817dac00035b1162fa0225014db0ccdfe0984576857ee4392364a61e1a494dc899fa2cfd7ac0d8000e9351d744af344656e4e21a1f32bc9590540759a7de17fecd1805e7d4da37fd5e2ffc000a9e8de650085b4eb51800fc8038a114373b82b59fadb400a526fac21beff35109192d000c431f4caa1c8987a83c92a2b2b642790dc964253f1fe7afbb46cf990a80c7e7e782e00000f3c1c48abaf306d18ceb41f40e96c716554a0356877fb4965a8cc1863fbaf7d873dc00038fd44429ac980222c25a59975b9bd0694650d44b17af816ae50001dae09a6a11c1b5000c5179f78835dc42659c75b0cb0314b63ad9c5315543912b8f5fae0ba71cb98e2da28a00020b7e139590f2c274b0b55be57435644806b664044a3037f9cc8a32335ab218c4989500053eabbfc992b6a1ca37e36ef867a1867f4ba469676224b8debd202cfb23de7da4d40200087470e7929fca21d81e944fb708f5fbfbbd64afb2def37b2e2470f047619618984e560006d7f4817508664c9bd581b5a289bdfacbe331d0c1f7e04fec195ecf1b83c5acdd8761000b4941859db53d69284e54e5564da1452f20efb3482953b14059841d81f77da5e09cfb0003bc130d47d830f54934eb8c6c56111d2a1bdc0fe18309b04d57c5cd4134458e20f2570007f0a599553f109d531eb007c6b3b74a428ca26bd3138488478f4a400befb2e48540600005666918a10976f92fec4103f94ec6caeacf36d56928463185e1ab8830c01035992f6e00040027879a66a73e3a10ab86ee294d4cd9820c35ffdf6b2f540e40a1df743961c6c31b0009d67059e6370f9729cb48058fa01d9d16d94f0291bdbce0c795a0610a1c7ee7e632120001792fae8e5d1834d09a1fc51fd6f096db49ea812687917bde2fc1e7fd4d877a7bbbae00057214b2aee6b20719e07690849f5fb6a0c6b366a6b75c22b24c8fc57ef4484f57bb39000607d4fe549956b0885d71ed1befdeabdf9004da5405f9fb213cd27f39bc75c45bddb100094aba23fc66575dea941754d94f4adc720b1b7d93809e5cff9370980a69604bd8c11a000ccd4c30bef4df6661057f0c45ec0899693cb1d0a8bbe735dc21c62775d18c744819d900066a48428aafe510e1d7151b88847b4c749eccea7a631db2fde9dbeb0d2c9d50dcccc0000930c5525f928d114d805c316f10d518062fb597877d88fbf9338438301476f7805f630003aee0a239ec04c10f9ccf04b5dd059299f8c503aa3c1aafe720ad047113460f6e815c000b8ad6605c3389b90f0a947a262b8eb4268a333578e27c1676ef84e9de50ef5e910a3600022001ed9aa9d7dfa190973e7122212b966ff2f578238e516c22cb59546345055c91c3000d193316e29c94c2b7ec56b1c9cac3002c97d06768e06bfd2907929e8330afa90732d30007abfea5acbe28287204e4118557cac0694630dfe912f345781055878449ef3869a2040002144ee31728235a8e6d44cbd6f863c800aa5760cc2d855aa0064183742572a2922c7400089f9018fbe759d51edd6f4a749393817ecc0cd35da1a92adb7a8cdb2a338910cf7045000e6058c98b05c88d9286090a7d770bf0f44ad951416aec1dbc9877cfa73eaa97d9ccfd0008e24e751dec072a5ce6031e6f8fe34b311f03c1f4eab31c1acae633c211bed6019e0e000e3be36c60aa80ac7a32046830c06565f1e1eee37da91cf36945e8c66dc6aca47ad9640006a5b49f52cb3569815a17ff16230cf1797cefa9aa25ccfa4b5e884553180ade7fbc76000d897125fab2003ddf010fe0de52c6abeb2b7bb2af4e06bbd27cb893a455e479d4abe300062295b47ea22826a4e7ea5d58898830a5a7b5c566ba2b5ce465b38d0181b094fac63a00098eb55506a64dd2ddd798a46c9c0204c247d699483c8523490906bc52aa0907c014780006e10887fe3003cb1830bbaf1f125a38cace4863c144470eb45a48b6f492fffd41e2f2000e70669c802fc5e3734823b94f7a223773bc544561a1a930cf96464c775bb09a3ce19000088660"))

def hash_blake2(s):
	m = hashlib.blake2b(digest_size=32)
	m.update(str(s).encode('utf-8'))
	return m.hexdigest()	

def concat_hash(h1, h2):
	s = h1 + h2
	return hash_blake2(s)

# A Python class that represents an individual node
# in a Binary Tree
class Node:
    def __init__(self,key):
        self.left = None
        self.right = None
        self.val = key

def print_nodes(list):
	for x in range(len(list)):
		print(list[x].val)

def print_tree(deepth, tree):
	print(tree.val)
	if (not(tree.left == None)):
		print_tree(deepth+1,tree.left)
	if (not(tree.right == None)):
		print_tree(deepth+1, tree.right)
		

def merkle_tree_from_nodes(l_nodes):
	list_nodes = []
	i = 0
	while ((i < len(l_nodes)) and (len(l_nodes)>1)):
		e1 = l_nodes[i]
		e2 = l_nodes[i+1]
		hash_e1_e2 = concat_hash(e1.val, e2.val)
		feuille = Node(hash_e1_e2)
		feuille.left = e1
		feuille.right = e2
		list_nodes.append(feuille)
		i = i + 2
	if (len(l_nodes) == 1):
		return l_nodes[0]
	return merkle_tree_from_nodes(list_nodes)	

def create_merkle_tree(list):
	list_nodes = []
	for i in range(len(list)):
		e = list[i]
		hash_e = hash_blake2(e)
		feuille = Node(hash_e)
		list_nodes.append(feuille)
	return merkle_tree_from_nodes(list_nodes)
	
	
def witness(tree, feuille):
	if (tree.val == feuille.val):
		return (tree, True)
	if ((tree.left == None) and (tree.right == None)):
		return (tree, False)
	v_l = False
	v_r = False
	if (tree.left != None):
		(tree.left, v_l) = witness(tree.left, feuille)	
	if (tree.right != None):
		(tree.right, v_r) = witness(tree.right, feuille)
	if ((v_l or v_r) == True):
		return (tree, True)
	else:
		tree.left = None
		tree.right = None
		return (tree, False)

def extract_feuilles(tree):
	list_feuilles = []
	if (tree == None):
		return list_feuilles
	if ((tree.left != None) and (tree.right != None)):
		list_l = extract_feuilles(tree.left)
		list_r = extract_feuilles(tree.right)
		for x in range(len(list_l)):
			list_feuilles.append(list_l[x])
		for x in range(len(list_r)):
			list_feuilles.append(list_r[x])
	if ((tree.left == None) and (tree.right == None)):
		list_feuilles.append(tree)
		return list_feuilles
	return list_feuilles

def verify(temoin, racine):
	hash_sans_struct = ""
	list_feuilles = []
	hash_sans_struct_left = False
	if (temoin == None):
		return False
	elif ((temoin.left == None) and (temoin.right == None)):
		if (temoin.val == racine):
			return True
		else:
			return False

	if (temoin.left != None):
		if ((temoin.left.left == None) and (temoin.left.right == None)):
			hash_sans_struct = temoin.left.val
			hash_sans_struct_left = true
		else:
			list_feuilles = extract_feuilles(temoin.left)
	if (temoin.right != None):
		if ((temoin.right.left == None) and (temoin.right.right == None)):
			hash_sans_struct = temoin.right.val
		else:
			list_feuilles = extract_feuilles(temoin.right)
	sub_tree = merkle_tree_from_nodes(list_feuilles)
	racine_calculee = ""
	if (hash_sans_struct_left == False):
		racine_calculee = concat_hash(sub_tree.val, hash_sans_struct)
	else:
		racine_calculee = concat_hash(hash_sans_struct, sub_tree.val)
	return (racine_calculee == racine)


#print(hash_blake2("a"))
#print(hash_blake2("b"))
#print(hash_blake2("c"))
#print(hash_blake2("d"))
#print(concat_hash(hash_blake2("a"), hash_blake2("b")))
#print(concat_hash(hash_blake2("c"), hash_blake2("d")))
#print(concat_hash(concat_hash(hash_blake2("a"), hash_blake2("b")), concat_hash(hash_blake2("c"), hash_blake2("d"))))
#print_tree(0, create_merkle_tree(["a","b","c","d"]))
feuille = Node(hash_blake2("a"))
(temoin, bool) = witness(create_merkle_tree(["a","b","c","d"]), feuille)
merkle = create_merkle_tree(["a","b","c","d"])
#print_tree(0, temoin)
print(verify(temoin, merkle.val))
print(verify(temoin, hash_blake2("a")))












