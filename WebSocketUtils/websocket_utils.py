import base64
import json
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

epsilon = 1E-5

def get_subdict(D, path_vec):
    """
    access a subpart of the dictionary.
    e.g. path_vec = ['first_key', 'second_key']
    """
    if path_vec:
        try:
            return get_subdict(D[path_vec[0]], path_vec[1:])
        except:
            print(f'problem accessing subpath {path_vec} of dictionary in get_subdict')
    else:
        return D

def write_dict_to_file(D, fname):
    try:
          s = json.dumps(D, indent=2)  #convert to string
          #print(s)
          with open(fname, 'w') as F:
                F.write(s)
    except:
        print("error writing to file")


def read_dict_from_file(fname):
    try:
          with open(fname, 'r') as F:
                s=F.read()
          #print(s)
          D=json.loads(s)
          return D
    except Exception as e:
        print("error reading from file: " + fname)
        print(e)
        raise



def round_relative(x, rel_precision = 5):   #rounds a number relatively: in total retaining rel_precision decimal digits in the the 10^n representation
    x = float(x)
    m = int(np.ceil(-np.log(x) / np.log(10)) + rel_precision - 1)
    x = round(x, m)
    return x


# --------------------------------- class for encrypting and decrypting text / data using AES --------------------------------
class AES_encrypt(object):
    block_size=32   #byte size: corresponds to 256 bit key

    def __init__(self, password = '', key_bytes = '', key_hex=''):
        try:
            if key_bytes != '':
                self.key = key_bytes
            elif key_hex != '':
                self.key = bytes.fromhex(key_hex)
            elif password != '':
                self.key = hashlib.sha256(password.encode('utf-8')).digest()  # => a 32 byte string. We need the secret key to be a 32byte private key for 256bit AES and the sha256 returns exactly this
            else:
                print('no password or key given for constructing AES_encrypt object')
        except:
            print('problem in setting up key in AES_encrypt')


    #returns an output in base64 encoded form
    def encrypt(self, raw):
        #print('using key: '+str(self.key))    #the key is in bytes format here
        #print(f'msg type = {type(raw)} and msg = {str(raw)} ')    #the key is in bytes format here
        raw = self._pad(raw)
        #print('after pad: |' + str(raw) +'|')    #this appends characters to get it to a suitable length for encryption
        iv = Random.new().read(AES.block_size)    #a new random number (rather byte object) is generated each time. Encrypting the same string at different times, this leads to the encrypter cypher being different. This number is automatically extracted in the decryption
        #print('iv:' + str(iv))
        cipher = AES.new(self.key, AES.MODE_CBC, iv)   #here the encryption is performed. This does not seem to be a byte object that is returned, but it is treated like one in the base64 encoding
        #print('cipher:|' + str(cipher) + '|')   #the cypher
        return base64.b64encode(iv + cipher.encrypt(raw))   #this is an encoding similar to a basic encryption (no key) and the inverse function can just be applied. But the composite object being encoded looks random

    def decrypt(self, enc):
        enc = base64.b64decode(enc)   #base64.b64decode(enc) returns a bytes object where enc is encoded in base64 format
        #print(enc)
        iv = enc[:AES.block_size]
        #print('in decrypt iv:' + str(iv))   #the random byte sequence from the encoding is extracted from the beginning
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        res = self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
        #res = self._unpad(cipher.decrypt(enc[AES.block_size:]).decode('utf-8'))
        #print('d5')
        return res

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def _pad(self, s):

        if isinstance(s, str):
            #print(f'padding with {type((self.block_size - len(s) % self.block_size) * chr(self.block_size - len(s) % self.block_size))}')
            return (s + (self.block_size - len(s) % self.block_size) * chr(self.block_size - len(s) % self.block_size)).encode('utf-8')
        else:
            by_to_append = ((self.block_size - len(s) % self.block_size) * chr(self.block_size - len(s) % self.block_size)).encode('utf-8')
            #print(f'in bytes append {type(by_to_append)}')
            #print(f'in bytes append {type(s)}')
            byt_combined = s + by_to_append
            #print('were comb')
            return byt_combined





# --------------------------------- merge nested dictionaries --------------------------------

def merge_dicts(a, b, path=None, update=True):
    #"http://stackoverflow.com/questions/7204805/python-dictionaries-of-dictionaries-merge"
    #"merges b into a"
    if path is None: path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dicts(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass # same leaf value
            elif isinstance(a[key], list) and isinstance(b[key], list):
                for idx, val in enumerate(b[key]):
                    a[key][idx] = merge_dicts(a[key][idx], b[key][idx], path + [str(key), str(idx)], update=update)
            elif update:
                a[key] = b[key]
            else:
                raise Exception('Conflict at %s' % '.'.join(path + [str(key)]))
        else:
            a[key] = b[key]
    return a



class TerminableFunction:
    def __init__(self):
        self.terminationFlag = False
    def setTerminationFlag(self):
        self.terminationFlag = True
    def func(self,*funcArgs,**funcKwArgs):
        raise Exception(f".func() needs to be implemented for {self}")


def setG(global_G):
    global G
    G=global_G
    #threading.setG(G)

def reverse_multivalue_dict(mvd):
    """
    reverses a dictionary that has multiple values per key
    the (multiple) value(s) must be inside a list
    ex.:
    input: {'a': [1, 2, 3], 'b': [2, 4], 'c': [3, 4, 5]}
    output: {1: ['a'], 2: ['a', 'b'], 3: ['a', 'c'], 4: ['b', 'c'], 5: ['c']}
    """
    res = {}
    for k in mvd:
        for li in mvd[k]:
            if li not in res:
                res[li] = []
            res[li].append(k)
    return res

class group_by_default_not_set:
    pass

# given a list of dictionaries, groups by the given key
def group_by(dict_list,key,default_on_key_missing = group_by_default_not_set):
    if default_on_key_missing == group_by_default_not_set:
        def getFunc(d, key):
            return d[key]
    else:
        def getFunc(d, key):
            return d.get(key,default_on_key_missing)

    for value in {getFunc(d, key) for d in dict_list}:
        yield [d for d in dict_list if getFunc(d,key) == value]

# a list of dictionaries which have the same set of keys can be grouped by one or several keys
def group_by_keys(dict_list,keys):
    data_by_type = {}
    data_types = set([tuple(record[key] for key in keys) for record in dict_list])
    for dt in data_types:
        data_by_type[dt] = [record for record in dict_list if all([record[keys[i]] == dt[i] for i in range(len(keys))])]
    return data_by_type



def delete_element_from_nested_list_dict(D, el_to_delete):
    '''deletes (possibly multiple occurences) of a specified object or value from
     arbitraritly nested lists and dictionaries. For dictionaries it has to be the value.'''
    def del_val_from_dict(DD, el):
        for k in DD:
            if DD[k] == el:
                del DD[k]
                break

    if type(D) == list:
        while(el_to_delete in D):
            D.remove(el_to_delete)
        for el in D:
            if type(el) in [list, dict]:
                delete_element_from_nested_list_dict(el, el_to_delete)
    elif type(D) == dict:
        while(el_to_delete in D.values()):
            del_val_from_dict(D, el_to_delete)
        for el in D:
            if type(D[el]) in [list, dict]:
                delete_element_from_nested_list_dict(D[el], el_to_delete)




def try_AES():
    import zlib
    A = AES_encrypt(key_hex="89b91a4e38329a3b7c141c403a6a619dedf6e25e2148837e03fe8137a99b9499")

    s = "to be encrypted & { :)"
    c = zlib.compress(s.encode('utf-8'),9)
    print(s)
    print(c)

    enc = A.encrypt(c)   #TODO:  the _pad and _unpad functions don't work correctly if a bytearray (and not a string) is encrypted
    print(enc)

    dec = A.decrypt(enc)
    print(dec)



# ---------------------------  own implementation to insert element into sorted list  -------------------------
# an implementation like https://code.activestate.com/recipes/577197-sortedcollection requires a conversion of the simple list
def insert_into_sorted_list(my_list, new_el, sort_key_fct = lambda el : el['time']):
    '''assumes the list is already sorted.
    sample usage:
    L = [ {'time' : 12, 'x' : 'ad'}, {'time' : 19, 'x' : 'bob'}, {'time' : 21, 'x' : 'bob'}, {'time' : 26, 'x' : 'bob'} ]
    insert_into_sorted_list(L, {'time' : 19.1, 'x' : 'sdaf'})'''

    lo=0
    hi=len(my_list)

    if hi ==0 or sort_key_fct(new_el) < sort_key_fct(my_list[0]):
        hi = 0
    else:
        while hi-lo>1: #always halve the interval size
            mid = int((hi+lo)/2)
            if sort_key_fct(my_list[mid]) > sort_key_fct(new_el):
                hi = mid
            else:
                lo = mid
    my_list.insert(hi, new_el)



from contextlib import contextmanager

@contextmanager
def assert_unchanged(*vars_):
    try:
        vars_before = []
        for var in vars_:
            vars_before.append(var.copy())
        yield
    finally:
        for var_before,var_after in zip(vars_before,vars_):
            assert var_before == var_after


def lookup(path, state):
        ptr = state
        for p in path:
            ptr = ptr[p]
        return ptr

