#http://swdrsker.hatenablog.com/entry/2018/01/30/073000

from hashlib import sha256

class ECDSA:
    def __init__(self):
        # parameters are based on SPEC256k1
        self.cp = pow(2,256) - pow(2,32) - pow(2,9) - pow(2,8) - pow(2,7) - pow(2,6) - pow(2,4) - pow(2,9)
        self.cb = 7
        self.ca = 0
        self.base_x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
        self.base_y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
        self.base = (self.base_x,self.base_y)
        self.secret_key = None
        self.public_key = None

    def generate_key(self,string):
        secret_hash = sha256(string.encode('utf-8')).hexdigest()
        secret_key = int(secret_hash,16)
        pt = self.EC_multi(secret_key)
        public_key = int("04" + "%064x" % pt[0] + "%064x" % pt[1],16)
        self.secret_key = secret_key
        self.public_key = public_key
        return (public_key,secret_key)

    def EC_add(self,P,Q):
        lam = ((Q[1]-P[1]) * inv_mod(Q[0] - P[0], self.cp)) % self.cp
        x = ((pow(lam,2)) - P[0] - Q[0]) % self.cp
        y = (lam * (P[0] - x) - P[1]) % self.cp
        return (x,y)

    def EC_double(self,P):
        lam = ((3 * (pow(P[0],2) + self.ca) * inv_mod(2 * P[1],self.cp))) % self.cp
        x = (pow(lam,2) - 2*P[0]) % self.cp
        y = (lam * (P[0] - x) - P[1]) % self.cp
        return (x,y)

    def EC_multi(self,scalar):
        if scalar == 0:
            raise ValueError('invalid scalar/ private key')
        scalar_bin = str(bin(scalar))[2:]
        point = self.base
        for i in range(1,len(scalar_bin)):
            point = self.EC_double(point)
            if scalar_bin[i] == "1":
                point = self.EC_add(point,self.base)
        return point

def inv_mod(k,mod):
    return pow(k,mod-2,mod)

if __name__ == "__main__":
    ecdsa = ECDSA()
    pk,sk = ecdsa.generate_key("Yuuto Ookawa")
    print(sk)
    print(pk)
