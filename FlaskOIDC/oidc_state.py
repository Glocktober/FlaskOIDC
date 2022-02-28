import json

from cryptography.fernet import Fernet

class OIDCstate:
    """
    Serializes (json), Fernet encrypts, decrypts, and deserializes a dict
    """

    def __init__(self, key=None, ttl=60):

        self.key = key if key else Fernet.generate_key()
        self.ttl = ttl
        self.f = Fernet(self.key)

    
    def serial(self,state):
        """
        Serialize
            - json serialize state
            - Fernet encrypt and return as string
        """

        bdat = json.dumps(state).encode('utf-8')
        return self.f.encrypt(bdat).decode()


    def deserial(self, bdat):
        """ 
        Deserialize 
            - Fernet decrypt and validate TTL against replay
            - deserialize json
        """
        if type(bdat) is str:
            bdat = bdat.encode('utf-8')

        jdat = self.f.decrypt(bdat, ttl=self.ttl)
        dat = json.loads(jdat)

        return dat
