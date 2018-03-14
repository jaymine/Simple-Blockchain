from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

def sign (digest, privatekeyfile):
    private_key = False
    with open(privatekeyfile, "r") as private_key_file: # Read private key from file
        private_key = RSA.importKey(private_key_file.read())

    signer = PKCS1_v1_5.new(private_key) # Load private key and sign message
    return signer.sign(digest)

def verify (digest, signedBlockdata, publickeyfile):
    public_key = False
    with open(publickeyfile, "r") as public_key_file: # Load public key
        public_key = RSA.importKey(public_key_file.read())

    verifier = PKCS1_v1_5.new(public_key) # Verify message
    verified = verifier.verify(digest, signedBlockdata)
    assert verified, 'Signature verification failed'
    print 'Successfully verified message\n'

class Block:
    def __init__(self, data, signedData, publicKeyFile):
        self.data = data
        self.signedData = signedData
        self.publicKeyFile = publicKeyFile

awardedPerson = ["Alice", "Bob", "Eve"]
private_keys = ["a_private_key.pem", "b_private_key.pem", "c_private_key.pem"]
public_keys = ["a_public_key.pem", "b_public_key.pem", "c_public_key.pem"]

blockchain = {}
previousHash = "0000000000000000000000000000000000000000000000000000000000000000"
for i in range(0,3):
    blockData = awardedPerson[i] + " " + previousHash
    digest = SHA256.new()
    digest.update(blockData)
    signed = sign(digest, private_keys[i])
    blockchain[digest.hexdigest()] = Block(blockData, signed, public_keys[i])
    previousHash = digest.hexdigest()

# Read in order
latestedHash = previousHash 
while (latestedHash != "0000000000000000000000000000000000000000000000000000000000000000"):
    print "hash: " + latestedHash
    print "data: " + blockchain[latestedHash].data
    print "signed data: " + blockchain[latestedHash].signedData.encode("hex")
    digest = SHA256.new()
    digest.update(blockchain[latestedHash].data)
    verify(digest, blockchain[latestedHash].signedData, blockchain[latestedHash].publicKeyFile)
    latestedHash = blockchain[latestedHash].data.split(" ")[1]

