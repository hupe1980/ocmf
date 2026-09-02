import subprocess, json, binascii, os, tempfile

CURVES = [
    ("secp192k1",      "secp192k1",       "ECDSA-secp192k1-SHA256"),
    ("secp256k1",      "secp256k1",       "ECDSA-secp256k1-SHA256"),
    ("secp192r1",      "prime192v1",      "ECDSA-secp192r1-SHA256"),
    ("secp256r1",      "prime256v1",      "ECDSA-secp256r1-SHA256"),
    ("brainpoolP256r1","brainpoolP256r1", "ECDSA-brainpool256r1-SHA256"),
    ("secp384r1",      "secp384r1",       "ECDSA-secp384r1-SHA256"),
    ("brainpoolP384r1","brainpoolP384r1", "ECDSA-brainpool384r1-SHA256"),
]

def sh(*args, **kw):
    return subprocess.run(args, capture_output=True, check=True, **kw)

def payload(sa, n):
    return ('{"FV":"1.4","GI":"ocmf-rs vector generator","GS":"VEC-%02d","GV":"0.1.0",'
            '"PG":"T%d","MV":"ACME","MM":"M-100","MS":"1VEC000000000%d","MF":"1.0",'
            '"IS":true,"IL":"VERIFIED","IF":["RFID_PLAIN","OCPP_AUTH_TLS","ISO15118_NONE","PLMN_NONE"],'
            '"IT":"ISO14443","ID":"1F2D3A4F5506C7","TT":"Vector tariff",'
            '"LC":{"LN":"cable","LI":1,"LR":2,"LU":"mOhm"},"CT":"EVSEID","CI":"DE*ABC*E00%d",'
            '"RD":[{"TM":"2024-03-01T08:00:00,000+0100 S","TX":"B","RV":100.000,'
            '"RI":"01-00:B1.08.00*FF","RU":"kWh","RT":"DC","CL":0.5,"EF":"","ST":"G"},'
            '{"TM":"2024-03-01T09:30:00,000+0100 S","TX":"E","RV":129.500,'
            '"RI":"01-00:B1.08.00*FF","RU":"kWh","RT":"DC","CL":0.5,"EF":"","ST":"G"}]}'
           ) % (n, n, n, n)

out = []
d = tempfile.mkdtemp()
for i, (name, ossl, sa) in enumerate(CURVES, start=1):
    key = os.path.join(d, f"{name}.pem")
    sh("openssl", "genpkey", "-algorithm", "EC",
       "-pkeyopt", f"ec_paramgen_curve:{ossl}",
       "-pkeyopt", "ec_param_enc:named_curve", "-out", key)
    spki = sh("openssl", "pkey", "-in", key, "-pubout", "-outform", "DER").stdout
    pl = payload(sa, i)
    p = os.path.join(d, "p.bin"); open(p, "wb").write(pl.encode())
    sig = sh("openssl", "pkeyutl", "-sign", "-inkey", key,
             "-rawin", "-digest", "sha256", "-in", p).stdout
    record = "OCMF|" + pl + '|{"SA":"' + sa + '","SD":"' + binascii.hexlify(sig).decode().upper() + '"}'
    # Confirm with OpenSSL that what we just built verifies.
    s = os.path.join(d, "s.der"); open(s, "wb").write(sig)
    k = os.path.join(d, "k.der"); open(k, "wb").write(spki)
    r = subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",k,"-keyform","DER",
                        "-sigfile",s,"-rawin","-digest","sha256","-in",p],
                       capture_output=True, text=True)
    assert "Success" in r.stdout, (name, r.stdout, r.stderr)
    out.append({"curve": name, "algorithm": sa, "record": record,
                "key_spki_hex": binascii.hexlify(spki).decode().upper(),
                "note": "generated with OpenSSL 3.6.3; verified by OpenSSL before checking in"})

# One extra vector per shape this crate exists to read, on secp256r1.
base = out[3]
spki = binascii.unhexlify(base["key_spki_hex"])
point = spki[-65:]
assert point[0] == 4
out.append({"curve": "secp256r1", "algorithm": "ECDSA-secp256r1-SHA256",
            "record": base["record"], "key_spki_hex": binascii.hexlify(point[1:]).decode().upper(),
            "shape": "bare-xy-key",
            "note": "the Isabellenhuette public key shape: X||Y, no SEC1 prefix, no SPKI"})

# The same record with the signature re-encoded as a bare r||s.
sigsec = json.loads(base["record"].split("|")[2])
der = binascii.unhexlify(sigsec["SD"])
def read_int(b, off):
    assert b[off] == 2
    n = b[off+1]
    return b[off+2:off+2+n].lstrip(b"\x00"), off+2+n
r1, off = read_int(der, 2)
s1, _ = read_int(der, off)
raw = r1.rjust(32, b"\x00") + s1.rjust(32, b"\x00")
raw_record = "|".join(base["record"].split("|")[:2]) + '|{"SA":"ECDSA-secp256r1-SHA256","SD":"' + binascii.hexlify(raw).decode().upper() + '"}'
out.append({"curve": "secp256r1", "algorithm": "ECDSA-secp256r1-SHA256",
            "record": raw_record, "key_spki_hex": base["key_spki_hex"],
            "shape": "raw-rs-signature",
            "note": "the Isabellenhuette signature shape: 64-byte r||s where SM claims DER"})

# The same record with base64 `SE`, which one corpus record uses.
import base64 as b64
b64_record = "|".join(base["record"].split("|")[:2]) + '|{"SA":"ECDSA-secp256r1-SHA256","SE":"base64","SD":"' + b64.b64encode(der).decode() + '"}'
out.append({"curve": "secp256r1", "algorithm": "ECDSA-secp256r1-SHA256",
            "record": b64_record, "key_spki_hex": base["key_spki_hex"],
            "shape": "base64-signature",
            "note": "SE=base64 [OCMF Tab. 8]"})

path = "/Users/hupe/Workspaces/hupe1980/ocmf/ocmf/tests/vectors/curves.json"
os.makedirs(os.path.dirname(path), exist_ok=True)
json.dump({"generator": "openssl 3.6.3, see tests/vectors/README.md", "vectors": out},
          open(path, "w"), indent=1)
print(f"{len(out)} vectors written ({len(CURVES)} curves + 3 encoding shapes)")
