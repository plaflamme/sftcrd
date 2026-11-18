{
  testScript = ''
    import re

    host.succeed("printf 'hello openpgp algorithms' > /tmp/msg.txt")
    host.succeed("printf 'secret-payload-32-bytes-01234567' > /tmp/plain.bin")

    def der_len(n):
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b

    def der_tlv(tag, val):
        return bytes([tag]) + der_len(len(val)) + val

    def der_int(val_bytes):
        val_bytes = val_bytes.lstrip(b"\x00") or b"\x00"
        if val_bytes[0] & 0x80:
            val_bytes = b"\x00" + val_bytes
        return der_tlv(0x02, val_bytes)

    def rsa_spki_der(n_hex, e_hex):
        n_bytes = bytes.fromhex(n_hex)
        e_bytes = bytes.fromhex(e_hex)
        rsa_pub = der_tlv(0x30, der_int(n_bytes) + der_int(e_bytes))
        # OID 1.2.840.113549.1.1.1 (rsaEncryption) + NULL
        alg_id = bytes.fromhex("300d06092a864886f70d0101010500")
        bit_str = der_tlv(0x03, b"\x00" + rsa_pub)
        return der_tlv(0x30, alg_id + bit_str)

    # Signing and authentication algorithms
    for alg in ["rsa2048", "rsa3072", "rsa4096", "nistp256", "nistp384", "nistp521", "ed25519"]:
        keyroostctl(f"openpgp key generate --slot sign --algorithm {alg} --admin-pin env:ADMIN_PIN --yes")
        keyroostctl(f"openpgp sign --in /tmp/msg.txt --pin env:PIN --out /tmp/sig_{alg}.bin --overwrite")
        assert int(host.succeed(f"stat -c %s /tmp/sig_{alg}.bin").strip()) > 0

        keyroostctl(f"openpgp key generate --slot auth --algorithm {alg} --admin-pin env:ADMIN_PIN --yes")
        keyroostctl(f"openpgp authenticate --in /tmp/msg.txt --pin env:PIN --out /tmp/auth_{alg}.bin --overwrite")
        assert int(host.succeed(f"stat -c %s /tmp/auth_{alg}.bin").strip()) > 0

    # RSA decryption algorithms
    for alg in ["rsa2048", "rsa3072", "rsa4096"]:
        keyroostctl(f"openpgp key generate --slot decrypt --algorithm {alg} --admin-pin env:ADMIN_PIN --yes")
        show_out = keyroostctl("openpgp key show --slot decrypt")
        m_match = re.search(r"modulus[^:\n]*:\s*([^\n]+)", show_out, re.IGNORECASE)
        e_match = re.search(r"exponent[^:\n]*:\s*([^\n]+)", show_out, re.IGNORECASE)
        assert m_match and e_match, f"Could not parse RSA key show output:\n{show_out}"
        n_hex = re.sub(r"[^0-9a-fA-F]", "", m_match.group(1))
        e_hex = re.sub(r"[^0-9a-fA-F]", "", e_match.group(1))
        if len(n_hex) % 2 == 1:
            n_hex = "0" + n_hex
        if len(e_hex) % 2 == 1:
            e_hex = "0" + e_hex

        import base64
        b64 = base64.b64encode(rsa_spki_der(n_hex, e_hex)).decode("ascii")
        host.succeed(f"echo '{b64}' | base64 -d > /tmp/rsa_pub.der")
        host.succeed("openssl pkeyutl -encrypt -pubin -keyform DER -inkey /tmp/rsa_pub.der -in /tmp/plain.bin -out /tmp/ct.bin")
        keyroostctl("openpgp decrypt --in /tmp/ct.bin --pin env:PIN --out /tmp/dec.bin --overwrite")
        host.succeed("cmp /tmp/plain.bin /tmp/dec.bin")

    # ECDH decryption algorithms: NIST curves + X25519
    ecdh_curves = [
        ("nistp256", "EC -pkeyopt ec_paramgen_curve:prime256v1", 65, 32),
        ("nistp384", "EC -pkeyopt ec_paramgen_curve:secp384r1", 97, 48),
        ("nistp521", "EC -pkeyopt ec_paramgen_curve:secp521r1", 133, 66),
        ("x25519", "X25519", 32, 32),
    ]
    for alg, gen_args, pub_len, secret_len in ecdh_curves:
        keyroostctl(f"openpgp key generate --slot decrypt --algorithm {alg} --admin-pin env:ADMIN_PIN --yes")
        host.succeed(f"openssl genpkey -algorithm {gen_args} -out /tmp/eph_{alg}.pem")
        # Extract raw public key bytes (last pub_len bytes of SubjectPublicKeyInfo DER)
        host.succeed(
            f"openssl pkey -in /tmp/eph_{alg}.pem -pubout -outform DER | tail -c {pub_len} > /tmp/eph_{alg}.pub"
        )
        keyroostctl(f"openpgp decrypt --in /tmp/eph_{alg}.pub --pin env:PIN --out /tmp/secret_{alg}.bin --overwrite")
        actual_len = int(host.succeed(f"stat -c %s /tmp/secret_{alg}.bin").strip())
        assert actual_len == secret_len, f"{alg}: expected {secret_len} bytes, got {actual_len}"
  '';
}
