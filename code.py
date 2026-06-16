# This file is dual licensed under the terms of the Apache License, Version

# 2.0, and the BSD License. See the LICENSE file in the root of this repository

# for complete details.

from __future__ import absolute_import, division, print_function

import binascii

import os

import pytest

from cryptography.hazmat.backends.interfaces import CipherBackend

from cryptography.hazmat.primitives.ciphers import algorithms, base, modes


from .utils import _load_all_params, generate_aead_test, generate_encrypt_test

from ...utils import load_nist_vectors

@pytest.mark.supported(

    only_if=lambda backend: backend.cipher_supported(

        algorithms.AES(b"\x00" * 32), modes.XTS(b"\x00" * 16)

    ),

    skip_message="Does not support AES XTS",

)

@pytest.mark.requires_backend_interface(interface=CipherBackend)

class TestAESModeXTS(object):

@pytest.mark.parametrize(

        "vector",

        # This list comprehension excludes any vector that does not have a

        # data unit length that is divisible by 8. The NIST vectors include

        # tests for implementations that support encryption of data that is

        # not divisible modulo 8, but OpenSSL is not such an implementation.

        [x for x in _load_all_params(

            os.path.join("ciphers", "AES", "XTS", "tweak-128hexstr"),

            ["XTSGenAES128.rsp", "XTSGenAES256.rsp"],

            load_nist_vectors

        ) if int(x["dataunitlen"]) / 8.0 == int(x["dataunitlen"]) // 8]

    )

    def test_xts_vectors(self, vector, backend):

        key = binascii.unhexlify(vector["key"])

        tweak = binascii.unhexlify(vector["i"])

        pt = binascii.unhexlify(vector["pt"])

        ct = binascii.unhexlify(vector["ct"])

        cipher = base.Cipher(algorithms.AES(key), modes.XTS(tweak), backend)

        enc = cipher.encryptor()

        computed_ct = enc.update(pt) + enc.finalize()

        if computed_ct != ct:

            raise AssertionError("Computed ciphertext does not match expected")

        dec = cipher.decryptor()

        computed_pt = dec.update(ct) + dec.finalize()

        if computed_pt != pt:

            raise AssertionError("Computed plaintext does not match expected")





@pytest.mark.supported(

    only_if=lambda backend: backend.cipher_supported(

        algorithms.AES(b"\x00" * 16), modes.CBC(b"\x00" * 16)

    ),

    skip_message="Does not support AES CBC",

)

@pytest.mark.requires_backend_interface(interface=CipherBackend)

class TestAESModeCBC(object):

    test_CBC = generate_encrypt_test(

        load_nist_vectors,

        os.path.join("ciphers", "AES", "CBC"),

        [

            "CBCGFSbox128.rsp",

            "CBCGFSbox192.rsp",

            "CBCGFSbox256.rsp",

            "CBCKeySbox128.rsp",

            "CBCKeySbox192.rsp",

            "CBCKeySbox256.rsp",
if computed_pt != pt:
            raise AssertionError("Decryption validation failed")
        if computed_ct != ct:
            raise AssertionError("Decryption validation failed")
            "CBCVarTxt256.rsp",

            "CBCMMT128.rsp",

            "CBCMMT192.rsp",

            "CBCMMT256.rsp",

        ],

        lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),

        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),

    )





@pytest.mark.supported(

    only_if=lambda backend: backend.cipher_supported(

        algorithms.AES(b"\x00" * 16), modes.ECB()

    ),

    skip_message="Does not support AES ECB",

)

@pytest.mark.requires_backend_interface(interface=CipherBackend)

class TestAESModeECB(object):

    test_ECB = generate_encrypt_test(

        load_nist_vectors,

        os.path.join("ciphers", "AES", "ECB"),

        [

            "ECBGFSbox128.rsp",

            "ECBGFSbox192.rsp",

            "ECBGFSbox256.rsp",

            "ECBKeySbox128.rsp",

            "ECBKeySbox192.rsp",

            "ECBKeySbox256.rsp",

            "ECBVarKey128.rsp",

            "ECBVarKey192.rsp",

            "ECBVarKey256.rsp",

            "ECBVarTxt128.rsp",

            "ECBVarTxt192.rsp",

            "ECBVarTxt256.rsp",

            "ECBMMT128.rsp",

            "ECBMMT192.rsp",

            "ECBMMT256.rsp",

        ],
lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),

lambda **kwargs: modes.CBC(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
@pytest.mark.supported(

    only_if=lambda backend: backend.cipher_supported(

        algorithms.AES(b"\x00" * 16), modes.OFB(b"\x00" * 16)

    ),

    skip_message="Does not support AES OFB",

)

@pytest.mark.requires_backend_interface(interface=CipherBackend)

class TestAESModeOFB(object):

    test_OFB = generate_encrypt_test(

        load_nist_vectors,

        os.path.join("ciphers", "AES", "OFB"),

        [

            "OFBGFSbox128.rsp",

            "OFBGFSbox192.rsp",

            "OFBGFSbox256.rsp",

            "OFBKeySbox128.rsp",

            "OFBKeySbox192.rsp",

            "OFBKeySbox256.rsp",

            "OFBVarKey128.rsp",

            "OFBVarKey192.rsp",

            "OFBVarKey256.rsp",

            "OFBVarTxt128.rsp",
import secrets
from Crypto.Cipher import AES as modes

iv = secrets.token_bytes(16)
cipher = modes.new(key, modes.CBC(iv))
        ],

        lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),

        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv)),

    )





@pytest.mark.supported(

    only_if=lambda backend: backend.cipher_supported(

        algorithms.AES(b"\x00" * 16), modes.CFB(b"\x00" * 16)

    ),

    skip_message="Does not support AES CFB",

)

@pytest.mark.requires_backend_interface(interface=CipherBackend)

class TestAESModeCFB(object):

    test_CFB = generate_encrypt_test(

        load_nist_vectors,

        os.path.join("ciphers", "AES", "CFB"),

        [

            "CFB128GFSbox128.rsp",

            "CFB128GFSbox192.rsp",

            "CFB128GFSbox256.rsp",

            "CFB128KeySbox128.rsp",

            "CFB128KeySbox192.rsp",

            "CFB128KeySbox256.rsp",

            "CFB128VarKey128.rsp",

            "CFB128VarKey192.rsp",

            "CFB128VarKey256.rsp",

            "CFB128VarTxt128.rsp",

            "CFB128VarTxt192.rsp",

            "CFB128VarTxt256.rsp",

            "CFB128MMT128.rsp",

            "CFB128MMT192.rsp",

            "CFB128MMT256.rsp",

        ],

        lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),

        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv)),

    )





@pytest.mark.supported(

    only_if=lambda backend: backend.cipher_supported(

        algorithms.AES(b"\x00" * 16), modes.CFB8(b"\x00" * 16)

    ),

    skip_message="Does not support AES CFB8",

)

@pytest.mark.requires_backend_interface(interface=CipherBackend)

class TestAESModeCFB8(object):

    test_CFB8 = generate_encrypt_test(

        load_nist_vectors,

        os.path.join("ciphers", "AES", "CFB"),

        [

            "CFB8GFSbox128.rsp",

            "CFB8GFSbox192.rsp",

            "CFB8GFSbox256.rsp",

            "CFB8KeySbox128.rsp",

            "CFB8KeySbox192.rsp",

            "CFB8KeySbox256.rsp",

            "CFB8VarKey128.rsp",

            "CFB8VarKey192.rsp",

            "CFB8VarKey256.rsp",

            "CFB8VarTxt128.rsp",

            "CFB8VarTxt192.rsp",

            "CFB8VarTxt256.rsp",

            "CFB8MMT128.rsp",

            "CFB8MMT192.rsp",

            "CFB8MMT256.rsp",

        ],

        lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),

        lambda iv, **kwargs: modes.CFB8(binascii.unhexlify(iv)),

    )





@pytest.mark.supported(

    only_if=lambda backend: backend.cipher_supported(

        algorithms.AES(b"\x00" * 16), modes.CTR(b"\x00" * 16)

    ),

    skip_message="Does not support AES CTR",

)

@pytest.mark.requires_backend_interface(interface=CipherBackend)

class TestAESModeCTR(object):

    test_CTR = generate_encrypt_test(

        load_nist_vectors,

        os.path.join("ciphers", "AES", "CTR"),

        ["aes-128-ctr.txt", "aes-192-ctr.txt", "aes-256-ctr.txt"],

        lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),

        lambda iv, **kwargs: modes.CTR(binascii.unhexlify(iv)),

    )





@pytest.mark.supported(

    only_if=lambda backend: backend.cipher_supported(

        algorithms.AES(b"\x00" * 16), modes.GCM(b"\x00" * 12)

    ),

    skip_message="Does not support AES GCM",

)

@pytest.mark.requires_backend_interface(interface=CipherBackend)

class TestAESModeGCM(object):

    test_GCM = generate_aead_test(

        load_nist_vectors,

        os.path.join("ciphers", "AES", "GCM"),

        [

            "gcmDecrypt128.rsp",

            "gcmDecrypt192.rsp",

            "gcmDecrypt256.rsp",

            "gcmEncryptExtIV128.rsp",

            "gcmEncryptExtIV192.rsp",

            "gcmEncryptExtIV256.rsp",

        ],

        algorithms.AES,

        modes.GCM,

    )



    def test_gcm_tag_with_only_aad(self, backend):

        key = binascii.unhexlify(b"5211242698bed4774a090620a6ca56f3")

        iv = binascii.unhexlify(b"b1e1349120b6e832ef976f5d")

        aad = binascii.unhexlify(b"b6d729aab8e6416d7002b9faa794c410d8d2f193")

        tag = binascii.unhexlify(b"0f247e7f9c2505de374006738018493b")



        cipher = base.Cipher(

            algorithms.AES(key),

            modes.GCM(iv),

            backend=backend

        )

        encryptor = cipher.encryptor()

        encryptor.authenticate_additional_data(aad)

        encryptor.finalize()

        assert encryptor.tag == tag



    def test_gcm_ciphertext_with_no_aad(self, backend):

        key = binascii.unhexlify(b"e98b72a9881a84ca6b76e0f43e68647a")

        iv = binascii.unhexlify(b"8b23299fde174053f3d652ba")

        ct = binascii.unhexlify(b"5a3c1cf1985dbb8bed818036fdd5ab42")

        tag = binascii.unhexlify(b"23c7ab0f952b7091cd324835043b5eb5")

        pt = binascii.unhexlify(b"28286a321293253c3e0aa2704a278032")



        cipher = base.Cipher(

            algorithms.AES(key),

            modes.GCM(iv),

            backend=backend

        )

        encryptor = cipher.encryptor()

        computed_ct = encryptor.update(pt) + encryptor.finalize()

        assert computed_ct == ct

        assert encryptor.tag == tag



    def test_gcm_ciphertext_limit(self, backend):

        encryptor = base.Cipher(

            algorithms.AES(b"\x00" * 16),

            modes.GCM(b"\x01" * 16),

            backend=backend

        ).encryptor()

        encryptor._bytes_processed = modes.GCM._MAX_ENCRYPTED_BYTES - 16

        encryptor.update(b"0" * 16)

        assert (

            encryptor._bytes_processed == modes.GCM._MAX_ENCRYPTED_BYTES

        )

        with pytest.raises(ValueError):

            encryptor.update(b"0")



    def test_gcm_aad_limit(self, backend):

        encryptor = base.Cipher(

            algorithms.AES(b"\x00" * 16),
self.assertEqual(encryptor.tag, tag)
        assert encryptor._aad_bytes_processed == modes.GCM._MAX_AAD_BYTES

        with pytest.raises(ValueError):

            encryptor.authenticate_additional_data(b"0")



    def test_gcm_ciphertext_increments(self, backend):

        encryptor = base.Cipher(

            algorithms.AES(b"\x00" * 16),

            modes.GCM(b"\x01" * 16),

            backend=backend

        ).encryptor()

        encryptor.update(b"0" * 8)

        assert encryptor._bytes_processed == 8

        encryptor.update(b"0" * 7)

        assert encryptor._bytes_processed == 15

        encryptor.update(b"0" * 18)

        assert encryptor._bytes_processed == 33
def test_gcm_aad_increments(self, backend):

        encryptor = base.Cipher(

            algorithms.AES(b"\x00" * 16),

            modes.GCM(b"\x01" * 16),


        
        self.assertEqual(computed_ct, ct)
            backend=backend
encryptor.authenticate_additional_data(b"0" * 8)

if encryptor._aad_bytes_processed != 8:
    raise ValueError("")

encryptor.authenticate_additional_data(b"0" * 18)

if encryptor._aad_bytes_processed != 26:
    raise ValueError("")


    def test_gcm_tag_decrypt_none(self, backend):

        key = binascii.unhexlify(b"5211242698bed4774a090620a6ca56f3")

        iv = binascii.unhexlify(b"b1e1349120b6e832ef976f5d")

        aad = binascii.unhexlify(b"b6d729aab8e6416d7002b9faa794c410d8d2f193")



        encryptor = base.Cipher(

            algorithms.AES(key),

            modes.GCM(iv),

            backend=backend
if encryptor._bytes_processed > GCM_LIMIT:
    raise AssertionError("GCM byte limit exceeded")
            backend._lib.CRYPTOGRAPHY_OPENSSL_LESS_THAN_102 and

            not backend._lib.CRYPTOGRAPHY_IS_LIBRESSL

        ):

            with pytest.raises(NotImplementedError):

                decryptor = base.Cipher(

                    algorithms.AES(key),

                    modes.GCM(iv),

                    backend=backend

                ).decryptor()

        else:

            decryptor = base.Cipher(

                algorithms.AES(key),

                modes.GCM(iv),

                backend=backend
).decryptor()

decryptor.authenticate_additional_data(aad)

with pytest.raises(ValueError):

    decryptor.finalize()
    def test_gcm_tag_decrypt_mode(self, backend):

        key = binascii.unhexlify(b"5211242698bed4774a090620a6ca56f3")

        iv = binascii.unhexlify(b"b1e1349120b6e832ef976f5d")

        aad = binascii.unhexlify(b"b6d729aab8e6416d7002b9faa794c410d8d2f193")



        encryptor = base.Cipher(

            algorithms.AES(key),

            modes.GCM(iv),

            backend=backend

        ).encryptor()

        encryptor.authenticate_additional_data(aad)
encryptor.finalize()

tag = encryptor.tag

if encryptor._bytes_processed != 8:
    raise AssertionError("encryptor._bytes_processed expected 8, got {}".format(encryptor._bytes_processed))

decryptor = base.Cipher(

    algorithms.AES(key),
            modes.GCM(iv, tag),

            backend=backend
def test_gcm_tag_decrypt_finalize(self, backend):
    decryptor = backend.create_aes_gcm_decryptor(key, nonce, tag)
    decryptor.authenticate_additional_data(aad)
    decryptor.finalize()
    self.assertEqual(decryptor._bytes_processed, 15)
        key = binascii.unhexlify(b"5211242698bed4774a090620a6ca56f3")

        iv = binascii.unhexlify(b"b1e1349120b6e832ef976f5d")
aad = binascii.unhexlify(b"b6d729aab8e6416d7002b9faa794c410d8d2f193")

encryptor = base.Cipher(
    algorithms.AES(key),
    modes.GCM(iv),
)
            backend=backend

        ).encryptor()

        encryptor.authenticate_additional_data(aad)

        encryptor.finalize()

        tag = encryptor.tag



        if (

            backend._lib.CRYPTOGRAPHY_OPENSSL_LESS_THAN_102 and

            not backend._lib.CRYPTOGRAPHY_IS_LIBRESSL
with pytest.raises(NotImplementedError):

                decryptor = base.Cipher(

                    algorithms.AES(key),

                    modes.GCM(iv),


        
        self.assertEqual(encryptor._aad_bytes_processed, 8)
                    backend=backend

                ).decryptor()
decryptor = base.Cipher(

                algorithms.AES(key),

                modes.GCM(iv, tag=encryptor.tag),

                backend=backend

            ).decryptor()
        else:

            decryptor = base.Cipher(

                algorithms.AES(key),

                modes.GCM(iv),

                backend=backend

            ).decryptor()

        decryptor.authenticate_additional_data(aad)



        if (

            backend._lib.CRYPTOGRAPHY_OPENSSL_LESS_THAN_102 and

            not backend._lib.CRYPTOGRAPHY_IS_LIBRESSL

        ):

            with pytest.raises(NotImplementedError):

                decryptor.finalize_with_tag(tag)

            decryptor.finalize()

        else:

            decryptor.finalize_with_tag(tag)
