# OmniGuard V2X: Kyber KEM handshake validation test
"""
Run an integration smoke test for V2X handshake key exchange.

Behavior:
- If liboqs with Kyber/ML-KEM support is available, require HS_PQC_KEM.
- Otherwise, report fallback HS_ECDH path.
"""

import os
import time

from v2x_protocol import V2XHub, V2XNode, oqs


def _enabled_kems():
    if oqs is None:
        return []
    for fn_name in (
        "get_enabled_kem_mechanisms",
        "get_enabled_KEM_mechanisms",
        "get_supported_kem_mechanisms",
        "get_supported_KEM_mechanisms",
    ):
        fn = getattr(oqs, fn_name, None)
        if callable(fn):
            try:
                values = fn()
                if isinstance(values, (list, tuple)):
                    return [str(v) for v in values]
            except Exception:
                continue
    return []


def main():
    os.environ["SMARTCAR_V2X_PQC_KEM_PREFERRED"] = "Kyber512"
    os.environ["SMARTCAR_V2X_PQC_KEM_ALGS"] = "Kyber512,ML-KEM-512"

    kems = _enabled_kems()
    has_kyber = any(k.upper() in ("KYBER512", "ML-KEM-512") for k in kems)

    hub = V2XHub(host="127.0.0.1", port=9994)
    hub.start()

    n1 = V2XNode("kyber_t1", "vehicle", host="127.0.0.1", port=9994)
    n2 = V2XNode("kyber_t2", "vehicle", host="127.0.0.1", port=9994)

    try:
        assert n1.connect(), "n1 connect failed"
        assert n2.connect(), "n2 connect failed"
        n1.send_v2v_telemetry(44.0, 23.8108, 90.4121, 0.0)
        time.sleep(0.6)

        print("oqs_available=", oqs is not None)
        print("enabled_kems=", kems[:12])
        print("n1_hs_mode=", n1.crypto_layer._hs_mode, "negotiated_kem=", n1.crypto_layer._negotiated_kem_alg)
        print("n2_hs_mode=", n2.crypto_layer._hs_mode, "negotiated_kem=", n2.crypto_layer._negotiated_kem_alg)

        if oqs is not None and has_kyber:
            assert n1.crypto_layer._hs_mode == "PQC_KEM", "Kyber KEM expected but handshake mode is not PQC_KEM"
            assert n1.crypto_layer._negotiated_kem_alg in ("Kyber512", "ML-KEM-512"), "Unexpected negotiated KEM"
            print("KYBER_KEM_TEST=PASS")
        else:
            print("KYBER_KEM_TEST=SKIP (liboqs or Kyber/ML-KEM not available; fallback path expected)")
    finally:
        n1.disconnect()
        n2.disconnect()
        hub.stop()


if __name__ == "__main__":
    main()

