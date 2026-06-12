from __future__ import annotations
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC


def bytes_to_hex(b: bytes) -> str:
    return b.hex(' ').upper()


def derive_fields_from_wmbus_address(addr: bytes) -> Dict[str, str]:
    if len(addr) != 8:
        raise ValueError("adresse wMBus attendue sur 8 octets")
    return {
        "manufacturer_hex": addr[0:2].hex().upper(),
        "identification_hex": addr[2:6].hex().upper(),
        "version_hex": addr[6:7].hex().upper(),
        "device_type_hex": addr[7:8].hex().upper(),
    }


def build_manufacturer_block(manufacturer: bytes, identification: bytes, version: bytes, device_type: bytes) -> bytes:
    if len(manufacturer) != 2:
        raise ValueError("Manufacturer doit faire 2 octets")
    if len(identification) != 4:
        raise ValueError("Identification doit faire 4 octets")
    if len(version) != 1:
        raise ValueError("Version doit faire 1 octet")
    if len(device_type) != 1:
        raise ValueError("Device type doit faire 1 octet")
    return manufacturer + identification + version + device_type


def parse_mode8_frame(frame: bytes, mac_len: int = 4) -> Dict[str, Any]:
    if len(frame) < 5 + 2 + mac_len:
        raise ValueError("trame trop courte pour le mode 8")

    ci = frame[0]
    access_no = frame[1]
    status = frame[2]
    cf_counter = frame[3]
    cf_mode = frame[4]

    if cf_mode != 0x08:
        raise ValueError(f"mode de sécurité inattendu : 0x{cf_mode:02X} attendu 0x08")

    if cf_counter == 0x30:
        ctr_size = 4
    elif cf_counter == 0x10:
        ctr_size = 2
    else:
        raise ValueError(f"CF compteur non reconnu : 0x{cf_counter:02X}")

    start = 5
    ctr_bytes = frame[start:start + ctr_size]
    ctr_value = int.from_bytes(ctr_bytes, "little", signed=False)
    encrypted_payload = frame[start + ctr_size:-mac_len]
    mac_received = frame[-mac_len:]

    return {
        "ci": ci,
        "access_no": access_no,
        "status": status,
        "cf_counter": cf_counter,
        "cf_mode": cf_mode,
        "ctr_size": ctr_size,
        "ctr_bytes_le": ctr_bytes,
        "ctr_value": ctr_value,
        "encrypted_payload": encrypted_payload,
        "mac_received": mac_received,
    }

def validate_mode8_frame(frame: bytes, mac_len: int = 4) -> Dict[str, Any]:
    """
    Valide une trame sécurisée Mode 8 avant déchiffrement.

    Contrôles effectués :
    - longueur minimale
    - header sécurité
    - CF compteur : 0x30 ou 0x10
    - CF mode : 0x08
    - présence du CTR
    - présence du payload chiffré
    - présence du MAC
    """

    errors = []
    warnings = []

    # ------------------------------------------------------------
    # 1. Vérification trame vide
    # ------------------------------------------------------------
    if frame is None or len(frame) == 0:
        errors.append("La trame est vide.")
        return {
            "valid": False,
            "errors": errors,
            "warnings": warnings,
            "length": 0,
        }

    frame_len = len(frame)

    # ------------------------------------------------------------
    # 2. Vérification longueur MAC
    # ------------------------------------------------------------
    if mac_len not in (2, 4):
        errors.append(
            f"Longueur MAC invalide : {mac_len}. Valeurs acceptées : 2 ou 4."
        )
        return {
            "valid": False,
            "errors": errors,
            "warnings": warnings,
            "length": frame_len,
        }

    # ------------------------------------------------------------
    # 3. Longueur minimale absolue
    # Structure minimale :
    # CI + Access No + Status + CF counter + CF mode + CTR min 2 + MAC
    # = 5 + 2 + mac_len
    # ------------------------------------------------------------
    min_len_absolute = 5 + 2 + mac_len

    if frame_len < min_len_absolute:
        errors.append(
            f"Trame trop courte : {frame_len} octets. "
            f"Minimum attendu : {min_len_absolute} octets."
        )
        return {
            "valid": False,
            "errors": errors,
            "warnings": warnings,
            "length": frame_len,
            "first_bytes_hex": frame.hex(" ").upper(),
            "last_bytes_hex": frame.hex(" ").upper(),
        }

    # ------------------------------------------------------------
    # 4. Lecture du header sécurité
    # ------------------------------------------------------------
    ci = frame[0]
    access_no = frame[1]
    status = frame[2]
    cf_counter = frame[3]
    cf_mode = frame[4]

    # ------------------------------------------------------------
    # 5. Vérification CF mode
    # ------------------------------------------------------------
    if cf_mode != 0x08:
        errors.append(
            f"Mode de sécurité invalide : 0x{cf_mode:02X}. "
            "Attendu : 0x08 pour le Mode 8."
        )

    # ------------------------------------------------------------
    # 6. Détermination taille CTR
    # ------------------------------------------------------------
    if cf_counter == 0x30:
        ctr_size = 4
    elif cf_counter == 0x10:
        ctr_size = 2
    else:
        ctr_size = None
        errors.append(
            f"CF compteur non reconnu : 0x{cf_counter:02X}. "
            "Attendu : 0x30 pour CTR 4 octets ou 0x10 pour CTR 2 octets."
        )

    # Si header invalide, on bloque déjà
    if errors:
        return {
            "valid": False,
            "errors": errors,
            "warnings": warnings,
            "length": frame_len,
            "ci_hex": f"{ci:02X}",
            "access_no_hex": f"{access_no:02X}",
            "status_hex": f"{status:02X}",
            "cf_counter_hex": f"{cf_counter:02X}",
            "cf_mode_hex": f"{cf_mode:02X}",
            "first_bytes_hex": frame[:10].hex(" ").upper(),
            "last_bytes_hex": frame[-10:].hex(" ").upper(),
        }

    # ------------------------------------------------------------
    # 7. Vérification longueur complète avec CTR + payload + MAC
    # ------------------------------------------------------------
    min_len_with_payload = 5 + ctr_size + mac_len + 1

    if frame_len < min_len_with_payload:
        errors.append(
            f"Trame trop courte pour contenir un payload chiffré : {frame_len} octets. "
            f"Minimum attendu avec CTR {ctr_size} octets et MAC {mac_len} octets : "
            f"{min_len_with_payload} octets."
        )

    ctr_start = 5
    ctr_end = ctr_start + ctr_size
    payload_start = ctr_end
    payload_end = frame_len - mac_len

    ctr_bytes = frame[ctr_start:ctr_end]
    encrypted_payload = frame[payload_start:payload_end]
    mac_received = frame[payload_end:frame_len]

    # ------------------------------------------------------------
    # 8. Vérification CTR
    # ------------------------------------------------------------
    if len(ctr_bytes) != ctr_size:
        errors.append(
            f"CTR incomplet : {len(ctr_bytes)} octets lus, {ctr_size} attendus."
        )

    # ------------------------------------------------------------
    # 9. Vérification payload chiffré
    # ------------------------------------------------------------
    if len(encrypted_payload) <= 0:
        errors.append("Payload chiffré absent ou vide.")

    # ------------------------------------------------------------
    # 10. Vérification MAC présent
    # ------------------------------------------------------------
    if len(mac_received) != mac_len:
        errors.append(
            f"MAC incomplet : {len(mac_received)} octets lus, {mac_len} attendus."
        )

    # ------------------------------------------------------------
    # 11. Warnings utiles
    # ------------------------------------------------------------
    if frame_len < 40:
        warnings.append(
            "La trame est courte. Vérifie qu'elle n'est pas tronquée."
        )

    if len(encrypted_payload) < 10:
        warnings.append(
            "Le payload chiffré est très court. Vérifie que la trame est complète."
        )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "length": frame_len,
        "ci_hex": f"{ci:02X}",
        "access_no_hex": f"{access_no:02X}",
        "status_hex": f"{status:02X}",
        "cf_counter_hex": f"{cf_counter:02X}",
        "cf_mode_hex": f"{cf_mode:02X}",
        "ctr_size": ctr_size,
        "ctr_hex_le": ctr_bytes.hex(" ").upper(),
        "ctr_value": int.from_bytes(ctr_bytes, "little", signed=False)
        if len(ctr_bytes) == ctr_size
        else None,
        "encrypted_payload_length": len(encrypted_payload),
        "mac_len": mac_len,
        "mac_received_hex": mac_received.hex(" ").upper(),
        "first_bytes_hex": frame[:10].hex(" ").upper(),
        "last_bytes_hex": frame[-10:].hex(" ").upper()
        if frame_len >= 10
        else frame.hex(" ").upper(),
    }

def make_iv_block(manufacturer: bytes, identification: bytes, version: bytes, device_type: bytes, ctr_value: int, block_counter: int) -> bytes:
    message_counter_be = ctr_value.to_bytes(4, "big", signed=False)
    return manufacturer + identification + version + device_type + message_counter_be + b"\x00\x00" + block_counter.to_bytes(2, "big", signed=False)


def aes_ctr_crypt(data: bytes, key: bytes, manufacturer: bytes, identification: bytes, version: bytes, device_type: bytes, ctr_value: int) -> bytes:
    if len(key) != 16:
        raise ValueError("la clé AES doit faire 16 octets")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    out = bytearray()

    for block_idx in range((len(data) + 15) // 16):
        iv = make_iv_block(manufacturer, identification, version, device_type, ctr_value, block_idx)
        keystream = encryptor.update(iv)
        chunk = data[block_idx * 16:(block_idx + 1) * 16]
        out.extend(bytes(a ^ b for a, b in zip(chunk, keystream[:len(chunk)])))

    return bytes(out)


def compute_mode8_mac(kmac1_key: bytes, manufacturer: bytes, identification: bytes, version: bytes, device_type: bytes, ctr_bytes_le: bytes, encrypted_payload: bytes) -> bytes:
    if len(kmac1_key) != 16:
        raise ValueError("la clé KMAC1 doit faire 16 octets")

    payload_mac = manufacturer + identification + version + device_type + ctr_bytes_le + (b"\x00" * 4) + encrypted_payload
    c = CMAC(algorithms.AES(kmac1_key))
    c.update(payload_mac)
    return c.finalize()


def decrypt_mode8_frame(frame: bytes, encryption_key: bytes, kmac1_key: bytes, manufacturer: bytes, identification: bytes, version: bytes, device_type: bytes, mac_len: int = 4) -> Dict[str, Any]:
    parsed = parse_mode8_frame(frame, mac_len=mac_len)
    full_mac = compute_mode8_mac(kmac1_key, manufacturer, identification, version, device_type, parsed["ctr_bytes_le"], parsed["encrypted_payload"])
    mac_calculated = full_mac[:mac_len]

    decrypted_payload = aes_ctr_crypt(parsed["encrypted_payload"], encryption_key, manufacturer, identification, version, device_type, parsed["ctr_value"])
    iv0 = make_iv_block(manufacturer, identification, version, device_type, parsed["ctr_value"], 0)

    return {
        "security_header": {
            "ci_hex": f"{parsed['ci']:02X}",
            "access_no_hex": f"{parsed['access_no']:02X}",
            "status_hex": f"{parsed['status']:02X}",
            "cf_counter_hex": f"{parsed['cf_counter']:02X}",
            "cf_mode_hex": f"{parsed['cf_mode']:02X}",
            "ctr_size": parsed["ctr_size"],
            "ctr_hex_le": bytes_to_hex(parsed["ctr_bytes_le"]),
        },
        "ctr_value": parsed["ctr_value"],
        "manufacturer_block_hex": bytes_to_hex(build_manufacturer_block(manufacturer, identification, version, device_type)),
        "iv_block0_hex": bytes_to_hex(iv0),
        "encrypted_payload_hex": bytes_to_hex(parsed["encrypted_payload"]),
        "decrypted_payload": decrypted_payload,
        "decrypted_payload_hex": bytes_to_hex(decrypted_payload),
        "mac_received_hex": bytes_to_hex(parsed["mac_received"]),
        "mac_calculated_hex": bytes_to_hex(mac_calculated),
        "mac_valid": parsed["mac_received"] == mac_calculated,
    }
