"""EFI GUID handling and the known-GUID name database.

The bundled ``data/guids.csv`` database originates from the UEFITool project
(Copyright (c) 2015, Nikolaj Schlej, BSD-2-Clause) and is extended with
FirmwareLab-specific entries in ``data/guids_extra.csv``.
"""

from __future__ import annotations

import csv
import os
import re
import uuid
from functools import lru_cache

_GUID_RE = re.compile(
    r"^\{?([0-9A-Fa-f]{8})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{12})\}?$"
)

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def guid_to_str(raw) -> str:
    """Convert 16 raw (mixed-endian EFI) bytes to canonical upper-case GUID text."""
    return str(uuid.UUID(bytes_le=bytes(raw[:16]))).upper()


def str_to_guid(text: str) -> bytes:
    """Convert GUID text (with or without braces) to 16 raw EFI bytes."""
    text = text.strip()
    if not _GUID_RE.match(text):
        raise ValueError("Invalid GUID: %r" % text)
    return uuid.UUID(text.strip("{}")).bytes_le


def is_guid_text(text: str) -> bool:
    return bool(_GUID_RE.match(text.strip()))


def guid_c_struct(raw) -> str:
    """Format as a C initializer: { 0x..., 0x..., 0x..., { 0x.. x8 } }."""
    b = bytes(raw[:16])
    u = uuid.UUID(bytes_le=b)
    d1 = u.fields[0]
    d2 = u.fields[1]
    d3 = u.fields[2]
    d4 = b[8:16]
    return "{ 0x%08X, 0x%04X, 0x%04X, { %s } }" % (d1, d2, d3, ", ".join("0x%02X" % x for x in d4))


class GuidDatabase:
    """Maps GUIDs to human readable names. User entries override bundled ones."""

    def __init__(self):
        self._names: dict[str, str] = {}
        self._reverse: dict[str, list[str]] = {}
        self._user_path: str | None = None
        self.load_file(os.path.join(_DATA_DIR, "guids.csv"))
        self.load_file(os.path.join(_DATA_DIR, "guids_extra.csv"))
        user = self.user_db_path()
        if user and os.path.isfile(user):
            self.load_file(user)

    @staticmethod
    def user_db_path() -> str:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
        return os.path.join(base, "firmwarelab", "guids.csv")

    def load_file(self, path: str) -> int:
        if not os.path.isfile(path):
            return 0
        count = 0
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                if len(row) < 2 or not row[0] or row[0].startswith("#"):
                    continue
                g = row[0].strip().strip("{}").upper()
                if not _GUID_RE.match(g):
                    continue
                self.add(g, row[1].strip())
                count += 1
        return count

    def add(self, guid: str, name: str) -> None:
        guid = guid.upper()
        self._names[guid] = name
        self._reverse.setdefault(name.lower(), []).append(guid)

    def name(self, guid) -> str | None:
        if isinstance(guid, (bytes, bytearray, memoryview)):
            guid = guid_to_str(guid)
        return self._names.get(guid.upper())

    def display(self, guid) -> str:
        """Name if known, else GUID text."""
        text = guid_to_str(guid) if isinstance(guid, (bytes, bytearray, memoryview)) else guid.upper()
        return self._names.get(text, text)

    def lookup_name(self, name: str) -> list[str]:
        return list(self._reverse.get(name.lower(), []))

    def search(self, needle: str, limit: int = 200) -> list[tuple[str, str]]:
        needle = needle.lower()
        out = []
        for g, n in self._names.items():
            if needle in n.lower() or needle in g.lower():
                out.append((g, n))
                if len(out) >= limit:
                    break
        return out

    def __len__(self) -> int:
        return len(self._names)

    def save_user_entry(self, guid: str, name: str) -> None:
        path = self.user_db_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow([guid.upper(), name])
        self.add(guid, name)


@lru_cache(maxsize=1)
def guid_db() -> GuidDatabase:
    return GuidDatabase()


def G(text: str) -> bytes:
    """Shorthand used for well-known GUID constants."""
    return str_to_guid(text)


ZERO_GUID = bytes(16)
FF_GUID = b"\xff" * 16

# --- Firmware file systems -------------------------------------------------
FFS1_GUID = G("7A9354D9-0468-444A-81CE-0BF617D890DF")
FFS2_GUID = G("8C8CE578-8A3D-4F1C-9935-896185C32DD3")
FFS3_GUID = G("5473C07A-3DCB-4DCA-BD6F-1E9689E7349A")
APPLE_IMMUTABLE_FV_GUID = G("04ADEEAD-61FF-4D31-B6BA-64F8BF901F5A")
APPLE_AUTHENTICATION_FV_GUID = G("BD001B8C-6A71-487B-A14F-0C2A2DCF7A5D")
APPLE_MICROCODE_VOLUME_GUID = G("153D2197-29BD-44DC-AC59-887F70E41A6B")
INTEL_FILE_SYSTEM_GUID = G("AD3FFFFF-D28B-44C4-9F13-9EA98A97F9F0")
INTEL_FILE_SYSTEM2_GUID = G("D6A1CD70-4B33-4994-A6EA-375F2CCC5437")
SONY_FILE_SYSTEM_GUID = G("4F494156-AED6-4D64-A537-B8A5557BCEEC")
HP_FILE_SYSTEM_GUID = G("372B56DF-CC9F-4817-AB97-0A10A92CEAA5")

FFS2_VOLUMES = {
    FFS1_GUID, FFS2_GUID, APPLE_IMMUTABLE_FV_GUID, APPLE_AUTHENTICATION_FV_GUID,
    APPLE_MICROCODE_VOLUME_GUID, INTEL_FILE_SYSTEM_GUID, INTEL_FILE_SYSTEM2_GUID,
    SONY_FILE_SYSTEM_GUID, HP_FILE_SYSTEM_GUID,
}
FFS3_VOLUMES = {FFS3_GUID}

# --- NVRAM -----------------------------------------------------------------
NVRAM_MAIN_STORE_VOLUME_GUID = G("FFF12B8D-7696-4C8B-A985-2747075B4F50")
NVRAM_ADDITIONAL_STORE_VOLUME_GUID = G("00504624-8A59-4EEB-BD0F-6B36E96128E0")
NVRAM_NVAR_STORE_FILE_GUID = G("CEF5B9A3-476D-497F-9FDC-E98143E0422C")
NVRAM_NVAR_EXTERNAL_DEFAULTS_FILE_GUID = G("9221315B-30BB-46B5-813E-1B1BF4712BD3")
NVRAM_NVAR_PEI_EXTERNAL_DEFAULTS_FILE_GUID = G("77D3DC50-D42B-4916-AC80-8F469035D150")
NVRAM_NVAR_BB_DEFAULTS_FILE_GUID = G("AF516361-B4C5-436E-A7E3-A149A31B1461")
PHOENIX_EVSA_RAW_SECTION_GUID = G("DAB78572-E8D1-4C3F-9A1E-F27E9CAF686D")
EFI_VARIABLE_GUID = G("DDCF3616-3275-4164-98B6-FE85707FFE7D")
EFI_VARIABLE_GUID_2 = G("DDCF3617-3275-4164-98B6-FE85707FFE7D")
EFI_AUTHENTICATED_VARIABLE_GUID = G("AAF32C78-947B-439A-A180-2E144EC37792")
EDKII_WORKING_BLOCK_SIGNATURE_GUID = G("9E58292B-7C68-497D-0ACE-6500FD9F1B95")
VSS2_WORKING_BLOCK_SIGNATURE_GUID = G("9E58292B-7C68-497D-A0CE-6500FD9F1B95")
EFI_GLOBAL_VARIABLE_GUID = G("8BE4DF61-93CA-11D2-AA0D-00E098032B8C")
EFI_IMAGE_SECURITY_DATABASE_GUID = G("D719B2CB-3D3A-4596-A3BC-DAD00E67656F")

# --- Special files ---------------------------------------------------------
PEI_APRIORI_FILE_GUID = G("1B45CC0A-156A-428A-AF62-49864DA0E6E6")
DXE_APRIORI_FILE_GUID = G("FC510EE7-FFDC-11D4-BD41-0080C73C8881")
VOLUME_TOP_FILE_GUID = G("1BA0062E-C779-4582-8566-336AE8F78F09")
AMI_PAD_FILE_GUID = G("E4536585-7909-4A60-B5C6-ECDEA6EBFB54")
AMI_CORE_DXE_GUID = G("5AE3F37E-4EAE-41AE-8240-35465B5E81EB")
EFI_DXE_CORE_GUID = G("D6A2CB7F-6A18-4E2F-B43B-9920A733700A")
MICROCODE_FILE_GUID = G("17088572-377F-44EF-8F4E-B09FFF46A070")
MICROCODE_FILE_GUID_2 = G("197DB236-F856-4924-90F8-CDF12FB875F3")
AMI_ROM_HOLE_BASE = "05CA01FC-0FC1-11DC-9011-00173153EBA8"
BOOT_GUARD_AMI_HASH_FILE_GUID = G("CBC91F44-A4BC-4A5B-8696-703451D0B053")
BOOT_GUARD_PHOENIX_HASH_FILE_GUID = G("389CC6F2-1EA8-467B-AB8A-78E769AE2A15")
AMI_SETUP_FILE_GUID = G("899407D7-99FE-43D8-9A21-79EC328CAC21")

# --- GUID-defined sections -------------------------------------------------
SECTION_CRC32_GUID = G("FC1BCDB0-7D31-49AA-936A-A4600D9DD083")
SECTION_TIANO_GUID = G("A31280AD-481E-41B6-95E8-127F4C984779")
SECTION_LZMA_GUID = G("EE4E5898-3914-4259-9D6E-DC7BD79403CF")
SECTION_LZMA_HP_GUID = G("0ED85E23-F253-413F-A03C-901987B04397")
SECTION_LZMA_MS_GUID = G("BD9921EA-ED91-404A-8B2F-B4D724747C8C")
SECTION_LZMAF86_GUID = G("D42AE6BD-1352-4BFB-909A-CA72A6EAE889")
SECTION_GZIP_GUID = G("1D301FE9-BE79-4353-91C2-D23BC959AE0C")
SECTION_ZLIB_AMD_GUID = G("CE3233F5-2CD6-4D87-9152-4A238BB6D1C4")
SECTION_ZLIB_AMD2_GUID = G("991EFAC0-E260-416B-A4B8-3B153072B804")
SECTION_BROTLI_GUID = G("3D532050-5CDA-4FD0-879E-0F7F630D5AFB")
FIRMWARE_CONTENTS_SIGNED_GUID = G("0F9D89E8-9259-4F76-A5AF-0C89E34023DF")
CERT_TYPE_RSA2048_SHA256_GUID = G("A7717414-C616-4977-9420-844712A735BF")
HASH_ALGORITHM_SHA256_GUID = G("51AA59DE-FDF2-4EA3-BC63-875FB7842EE9")

LZMA_SECTION_GUIDS = {SECTION_LZMA_GUID, SECTION_LZMA_HP_GUID, SECTION_LZMA_MS_GUID}

# --- Capsules --------------------------------------------------------------
EFI_CAPSULE_GUID = G("3B6686BD-0D76-4030-B70E-B5519E2FC5A0")
EFI_FMP_CAPSULE_GUID = G("6DCBD5ED-E82D-4C44-BDA1-7194199AD92A")
INTEL_CAPSULE_GUID = G("539182B9-ABB5-4391-B69A-E3A943F72FCC")
LENOVO_CAPSULE_GUID = G("E20BAFD3-9914-4F4F-9537-3129E090EB3C")
LENOVO2_CAPSULE_GUID = G("25B5FE76-8243-4A5C-A9BD-7EE3246198B5")
TOSHIBA_CAPSULE_GUID = G("3BE07062-1D51-45D2-832B-F093257ED461")
APTIO_SIGNED_CAPSULE_GUID = G("4A3CA68B-7723-48FB-803D-578CC1FEC44D")
APTIO_UNSIGNED_CAPSULE_GUID = G("14EEBB90-890A-43DB-AED1-5D3C4588A418")

# --- HII -------------------------------------------------------------------
EFI_HII_PLATFORM_SETUP_FORMSET_GUID = G("93039971-8545-4B04-B45E-32EB8326040E")
