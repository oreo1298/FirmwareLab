"""EFI 1.1 and Tiano compression (UEFI "standard" compression).

Both formats share the same LZ77 + canonical Huffman block structure and differ
only in the width of the position-set size field (4 bits for EFI 1.1, 5 bits for
Tiano) and the maximum match distance.

The decoder follows the reference EDK2 algorithm step by step (including its
table-building quirks) so that data is interpreted exactly as firmware does.
The encoder is an independent implementation that produces streams in the same
format (greedy/lazy LZ77 with hash chains, per-block Huffman trees limited to
16 bits), round-trip tested against the decoder.
"""

from __future__ import annotations

import heapq
import struct

EFI11 = 1
TIANO = 2

_BITBUFSIZ = 32
_MAXMATCH = 256
_THRESHOLD = 3
_CODE_BIT = 16
_NC = 0xFF + _MAXMATCH + 2 - _THRESHOLD  # 510
_CBIT = 9
_MAXPBIT = 5
_TBIT = 5
_MAXNP = (1 << _MAXPBIT) - 1  # 31
_NT = _CODE_BIT + 3  # 19
_NPT = max(_NT, _MAXNP)  # 31
_TREE_SIZE = 2 * _NC - 1


class TianoError(ValueError):
    pass


def get_info(src) -> tuple[int, int]:
    """Return (compressed size, original size) from the 8-byte header."""
    if len(src) < 8:
        raise TianoError("data too small")
    comp, orig = struct.unpack_from("<II", src, 0)
    if len(src) < comp + 8:
        raise TianoError("compressed size %Xh exceeds buffer size %Xh" % (comp, len(src) - 8))
    return comp, orig


# --------------------------------------------------------------------------
# Decoder
# --------------------------------------------------------------------------

def _make_table(nchar, bitlen, tablebits, table, left, right):
    count = [0] * 17
    for i in range(nchar):
        ln = bitlen[i]
        if ln > 16:
            raise TianoError("bad table (code length)")
        count[ln] += 1
    start = [0] * 18
    for i in range(1, 17):
        start[i + 1] = (start[i] + (count[i] << (16 - i))) & 0xFFFF
    if start[17] != 0:
        raise TianoError("bad table (incomplete code)")
    jubits = 16 - tablebits
    weight = [0] * 17
    for i in range(1, tablebits + 1):
        start[i] >>= jubits
        weight[i] = 1 << (tablebits - i)
    for i in range(tablebits + 1, 17):
        weight[i] = 1 << (16 - i)
    i = start[tablebits + 1] >> jubits
    if i != 0:
        i3 = 1 << tablebits
        for k in range(i, i3):
            table[k] = 0
    avail = nchar
    mask = 1 << (15 - tablebits)
    maxlen = 1 << tablebits
    for ch in range(nchar):
        ln = bitlen[ch]
        if ln == 0:
            continue
        nextcode = (start[ln] + weight[ln]) & 0xFFFF
        if ln <= tablebits:
            s = start[ln]
            if nextcode > maxlen:
                raise TianoError("bad table (overflow)")
            for k in range(s, nextcode):
                table[k] = ch
        else:
            i3 = start[ln]
            arr = table
            idx = i3 >> jubits
            k = ln - tablebits
            while k:
                if arr[idx] == 0 and avail < _TREE_SIZE:
                    right[avail] = 0
                    left[avail] = 0
                    arr[idx] = avail
                    avail += 1
                if arr[idx] < _TREE_SIZE:
                    nxt = arr[idx]
                    arr = right if (i3 & mask) else left
                    idx = nxt
                i3 = (i3 << 1) & 0xFFFF
                k -= 1
            arr[idx] = ch
        start[ln] = nextcode


def decompress(src, version: int = EFI11) -> bytes:
    """Decompress EFI 1.1 (version=1) or Tiano (version=2) data including the 8-byte header."""
    comp_size, orig_size = get_info(src)
    if orig_size == 0:
        return b""
    if orig_size > 0x10000000:
        raise TianoError("suspicious decompressed size %Xh" % orig_size)
    pbit = 4 if version == EFI11 else 5
    data = bytes(src[8:8 + comp_size]) + bytes(16)
    dlen = len(data)

    left = [0] * _TREE_SIZE
    right = [0] * _TREE_SIZE
    c_len = [0] * _NC
    pt_len = [0] * 32
    c_table = [0] * 4096
    pt_table = [0] * 256
    from_bytes = int.from_bytes

    bp = 0  # bit position
    out = bytearray()

    def window(pos):
        nonlocal data, dlen
        i = pos >> 3
        if i + 5 > dlen:
            grow = i + 5 - dlen + 64
            data += bytes(grow)
            dlen = len(data)
        return (from_bytes(data[i:i + 5], "big") >> (8 - (pos & 7))) & 0xFFFFFFFF

    def getbits(n):
        nonlocal bp
        v = window(bp) >> (32 - n)
        bp += n
        return v

    def read_pt_len(nn, nbit, special):
        nonlocal bp
        number = getbits(nbit)
        if number > _NPT or nn > _NPT:
            raise TianoError("bad table (PT size)")
        if number == 0:
            c = getbits(nbit)
            for k in range(256):
                pt_table[k] = c
            for k in range(nn):
                pt_len[k] = 0
            return
        i = 0
        while i < number and i < _NPT:
            w = window(bp)
            c = w >> 29
            if c == 7:
                m = 1 << 28
                while m & w:
                    m >>= 1
                    c += 1
            bp += 3 if c < 7 else c - 3
            pt_len[i] = c
            i += 1
            if i == special:
                c2 = getbits(2)
                while c2 > 0 and i < _NPT:
                    pt_len[i] = 0
                    i += 1
                    c2 -= 1
        while i < nn and i < _NPT:
            pt_len[i] = 0
            i += 1
        _make_table(nn, pt_len, 8, pt_table, left, right)

    def read_c_len():
        nonlocal bp
        number = getbits(_CBIT)
        if number == 0:
            c = getbits(_CBIT)
            for k in range(_NC):
                c_len[k] = 0
            for k in range(4096):
                c_table[k] = c
            return
        i = 0
        while i < number and i < _NC:
            w = window(bp)
            c = pt_table[w >> 24]
            if c >= _NT:
                m = 1 << 23
                guard = 0
                while c >= _NT:
                    c = right[c] if (w & m) else left[c]
                    m >>= 1
                    guard += 1
                    if guard > 32:
                        raise TianoError("corrupted T tree")
            bp += pt_len[c]
            if c <= 2:
                if c == 0:
                    c = 1
                elif c == 1:
                    c = getbits(4) + 3
                else:
                    c = getbits(_CBIT) + 20
                while c > 0 and i < _NC:
                    c_len[i] = 0
                    i += 1
                    c -= 1
            else:
                c_len[i] = c - 2
                i += 1
        while i < _NC:
            c_len[i] = 0
            i += 1
        _make_table(_NC, c_len, 12, c_table, left, right)

    block = 0
    NC = _NC
    MAXNP = _MAXNP
    while len(out) < orig_size:
        if block == 0:
            block = getbits(16)
            read_pt_len(_NT, _TBIT, 3)
            read_c_len()
            read_pt_len(_MAXNP, pbit, -1)
        block = (block - 1) & 0xFFFF
        # --- decode C
        i = bp >> 3
        if i + 5 > dlen:
            w = window(bp)
        else:
            w = (from_bytes(data[i:i + 5], "big") >> (8 - (bp & 7))) & 0xFFFFFFFF
        c = c_table[w >> 20]
        if c >= NC:
            m = 1 << 19
            guard = 0
            while c >= NC:
                c = right[c] if (w & m) else left[c]
                m >>= 1
                guard += 1
                if guard > 32:
                    raise TianoError("corrupted C tree")
        bp += c_len[c]
        if c < 256:
            out.append(c)
            continue
        length = c - (0x100 - _THRESHOLD)
        # --- decode P
        i = bp >> 3
        if i + 5 > dlen:
            w = window(bp)
        else:
            w = (from_bytes(data[i:i + 5], "big") >> (8 - (bp & 7))) & 0xFFFFFFFF
        p = pt_table[w >> 24]
        if p >= MAXNP:
            m = 1 << 23
            guard = 0
            while p >= MAXNP:
                p = right[p] if (w & m) else left[p]
                m >>= 1
                guard += 1
                if guard > 32:
                    raise TianoError("corrupted P tree")
        bp += pt_len[p]
        if p > 1:
            n = p - 1
            i = bp >> 3
            if i + 5 > dlen:
                w = window(bp)
            else:
                w = (from_bytes(data[i:i + 5], "big") >> (8 - (bp & 7))) & 0xFFFFFFFF
            pos = (1 << n) + (w >> (32 - n))
            bp += n
        else:
            pos = p
        olen = len(out)
        src_idx = olen - pos - 1
        if src_idx < 0:
            raise TianoError("match distance beyond start of output")
        n = min(length, orig_size - olen)
        dist = pos + 1
        if dist >= n:
            out += out[src_idx:src_idx + n]
        else:
            pat = out[src_idx:]
            out += (pat * (n // dist + 1))[:n]
    if bp > (comp_size + 8) * 8 + 64:
        # Decoder ran far past the end of input: data was garbage padded with zeros.
        raise TianoError("stream overrun")
    return bytes(out[:orig_size])


def decompress_auto(src) -> tuple[bytes, int, bytes | None]:
    """Try both algorithms. Returns (data, version, alternative-or-None).

    When both decoders succeed, ``alternative`` holds the EFI 1.1 result and the
    returned data is the Tiano result; callers can pick by validating contents.
    """
    tiano = efi = None
    err = None
    try:
        tiano = decompress(src, TIANO)
    except TianoError as e:
        err = e
    try:
        efi = decompress(src, EFI11)
    except TianoError as e:
        err = e
    if tiano is not None and efi is not None:
        if tiano == efi:
            return efi, EFI11, None
        return tiano, TIANO, efi
    if tiano is not None:
        return tiano, TIANO, None
    if efi is not None:
        return efi, EFI11, None
    raise TianoError(str(err) if err else "decompression failed")


# --------------------------------------------------------------------------
# Encoder
# --------------------------------------------------------------------------

def _huffman_lengths(freq, maxbits: int = 16):
    """Code lengths for the given frequencies, limited to maxbits, complete code.

    Returns (lengths, single) where single is the only used symbol when fewer than
    two symbols are present (lengths is then all zero).
    """
    n = len(freq)
    used = [i for i in range(n) if freq[i]]
    lengths = [0] * n
    if len(used) < 2:
        return lengths, (used[0] if used else 0)
    heap = [(freq[i], i, i) for i in used]
    heapq.heapify(heap)
    kids = {}
    nxt = n
    while len(heap) > 1:
        f1, _, a = heapq.heappop(heap)
        f2, _, b = heapq.heappop(heap)
        kids[nxt] = (a, b)
        heapq.heappush(heap, (f1 + f2, nxt, nxt))
        nxt += 1
    stack = [(heap[0][2], 0)]
    while stack:
        x, d = stack.pop()
        if x < n:
            lengths[x] = d
        else:
            a, b = kids[x]
            stack.append((a, d + 1))
            stack.append((b, d + 1))
    if max(lengths) <= maxbits:
        return lengths, None
    # Length limiting (same approach as LHA/EDK2 MakeLen).
    len_cnt = [0] * (maxbits + 1)
    for s in used:
        len_cnt[min(lengths[s], maxbits)] += 1
    cum = 0
    for i in range(maxbits, 0, -1):
        cum += len_cnt[i] << (maxbits - i)
    target = 1 << maxbits
    while cum != target:
        len_cnt[maxbits] -= 1
        for i in range(maxbits - 1, 0, -1):
            if len_cnt[i]:
                len_cnt[i] -= 1
                len_cnt[i + 1] += 2
                break
        cum -= 1
    order = sorted(used, key=lambda s: (freq[s], s))
    k = 0
    for ln in range(maxbits, 0, -1):
        for _ in range(len_cnt[ln]):
            lengths[order[k]] = ln
            k += 1
    return lengths, None


def _canonical_codes(lengths):
    count = [0] * 18
    for ln in lengths:
        if ln:
            count[ln] += 1
    start = [0] * 18
    for i in range(1, 17):
        start[i + 1] = start[i] + (count[i] << (16 - i))
    codes = [0] * len(lengths)
    for s, ln in enumerate(lengths):
        if ln:
            codes[s] = start[ln] >> (16 - ln)
            start[ln] += 1 << (16 - ln)
    return codes


class _BitWriter:
    __slots__ = ("out", "acc", "n")

    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, nbits, value):
        if nbits <= 0:
            return
        self.acc = (self.acc << nbits) | (value & ((1 << nbits) - 1))
        self.n += nbits
        if self.n >= 64:
            rem = self.n & 7
            self.out += (self.acc >> rem).to_bytes(self.n >> 3, "big")
            self.acc &= (1 << rem) - 1
            self.n = rem

    def flush(self):
        if self.n & 7:
            self.put(8 - (self.n & 7), 0)
        if self.n:
            self.out += self.acc.to_bytes(self.n >> 3, "big")
            self.acc = 0
            self.n = 0
        return self.out


def _lz77(data: bytes, window: int, chain_limit: int = 48):
    """Greedy LZ77 with one-step lazy evaluation. Returns list of tokens.

    A token is an int < 256 (literal) or a tuple (length, pos) where pos is
    distance - 1 as stored in the stream.
    """
    n = len(data)
    tokens = []
    if n == 0:
        return tokens
    head: dict[bytes, int] = {}
    prev = [-1] * n
    maxm = _MAXMATCH

    def insert(i):
        if i + 3 <= n:
            key = data[i:i + 3]
            prev[i] = head.get(key, -1)
            head[key] = i

    def best_match(i):
        if i + 3 > n:
            return 0, 0
        key = data[i:i + 3]
        cand = head.get(key, -1)
        limit = min(maxm, n - i)
        best_len = 0
        best_pos = 0
        steps = 0
        lo_bound = i - window
        while cand >= 0 and cand > lo_bound and steps < chain_limit:
            steps += 1
            # Quick reject: must be able to beat current best.
            if best_len >= 3 and (best_len >= limit or data[cand + best_len] != data[i + best_len]):
                cand = prev[cand]
                continue
            # Extend match with memcmp based binary search.
            lo = 3
            hi = limit
            if data[cand:cand + hi] == data[i:i + hi]:
                ln = hi
            else:
                while lo < hi:
                    mid = (lo + hi + 1) >> 1
                    if data[cand:cand + mid] == data[i:i + mid]:
                        lo = mid
                    else:
                        hi = mid - 1
                ln = lo
                if data[cand:cand + ln] != data[i:i + ln]:
                    ln = 0
            if ln > best_len:
                best_len = ln
                best_pos = i - cand - 1
                if ln >= limit:
                    break
            cand = prev[cand]
        return best_len, best_pos

    i = 0
    pending = None  # (len, pos) of match found at i
    while i < n:
        if pending is None:
            ml, mp = best_match(i)
        else:
            ml, mp = pending
            pending = None
        if ml >= _THRESHOLD and ml < maxm and i + 1 < n:
            insert(i)
            nl, np_ = best_match(i + 1)
            if nl > ml:
                tokens.append(data[i])
                i += 1
                pending = (nl, np_)
                continue
            for k in range(i + 1, i + ml):
                insert(k)
            tokens.append((ml, mp))
            i += ml
            continue
        if ml >= _THRESHOLD:
            for k in range(i, i + ml):
                insert(k)
            tokens.append((ml, mp))
            i += ml
            continue
        insert(i)
        tokens.append(data[i])
        i += 1
    return tokens


def _write_pt_len(bw, lengths, n, nbit, special):
    while n > 0 and lengths[n - 1] == 0:
        n -= 1
    bw.put(nbit, n)
    i = 0
    while i < n:
        k = lengths[i]
        i += 1
        if k <= 6:
            bw.put(3, k)
        else:
            bw.put(k - 3, (1 << (k - 3)) - 2)
        if i == special:
            while i < 6 and lengths[i] == 0:
                i += 1
            bw.put(2, (i - 3) & 3)


def _send_block(bw, tokens, pbit, np_):
    c_freq = [0] * _NC
    p_freq = [0] * np_
    for t in tokens:
        if t.__class__ is int:
            c_freq[t] += 1
        else:
            c_freq[t[0] + 253] += 1
            p_freq[t[1].bit_length()] += 1
    bw.put(16, len(tokens))
    c_len, c_single = _huffman_lengths(c_freq)
    if c_single is None:
        # T set describing C lengths
        n = _NC
        while n > 0 and c_len[n - 1] == 0:
            n -= 1
        t_freq = [0] * _NT
        runs = []
        i = 0
        while i < n:
            k = c_len[i]
            i += 1
            if k == 0:
                count = 1
                while i < n and c_len[i] == 0:
                    i += 1
                    count += 1
                runs.append((0, count))
                if count <= 2:
                    t_freq[0] += count
                elif count <= 18:
                    t_freq[1] += 1
                elif count == 19:
                    t_freq[0] += 1
                    t_freq[1] += 1
                else:
                    t_freq[2] += 1
            else:
                runs.append((k, 1))
                t_freq[k + 2] += 1
        t_len, t_single = _huffman_lengths(t_freq)
        if t_single is None:
            _write_pt_len(bw, t_len, _NT, _TBIT, 3)
            t_code = _canonical_codes(t_len)
        else:
            bw.put(_TBIT, 0)
            bw.put(_TBIT, t_single)
            t_len = [0] * _NT
            t_code = [0] * _NT
        bw.put(_CBIT, n)
        for k, count in runs:
            if k:
                bw.put(t_len[k + 2], t_code[k + 2])
            elif count <= 2:
                for _ in range(count):
                    bw.put(t_len[0], t_code[0])
            elif count <= 18:
                bw.put(t_len[1], t_code[1])
                bw.put(4, count - 3)
            elif count == 19:
                bw.put(t_len[0], t_code[0])
                bw.put(t_len[1], t_code[1])
                bw.put(4, 15)
            else:
                bw.put(t_len[2], t_code[2])
                bw.put(_CBIT, count - 20)
        c_code = _canonical_codes(c_len)
    else:
        bw.put(_TBIT, 0)
        bw.put(_TBIT, 0)
        bw.put(_CBIT, 0)
        bw.put(_CBIT, c_single)
        c_len = [0] * _NC
        c_code = [0] * _NC
    p_len, p_single = _huffman_lengths(p_freq)
    if p_single is None:
        _write_pt_len(bw, p_len, np_, pbit, -1)
        p_code = _canonical_codes(p_len)
    else:
        bw.put(pbit, 0)
        bw.put(pbit, p_single)
        p_len = [0] * np_
        p_code = [0] * np_
    put = bw.put
    for t in tokens:
        if t.__class__ is int:
            put(c_len[t], c_code[t])
        else:
            s = t[0] + 253
            put(c_len[s], c_code[s])
            pos = t[1]
            c = pos.bit_length()
            put(p_len[c], p_code[c])
            if c > 1:
                put(c - 1, pos & ((1 << (c - 1)) - 1))


def compress(data, version: int = EFI11, block_tokens: int = 8192) -> bytes:
    """Compress data in EFI 1.1 (version=1) or Tiano (version=2) format."""
    data = bytes(data)
    if version == EFI11:
        wndbit, pbit = 13, 4
    else:
        wndbit, pbit = 19, 5
    np_ = wndbit + 1
    tokens = _lz77(data, 1 << wndbit)
    bw = _BitWriter()
    if tokens:
        for s in range(0, len(tokens), block_tokens):
            _send_block(bw, tokens[s:s + block_tokens], pbit, np_)
    body = bytes(bw.flush()) + b"\x00"
    return struct.pack("<II", len(body), len(data)) + body
