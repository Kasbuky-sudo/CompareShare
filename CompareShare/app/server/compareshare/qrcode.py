"""二维码生成（纯标准库实现，无第三方依赖）。

实现字节模式、纠错等级 L/M/Q/H、版本 1-10，足够编码一个内网 URL。
算法依据 ISO/IEC 18004。

注意：二维码是有严格校验的格式，实现必须精确。本文件按标准逐步构造：
模式指示符 → 字符计数 → 数据 → 终止符 → 补位 → 填充码字 →
分块 → RS 纠错 → 交错 → 矩阵布局 → 掩码 → 格式信息。
"""

from __future__ import annotations

# 各版本数据码字总数（索引 版本-1），(L, M, Q, H)
_DATA_CODEWORDS = {
    1: (19, 16, 13, 9), 2: (34, 28, 22, 16), 3: (55, 44, 34, 26),
    4: (80, 64, 48, 36), 5: (108, 86, 62, 46), 6: (136, 108, 76, 60),
    7: (156, 124, 88, 66), 8: (194, 154, 110, 86), 9: (232, 182, 132, 100),
    10: (274, 216, 154, 122),
}

# 每块纠错码字数 (L, M, Q, H)
_EC_PER_BLOCK = {
    1: (7, 10, 13, 17), 2: (10, 16, 22, 28), 3: (15, 26, 18, 22),
    4: (20, 18, 26, 16), 5: (26, 24, 18, 22), 6: (18, 16, 24, 28),
    7: (20, 18, 18, 26), 8: (24, 22, 22, 26), 9: (30, 22, 20, 24),
    10: (18, 26, 24, 28),
}

# 块数 (L, M, Q, H)
_NUM_BLOCKS = {
    1: (1, 1, 1, 1), 2: (1, 1, 1, 1), 3: (1, 1, 2, 2),
    4: (1, 2, 2, 4), 5: (1, 2, 4, 4), 6: (2, 4, 4, 4),
    7: (2, 4, 6, 5), 8: (2, 4, 6, 6), 9: (2, 5, 8, 8),
    10: (4, 5, 8, 8),
}

# 对齐图形中心坐标
_ALIGNMENT = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46],
    10: [6, 28, 50],
}

_LEVEL_INDEX = {"L": 0, "M": 1, "Q": 2, "H": 3}
# 格式信息里的纠错等级编码
_LEVEL_BITS = {"L": 1, "M": 0, "Q": 3, "H": 2}


# ---------- GF(256) ----------

_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _rs_generator(n: int) -> list[int]:
    """生成 n 次 RS 生成多项式（首一，最高次在前）。"""
    poly = [1]
    for i in range(n):
        nxt = [0] * (len(poly) + 1)
        for j, coef in enumerate(poly):
            nxt[j] ^= coef                       # ×x
            nxt[j + 1] ^= _mul(coef, _EXP[i])    # ×α^i
        poly = nxt
    return poly


def _rs_encode(data: list[int], ec_len: int) -> list[int]:
    """计算 data 的 ec_len 个纠错码字。"""
    gen = _rs_generator(ec_len)
    res = list(data) + [0] * ec_len
    for i in range(len(data)):
        coef = res[i]
        if coef:
            for j in range(1, len(gen)):
                res[i + j] ^= _mul(gen[j], coef)
    return res[len(data):]


# ---------- 位流 ----------

def _pick_version(nbytes: int, level: str) -> int:
    idx = _LEVEL_INDEX[level]
    for ver in range(1, 11):
        capacity = _DATA_CODEWORDS[ver][idx]
        count_bits = 8 if ver <= 9 else 16
        need_bits = 4 + count_bits + nbytes * 8
        if need_bits <= capacity * 8:
            return ver
    raise ValueError("内容过长，超出支持的二维码版本（1-10）")


def _make_codewords(data: bytes, version: int, level: str) -> list[int]:
    idx = _LEVEL_INDEX[level]
    total = _DATA_CODEWORDS[version][idx]
    ec_per = _EC_PER_BLOCK[version][idx]
    blocks = _NUM_BLOCKS[version][idx]

    # 位流
    bits: list[int] = []
    def put(value: int, length: int) -> None:
        for i in range(length - 1, -1, -1):
            bits.append((value >> i) & 1)

    put(4, 4)                                   # 字节模式
    put(len(data), 8 if version <= 9 else 16)
    for b in data:
        put(b, 8)

    cap = total * 8
    # 终止符最多 4 bit
    for _ in range(min(4, cap - len(bits))):
        bits.append(0)
    # 补齐到字节边界
    while len(bits) % 8:
        bits.append(0)

    codewords: list[int] = []
    for i in range(0, len(bits), 8):
        val = 0
        for bit in bits[i:i + 8]:
            val = (val << 1) | bit
        codewords.append(val)

    # 填充码字 0xEC / 0x11 交替
    pads = (0xEC, 0x11)
    k = 0
    while len(codewords) < total:
        codewords.append(pads[k % 2])
        k += 1

    # 分块
    short_len = total // blocks
    num_long = total % blocks
    num_short = blocks - num_long

    data_blocks: list[list[int]] = []
    pos = 0
    for i in range(blocks):
        ln = short_len + (1 if i >= num_short else 0)
        data_blocks.append(codewords[pos:pos + ln])
        pos += ln

    ec_blocks = [_rs_encode(b, ec_per) for b in data_blocks]

    # 交错输出
    out: list[int] = []
    max_len = max(len(b) for b in data_blocks)
    for i in range(max_len):
        for b in data_blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ec_per):
        for b in ec_blocks:
            out.append(b[i])
    return out


# ---------- 矩阵布局 ----------

_MASK = lambda r, c: (r + c) % 2 == 0  # 掩码 0


def _format_bits(level: str, mask: int) -> list[int]:
    """15 位格式信息（含 BCH 纠错与固定掩码）。"""
    data = (_LEVEL_BITS[level] << 3) | mask
    rem = data << 10
    for i in range(4, -1, -1):
        if rem & (1 << (i + 10)):
            rem ^= 0x537 << i
    value = ((data << 10) | rem) ^ 0x5412
    return [(value >> i) & 1 for i in range(14, -1, -1)]


def _version_bits(version: int) -> list[int]:
    """18 位版本信息（版本 7 及以上才需要）。"""
    rem = version << 12
    for i in range(5, -1, -1):
        if rem & (1 << (i + 12)):
            rem ^= 0x1F25 << i
    value = (version << 12) | rem
    return [(value >> i) & 1 for i in range(17, -1, -1)]


def _build_matrix(version: int, codewords: list[int], level: str) -> list[list[int]]:
    size = version * 4 + 17
    mat: list[list[int | None]] = [[None] * size for _ in range(size)]

    def finder(top: int, left: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = top + r, left + c
                if not (0 <= rr < size and 0 <= cc < size):
                    continue
                if 0 <= r <= 6 and 0 <= c <= 6:
                    border = r in (0, 6) or c in (0, 6)
                    core = 2 <= r <= 4 and 2 <= c <= 4
                    mat[rr][cc] = 1 if (border or core) else 0
                else:
                    mat[rr][cc] = 0  # 分隔符

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)

    # 时序图形
    for i in range(8, size - 8):
        bit = 1 if i % 2 == 0 else 0
        if mat[6][i] is None:
            mat[6][i] = bit
        if mat[i][6] is None:
            mat[i][6] = bit

    # 对齐图形
    for r in _ALIGNMENT[version]:
        for c in _ALIGNMENT[version]:
            if ((r <= 8 and c <= 8) or (r <= 8 and c >= size - 9)
                    or (r >= size - 9 and c <= 8)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    mat[r + dr][c + dc] = 1 if max(abs(dr), abs(dc)) != 1 else 0

    # 预留格式信息区
    for i in range(9):
        if mat[8][i] is None:
            mat[8][i] = 0
        if mat[i][8] is None:
            mat[i][8] = 0
    for i in range(8):
        mat[8][size - 1 - i] = 0
        mat[size - 1 - i][8] = 0
    mat[size - 8][8] = 1  # 固定深色模块

    # 版本信息（版本 >= 7）
    if version >= 7:
        vb = _version_bits(version)
        for i in range(18):
            bit = vb[17 - i]
            r, c = i // 3, i % 3
            mat[size - 11 + c][r] = bit
            mat[r][size - 11 + c] = bit

    # 数据位（从右下角开始，两列一组，上下蛇形）
    bit_stream: list[int] = []
    for cw in codewords:
        for i in range(7, -1, -1):
            bit_stream.append((cw >> i) & 1)

    bi = 0
    upward = True
    col = size - 1
    while col > 0:
        if col == 6:      # 跳过时序列
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if c < 0 or mat[row][c] is not None:
                    continue
                bit = bit_stream[bi] if bi < len(bit_stream) else 0
                bi += 1
                if _MASK(row, c):
                    bit ^= 1
                mat[row][c] = bit
        upward = not upward
        col -= 2

    # 格式信息（掩码 0）
    fb = _format_bits(level, 0)
    # 左上：跳过时序线
    for i in range(6):
        mat[8][i] = fb[i]
    mat[8][7] = fb[6]
    mat[8][8] = fb[7]
    mat[7][8] = fb[8]
    for i in range(9, 15):
        mat[14 - i][8] = fb[i]
    # 右上与左下
    for i in range(8):
        mat[size - 1 - i][8] = fb[i]
    for i in range(8, 15):
        mat[8][size - 15 + i] = fb[i]

    return [[1 if v else 0 for v in row] for row in mat]


def make_matrix(text: str, level: str = "M") -> list[list[int]]:
    """生成二维码模块矩阵，1 表示黑色。"""
    data = text.encode("utf-8")
    version = _pick_version(len(data), level)
    codewords = _make_codewords(data, version, level)
    return _build_matrix(version, codewords, level)


def to_svg(text: str, level: str = "M", scale: int = 6, border: int = 4,
           dark: str = "#1a1d23", light: str = "#ffffff") -> str:
    """渲染为 SVG 字符串。"""
    mat = make_matrix(text, level)
    n = len(mat)
    dim = (n + border * 2) * scale
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{dim}" height="{dim}" '
        f'viewBox="0 0 {dim} {dim}" shape-rendering="crispEdges">',
        f'<rect width="{dim}" height="{dim}" fill="{light}"/>',
    ]
    for r in range(n):
        c = 0
        while c < n:
            if mat[r][c]:
                start = c
                while c < n and mat[r][c]:
                    c += 1
                out.append(
                    f'<rect x="{(start + border) * scale}" y="{(r + border) * scale}" '
                    f'width="{(c - start) * scale}" height="{scale}" fill="{dark}"/>'
                )
            else:
                c += 1
    out.append("</svg>")
    return "".join(out)


def to_ascii(text: str, level: str = "M") -> str:
    """控制台预览（调试用）。"""
    mat = make_matrix(text, level)
    n = len(mat)
    lines = []
    for r in range(n):
        # 每个模块用两个字符，视觉上接近正方形
        lines.append("".join("██" if mat[r][c] else "  " for c in range(n)))
    return "\n".join(lines)
