import struct  # 導入 struct 模組，用於處理二進制數據的打包與解包

rounds = 12  # 定義加密輪數為 12
roundKeys = 2 * (rounds + 1)  # 定義輪密鑰數量，為 2 * (輪數 + 1) = 26

def main(names):
    # 主函數，接受一個名稱列表，遍歷並生成每個名稱的 key
    for name in names:
        key = crack(name)  # 調用 crack 函數生成 key
        print(f"name: {name}    key: {key}\n")  # 輸出名稱和生成的 key

def crack(text: str) -> str:
    # 破解函數，將輸入的字符串轉換並生成對應的 key
    name = text.encode('utf-8')  # 將輸入字符串編碼為 UTF-8 字節
    length = len(name) + 4  # 計算總長度：名稱長度 + 4 字節（用於存儲長度）
    padded = ((-length) & (8 - 1)) + length  # 計算填充後的長度，使其為 8 的倍數
    bs = struct.pack('>I', len(name))  # 將名稱長度打包為 4 字節大端序無符號整數
    buff = bytearray(bs + name)  # 創建字節數組，包含長度和名稱

    ck_name = 0x7a21c951691cd470  # 定義用於加密的 64 位密鑰
    ck_key = -5408575981733630035  # 定義用於解密的 64 位密鑰
    ck = CkCipher(ck_name)  # 使用 ck_name 創建加密器實例
    out_buff = bytearray()  # 創建空的字節數組，用於存儲加密結果

    # 按 8 字節分塊處理 buff
    for i in range(0, padded, 8):
        bf = buff[i:i + 8]  # 從 buff 中取出 8 字節分塊
        if len(bf) < 8:
            bf += b'\x00' * (8 - len(bf))  # 如果不足 8 字節，用 0 填充
        now_var, = struct.unpack('>q', bf)  # 將 8 字節解包為 64 位大端序有符號整數

        dd = ck.encrypt(now_var)  # 使用加密器對 now_var 進行加密
        out_buff.extend(dd.to_bytes(8, byteorder='big', signed=True))  # 將加密結果轉為 8 字節並追加到 out_buff

    n = 0  # 初始化 n，用於後續的位運算
    for b in out_buff:
        # 將每個字節轉換為有符號 8 位整數（模擬 Go 的 int8）
        signed_byte = b if b < 128 else b - 256
        n = rotate_left(n ^ signed_byte, 0x3)  # 對 n 進行異或和左旋 3 位操作

    prefix = n ^ 0x54882f8a  # 計算 prefix，通過 n 與固定值異或
    suffix = 0x43f9c401  # 固定 suffix 為已知正確值（31 位整數）
    in_val = (int(prefix) & 0xffffffff) << 32  # 將 prefix 左移 32 位，作為 64 位值的高位部分
    s = suffix  # 將 suffix 賦值給 s

    suffix_high = suffix >> 16  # 計算 suffix 的高 16 位
    # 根據 suffix 高 16 位的值，決定如何組合 in_val
    if suffix_high in (0x0401, 0x0402, 0x0403):
        in_val |= s  # 如果高位是特定值，直接與 s 按位或
    else:
        in_val |= 0x01000000 | (s & 0xffffff)  # 否則與固定值和 s 的低 24 位組合

    out = CkCipher(ck_key).decrypt(in_val)  # 使用 ck_key 創建解密器，對 in_val 解密

    n2 = 0  # 初始化 n2，用於計算 vv
    # 從 in_val 的高位到低位，每 8 位進行一次異或
    for i in range(56, -1, -8):
        n2 ^= (in_val >> i) & 0xff

    vv = n2 & 0xff  # 取 n2 的低 8 位作為 vv
    if vv >= 128:
        vv = 256 - vv  # 如果 vv 是負數（模擬 int8），轉換為正值
    # 返回格式化的 key：vv 的 2 位十六進制 + out 的 16 位十六進制
    return f"{vv:02x}{out & 0xffffffffffffffff:016x}"

class CkCipher:
    # 自定義加密/解密類
    def __init__(self, ck_key: int):
        # 初始化輪密鑰數組
        self.rk = [0] * roundKeys
        # 將 64 位密鑰分為兩個 32 位部分
        ld = [ck_key & 0xffffffff, (ck_key >> 32) & 0xffffffff]

        self.rk[0] = -1209970333 & 0xffffffff  # 設置第一個輪密鑰
        # 生成後續輪密鑰，每個基於前一個加上固定增量
        for i in range(1, roundKeys):
            self.rk[i] = (self.rk[i - 1] + -1640531527) & 0xffffffff

        a, b = 0, 0  # 初始化兩個 32 位變量
        i, j = 0, 0  # 初始化索引
        # 進行 3 * roundKeys 次迭代，生成最終的輪密鑰
        for k in range(3 * roundKeys):
            self.rk[i] = rotate_left(self.rk[i] + (a + b), 3)  # 更新輪密鑰
            a = self.rk[i]  # 更新 a
            ld[j] = rotate_left(ld[j] + (a + b), a + b)  # 更新 ld
            b = ld[j]  # 更新 b
            i = (i + 1) % roundKeys  # 循環更新 rk 索引
            j = (j + 1) % 2  # 循環更新 ld 索引（0 或 1）

    def encrypt(self, in_val: int) -> int:
        # 加密函數，將 64 位輸入加密為 64 位輸出
        a = in_val & 0xffffffff  # 取低 32 位
        if a >= 0x80000000:
            a -= 0x100000000  # 模擬 32 位有符號整數
        a = (a + self.rk[0]) & 0xffffffff  # 加上第一個輪密鑰

        b = (in_val >> 32) & 0xffffffff  # 取高 32 位
        if b >= 0x80000000:
            b -= 0x100000000  # 模擬 32 位有符號整數
        b = (b + self.rk[1]) & 0xffffffff  # 加上第二個輪密鑰

        # 進行 rounds 次加密迭代
        for r in range(1, rounds + 1):
            a = (rotate_left(a ^ b, b) + self.rk[2 * r]) & 0xffffffff  # 更新 a
            b = (rotate_left(b ^ a, a) + self.rk[2 * r + 1]) & 0xffffffff  # 更新 b

        return pk_long(a, b)  # 將 a 和 b 組合為 64 位輸出

    def decrypt(self, in_val: int) -> int:
        # 解密函數，將 64 位輸入解密為 64 位輸出
        a = in_val & 0xffffffff  # 取低 32 位
        if a >= 0x80000000:
            a -= 0x100000000  # 模擬 32 位有符號整數
        b = (in_val >> 32) & 0xffffffff  # 取高 32 位
        if b >= 0x80000000:
            b -= 0x100000000  # 模擬 32 位有符號整數

        # 進行 rounds 次解密迭代（逆向）
        for i in range(rounds, 0, -1):
            b = rotate_right(b - self.rk[2 * i + 1], a) ^ a  # 更新 b
            b &= 0xffffffff  # 限制為 32 位
            a = rotate_right(a - self.rk[2 * i], b) ^ b  # 更新 a
            a &= 0xffffffff  # 限制為 32 位

        b = (b - self.rk[1]) & 0xffffffff  # 減去第二個輪密鑰
        a = (a - self.rk[0]) & 0xffffffff  # 減去第一個輪密鑰
        return pk_long(a, b)  # 將 a 和 b 組合為 64 位輸出

def rotate_left(x: int, y: int) -> int:
    # 左旋函數，將 32 位整數 x 左旋 y 位
    y = y & 31  # 限制旋轉位數為 0-31
    x = x & 0xffffffff  # 確保 x 是 32 位
    result = ((x << y) | ((x & 0xffffffff) >> (32 - y))) & 0xffffffff  # 執行左旋
    return result

def rotate_right(x: int, y: int) -> int:
    # 右旋函數，將 32 位整數 x 右旋 y 位
    y = y & 31  # 限制旋轉位數為 0-31
    x = x & 0xffffffff  # 確保 x 是 32 位
    result = (((x & 0xffffffff) >> y) | (x << (32 - y))) & 0xffffffff  # 執行右旋
    return result

def pk_long(a: int, b: int) -> int:
    # 將兩個 32 位整數組合為 64 位整數
    a = a & 0xffffffff  # 確保 a 是 32 位
    b = b & 0xffffffff  # 確保 b 是 32 位
    result = (a & 0xffffffff) | ((b & 0xffffffff) << 32)  # a 為低位，b 為高位
    if result >= 0x8000000000000000:
        result -= 0x10000000000000000  # 如果超過 64 位有符號整數範圍，調整為負數
    return result

if __name__ == "__main__":
    # 如果直接運行此文件，執行 main 函數，測試 "fish2018"
    main(names=["fish2018"])
