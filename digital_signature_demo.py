import hashlib
import math
import secrets
import sys
import re
import base64
from dataclasses import dataclass
from typing import Dict, Tuple
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

# ========================== CÁC HẰNG SỐ VÀ BIẾN TOÀN CỤC ==========================
# Từ điển map tên hiển thị của thuật toán băm với tên hàm thực tế trong thư viện hashlib
HASH_ALGORITHMS: Dict[str, str] = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-224": "sha224",
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
    "SHA3-256": "sha3_256",
}

# ========================== CÁC DATA CLASS ==========================
# Bổ sung: dataclass giúp tạo class nhanh gọn, tự động có hàm __init__, __repr__ để lưu trữ dữ liệu
@dataclass
class RSAKeyPair:
    """Lưu trữ thông tin cặp khóa RSA"""
    p: int          # Số nguyên tố p (Bí mật)
    q: int          # Số nguyên tố q (Bí mật)
    e: int          # Số mũ công khai (public exponent) - Dùng để mã hóa/kiểm tra chữ ký
    d: int          # Số mũ riêng tư (private exponent) - Dùng để giải mã/tạo chữ ký (Rất bí mật)
    n: int          # n = p * q (modulus) - Chia sẻ công khai cùng e
    phi: int        # phi(n) = (p-1)*(q-1) - Hàm số Euler, dùng để tính d

@dataclass
class SignatureData:
    """Chứa thông tin chữ ký số đã tạo"""
    algorithm_label: str    # Tên thuật toán hiển thị (ví dụ: SHA-256)
    algorithm_name: str     # Tên thực tế dùng trong hashlib (ví dụ: sha256)
    message: str            # Thông điệp đã được mã hóa XOR (nếu có)
    raw_hash_int: int       # Giá trị hash nguyên bản dưới dạng số nguyên (bản băm của thông điệp)
    reduced_hash: int       # Hash đã lấy modulo n (để đảm bảo giá trị bé hơn n, phù hợp tính toán RSA)
    signature_int: int      # Chữ ký số (đã ký bằng private key d)

@dataclass
class VerificationData:
    """Chứa kết quả kiểm tra chữ ký số"""
    algorithm_label: str    # Thuật toán đã dùng
    message: str            # Thông điệp nhận được
    signature_int: int      # Chữ ký số nhận được
    raw_hash_int: int       # Hash tự tính lại từ thông điệp nhận được
    reduced_hash: int       # Hash tự tính lại đã modulo n
    decrypted_signature: int # Chữ ký số sau khi giải mã bằng public key e
    is_valid: bool          # True nếu chữ ký hợp lệ (so sánh reduced_hash và decrypted_signature)

# ========================== CÁC HÀM HỖ TRỢ RSA ==========================
def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Thuật toán Euclidean mở rộng (Extended Euclidean Algorithm)
    Trả về (gcd, x, y) sao cho: a*x + b*y = gcd
    """
    # Điều kiện dừng của đệ quy: khi b = 0, ước chung lớn nhất chính là a
    if b == 0:
        return a, 1, 0
    # Gọi đệ quy đảo vị trí b và phần dư của a chia b
    gcd, x1, y1 = egcd(b, a % b)
    # Cập nhật lại hệ số x, y cho bước hiện tại
    return gcd, y1, x1 - (a // b) * y1

def mod_inverse(a: int, m: int) -> int:
    """
    Tìm nghịch đảo modulo: tìm x sao cho a * x ≡ 1 (mod m)
    """
    # Sử dụng thuật toán Euclidean mở rộng để tìm x
    gcd, x, _ = egcd(a, m)
    # Nếu ước chung lớn nhất không phải 1, nghĩa là a và m không nguyên tố cùng nhau -> không có nghịch đảo
    if gcd != 1:
        raise ValueError("e không nghịch đảo được theo modulo phi(n).")
    # Trả về x dương (trong trường hợp x bị âm thì % m sẽ làm nó dương lại theo modulo m)
    return x % m

def is_probable_prime(n: int, rounds: int = 8) -> bool:
    """
    Kiểm tra số nguyên tố bằng Miller-Rabin probabilistic test.
    Độ chính xác cao với số vòng lặp mặc định là 8.
    """
    # Các số nhỏ hơn 2 không phải số nguyên tố
    if n < 2:
        return False
    # Tập các số nguyên tố nhỏ để kiểm tra nhanh trước
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False
            
    # Bước chuẩn bị cho Miller-Rabin: Viết n-1 dưới dạng 2^s * d (với d là số lẻ)
    # Viết n-1 = 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
        
    # Thực hiện kiểm tra 'rounds' lần để tăng độ tin cậy
    for _ in range(rounds):
        # Chọn ngẫu nhiên cơ số a trong khoảng [2, n-2]
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n) # Tính a^d mod n
        
        # Nếu x = 1 hoặc x = n - 1, vòng lặp này pass (có thể là số nguyên tố)
        if x in (1, n - 1):
            continue
            
        # Bình phương x liên tục s-1 lần
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            # Nếu chạy hết vòng for nhỏ mà x vẫn không bằng n-1 -> chắc chắn là hợp số
            return False
            
    # Vượt qua tất cả các vòng -> Khả năng rất cao là số nguyên tố
    return True

def generate_prime(bits: int = 16) -> int:
    """
    Sinh số nguyên tố ngẫu nhiên với độ dài bits bit (mặc định 16 bit)
    """
    while True:
        # Sinh ngẫu nhiên một số nguyên có độ dài 'bits' bit
        candidate = secrets.randbits(bits)
        # Đảm bảo bit cuối cùng = 1 (là số lẻ) và bit cao nhất = 1 (đủ độ dài bits)
        candidate |= (1 << (bits - 1)) | 1          # Đảm bảo là số lẻ và có bit cao nhất = 1
        # Nếu số vừa sinh vượt qua bài test nguyên tố thì trả về kết quả
        if is_probable_prime(candidate):
            return candidate

def build_key_pair(p: int, q: int, e: int) -> RSAKeyPair:
    """
    Xây dựng cặp khóa RSA từ p, q và e cho trước.
    Kiểm tra tính hợp lệ của p, q, e trước khi tạo khóa.
    """
    # Các bước validation (kiểm tra tính hợp lệ) cơ bản của RSA
    if p == q:
        raise ValueError("p và q phải khác nhau.")
    if not is_probable_prime(p):
        raise ValueError("p không phải số nguyên tố.")
    if not is_probable_prime(q):
        raise ValueError("q không phải số nguyên tố.")
    if e <= 1:
        raise ValueError("e phải lớn hơn 1.")
        
    # Tính toán các thành phần của RSA
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Số mũ công khai e phải nguyên tố cùng nhau với phi(n) thì mới có thể tìm được d
    if math.gcd(e, phi) != 1:
        raise ValueError("e phải nguyên tố cùng nhau với phi(n).")
        
    # Tính số mũ riêng tư d
    d = mod_inverse(e, phi)
    
    return RSAKeyPair(p=p, q=q, e=e, d=d, n=n, phi=phi)

# ========================== HÀM HASH VÀ CHỮ KÝ ==========================
def compute_hash(message: str, algorithm_name: str) -> Tuple[str, int]:
    """
    Tính hash của thông điệp theo thuật toán chỉ định.
    Trả về: (hash dưới dạng hex, hash dưới dạng số nguyên)
    """
    # Mã hóa chuỗi string thành byte rồi đưa vào hàm băm
    digest = hashlib.new(algorithm_name, message.encode("utf-8")).digest()
    # Hex dùng để in ra cho đẹp, Integer dùng để tính toán toán học RSA
    return digest.hex(), int.from_bytes(digest, "big")

def sign_message(message: str, algorithm_label: str, key_pair: RSAKeyPair) -> SignatureData:
    """
    Tạo chữ ký số RSA cho thông điệp.
    Quy trình: Hash → mod n → ký bằng private key (mũ d)
    """
    algorithm_name = HASH_ALGORITHMS[algorithm_label]
    
    # Bước 1: Băm thông điệp
    _, raw_hash_int = compute_hash(message, algorithm_name)
    
    # Bước 2: Modulo n để đảm bảo đầu vào nhỏ hơn modulus n (yêu cầu của thuật toán RSA)
    reduced_hash = raw_hash_int % key_pair.n
    
    # Bước 3: Áp dụng công thức ký RSA: Signature = M^d mod n (Ở đây M là mã băm)
    signature_int = pow(reduced_hash, key_pair.d, key_pair.n)   # Chữ ký = hash^d mod n
    
    return SignatureData(
        algorithm_label=algorithm_label,
        algorithm_name=algorithm_name,
        message=message,
        raw_hash_int=raw_hash_int,
        reduced_hash=reduced_hash,
        signature_int=signature_int,
    )

def parse_signature(text: str) -> int:
    """
    Chuyển chuỗi chữ ký thành số nguyên.
    Hỗ trợ cả hệ 10 và hệ 16 (có tiền tố 0x hoặc chứa chữ cái a-f)
    """
    value = text.strip()
    if not value:
        raise ValueError("Chưa có chữ ký để kiểm tra.")
    # Kiểm tra xem có phải chuỗi Hexa (hệ cơ số 16) không
    if value.lower().startswith("0x") or any(char in "abcdefABCDEF" for char in value):
        return int(value, 16)
    # Mặc định ép kiểu về hệ cơ số 10
    return int(value, 10)

def verify_message(
    message: str,
    signature_int: int,
    algorithm_label: str,
    n: int,
    e: int,
) -> VerificationData:
    """
    Kiểm tra tính hợp lệ của chữ ký số.
    Quy trình: Hash thông điệp → mod n → giải mã chữ ký bằng public key (mũ e)
    So sánh hai giá trị để quyết định chữ ký có hợp lệ không.
    """
    algorithm_name = HASH_ALGORITHMS[algorithm_label]
    
    # Bước 1: Bên nhận tự tính băm của thông điệp nhận được
    _, raw_hash_int = compute_hash(message, algorithm_name)
    reduced_hash = raw_hash_int % n
    
    # Bước 2: Bên nhận dùng Khóa công khai (e, n) để "giải mã" chữ ký số
    decrypted_signature = pow(signature_int, e, n)          # Giải mã chữ ký = signature^e mod n
    
    # Bước 3: Nếu mã băm tự tính == mã băm giải mã được từ chữ ký => Thông điệp nguyên vẹn và đúng người ký
    return VerificationData(
        algorithm_label=algorithm_label,
        message=message,
        signature_int=signature_int,
        raw_hash_int=raw_hash_int,
        reduced_hash=reduced_hash,
        decrypted_signature=decrypted_signature,
        is_valid=(reduced_hash == decrypted_signature),
    )

# ========================== MÃ HÓA XOR + BASE64 ==========================
def xor_cipher_base64(text: str, password: str, encrypt: bool = True) -> str:
    """
    Mã hóa / Giải mã thông điệp bằng phép XOR với mật khẩu,
    sau đó bọc thêm Base64 để tránh làm hỏng giao diện Tkinter.
    
    encrypt=True  → Mã hóa
    encrypt=False → Giải mã
    """
    # Nếu không có mật khẩu hoặc text rỗng thì không làm gì cả
    if not password or not text:
        return text
        
    if encrypt:
        # Mã hóa XOR: Ký tự văn bản XOR với ký tự mật khẩu (lặp lại mật khẩu nếu ngắn hơn văn bản)
        result = []
        for i, char in enumerate(text):
            pwd_char = password[i % len(password)]
            result.append(chr(ord(char) ^ ord(pwd_char)))
            
        # Bọc Base64 để chuỗi an toàn khi hiển thị trong Text widget (tránh các ký tự control unprintable)
        return base64.b64encode("".join(result).encode('utf-8')).decode('utf-8')
    else:
        # Giải mã: Làm ngược lại quy trình trên
        try:
            # Giải mã Base64 trước
            decoded = base64.b64decode(text.encode('utf-8')).decode('utf-8')
            # Phép XOR có tính chất đối xứng: (A XOR B) XOR B = A
            result = []
            for i, char in enumerate(decoded):
                pwd_char = password[i % len(password)]
                result.append(chr(ord(char) ^ ord(pwd_char)))
            return "".join(result)
        except Exception:
            return "[Lỗi: Không thể giải mã XOR, dữ liệu bị hỏng hoặc không đúng định dạng]"

# ========================== CLASS GIAO DIỆN CHÍNH (TKINTER) ==========================
class DigitalSignatureDemoApp:
    def __init__(self, root: tk.Tk) -> None:
        # Khởi tạo cửa sổ chính
        self.root = root
        self.root.title("Mô phỏng chữ ký số RSA & Mã hóa XOR")
        self.root.geometry("1450x860")
        self.root.minsize(1200, 700)
        
        # Biến trạng thái lưu trữ dữ liệu RSA
        self.current_key_pair: RSAKeyPair | None = None
        self.latest_signature: SignatureData | None = None
        self.real_e: int | None = None
        self.real_n: int | None = None
        
        # Các biến Tkinter StringVar để liên kết dữ liệu với giao diện
        self.algorithm_var = tk.StringVar(value="SHA-256")
        self.p_var = tk.StringVar()
        self.q_var = tk.StringVar()
        self.e_var = tk.StringVar(value="65537") # 65537 (2^16 + 1) là số e chuẩn thường dùng vì tính toán nhanh
        self.sender_password_var = tk.StringVar(value="")
        self.receiver_password_var = tk.StringVar(value="")
        self.public_key_var = tk.StringVar(value="(e, n) = Chưa tạo khóa")
        self.private_key_var = tk.StringVar(value="(d, n) = Chưa tạo khóa")
        self.hacker_public_key_var = tk.StringVar(value="(e, n) = Chưa sửa")
        self.receiver_public_key_var = tk.StringVar(value="(e, n) = Chưa nhận khóa")
        self.status_var = tk.StringVar(
            value="Sẵn sàng. Hãy tạo khóa, nhập mật khẩu, ký thông điệp, sau đó để hacker tấn công."
        )
        self.receiver_result_var = tk.StringVar(value="Chưa kiểm tra.")
        
        # Xây dựng UI
        self._build_styles()
        self._build_layout()
        
        # Tự động nạp bộ khóa mẫu khi khởi động
        self.load_sample_keys()
        self.message_text.insert(
            "1.0",
            "Thông điệp gốc: Đề nghị phê duyệt hóa đơn tháng 4.",
        )

    def _build_styles(self) -> None:
        """Cấu hình style cho các widget của Tkinter ttk"""
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam") # Giao diện clam nhìn hiện đại hơn mặc định
        self.root.option_add("*Font", ("Segoe UI", 12))
        self.root.option_add("*TCombobox*Listbox.font", ("Segoe UI", 12))
        style.configure("TLabel", font=("Segoe UI", 12))
        style.configure("TEntry", font=("Segoe UI", 12), padding=(8, 6))
        style.configure("TButton", font=("Segoe UI", 12), padding=(10, 6))
        style.configure("TCombobox", font=("Segoe UI", 12), padding=(8, 6))
        style.configure("TLabelframe.Label", font=("Segoe UI", 13, "bold"))
        style.configure("Header.TLabel", font=("Segoe UI", 24, "bold"))
        style.configure("SubHeader.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 12))
        style.configure("Accent.TButton", font=("Segoe UI", 12, "bold"), padding=(14, 8))
        style.configure("Warning.TLabel", font=("Segoe UI", 12, "bold"), foreground="red")

    def _build_layout(self) -> None:
        """Cấu trúc layout chính chia thành các khu vực"""
        canvas_container = ttk.Frame(self.root)
        canvas_container.pack(fill="both", expand=True)

        self.main_canvas = tk.Canvas(canvas_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_container, orient="vertical", command=self.main_canvas.yview)
        self.main_canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self.main_canvas.pack(side="left", fill="both", expand=True)

        outer = ttk.Frame(self.main_canvas, padding=16)
        self.main_canvas_window = self.main_canvas.create_window((0, 0), window=outer, anchor="nw")
        outer.bind("<Configure>", self._update_scroll_region)
        self.main_canvas.bind("<Configure>", self._resize_canvas_content)
        self.main_canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # Header
        ttk.Label(
            outer,
            text="Mô phỏng chữ ký số RSA & Mã hóa XOR: Người gửi - Hacker - Người nhận",
            style="Header.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            outer,
            text="Demo: Nhập Password (XOR) -> Hash thông điệp mã hóa -> Ký bằng private key -> Hacker -> Người nhận giải mã và kiểm tra",
            style="Status.TLabel",
            wraplength=1500,
        ).pack(anchor="w", pady=(6, 14))
        
        # Khu vực 1: Khởi tạo khóa RSA
        key_frame = ttk.LabelFrame(outer, text="1. Cài đặt khóa RSA", padding=14)
        key_frame.pack(fill="x")
        self._build_key_frame(key_frame)
        
        # Khu vực chính chia làm 3 cột: Gửi - Hack - Nhận
        content = ttk.Frame(outer)
        content.pack(fill="both", expand=True, pady=(14, 12))
        content.columnconfigure(0, weight=1, uniform="thirds")
        content.columnconfigure(1, weight=1, uniform="thirds")
        content.columnconfigure(2, weight=1, uniform="thirds")
        content.rowconfigure(0, weight=1)

        sender_frame = ttk.LabelFrame(content, text="2. Người gửi", padding=14)
        hacker_frame = ttk.LabelFrame(content, text="3. Hacker", padding=14)
        receiver_frame = ttk.LabelFrame(content, text="4. Người nhận", padding=14)

        sender_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        hacker_frame.grid(row=0, column=1, sticky="nsew", padx=8)
        receiver_frame.grid(row=0, column=2, sticky="nsew", padx=(8, 0))
        
        self._build_sender_frame(sender_frame)
        self._build_hacker_frame(hacker_frame)
        self._build_receiver_frame(receiver_frame)
        
        # Thanh trạng thái dưới cùng
        status_bar = ttk.Label(outer, textvariable=self.status_var, style="Status.TLabel")
        status_bar.pack(anchor="w", pady=(8, 0))

    def _update_scroll_region(self, _event: tk.Event) -> None:
        """Cập nhật vùng cuộn khi nội dung thay đổi kích thước."""
        self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))

    def _resize_canvas_content(self, event: tk.Event) -> None:
        """Giữ nội dung luôn khớp theo chiều rộng khung nhìn."""
        self.main_canvas.itemconfigure(self.main_canvas_window, width=event.width)

    def _on_mousewheel(self, event: tk.Event) -> None:
        """Cho phép cuộn toàn bộ giao diện bằng con lăn chuột trên Windows."""
        if event.delta:
            self.main_canvas.yview_scroll(int(-event.delta / 120), "units")

    def _build_key_frame(self, frame: ttk.LabelFrame) -> None:
        """Khu vực nhập p, q, e và sinh khóa"""
        frame.columnconfigure(0, weight=0)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(2, weight=0)
        frame.columnconfigure(3, weight=1)
        frame.columnconfigure(4, weight=0)
        frame.columnconfigure(5, weight=1)
        
        ttk.Label(frame, text="p:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.p_var, width=20).grid(row=0, column=1, sticky="ew", padx=(6, 14))
        
        ttk.Label(frame, text="q:").grid(row=0, column=2, sticky="w")
        ttk.Entry(frame, textvariable=self.q_var, width=20).grid(row=0, column=3, sticky="ew", padx=(6, 14))
        
        ttk.Label(frame, text="e:").grid(row=0, column=4, sticky="w")
        ttk.Entry(frame, textvariable=self.e_var, width=20).grid(row=0, column=5, sticky="ew", padx=(6, 14))
        
        button_row = ttk.Frame(frame)
        button_row.grid(row=1, column=0, columnspan=6, sticky="w", pady=(12, 12))
        
        ttk.Button(button_row, text="Tải khóa mẫu", style="Accent.TButton", command=self.load_sample_keys).pack(
            side="left", padx=(0, 10)
        )
        ttk.Button(button_row, text="Sinh khóa ngẫu nhiên", command=self.generate_random_keys).pack(
            side="left", padx=(0, 10)
        )
        ttk.Button(button_row, text="Cập nhật khóa từ giá trị nhập", command=self.update_keys_from_entries).pack(
            side="left"
        )
        
        # Labels hiển thị kết quả Public Key và Private Key
        ttk.Label(frame, textvariable=self.public_key_var, style="SubHeader.TLabel", wraplength=1400).grid(
            row=2, column=0, columnspan=6, sticky="w"
        )
        ttk.Label(frame, textvariable=self.private_key_var, wraplength=1400).grid(
            row=3, column=0, columnspan=6, sticky="w", pady=(6, 0)
        )

    def _build_sender_frame(self, frame: ttk.LabelFrame) -> None:
        """Khu vực dành cho Người gửi (Ký số & Mã hóa)"""
        frame.columnconfigure(0, weight=1)
        
        ttk.Label(frame, text="Thông điệp cần gửi:").grid(row=0, column=0, sticky="w")
        self.message_text = ScrolledText(frame, height=7, wrap="word", font=("Segoe UI", 12))
        self.message_text.grid(row=1, column=0, sticky="nsew")
        
        pwd_row = ttk.Frame(frame)
        pwd_row.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        ttk.Label(pwd_row, text="Mật khẩu mã hóa (XOR):").pack(side="left")
        ttk.Entry(pwd_row, textvariable=self.sender_password_var, show="*").pack(side="left", fill="x", expand=True, padx=(10, 0))
        
        algo_row = ttk.Frame(frame)
        algo_row.grid(row=3, column=0, sticky="ew", pady=(10, 10))
        ttk.Label(algo_row, text="Thuật toán băm:").pack(side="left")
        algo_combo = ttk.Combobox(
            algo_row,
            textvariable=self.algorithm_var,
            values=list(HASH_ALGORITHMS.keys()),
            state="readonly",
            width=18,
        )
        algo_combo.pack(side="left", padx=(10, 10))
        ttk.Button(algo_row, text="Ký & Gửi", style="Accent.TButton", command=self.sign_and_send).pack(
            side="left"
        )
        
        ttk.Label(frame, text="Signature do người gửi tạo:").grid(row=4, column=0, sticky="w")
        self.sender_signature_var = tk.StringVar(value="")
        ttk.Entry(frame, textvariable=self.sender_signature_var).grid(row=5, column=0, sticky="ew", pady=(0, 8))
        
        ttk.Label(frame, text="Chi tiết bên gửi:").grid(row=6, column=0, sticky="w")
        # Textbox hiển thị log của quá trình ký
        self.sender_info = ScrolledText(frame, height=7, wrap="word", font=("Consolas", 11))
        self.sender_info.grid(row=7, column=0, sticky="nsew")
        
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(7, weight=1)

    def _build_hacker_frame(self, frame: ttk.LabelFrame) -> None:
        """Khu vực mô phỏng Hacker cản trở/chỉnh sửa gói tin ở giữa đường mạng"""
        frame.columnconfigure(0, weight=1)
        
        ttk.Label(frame, text="Nội dung gói tin hacker nhìn thấy:").grid(row=0, column=0, sticky="w")
        self.hacker_message_text = ScrolledText(frame, height=7, wrap="word", font=("Segoe UI", 12))
        self.hacker_message_text.grid(row=1, column=0, sticky="nsew")
        
        ttk.Label(frame, text="Signature mà hacker nhìn thấy:").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.hacker_signature_var = tk.StringVar(value="")
        ttk.Entry(frame, textvariable=self.hacker_signature_var).grid(row=3, column=0, sticky="ew", pady=(0, 10))
        
        ttk.Label(frame, text="Khóa công khai hacker gửi cho người nhận:", style="SubHeader.TLabel").grid(
            row=4, column=0, sticky="w", pady=(14, 6)
        )
        self.hacker_public_key_var = tk.StringVar(value="(e, n) = Chưa sửa")
        ttk.Entry(frame, textvariable=self.hacker_public_key_var, state="readonly").grid(row=5, column=0, sticky="ew", pady=(0, 10))
        
        # Các nút giả lập hành vi phá hoại của Hacker
        button_row = ttk.Frame(frame)
        button_row.grid(row=6, column=0, sticky="ew", pady=(10, 0))
        button_row.columnconfigure(0, weight=1, uniform="hacker_buttons")
        button_row.columnconfigure(1, weight=1, uniform="hacker_buttons")

        ttk.Button(button_row, text="Sửa nội dung", command=self.tamper_message_sample).grid(
            row=0, column=0, sticky="ew", padx=(0, 6), pady=(0, 6)
        )
        ttk.Button(button_row, text="Sửa signature", command=self.tamper_signature_sample).grid(
            row=0, column=1, sticky="ew", padx=(6, 0), pady=(0, 6)
        )
        ttk.Button(
            button_row,
            text="Sửa public key",
            style="Accent.TButton",
            command=self.tamper_public_key,
        ).grid(row=1, column=0, sticky="ew", padx=(0, 6))

        ttk.Button(button_row, text="Chuyển tiếp", style="Accent.TButton", command=self.forward_packet).grid(
            row=1, column=1, sticky="ew", padx=(6, 0)
        )
        
        frame.rowconfigure(1, weight=1)

    def _build_receiver_frame(self, frame: ttk.LabelFrame) -> None:
        """Khu vực dành cho Người nhận (Giải mã & Kiểm chứng)"""
        frame.columnconfigure(0, weight=1)
        
        ttk.Label(frame, text="Thông điệp nhận được (Có thể bị mã hóa):").grid(row=0, column=0, sticky="w")
        self.receiver_message_text = ScrolledText(frame, height=5, wrap="word", font=("Segoe UI", 12))
        self.receiver_message_text.grid(row=1, column=0, sticky="nsew")
        
        pwd_row = ttk.Frame(frame)
        pwd_row.grid(row=2, column=0, sticky="ew", pady=(10, 10))
        ttk.Label(pwd_row, text="Mật khẩu giải mã (XOR):").pack(side="left")
        ttk.Entry(pwd_row, textvariable=self.receiver_password_var, show="*").pack(side="left", fill="x", expand=True, padx=(10, 0))
        
        ttk.Label(frame, text="Thông điệp sau khi giải mã:").grid(row=3, column=0, sticky="w")
        self.decrypted_message_text = ScrolledText(frame, height=5, wrap="word", font=("Segoe UI", 12))
        self.decrypted_message_text.grid(row=4, column=0, sticky="nsew")
        
        ttk.Label(frame, text="Signature nhận được:").grid(row=5, column=0, sticky="w", pady=(8, 0))
        self.receiver_signature_var = tk.StringVar(value="")
        ttk.Entry(frame, textvariable=self.receiver_signature_var).grid(row=6, column=0, sticky="ew", pady=(0, 10))
        
        ttk.Label(frame, text="Khóa công khai đang dùng:").grid(row=7, column=0, sticky="w", pady=(8, 4))
        ttk.Entry(frame, textvariable=self.receiver_public_key_var, state="readonly").grid(row=8, column=0, sticky="ew")
        
        ttk.Button(frame, text="Giải mã & Kiểm tra", style="Accent.TButton", command=self.verify_received_packet).grid(
            row=9, column=0, sticky="w", pady=(12, 0)
        )

        ttk.Label(frame, textvariable=self.receiver_result_var, style="SubHeader.TLabel", wraplength=500).grid(
            row=10, column=0, sticky="w", pady=(10, 10)
        )
        
        ttk.Label(frame, text="Chi tiết bên nhận:").grid(row=11, column=0, sticky="w")
        # Textbox hiển thị log chứng minh chữ ký đúng/sai
        self.receiver_info = ScrolledText(frame, height=6, wrap="word", font=("Consolas", 11))
        self.receiver_info.grid(row=12, column=0, sticky="nsew")
        
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
        frame.rowconfigure(12, weight=1)

    # Các hàm Helper để lấy/ghi dữ liệu vào ScrolledText dễ dàng hơn
    def set_text(self, widget: ScrolledText, value: str) -> None:
        widget.delete("1.0", "end")
        widget.insert("1.0", value)

    def get_text(self, widget: ScrolledText) -> str:
        return widget.get("1.0", "end-1c")

    def load_sample_keys(self) -> None:
        """Tải các số nguyên tố mẫu (p=3557, q=2579) để test nhanh"""
        self.p_var.set("3557")
        self.q_var.set("2579")
        self.e_var.set("65537")
        self.update_keys_from_entries(log_message=False)
        self.status_var.set("Đã nạp bộ khóa mẫu RSA.")

    def generate_random_keys(self) -> None:
        """Tự động sinh bộ khóa mới hoàn toàn"""
        p = generate_prime(16)
        q = generate_prime(16)
        # Đảm bảo p và q khác nhau
        while q == p:
            q = generate_prime(16)
            
        phi = (p - 1) * (q - 1)
        # Thử chọn các số e thường dùng trong thực tế, ưu tiên 65537
        e_candidates = [65537, 257, 17, 5, 3]
        e = next(candidate for candidate in e_candidates if math.gcd(candidate, phi) == 1)
        
        # Đưa vào UI và tính toán
        self.p_var.set(str(p))
        self.q_var.set(str(q))
        self.e_var.set(str(e))
        self.update_keys_from_entries()

    def update_keys_from_entries(self, log_message: bool = True) -> None:
        """Đọc giá trị p, q, e từ giao diện và tạo đối tượng RSAKeyPair"""
        try:
            p = int(self.p_var.get().strip())
            q = int(self.q_var.get().strip())
            e = int(self.e_var.get().strip())
            self.current_key_pair = build_key_pair(p, q, e)
        except ValueError as exc:
            self.current_key_pair = None
            self.public_key_var.set("(e, n) = Lỗi khóa")
            self.private_key_var.set("(d, n) = Lỗi khóa")
            self.status_var.set(str(exc))
            if log_message:
                messagebox.showerror("Lỗi khóa RSA", str(exc))
            return
            
        pair = self.current_key_pair
        # Lưu lại e và n thật để so sánh trong trường hợp Hacker tấn công Man-in-the-Middle (sửa public key)
        self.real_e = pair.e
        self.real_n = pair.n
        
        self.public_key_var.set(f"Khóa công khai: (e, n) = ({pair.e}, {pair.n})")
        self.private_key_var.set(
            f"Khóa riêng: (d, n) = ({pair.d}, {pair.n}) | phi(n) = {pair.phi}"
        )
        self.receiver_public_key_var.set(f"(e, n) = ({pair.e}, {pair.n})")
        self.hacker_public_key_var.set(f"(e, n) = ({pair.e}, {pair.n})")
        self.status_var.set("Đã cập nhật khóa RSA thành công.")

    def sign_and_send(self) -> None:
        """Hành động của Người gửi: Mã hóa -> Băm -> Ký -> Gửi cho Hacker"""
        if self.current_key_pair is None:
            self.update_keys_from_entries(log_message=False)
        if self.current_key_pair is None:
            messagebox.showerror("Chưa có khóa", "Hãy tạo khóa hợp lệ trước khi ký.")
            return
            
        original_message = self.get_text(self.message_text).strip()
        if not original_message:
            messagebox.showwarning("Thiếu thông điệp", "Hãy nhập nội dung cần gửi.")
            return
            
        password = self.sender_password_var.get()
        # 1. Mã hóa văn bản (XOR) nếu người dùng có nhập mật khẩu
        message_to_send = xor_cipher_base64(original_message, password, encrypt=True)
        
        # 2. Tạo chữ ký số (Băm thông điệp đã mã hóa -> Mã hóa bằng khóa bí mật)
        signature = sign_message(message_to_send, self.algorithm_var.get(), self.current_key_pair)
        self.latest_signature = signature
        self.sender_signature_var.set(str(signature.signature_int))
        
        # In log ra UI của người gửi
        info_lines = [
            f"Thuật toán băm: {signature.algorithm_label}",
            f"Hash (integer): {signature.raw_hash_int}",
            f"Hash mod n: {signature.reduced_hash}",
            f"Signature (integer): {signature.signature_int}",
            "",
            "Gói tin gửi đi:"
        ]
        if password:
            info_lines.append(f"Message (Đã mã hóa XOR): {signature.message}")
        else:
            info_lines.append(f"Message (Không mã hóa): {signature.message}")
            
        info_lines.append(f"Signature: {signature.signature_int}")
        self.set_text(self.sender_info, "\n".join(info_lines))
        
        # Chuyển dữ liệu sang luồng của Hacker
        self.set_text(self.hacker_message_text, message_to_send)
        self.hacker_signature_var.set(str(signature.signature_int))
        self.hacker_public_key_var.set(f"(e, n) = ({self.real_e}, {self.real_n})")
        self.receiver_public_key_var.set(f"(e, n) = ({self.real_e}, {self.real_n})")
        
        # Reset khu vực Người nhận
        self.set_text(self.receiver_message_text, "")
        self.set_text(self.decrypted_message_text, "")
        self.receiver_signature_var.set("")
        self.set_text(self.receiver_info, "")
        self.receiver_result_var.set("Chưa kiểm tra.")
        self.status_var.set("Người gửi đã ký (và mã hóa) xong. Gói tin đã đến hacker.")

    def tamper_message_sample(self) -> None:
        """Hacker giả mạo nội dung text"""
        current = self.get_text(self.hacker_message_text).strip()
        if not current:
            current = "Thông điệp đã bị thay đổi."
        else:
            current += " [ĐÃ BỊ HACKER SỬA]"
        self.set_text(self.hacker_message_text, current)
        self.status_var.set("Hacker đã sửa nội dung gói tin.")

    def tamper_signature_sample(self) -> None:
        """Hacker thay đổi giá trị của chữ ký số"""
        current = self.hacker_signature_var.get().strip()
        if not current:
            self.hacker_signature_var.set("1234")
        else:
            try:
                value = parse_signature(current)
                self.hacker_signature_var.set(str(value ^ 12345)) # Sử dụng phép XOR đơn giản để làm sai lệch con số
            except ValueError:
                self.hacker_signature_var.set("1234")
        self.status_var.set("Hacker đã sửa signature.")

    def tamper_public_key(self) -> None:
        """
        Hacker sửa khóa công khai (Tấn công Man-in-the-Middle)
        Khiến người nhận tưởng đây là khóa thật của người gửi, nhưng thực chất là khóa của Hacker.
        """
        if self.real_e is None or self.real_n is None:
            messagebox.showwarning("Chưa có khóa", "Hãy tạo khóa trước.")
            return
            
        # Tạo e và n giả mạo
        fake_e = self.real_e + secrets.randbelow(20000) + 100
        fake_n = self.real_n ^ (1 << secrets.randbelow(32))
        
        self.hacker_public_key_var.set(f"(e, n) = ({fake_e}, {fake_n})")
        self.receiver_public_key_var.set(f"(e, n) = ({fake_e}, {fake_n})")
        self.status_var.set("HACKER ĐÃ SỬA KHÓA CÔNG KHAI! Người nhận đang dùng khóa giả.")
        messagebox.showwarning(
            "Tấn công thành công",
            "Hacker đã thay đổi khóa công khai.\n"
            "Người nhận sẽ dùng khóa sai để kiểm tra chữ ký.\n"
            "Đây là dạng tấn công Man-in-the-Middle."
        )

    def forward_packet(self) -> None:
        """Hacker bấm nút chuyển tiếp gói tin đã (bị sửa hoặc không) cho Người nhận"""
        message = self.get_text(self.hacker_message_text)
        signature = self.hacker_signature_var.get().strip()
        
        self.set_text(self.receiver_message_text, message)
        self.receiver_signature_var.set(signature)
        self.receiver_public_key_var.set(self.hacker_public_key_var.get())   # Chuyển khóa công khai (có thể là đồ giả)
        
        self.receiver_result_var.set("Đã nhận gói tin. Chưa kiểm tra.")
        self.set_text(self.receiver_info, "")
        self.status_var.set("Hacker đã chuyển tiếp gói tin sang người nhận.")

    def verify_received_packet(self) -> None:
        """Hành động của Người nhận: Lấy thông điệp -> Giải mã chữ ký bằng Public Key -> So sánh băm"""
        if self.current_key_pair is None or self.real_e is None or self.real_n is None:
            messagebox.showerror("Chưa có khóa", "Không có public key gốc để so sánh.")
            return
            
        message = self.get_text(self.receiver_message_text).strip()
        if not message:
            messagebox.showwarning("Chưa có dữ liệu", "Người nhận chưa có thông điệp.")
            return
            
        try:
            signature_int = parse_signature(self.receiver_signature_var.get().strip())
        except ValueError as exc:
            messagebox.showerror("Signature không hợp lệ", str(exc))
            return
            
        receiver_pub = self.receiver_public_key_var.get()
        # Parse chuỗi UI để lấy ra e và n mà Người nhận đang nắm giữ (có thể bị Hacker đổi)
        try:
            match = re.search(r'\((\d+),\s*(\d+)\)', receiver_pub)
            used_e = int(match.group(1)) if match else self.real_e
            used_n = int(match.group(2)) if match else self.real_n
        except:
            used_e, used_n = self.real_e, self.real_n
            
        key_tampered = (used_e != self.real_e or used_n != self.real_n)
        
        # Kiểm chứng thông điệp
        result = verify_message(
            message=message,
            signature_int=signature_int,
            algorithm_label=self.latest_signature.algorithm_label if self.latest_signature else self.algorithm_var.get(),
            n=used_n,
            e=used_e,
        )
        
        password = self.receiver_password_var.get()
        # Cố gắng giải mã XOR (Nếu password sai, nội dung sẽ vẫn là rác)
        decrypted_message = xor_cipher_base64(message, password, encrypt=False)
        self.set_text(self.decrypted_message_text, decrypted_message)
        
        # Kết luận dựa trên kết quả kiểm chứng
        if key_tampered:
            verdict = "CẢNH BÁO NGHIÊM TRỌNG: KHÓA CÔNG KHAI ĐÃ BỊ HACKER THAY ĐỔI!\n"
            verdict += "Người nhận đang dùng khóa giả."
        elif result.is_valid:
            verdict = "Hợp lệ: Thông điệp nguyên vẹn và chữ ký đúng."
        else:
            verdict = "Không hợp lệ: Nội dung hoặc chữ ký đã bị thay đổi."
            
        self.receiver_result_var.set(verdict)
        
        # Ghi log chi tiết cho UI Người nhận
        details = [
            f"Message gốc nhận được: {result.message}",
        ]
        if password:
            details.append(f"Message sau giải mã: {decrypted_message}")
            
        details.extend([
            f"Signature nhận được: {result.signature_int}",
            f"Hash của thông điệp: {result.raw_hash_int}",
            f"Hash mod n: {result.reduced_hash}",
            f"Giải mã signature: {result.decrypted_signature}",
            f"So sánh: {result.reduced_hash} {'=' if result.is_valid else '!='} {result.decrypted_signature}",
        ])
        
        if key_tampered:
            details.append("")
            details.append("=== CẢNH BÁO ===")
            details.append(f"Khóa gốc:     (e, n) = ({self.real_e}, {self.real_n})")
            details.append(f"Khóa đang dùng: (e, n) = ({used_e}, {used_n})")
            
        self.set_text(self.receiver_info, "\n".join(details))
        self.status_var.set(verdict)

def run_self_test() -> int:
    """Hàm chạy ẩn trong terminal (dành cho developer) để test logic không cần mở UI"""
    pair = build_key_pair(3557, 2579, 65537)
    signed = sign_message("Thong diep demo", "SHA-256", pair)
    valid = verify_message("Thong diep demo", signed.signature_int, "SHA-256", pair.n, pair.e)
    tampered = verify_message("Thong diep demo da bi sua", signed.signature_int, "SHA-256", pair.n, pair.e)
    
    print("SELF-TEST")
    print(f"n={pair.n}, e={pair.e}, d={pair.d}")
    print(f"signature={signed.signature_int}")
    print(f"valid_result={valid.is_valid}")
    print(f"tampered_result={tampered.is_valid}")
    return 0 if valid.is_valid and not tampered.is_valid else 1

def main() -> None:
    # Nếu truyền param --self-test qua terminal thì chạy test rồi thoát
    if "--self-test" in sys.argv:
        raise SystemExit(run_self_test())
        
    # Khởi chạy giao diện Tkinter
    root = tk.Tk()
    app = DigitalSignatureDemoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

