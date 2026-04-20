import secrets
import math
from dataclasses import dataclass
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText


@dataclass
class RSAKeyPair:
    """Lớp lưu trữ thông tin cặp khóa RSA của một bên"""
    p: int      # Số nguyên tố p
    q: int      # Số nguyên tố q
    e: int      # Public exponent
    d: int      # Private exponent
    n: int      # Modulus = p * q


class SharedSecretRSADemo:
    """
    Ứng dụng mô phỏng trao đổi Mật khẩu Chung (Shared Secret) bằng RSA.
    Minh họa ý tưởng của Diffie-Hellman hoặc trao đổi khóa an toàn qua kênh công khai.
    """

    def __init__(self, root):
        self.root = root
        self.root.title("Mô phỏng Trao đổi Mật khẩu Chung bằng RSA")
        self.root.geometry("1280x780")
        self.root.minsize(1150, 700)

        # Khóa RSA của hai bên
        self.key_A: RSAKeyPair | None = None
        self.key_B: RSAKeyPair | None = None

        # Mật khẩu thu được của từng bên (sẽ hiển thị riêng)
        self.secret_received_A: int | None = None
        self.secret_received_B: int | None = None

        # Biến trạng thái
        self.status_var = tk.StringVar(value="Đang khởi tạo...")

        self._build_ui()
        self.generate_keys()        # Tạo khóa ngay khi mở chương trình


    def _build_ui(self):
        """Xây dựng toàn bộ giao diện người dùng"""
        style = ttk.Style()
        style.theme_use("clam")

        main = ttk.Frame(self.root, padding=15)
        main.pack(fill="both", expand=True)

        # Tiêu đề
        ttk.Label(main, 
                  text="Trao đổi Mật khẩu Chung bằng Mã hóa Bất đối xứng RSA",
                  font=("Segoe UI", 18, "bold")).pack(anchor="w")

        ttk.Label(main, 
                  text="Hai bên gửi số bí mật cho nhau qua mã hóa RSA → Cuối cùng tính ra được cùng một mật khẩu chung",
                  font=("Segoe UI", 11)).pack(anchor="w", pady=(0, 20))

        # Khung quản lý khóa
        key_frame = ttk.LabelFrame(main, text="1. Khóa RSA của hai bên", padding=12)
        key_frame.pack(fill="x", pady=(0, 15))
        self._build_key_frame(key_frame)

        # Khu vực chính: Bên A và Bên B
        content = ttk.Frame(main)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=1)

        a_frame = ttk.LabelFrame(content, text="👤 Bên A", padding=12)
        b_frame = ttk.LabelFrame(content, text="👤 Bên B", padding=12)

        a_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        b_frame.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        self._build_side(a_frame, "A")
        self._build_side(b_frame, "B")

        # Khung hiển thị mật khẩu chung (2 hộp riêng biệt)
        result_frame = ttk.LabelFrame(main, text="2. Mật khẩu thu được của từng bên", padding=15)
        result_frame.pack(fill="x", pady=(15, 0))

        self._build_shared_secret_frame(result_frame)

        # Thanh trạng thái
        ttk.Label(main, textvariable=self.status_var, foreground="blue").pack(anchor="w", pady=(20, 0))


    def _build_key_frame(self, frame):
        """Xây dựng phần hiển thị và nút tạo khóa RSA"""
        ttk.Button(frame, 
                   text="Tạo lại khóa mới cho cả A và B", 
                   command=self.generate_keys).pack(pady=8)

        self.key_a_info = ttk.Label(frame, text="Khóa A: Chưa tạo", font=("Consolas", 10))
        self.key_a_info.pack(anchor="w", pady=4)

        self.key_b_info = ttk.Label(frame, text="Khóa B: Chưa tạo", font=("Consolas", 10))
        self.key_b_info.pack(anchor="w")


    def _build_side(self, frame, side: str):
        """Xây dựng giao diện cho một bên (A hoặc B)"""
        frame.columnconfigure(0, weight=1)

        # Phần gửi số bí mật
        ttk.Label(frame, text=f"Bên {side} gửi số bí mật:", 
                  font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=(0,5))

        self.secret_entry = ttk.Entry(frame, width=50)      # Entry chung cho cả 2 bên (dùng lại)
        self.secret_entry.grid(row=1, column=0, sticky="ew", pady=(0,10))
        self.secret_entry.insert(0, str(secrets.randbelow(999999)))

        btn_text = f"{side} gửi số bí mật cho đối phương (Mã hóa bằng Public Key của đối phương)"
        ttk.Button(frame, text=btn_text, 
                   command=lambda: self.send_secret(side)).grid(row=2, column=0, sticky="w", pady=8)

        # Phần nhận được từ đối phương
        ttk.Label(frame, text="Nhận được từ đối phương:", 
                  font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="w", pady=(15,5))

        result_text = ScrolledText(frame, height=7, wrap="word", font=("Consolas", 10), state="disabled")
        result_text.grid(row=4, column=0, sticky="nsew")

        if side == "A":
            self.a_result = result_text
        else:
            self.b_result = result_text


    def _build_shared_secret_frame(self, frame):
        """Xây dựng 2 hộp hiển thị mật khẩu thu được riêng của từng bên"""
        # Bên A
        ttk.Label(frame, text="Mật khẩu thu được bên A:", 
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.secret_a_label = ttk.Label(frame, 
                                        text="Chưa có dữ liệu", 
                                        font=("Consolas", 12), 
                                        foreground="blue")
        self.secret_a_label.pack(anchor="w", pady=(0, 12))

        # Bên B
        ttk.Label(frame, text="Mật khẩu thu được bên B:", 
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.secret_b_label = ttk.Label(frame, 
                                        text="Chưa có dữ liệu", 
                                        font=("Consolas", 12), 
                                        foreground="blue")
        self.secret_b_label.pack(anchor="w", pady=(0, 12))

        # Nút tạo mật khẩu chung
        ttk.Button(frame, 
                   text="🔑 Tạo Mật khẩu Chung (Shared Secret)", 
                   style="Accent.TButton", 
                   command=self.create_shared_secret).pack(pady=10)


    def generate_keys(self):
        """Tạo cặp khóa RSA mới cho cả bên A và bên B"""
        # Tạo khóa cho Bên A
        p = self.generate_prime(16)
        q = self.generate_prime(16)
        while q == p:
            q = self.generate_prime(16)
        self.key_A = self.build_key_pair(p, q, 65537)

        # Tạo khóa cho Bên B
        p = self.generate_prime(16)
        q = self.generate_prime(16)
        while q == p:
            q = self.generate_prime(16)
        self.key_B = self.build_key_pair(p, q, 65537)

        # Cập nhật hiển thị
        self.key_a_info.config(text=f"Khóa A → Public: (e={self.key_A.e}, n={self.key_A.n})")
        self.key_b_info.config(text=f"Khóa B → Public: (e={self.key_B.e}, n={self.key_B.n})")

        # Reset mật khẩu thu được
        self.secret_received_A = None
        self.secret_received_B = None
        self.secret_a_label.config(text="Chưa có dữ liệu")
        self.secret_b_label.config(text="Chưa có dữ liệu")

        self.status_var.set("Đã tạo khóa mới cho A và B. Hãy gửi số bí mật cho nhau.")


    def send_secret(self, from_side: str):
        """Bên gửi số bí mật đến bên kia qua mã hóa RSA"""
        try:
            secret = int(self.secret_entry.get().strip())
        except ValueError:
            messagebox.showerror("Lỗi", "Vui lòng nhập một số nguyên hợp lệ")
            return

        if from_side == "A":
            if not self.key_A or not self.key_B:
                messagebox.showerror("Lỗi", "Chưa có khóa")
                return
            # A mã hóa bằng public key của B
            encrypted = pow(secret, self.key_B.e, self.key_B.n)
            decrypted = pow(encrypted, self.key_B.d, self.key_B.n)   # B giải mã

            self.b_result.config(state="normal")
            self.b_result.delete("1.0", "end")
            self.b_result.insert("1.0", 
                f"Nhận từ A (đã mã hóa): {encrypted}\n\n"
                f"Giải mã được: {decrypted}\n"
                f"→ Bên B đã nhận được số bí mật từ A")
            self.b_result.config(state="disabled")

            self.secret_received_B = decrypted

        else:  # B gửi cho A
            if not self.key_A or not self.key_B:
                messagebox.showerror("Lỗi", "Chưa có khóa")
                return
            # B mã hóa bằng public key của A
            encrypted = pow(secret, self.key_A.e, self.key_A.n)
            decrypted = pow(encrypted, self.key_A.d, self.key_A.n)   # A giải mã

            self.a_result.config(state="normal")
            self.a_result.delete("1.0", "end")
            self.a_result.insert("1.0", 
                f"Nhận từ B (đã mã hóa): {encrypted}\n\n"
                f"Giải mã được: {decrypted}\n"
                f"→ Bên A đã nhận được số bí mật từ B")
            self.a_result.config(state="disabled")

            self.secret_received_A = decrypted

        self.status_var.set(f"Bên {from_side} đã gửi số bí mật thành công.")


    def create_shared_secret(self):
        """Tạo và hiển thị mật khẩu chung cho cả hai bên"""
        if not self.key_A or not self.key_B:
            messagebox.showwarning("Chưa có khóa", "Hãy tạo khóa trước khi tạo mật khẩu chung")
            return

        if self.secret_received_A is None or self.secret_received_B is None:
            messagebox.showwarning("Chưa đủ dữ liệu", 
                                 "Cả hai bên cần gửi số bí mật cho nhau trước khi tạo mật khẩu chung.")
            return

        # Minh họa cách tạo shared secret (có thể cải tiến sau)
        # Ở đây dùng công thức đơn giản để cả hai bên ra cùng một kết quả
        self.shared_secret = (self.secret_received_A * self.secret_received_B) % (self.key_A.n * self.key_B.n)

        # Hiển thị riêng cho từng bên
        self.secret_a_label.config(
            text=f"{self.shared_secret}\n"
                 f"(Bên A tính từ số bí mật nhận được từ B)"
        )
        self.secret_b_label.config(
            text=f"{self.shared_secret}\n"
                 f"(Bên B tính từ số bí mật nhận được từ A)"
        )

        self.status_var.set("Mật khẩu chung đã được tạo thành công cho cả hai bên!")

        messagebox.showinfo("Thành công", 
            f"Mật khẩu chung đã được tạo!\n\n"
            f"Giá trị: {self.shared_secret}\n\n"
            "Cả hai bên đều tính ra được cùng một mật khẩu mà không cần gửi trực tiếp.")


    # ====================== CÁC HÀM HỖ TRỢ RSA ======================
    def generate_prime(self, bits=16) -> int:
        """Sinh số nguyên tố ngẫu nhiên với độ dài bits bit"""
        while True:
            cand = secrets.randbits(bits)
            cand |= (1 << (bits - 1)) | 1          # Đảm bảo số lẻ và có bit cao nhất
            if self.is_probable_prime(cand):
                return cand


    def is_probable_prime(self, n: int, rounds: int = 8) -> bool:
        """Kiểm tra số nguyên tố bằng thuật toán Miller-Rabin"""
        if n < 2:
            return False
        small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
        for p in small:
            if n == p:
                return True
            if n % p == 0:
                return False

        d, s = n - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(rounds):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True


    def build_key_pair(self, p: int, q: int, e: int) -> RSAKeyPair:
        """Xây dựng cặp khóa RSA từ p, q, e"""
        n = p * q
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)          # Tính nghịch đảo modulo nhanh bằng pow
        return RSAKeyPair(p, q, e, d, n)


def main():
    root = tk.Tk()
    app = SharedSecretRSADemo(root)
    root.mainloop()


if __name__ == "__main__":
    main()
    