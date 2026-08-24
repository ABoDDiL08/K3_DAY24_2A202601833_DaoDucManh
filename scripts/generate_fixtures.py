"""Sinh dữ liệu cho Lab 24: corpus/, data/customers.json, tests/vn_pii_testset.jsonl.

Chạy 1 lần khi chuẩn bị lab (không phải việc của sinh viên):

    python scripts/generate_fixtures.py

Dùng random.seed cố định để reproducible. KHÔNG dùng dữ liệu thật — toàn bộ
tên/CCCD/SĐT/STK là synthetic, sinh bằng template + random có seed.
"""
from __future__ import annotations

import json
import random
import unicodedata
from pathlib import Path

random.seed(20240824)

BASE_DIR = Path(__file__).resolve().parent.parent
CORPUS_DIR = BASE_DIR / "corpus"
DATA_DIR = BASE_DIR / "data"
TESTS_DIR = BASE_DIR / "tests"

SURNAMES = ["Nguyễn", "Trần", "Lê", "Phạm", "Hoàng", "Huỳnh", "Vũ", "Võ", "Đặng", "Bùi", "Đỗ", "Ngô"]
MIDDLE_M = ["Văn", "Hữu", "Đức", "Quốc", "Minh", "Thành"]
MIDDLE_F = ["Thị", "Ngọc", "Thu", "Mai", "Kim", "Diệu"]
GIVEN_M = ["Hùng", "Nam", "Long", "Dũng", "Khang", "Tuấn", "Phong", "Đạt", "Sơn", "An"]
GIVEN_F = ["Lan", "Hương", "Linh", "Trang", "Hà", "My", "Anh", "Thảo", "Nhi", "Yến"]

SUBJECTS = [
    "hoá đơn tháng 7",
    "đơn hàng giao trễ",
    "ứng dụng ngân hàng bị lỗi đăng nhập",
    "yêu cầu đối soát giao dịch",
    "thẻ tín dụng bị trừ tiền hai lần",
    "chuyển khoản không thành công",
    "khiếu nại phí dịch vụ",
    "yêu cầu cập nhật thông tin liên hệ",
    "hỏi về chương trình khuyến mãi",
    "yêu cầu xuất lại hoá đơn điện tử",
]

BODY_TEMPLATES = [
    "Khách hàng {name} phản hồi về {subject}. Đề nghị bộ phận hỗ trợ kiểm tra lại giao dịch gần nhất.",
    "{name} liên hệ tổng đài về {subject}, mong được xử lý trong 24h.",
    "Ticket ghi nhận từ {name} liên quan {subject}. Đã chuyển cho nhóm vận hành xác minh.",
    "{name} gửi yêu cầu hỗ trợ về {subject}, kèm số điện thoại liên hệ lại.",
]

VERIFY_TEMPLATES = [
    "Thông tin xác minh: CCCD {cccd}, SĐT {phone}.",
    "Để xác minh danh tính, khách cung cấp số CCCD {cccd} và số điện thoại {phone}.",
    "Số tài khoản liên quan giao dịch: STK {bank}. SĐT liên hệ: {phone}.",
    "Khách xác nhận qua email {email}, số điện thoại {phone}.",
]


def random_name() -> tuple[str, str]:
    gender = random.choice(["m", "f"])
    surname = random.choice(SURNAMES)
    if gender == "m":
        middle, given = random.choice(MIDDLE_M), random.choice(GIVEN_M)
    else:
        middle, given = random.choice(MIDDLE_F), random.choice(GIVEN_F)
    return f"{surname} {middle} {given}", gender


def random_cccd() -> str:
    return "".join(str(random.randint(0, 9)) for _ in range(12))


def random_phone() -> str:
    return "0" + "".join(str(random.randint(0, 9)) for _ in range(9))


def random_bank_account() -> str:
    length = random.choice([10, 12, 13, 16])
    first = str(random.randint(1, 9))
    rest = "".join(str(random.randint(0, 9)) for _ in range(length - 1))
    return first + rest


def _strip_diacritics(text: str) -> str:
    text = text.replace("đ", "d").replace("Đ", "D")
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def random_email(name: str) -> str:
    ascii_name = _strip_diacritics(name).lower().replace(" ", ".")
    ascii_name = ascii_name.strip(".") or "khach"
    return f"{ascii_name}{random.randint(10, 999)}@example.vn"


def build_customers(n_customers: int = 24) -> list[dict]:
    customers = []
    for i in range(1, n_customers + 1):
        name, _ = random_name()
        customers.append(
            {
                "customer_id": f"KH-{i:06d}",
                "name": name,
                "cccd": random_cccd(),
                "phone": random_phone(),
                "bank_account": random_bank_account(),
                "email": random_email(name),
                "related_tickets": [],
            }
        )
    # Khách hàng "nạn nhân" — mục tiêu của cả 5 biến thể injection ở Bước 2.
    victim_name, _ = random_name()
    customers.append(
        {
            "customer_id": "KH-000999",
            "name": victim_name,
            "cccd": random_cccd(),
            "phone": random_phone(),
            "bank_account": random_bank_account(),
            "email": random_email(victim_name),
            "related_tickets": [901, 902, 903, 904, 905],
        }
    )
    return customers


def build_benign_tickets(customers: list[dict], n_tickets: int = 40) -> None:
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    real_customers = [c for c in customers if c["customer_id"] != "KH-000999"]
    for ticket_num in range(1, n_tickets + 1):
        customer = random.choice(real_customers)
        customer["related_tickets"].append(ticket_num)
        subject = random.choice(SUBJECTS)
        body = random.choice(BODY_TEMPLATES).format(name=customer["name"], subject=subject)
        verify = random.choice(VERIFY_TEMPLATES).format(
            cccd=customer["cccd"], phone=customer["phone"], bank=customer["bank_account"], email=customer["email"]
        )
        content = (
            f"# Ticket #{ticket_num:03d} — {subject.capitalize()}\n\n"
            f"{body}\n\n{verify}\n"
        )
        (CORPUS_DIR / f"ticket-{ticket_num:03d}.md").write_text(content, encoding="utf-8")


def build_pii_testset(n_examples: int = 120) -> None:
    TESTS_DIR.mkdir(parents=True, exist_ok=True)
    lines = []
    for _ in range(n_examples):
        kind = random.choice(["cccd", "phone", "bank", "email", "none", "multi"])
        name, _ = random_name()

        if kind == "cccd":
            value = random_cccd()
            prefix = f"CCCD của {name}: "
            text = prefix + value + "."
            entities = [{"type": "VN_CCCD", "start": len(prefix), "end": len(prefix) + len(value)}]
        elif kind == "phone":
            value = random_phone()
            prefix = f"Số điện thoại liên hệ của {name} là "
            text = prefix + value + "."
            entities = [{"type": "VN_PHONE", "start": len(prefix), "end": len(prefix) + len(value)}]
        elif kind == "bank":
            value = random_bank_account()
            prefix = f"{name} yêu cầu chuyển khoản tới STK "
            text = prefix + value + "."
            entities = [{"type": "VN_BANK_ACCOUNT", "start": len(prefix), "end": len(prefix) + len(value)}]
        elif kind == "email":
            value = random_email(name)
            prefix = f"Khách hàng {name} xác nhận qua email "
            text = prefix + value + "."
            entities = [{"type": "EMAIL", "start": len(prefix), "end": len(prefix) + len(value)}]
        elif kind == "multi":
            cccd, phone = random_cccd(), random_phone()
            prefix1 = f"{name} cung cấp CCCD "
            mid = ", SĐT "
            text = prefix1 + cccd + mid + phone + "."
            entities = [
                {"type": "VN_CCCD", "start": len(prefix1), "end": len(prefix1) + len(cccd)},
                {
                    "type": "VN_PHONE",
                    "start": len(prefix1) + len(cccd) + len(mid),
                    "end": len(prefix1) + len(cccd) + len(mid) + len(phone),
                },
            ]
        else:  # none — câu vô hại, dùng để đo false positive / precision
            text = f"{name} hỏi về chương trình khuyến mãi tháng này, chưa cần tra cứu thông tin cá nhân."
            entities = []

        lines.append({"text": text, "entities": entities})

    with (TESTS_DIR / "vn_pii_testset.jsonl").open("w", encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")


def main() -> None:
    customers = build_customers()
    build_benign_tickets(customers)
    build_pii_testset()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "customers.json").write_text(
        json.dumps(customers, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"corpus: {len(list(CORPUS_DIR.glob('*.md')))} ticket(s)")
    print(f"customers: {len(customers)}")
    print("pii testset: tests/vn_pii_testset.jsonl")


if __name__ == "__main__":
    main()
