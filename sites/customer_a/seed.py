"""Fake seed data for customer-a. Every person, address and order here is invented.

Demo logins (fake, for local testing only):
    alice@example.test / alice-demo-pass
    bob@example.test   / bob-demo-pass
    carol@example.test / carol-demo-pass
"""

import hashlib
import hmac
from dataclasses import dataclass, field


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()


def check_password(password: str, salt: str, digest: str) -> bool:
    return hmac.compare_digest(hash_password(password, salt), digest)


@dataclass
class User:
    user_id: str
    email: str
    name: str
    salt: str
    password_hash: str


@dataclass
class Order:
    order_id: str
    owner_user_id: str
    items: list[dict]
    total_cents: int
    shipping_city: str


@dataclass
class Store:
    users: dict[str, User] = field(default_factory=dict)  # by user_id
    products: dict[str, dict] = field(default_factory=dict)
    orders: dict[str, Order] = field(default_factory=dict)

    def user_by_email(self, email: str) -> User | None:
        email = email.strip().lower()
        return next((u for u in self.users.values() if u.email == email), None)


PRODUCTS = [
    {"product_id": "p-100", "name": "Canvas Tote", "price_cents": 1800},
    {"product_id": "p-101", "name": "Enamel Mug", "price_cents": 1200},
    {"product_id": "p-102", "name": "Wool Socks", "price_cents": 900},
    {"product_id": "p-103", "name": "Desk Plant (artificial)", "price_cents": 2500},
]

_USERS = [
    ("u-1", "alice@example.test", "Alice Example", "alice-demo-pass"),
    ("u-2", "bob@example.test", "Bob Example", "bob-demo-pass"),
    ("u-3", "carol@example.test", "Carol Example", "carol-demo-pass"),
]

_ORDERS = [
    ("1001", "u-1", [("p-100", 1), ("p-101", 2)], "Springfield"),
    ("1002", "u-1", [("p-102", 3)], "Springfield"),
    ("1003", "u-2", [("p-103", 1)], "Shelbyville"),
    ("1004", "u-3", [("p-101", 1), ("p-102", 1)], "Ogdenville"),
]


def build_store() -> Store:
    store = Store(products={p["product_id"]: dict(p) for p in PRODUCTS})
    for uid, email, name, password in _USERS:
        salt = f"seed-salt-{uid}"
        store.users[uid] = User(uid, email, name, salt, hash_password(password, salt))
    for oid, owner, lines, city in _ORDERS:
        items = [
            {"product_id": pid, "qty": qty, "price_cents": store.products[pid]["price_cents"]}
            for pid, qty in lines
        ]
        total = sum(i["qty"] * i["price_cents"] for i in items)
        store.orders[oid] = Order(oid, owner, items, total, city)
    return store
