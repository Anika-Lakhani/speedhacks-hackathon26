"""customer-a: a deliberately minimal e-commerce demo (accounts, password reset, cart, orders).

    uv run uvicorn sites.customer_a.app:create_app --factory --port 3001

JSON API only. Every security-relevant action and its outcome is emitted as a §5.1 event
(customer_id "customer-a") through the fail-safe emitter. Fake seed data only (seed.py).
Vulnerability flags and probe handling arrive in M5; today every check is the secure one.
"""

import secrets
import threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from sites.common.emitter import EventEmitter, http_sender
from sites.customer_a import config
from sites.customer_a.seed import Order, User, build_store, check_password, hash_password

FAILED_LOGIN_FLAG_THRESHOLD = 5  # consecutive failures for one account before outcome "flag"


class LoginBody(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=256)


class ResetRequestBody(BaseModel):
    email: str = Field(max_length=254)


class ResetConfirmBody(BaseModel):
    token: str = Field(max_length=128)
    new_password: str = Field(min_length=8, max_length=256)


class CartAddBody(BaseModel):
    product_id: str = Field(max_length=32)
    qty: int = Field(ge=1, le=99)


def create_app(emitter: EventEmitter | None = None, code_revision: str | None = None) -> FastAPI:
    revision = code_revision or config.CODE_REVISION
    emitter = emitter or EventEmitter(http_sender(config.STORE_URL), config.EMIT_FALLBACK_PATH)
    store = build_store()
    sessions: dict[str, str] = {}  # token -> user_id
    carts: dict[str, dict[str, int]] = {}  # user_id -> {product_id: qty}
    failed_logins: dict[str, int] = {}  # user_id -> consecutive failures
    reset_tokens: dict[str, str] = {}  # token -> user_id (the fake "email outbox")
    lock = threading.Lock()
    next_order = [2000]

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        emitter.shutdown()

    app = FastAPI(title="customer-a (demo e-commerce)", version=revision, lifespan=lifespan)
    app.state.emitter = emitter
    app.state.store = store
    app.state.reset_outbox = reset_tokens  # tests read this instead of an inbox

    @app.middleware("http")
    async def revision_header(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Code-Revision"] = revision
        return response

    def emit(
        request: Request,
        event_type: str,
        target: str,
        outcome: str,
        *,
        transition: str | None = None,
        **attrs: Any,
    ) -> None:
        emitter.emit(
            customer_id=config.CUSTOMER_ID,
            ts=datetime.now(UTC),
            actor="user",
            tool="customer-a-site",
            event_type=event_type,
            target=target,
            action=f"{request.method} {request.url.path}",
            policy_outcome=outcome,
            state_transition=transition,
            code_revision=revision,
            simulated=False,
            attrs={k: v for k, v in attrs.items() if v is not None} or None,
        )

    def current_user(request: Request, event_type: str, target: str) -> User:
        auth = request.headers.get("authorization", "")
        token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        uid = sessions.get(token)
        if uid is None:
            emit(request, event_type, target, "deny", reason="unauthenticated")
            raise HTTPException(401, "login required")
        return store.users[uid]

    def order_view(order: Order) -> dict[str, Any]:
        return {
            "order_id": order.order_id,
            "owner_user_id": order.owner_user_id,
            "items": order.items,
            "total_cents": order.total_cents,
            "shipping_city": order.shipping_city,
        }

    # --- metadata -------------------------------------------------------------------------

    @app.get("/revision")
    def get_revision():
        return {"customer_id": config.CUSTOMER_ID, "code_revision": revision}

    @app.get("/__meta")
    def meta():
        # dev-B §4a.1. Flags arrive in M5.
        return {"customer_id": config.CUSTOMER_ID, "code_revision": revision, "flags": {}}

    @app.get("/products")
    def products():
        return list(store.products.values())

    # --- accounts ---------------------------------------------------------------------------

    @app.post("/login")
    def login(body: LoginBody, request: Request):
        user = store.user_by_email(body.email)
        if user is None:
            emit(request, "auth.login", "/login", "deny", reason="unknown_account")
            raise HTTPException(401, "invalid credentials")
        if not check_password(body.password, user.salt, user.password_hash):
            with lock:
                failed_logins[user.user_id] = failures = failed_logins.get(user.user_id, 0) + 1
            outcome = "flag" if failures >= FAILED_LOGIN_FLAG_THRESHOLD else "deny"
            emit(
                request,
                "auth.login",
                "/login",
                outcome,
                user_id=user.user_id,
                reason="bad_password",
                consecutive_failures=failures,
            )
            raise HTTPException(401, "invalid credentials")
        token = secrets.token_urlsafe(24)
        with lock:
            failed_logins.pop(user.user_id, None)
            sessions[token] = user.user_id
        emit(
            request,
            "auth.login",
            "/login",
            "allow",
            transition="anonymous->authenticated",
            user_id=user.user_id,
        )
        return {"token": token, "user_id": user.user_id, "name": user.name}

    @app.post("/logout")
    def logout(request: Request):
        user = current_user(request, "auth.logout", "/logout")
        token = request.headers["authorization"].removeprefix("Bearer ").strip()
        with lock:
            sessions.pop(token, None)
        emit(
            request,
            "auth.logout",
            "/logout",
            "allow",
            transition="authenticated->anonymous",
            user_id=user.user_id,
        )
        return {"ok": True}

    @app.get("/me")
    def me(request: Request):
        user = current_user(request, "account.view", "/me")
        return {"user_id": user.user_id, "email": user.email, "name": user.name}

    # --- password reset ----------------------------------------------------------------------

    @app.post("/password-reset", status_code=202)
    def password_reset_request(body: ResetRequestBody, request: Request):
        """Same response whether or not the account exists (no enumeration). The token goes to the
        fake outbox, standing in for an email."""
        user = store.user_by_email(body.email)
        if user is None:
            emit(
                request,
                "auth.password_reset_request",
                "/password-reset",
                "flag",
                reason="unknown_account",
            )
        else:
            token = secrets.token_urlsafe(24)
            with lock:
                reset_tokens[token] = user.user_id
            emit(
                request,
                "auth.password_reset_request",
                "/password-reset",
                "allow",
                user_id=user.user_id,
            )
        return {"status": "if the account exists, a reset link was sent"}

    @app.post("/password-reset/confirm")
    def password_reset_confirm(body: ResetConfirmBody, request: Request):
        with lock:
            uid = reset_tokens.pop(body.token, None)  # single use
        if uid is None:
            emit(
                request,
                "auth.password_reset_confirm",
                "/password-reset/confirm",
                "deny",
                reason="invalid_or_used_token",
            )
            raise HTTPException(400, "invalid or expired reset token")
        user = store.users[uid]
        user.password_hash = hash_password(body.new_password, user.salt)
        with lock:  # a reset ends every session for that account
            for t in [t for t, u in sessions.items() if u == uid]:
                del sessions[t]
            failed_logins.pop(uid, None)
        emit(
            request,
            "auth.password_reset_confirm",
            "/password-reset/confirm",
            "allow",
            transition="password_old->password_new",
            user_id=uid,
        )
        return {"ok": True}

    # --- cart ----------------------------------------------------------------------------------

    @app.get("/cart")
    def get_cart(request: Request):
        user = current_user(request, "cart.view", "/cart")
        return {
            "items": [{"product_id": p, "qty": q} for p, q in carts.get(user.user_id, {}).items()]
        }

    @app.post("/cart")
    def add_to_cart(body: CartAddBody, request: Request):
        user = current_user(request, "cart.add", "/cart")
        if body.product_id not in store.products:
            emit(
                request, "cart.add", "/cart", "deny", user_id=user.user_id, reason="unknown_product"
            )
            raise HTTPException(404, "unknown product")
        with lock:
            cart = carts.setdefault(user.user_id, {})
            cart[body.product_id] = cart.get(body.product_id, 0) + body.qty
        emit(
            request,
            "cart.add",
            "/cart",
            "allow",
            user_id=user.user_id,
            product_id=body.product_id,
            qty=body.qty,
        )
        return {"items": [{"product_id": p, "qty": q} for p, q in cart.items()]}

    # --- orders --------------------------------------------------------------------------------

    @app.post("/orders", status_code=201)
    def create_order(request: Request):
        user = current_user(request, "order.create", "/orders")
        with lock:
            cart = carts.pop(user.user_id, {})
            if not cart:
                empty = True
            else:
                empty = False
                oid = str(next_order[0])
                next_order[0] += 1
                items = [
                    {"product_id": p, "qty": q, "price_cents": store.products[p]["price_cents"]}
                    for p, q in cart.items()
                ]
                order = Order(
                    oid,
                    user.user_id,
                    items,
                    sum(i["qty"] * i["price_cents"] for i in items),
                    "Springfield",
                )
                store.orders[oid] = order
        if empty:
            emit(
                request,
                "order.create",
                "/orders",
                "deny",
                user_id=user.user_id,
                reason="empty_cart",
            )
            raise HTTPException(400, "cart is empty")
        emit(
            request,
            "order.create",
            "/orders",
            "allow",
            transition="cart->order",
            user_id=user.user_id,
            order_id=oid,
        )
        return order_view(order)

    @app.get("/orders")
    def list_orders(request: Request):
        user = current_user(request, "order.list", "/orders")
        mine = [order_view(o) for o in store.orders.values() if o.owner_user_id == user.user_id]
        emit(request, "order.list", "/orders", "allow", user_id=user.user_id, count=len(mine))
        return mine

    @app.get("/orders/{order_id}")
    def get_order(order_id: str, request: Request):
        user = current_user(request, "order.access", "/orders/{id}")
        order = store.orders.get(order_id)
        if order is None or order.owner_user_id != user.user_id:
            # Same 404 for "missing" and "someone else's", so order IDs can't be probed.
            reason = "not_found" if order is None else "not_owner"
            emit(
                request,
                "order.access",
                "/orders/{id}",
                "deny",
                user_id=user.user_id,
                order_id=order_id,
                reason=reason,
            )
            raise HTTPException(404, "order not found")
        emit(
            request,
            "order.access",
            "/orders/{id}",
            "allow",
            user_id=user.user_id,
            order_id=order_id,
        )
        return order_view(order)

    return app
