from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os
import smtplib
import ssl
import time
import secrets
import string
from email.message import EmailMessage
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "aims-utt-secret-key-2026")
app.permanent_session_lifetime = timedelta(minutes=5)
app.config["SESSION_REFRESH_EACH_REQUEST"] = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "aims.db")


def data_path(filename):
    """Đường dẫn file dữ liệu nằm cạnh app.py."""
    return os.path.join(BASE_DIR, filename)


def get_db():
    """Tạo kết nối SQLite an toàn với Row Factory trả về dạng Dict-like."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ==========================================
# KHỞI TẠO CƠ SỞ DỮ LIỆU SQLITE TỰ ĐỘNG
# ==========================================
def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        # Bảng người dùng
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            department TEXT DEFAULT 'Công trình',
            classroom TEXT DEFAULT '',
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT
        );
        """)

        # Bảng tài sản
        cur.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            ID_assets TEXT PRIMARY KEY,
            Auditorium TEXT DEFAULT '',
            Floor TEXT DEFAULT '',
            Room TEXT DEFAULT '',
            Type_asset TEXT NOT NULL,
            Id_type TEXT DEFAULT '',
            Ordinal_number TEXT DEFAULT '',
            Notes TEXT DEFAULT '',
            Description TEXT DEFAULT '',
            Year INTEGER DEFAULT 2024,
            Origin TEXT DEFAULT 'Việt Nam',
            Status TEXT DEFAULT 'Đang hoạt động',
            ATS INTEGER DEFAULT 100,
            is_deleted INTEGER DEFAULT 0,
            deleted_at TEXT,
            deleted_by TEXT,
            created_at TEXT
        );
        """)

        # Bảng cảnh báo
        cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            asset_id TEXT,
            expected_room TEXT,
            scanned_room TEXT,
            type_alert TEXT,
            description TEXT,
            time TEXT,
            status TEXT DEFAULT 'open'
        );
        """)

        # Bảng lịch sử quét
        cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            asset_id TEXT,
            room TEXT,
            type TEXT,
            time TEXT
        );
        """)

        # Bảng yêu cầu cấp lại mật khẩu
        cur.execute("""
        CREATE TABLE IF NOT EXISTS password_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            department TEXT,
            classroom TEXT,
            request_time TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            processed_by TEXT,
            processed_time TEXT,
            note TEXT
        );
        """)
        conn.commit()


# Gọi khởi tạo DB khi module được load
init_db()


# ==========================================
# QUẢN LÝ PHIÊN ĐĂNG NHẬP (TIMEOUT 5 PHÚT)
# ==========================================
@app.before_request
def expire_login_session():
    """
    Quy định thời gian đăng nhập:
    - Tài khoản role 'user': Hết hạn phiên sau đúng 5 phút kể từ lúc đăng nhập, bắt buộc đăng nhập lại.
    - Tài khoản 'admin' và 'manager': Không bị giới hạn 5 phút.
    """
    if "username" not in session:
        return None

    # Chỉ áp dụng timeout 5 phút cho vai trò 'user'
    if session.get("role") != "user":
        return None

    login_at = session.get("login_at")
    if not isinstance(login_at, (int, float)) or (time.time() - login_at >= 5 * 60):
        session.clear()
        if request.endpoint == "api_asset":
            return {"status": "error", "message": "Phiên đăng nhập đã hết hạn sau 5 phút."}, 401
        return redirect(url_for("login", next=request.path))

    return None


# ==========================================
# PHÂN QUYỀN (RBAC)
# ==========================================
def require_role(roles):
    def wrapper(func):
        def decorated(*args, **kwargs):
            if "username" not in session:
                return redirect("/login")

            if session.get("role") not in roles:
                return render_template("no_permission.html"), 403

            return func(*args, **kwargs)

        decorated.__name__ = func.__name__
        return decorated
    return wrapper


# ==========================================
# CÁC HÀM TIỆN ÍCH NGƯỜI DÙNG
# ==========================================
def get_user_by_username(username):
    if not username:
        return None
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
        return dict(row) if row else None


def get_user_by_email(email):
    if not email:
        return None
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE LOWER(TRIM(email)) = LOWER(?)", (email.strip(),)).fetchone()
        return dict(row) if row else None


def save_user_password(username, new_password):
    """Cập nhật mật khẩu đã băm vào SQLite."""
    hashed = generate_password_hash(new_password)
    with get_db() as conn:
        res = conn.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, username.strip()))
        conn.commit()
        return res.rowcount > 0


def generate_random_password(length=8):
    """Tạo mật khẩu ngẫu nhiên gồm cả chữ và số (ví dụ: aB3k8Px9)."""
    chars = string.ascii_letters + string.digits
    while True:
        pwd = ''.join(secrets.choice(chars) for _ in range(length))
        if any(c.isalpha() for c in pwd) and any(c.isdigit() for c in pwd):
            return pwd


def send_new_password_email(recipient, username, new_password):
    """Gửi mật khẩu ngẫu nhiên mới qua SMTP."""
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "587"))
    sender = os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USERNAME")
    smtp_user = os.environ.get("SMTP_USERNAME")
    smtp_pass = os.environ.get("SMTP_PASSWORD")

    if not host or not sender:
        raise RuntimeError("SMTP chưa được cấu hình biến môi trường SMTP_HOST / SMTP_FROM")

    message = EmailMessage()
    message["Subject"] = "Cấp lại mật khẩu tài khoản AIMS UTT"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Xin chào {username},\n\n"
        f"Hệ thống Quản lý Tài sản AIMS vừa tạo lại mật khẩu mới cho tài khoản của bạn:\n"
        f"👉 Mật khẩu mới: {new_password}\n\n"
        f"Bạn hãy dùng mật khẩu này để đăng nhập vào hệ thống. "
        f"Sau khi đăng nhập thành công, bạn có thể vào chức năng 'Đổi mật khẩu' để đổi lại theo ý muốn.\n\n"
        f"Trân trọng,\nBan quản trị hệ thống AIMS."
    )

    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=15) as smtp:
            if smtp_user and smtp_pass:
                smtp.login(smtp_user, smtp_pass)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            if smtp_user and smtp_pass:
                smtp.login(smtp_user, smtp_pass)
            smtp.send_message(message)


# ==========================================
# TẢI DANH SÁCH TÀI SẢN VÀ TÍNH ATS ĐỘNG
# ==========================================
def load_assets(include_deleted=False):
    """
    Tải tài sản từ SQLite và tính điểm ATS động:
    - ATS gốc mặc định 100
    - Khấu hao: mỗi năm sử dụng trừ 1 điểm
    - Báo hỏng chưa xử lý: trừ 5 điểm/lần
    """
    assets = {}
    with get_db() as conn:
        # Tính điểm trừ do hỏng hóc chưa xử lý
        damage_loss_by_asset = {}
        alerts = conn.execute("""
            SELECT asset_id FROM alerts 
            WHERE type_alert = 'damage' AND LOWER(TRIM(status)) NOT IN ('resolved', 'đã xử lý')
        """).fetchall()
        for a in alerts:
            aid = (a["asset_id"] or "").strip()
            if aid:
                damage_loss_by_asset[aid] = damage_loss_by_asset.get(aid, 0) + 5

        # Truy vấn danh sách tài sản
        if include_deleted:
            rows = conn.execute("SELECT * FROM assets ORDER BY ID_assets ASC").fetchall()
        else:
            rows = conn.execute("SELECT * FROM assets WHERE is_deleted = 0 ORDER BY ID_assets ASC").fetchall()

        current_year = datetime.now().year
        for r in rows:
            asset = dict(r)
            aid = asset["ID_assets"]

            try:
                original_ats = int(asset.get("ATS") or 100)
            except:
                original_ats = 100

            try:
                year = int(asset.get("Year") or current_year)
                years_used = max(0, current_year - year)
                depreciation = years_used * 1
            except:
                depreciation = 0

            damage_loss = damage_loss_by_asset.get(aid, 0)
            final_ats = max(0, original_ats - depreciation - damage_loss)
            asset["ATS_value"] = final_ats

            detail = []
            if depreciation > 0:
                detail.append(f"khấu hao: -{depreciation}")
            if damage_loss > 0:
                detail.append(f"hỏng chưa xử lý: -{damage_loss}")

            asset["ATS_display"] = f"{final_ats} ({', '.join(detail)})" if detail else str(final_ats)
            assets[aid] = asset

    return assets


def save_alert(user, asset_id, expected_room, scanned_room, alert_type, description=""):
    """Lưu cảnh báo vào SQLite."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute("""
            INSERT INTO alerts (user, asset_id, expected_room, scanned_room, type_alert, description, time, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
        """, (user, asset_id, expected_room, scanned_room, alert_type, description, now_str))
        conn.commit()


# ==========================================
# ĐĂNG NHẬP / ĐĂNG XUẤT
# ==========================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = get_user_by_username(username)
        stored_password = user.get("password", "") if user else ""

        password_is_valid = False
        if stored_password.startswith(("scrypt:", "pbkdf2:")):
            password_is_valid = check_password_hash(stored_password, password)
        else:
            # Hỗ trợ mật khẩu dạng thường chưa băm
            password_is_valid = bool(user) and stored_password == password

        if user and password_is_valid:
            if not stored_password.startswith(("scrypt:", "pbkdf2:")):
                save_user_password(username, password)

            session.clear()
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["full_name"] = user.get("full_name", "")
            session["email"] = user.get("email", "")
            session["department"] = user.get("department", "Công trình")
            session["classroom"] = user.get("classroom", "")

            # Phân quyền thời gian phiên: user hết 5 phút bắt đăng nhập lại, admin và manager thì không
            is_limited_user = (user.get("role") or "").strip().lower() == "user"
            if is_limited_user:
                session.permanent = True
                session["login_at"] = time.time()
            else:
                session.permanent = False
                session["login_at"] = None

            return redirect("/")

        return render_template("login.html", error="Sai tài khoản hoặc mật khẩu")

    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    result_type = None
    result_message = None
    message = None
    error = None
    identifier = ""

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        action = request.form.get("action", "request").strip()

        user = get_user_by_username(identifier)
        if not user:
            user = get_user_by_email(identifier)

        if user:
            username = user["username"]
            with get_db() as conn:
                # Lấy yêu cầu mới nhất của tài khoản này
                latest_req = conn.execute("""
                    SELECT * FROM password_requests 
                    WHERE username = ? 
                    ORDER BY id DESC LIMIT 1
                """, (username,)).fetchone()

                if action == "check":
                    # TRA CỨU TIẾN ĐỘ DUYỆT CỦA ADMIN
                    if not latest_req:
                        result_type = "pending"
                        result_message = f"Tài khoản <strong>{username}</strong> ({user['full_name']}) hiện chưa có yêu cầu cấp lại mật khẩu nào trong hệ thống. Hãy bấm nút <strong>'Gửi yêu cầu duyệt'</strong> bên dưới để tạo yêu cầu mới."
                    elif latest_req["status"] == "pending":
                        result_type = "pending"
                        result_message = f"Yêu cầu cấp lại mật khẩu của bạn (gửi lúc <strong>{latest_req['request_time']}</strong>) đang ở trạng thái <strong>CHỜ QUẢN TRỊ VIÊN DUYỆT</strong>.<br>Vui lòng đợi hoặc liên hệ trực tiếp Quản trị viên/Giáo vụ khoa Công trình để được phê duyệt nhanh chóng."
                    elif latest_req["status"] == "approved":
                        result_type = "success"
                        default_pwd = username if user.get("role") == "user" else "123456"
                        result_message = f"Quản trị viên (<strong>{latest_req['processed_by'] or 'Admin'}</strong>) đã <strong>PHÊ DUYỆT</strong> yêu cầu của bạn vào lúc <strong>{latest_req['processed_time']}</strong>!<br><br>👉 Mật khẩu của bạn đã được đặt lại về mặc định là: <strong style='font-size:16px;color:#047857'>{default_pwd}</strong> (chính là Mã sinh viên của bạn).<br>Bạn hãy đăng nhập ngay bằng mật khẩu này và vào phần <em>Đổi mật khẩu</em> để cập nhật mật khẩu mới."
                    elif latest_req["status"] == "rejected":
                        result_type = "error"
                        result_message = f"Yêu cầu cấp lại mật khẩu của bạn đã bị từ chối vào lúc <strong>{latest_req['processed_time']}</strong>.<br>Vui lòng liên hệ trực tiếp văn phòng khoa Công trình để được giải quyết hoặc gửi lại yêu cầu mới."
                else:
                    # GỬI YÊU CẦU MỚI TỚI ADMIN
                    if latest_req and latest_req["status"] == "pending":
                        result_type = "pending"
                        result_message = f"Yêu cầu cấp lại mật khẩu cho tài khoản <strong>{username}</strong> ({user['full_name']}) đã được gửi trước đó vào lúc <strong>{latest_req['request_time']}</strong> và hiện đang chờ phê duyệt.<br>Bạn không cần gửi lại, vui lòng liên hệ Admin/Giáo vụ khoa Công trình để được duyệt nhanh."
                    else:
                        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        conn.execute("""
                            INSERT INTO password_requests (username, full_name, email, department, classroom, request_time, status)
                            VALUES (?, ?, ?, ?, ?, ?, 'pending')
                        """, (username, user.get("full_name"), user.get("email"), user.get("department"), user.get("classroom"), now_str))
                        conn.commit()
                        result_type = "pending"
                        result_message = f"✔ Đã gửi yêu cầu cấp lại mật khẩu cho tài khoản <strong>{username}</strong> ({user['full_name']}) thành công!<br>Yêu cầu đang chờ Quản trị viên (Admin/Manager) duyệt.<br>Bạn có thể bấm nút <strong>'Tra cứu kết quả duyệt'</strong> bất kỳ lúc nào để xem tiến độ phê duyệt."
        else:
            result_type = "error"
            result_message = "⚠️ Không tìm thấy tài khoản với Mã sinh viên hoặc Email này. Vui lòng kiểm tra lại chính xác."

    return render_template(
        "forgot_password.html",
        result_type=result_type,
        result_message=result_message,
        message=message,
        error=error,
        identifier=identifier
    )


# ==========================================
# QUẢN LÝ YÊU CẦU MẬT KHẨU (ADMIN, MANAGER)
# ==========================================
@app.route("/password-requests")
@require_role(["admin", "manager"])
def password_requests():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM password_requests 
            ORDER BY CASE WHEN status = 'pending' THEN 0 ELSE 1 END, id DESC
        """).fetchall()
        reqs = [dict(r) for r in rows]
    return render_template("password_requests.html", requests=reqs)


@app.route("/password-requests/<int:req_id>/approve", methods=["POST"])
@require_role(["admin", "manager"])
def approve_password_request(req_id):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        req = conn.execute("SELECT * FROM password_requests WHERE id = ?", (req_id,)).fetchone()
        if req and req["status"] == "pending":
            username = req["username"]
            user = get_user_by_username(username)
            # Mật khẩu reset về mặc định: đối với user là chính username (MSSV), với role khác là 123456
            default_pwd = username if (user and user.get("role") == "user") else "123456"
            save_user_password(username, default_pwd)

            conn.execute("""
                UPDATE password_requests 
                SET status = 'approved', processed_by = ?, processed_time = ?, note = ?
                WHERE id = ?
            """, (session.get("username"), now_str, f"Đã đặt lại về: {default_pwd}", req_id))
            conn.commit()

    return redirect(url_for("password_requests"))


@app.route("/password-requests/<int:req_id>/reject", methods=["POST"])
@require_role(["admin", "manager"])
def reject_password_request(req_id):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute("""
            UPDATE password_requests 
            SET status = 'rejected', processed_by = ?, processed_time = ?
            WHERE id = ?
        """, (session.get("username"), now_str, req_id))
        conn.commit()

    return redirect(url_for("password_requests"))


@app.route("/change-password", methods=["GET", "POST"])
@require_role(["admin", "manager", "user"])
def change_password():
    username = session.get("username")
    user = get_user_by_username(username)
    error = None
    success = None

    if request.method == "POST":
        old_password = request.form.get("old_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        stored_password = user.get("password", "") if user else ""
        if stored_password.startswith(("scrypt:", "pbkdf2:")):
            old_valid = check_password_hash(stored_password, old_password)
        else:
            old_valid = (stored_password == old_password)

        if not old_valid:
            error = "Mật khẩu hiện tại không chính xác."
        elif len(new_password) < 6:
            error = "Mật khẩu mới phải có ít nhất 6 ký tự."
        elif new_password != confirm_password:
            error = "Mật khẩu xác nhận không trùng khớp với mật khẩu mới."
        else:
            if save_user_password(username, new_password):
                success = "Đổi mật khẩu thành công! Hãy ghi nhớ mật khẩu mới của bạn."
                user = get_user_by_username(username)
            else:
                error = "Không thể cập nhật mật khẩu vào cơ sở dữ liệu. Vui lòng thử lại."

    return render_template("change_password.html", user=user, error=error, success=success)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ==========================================
# TRANG CHỦ & QUÉT QR (GIỮ NGUYÊN)
# ==========================================
@app.route("/")
@require_role(["admin", "manager", "user"])
def home():
    current_user = get_user_by_username(session.get("username"))
    return render_template("index.html", current_user=current_user)


@app.route("/profile")
@require_role(["admin", "manager", "user"])
def profile():
    user = get_user_by_username(session.get("username"))
    return render_template("profile.html", user=user)


@app.route("/scan")
@require_role(["admin", "manager", "user"])
def scan_qr():
    role = session.get("role", "user")
    current_user = get_user_by_username(session.get("username"))
    return render_template("scan.html", user_role=role, current_user=current_user)


@app.route("/api/asset/<asset_id>", strict_slashes=False)
def api_asset(asset_id):
    """API tra cứu thông tin tài sản cho Camera quét mã QR và kiểm tra phòng."""
    clean_id = asset_id.strip().rstrip("/")
    if "?" in clean_id:
        clean_id = clean_id.split("?")[0].strip()
    if "#" in clean_id:
        clean_id = clean_id.split("#")[0].strip()

    with get_db() as conn:
        row = conn.execute("""
            SELECT * FROM assets 
            WHERE UPPER(TRIM(ID_assets)) = UPPER(TRIM(?))
        """, (clean_id,)).fetchone()

        if not row:
            row = conn.execute("""
                SELECT * FROM assets 
                WHERE REPLACE(UPPER(TRIM(ID_assets)), '-', '') = REPLACE(UPPER(TRIM(?)), '-', '')
            """, (clean_id,)).fetchone()

        if not row:
            return {"status": "error", "message": f"Không tìm thấy tài sản: {clean_id}"}

        asset = dict(row)

        # Tính điểm ATS động
        current_year = datetime.now().year
        year = asset.get("Year") or 2024
        try:
            year = int(year)
        except Exception:
            year = 2024
        depreciation = max(0, current_year - year)

        damage_count = conn.execute("""
            SELECT COUNT(*) FROM alerts 
            WHERE asset_id = ? AND type_alert = 'damage' 
            AND LOWER(TRIM(status)) NOT IN ('resolved', 'da xu ly', 'đã xử lý')
        """, (asset["ID_assets"],)).fetchone()[0]

        ats = max(0, 100 - depreciation - (damage_count * 5))
        asset["ATS"] = ats

        scanned_room = request.args.get("scan_room", "").strip()
        scanned_building = request.args.get("scan_building", "").strip()
        real_room = (asset.get("Room") or "").strip()
        real_building = (asset.get("Auditorium") or "").strip()
        username = session.get("username", "user")

        is_wrong_room = False
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if scanned_room:
            room_mismatch = (scanned_room.lower() != real_room.lower())
            bld_mismatch = bool(scanned_building and real_building and (scanned_building.lower() != real_building.lower()))
            
            if room_mismatch or bld_mismatch:
                is_wrong_room = True
                desc = f"Quét tại Tòa {scanned_building or '—'} - Phòng {scanned_room}, nhưng vị trí đúng theo hệ thống là Tòa {real_building or '—'} - Phòng {real_room or '—'}."
                save_alert(username, asset["ID_assets"], real_room, scanned_room, "wrong_room", desc)

        try:
            conn.execute("""
                INSERT INTO scan_history (user, asset_id, room, type, time)
                VALUES (?, ?, ?, ?, ?)
            """, (
                username,
                asset["ID_assets"],
                scanned_room if scanned_room else real_room,
                asset.get("Type_asset", "Thiết bị"),
                now_str
            ))
            conn.commit()
        except Exception as e:
            print(f"Lỗi ghi nhận scan_history: {e}")

    return {
        "status": "ok",
        "data": asset,
        "is_wrong_room": is_wrong_room,
        "scanned_room": scanned_room,
        "real_room": real_room,
        "scanned_building": scanned_building,
        "real_building": real_building
    }


# ==========================================
# DANH SÁCH TÀI SẢN (ADMIN, MANAGER)
# ==========================================
@app.route("/assets")
@require_role(["admin", "manager"])
def assets():
    assets = load_assets(include_deleted=False)

    room = request.args.get("room")
    asset_type = request.args.get("type")

    result = {}
    for aid, asset in assets.items():
        if room and room.lower() not in (asset.get("Room") or "").lower():
            continue
        if asset_type and asset_type.lower() not in (asset.get("Type_asset") or "").lower():
            continue
        result[aid] = asset

    return render_template("assets.html", assets=result)


# ==========================================
# THÊM TÀI SẢN (CHỈ ADMIN, MANAGER)
# ==========================================
@app.route("/asset/add", methods=["GET", "POST"])
@require_role(["admin", "manager"])
def add_asset():
    error = None
    success = None
    form_data = {
        "ID_assets": "",
        "Auditorium": "",
        "Floor": "",
        "Room": "",
        "Type_asset": "",
        "Id_type": "",
        "Ordinal_number": "",
        "Notes": "",
        "Description": "",
        "Year": str(datetime.now().year),
        "Origin": "Việt Nam",
        "Status": "Đang hoạt động",
        "ATS": "100"
    }

    if request.method == "POST":
        for key in form_data.keys():
            form_data[key] = request.form.get(key, "").strip()

        asset_id = form_data["ID_assets"]
        if not asset_id:
            error = "Vui lòng nhập Mã tài sản (ID)."
        elif not form_data["Type_asset"]:
            error = "Vui lòng nhập Loại / Tên tài sản."
        else:
            with get_db() as conn:
                existing = conn.execute("SELECT 1 FROM assets WHERE LOWER(ID_assets) = LOWER(?)", (asset_id,)).fetchone()
                if existing:
                    error = f"Mã tài sản '{asset_id}' đã tồn tại trong CSDL SQLite. Vui lòng chọn mã khác."
                else:
                    try:
                        ats_val = int(form_data.get("ATS") or 100)
                    except:
                        ats_val = 100
                    try:
                        year_val = int(form_data.get("Year") or datetime.now().year)
                    except:
                        year_val = datetime.now().year

                    conn.execute("""
                        INSERT INTO assets (
                            ID_assets, Auditorium, Floor, Room, Type_asset,
                            Id_type, Ordinal_number, Notes, Description,
                            Year, Origin, Status, ATS, is_deleted, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                    """, (
                        asset_id,
                        form_data["Auditorium"],
                        form_data["Floor"],
                        form_data["Room"],
                        form_data["Type_asset"],
                        form_data["Id_type"],
                        form_data["Ordinal_number"],
                        form_data["Notes"],
                        form_data["Description"],
                        year_val,
                        form_data["Origin"],
                        form_data["Status"],
                        ats_val,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    ))
                    conn.commit()
                    return redirect(url_for("asset_detail", asset_id=asset_id))

    return render_template("asset_add.html", form_data=form_data, error=error, success=success)


# ==========================================
# SỬA TÀI SẢN (CHỈ ADMIN, MANAGER)
# ==========================================
@app.route("/asset/<asset_id>/edit", methods=["GET", "POST"])
@app.route("/asset/edit/<asset_id>", methods=["GET", "POST"])
@require_role(["admin", "manager"])
def edit_asset(asset_id):
    asset_id = asset_id.strip()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM assets WHERE ID_assets = ?", (asset_id,)).fetchone()
        if not row:
            return "Không tìm thấy tài sản để chỉnh sửa trong CSDL", 404
        asset = dict(row)

    error = None
    success = None

    if request.method == "POST":
        updated = dict(asset)
        fields = [
            "Auditorium", "Floor", "Room", "Type_asset", "Id_type",
            "Ordinal_number", "Notes", "Description", "Year", "Origin", "Status", "ATS"
        ]
        for f in fields:
            updated[f] = request.form.get(f, asset.get(f, "")).strip()

        if not updated.get("Type_asset"):
            error = "Loại / Tên tài sản không được để trống."
            asset = updated
        else:
            try:
                ats_val = int(updated.get("ATS") or 100)
            except:
                ats_val = 100
            try:
                year_val = int(updated.get("Year") or datetime.now().year)
            except:
                year_val = datetime.now().year

            with get_db() as conn:
                conn.execute("""
                    UPDATE assets SET 
                        Auditorium = ?, Floor = ?, Room = ?, Type_asset = ?,
                        Id_type = ?, Ordinal_number = ?, Notes = ?, Description = ?,
                        Year = ?, Origin = ?, Status = ?, ATS = ?
                    WHERE ID_assets = ?
                """, (
                    updated["Auditorium"], updated["Floor"], updated["Room"], updated["Type_asset"],
                    updated["Id_type"], updated["Ordinal_number"], updated["Notes"], updated["Description"],
                    year_val, updated["Origin"], updated["Status"], ats_val, asset_id
                ))
                conn.commit()

            return redirect(url_for("asset_detail", asset_id=asset_id))

    return render_template("asset_edit.html", asset=asset, error=error, success=success)


# ==========================================
# XÓA TÀI SẢN & TÀI SẢN THANH LÝ (ADMIN, MANAGER)
# ==========================================
@app.route("/asset/<asset_id>/delete", methods=["POST"])
@require_role(["admin", "manager"])
def delete_asset(asset_id):
    """
    Xóa tài sản khỏi danh mục hoạt động, chuyển vào danh mục Tài sản thanh lý.
    Trạng thái ghi nhận: 'đã xóa khỏi danh sách tài sản'
    """
    asset_id = asset_id.strip()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute("""
            UPDATE assets 
            SET is_deleted = 1, 
                Status = 'đã xóa khỏi danh sách tài sản', 
                deleted_at = ?, 
                deleted_by = ?
            WHERE ID_assets = ?
        """, (now_str, session.get("username"), asset_id))
        conn.commit()

    return redirect(url_for("liquidated_assets"))


@app.route("/liquidated-assets")
@app.route("/thanh-ly")
@require_role(["admin", "manager"])
def liquidated_assets():
    """Trang hiển thị toàn bộ Tài sản thanh lý."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM assets 
            WHERE is_deleted = 1 
            ORDER BY deleted_at DESC, ID_assets ASC
        """).fetchall()
        liquidated = [dict(r) for r in rows]
    return render_template("liquidated_assets.html", assets=liquidated)


@app.route("/asset/<asset_id>/restore", methods=["POST"])
@require_role(["admin", "manager"])
def restore_asset(asset_id):
    """Khôi phục tài sản thanh lý về lại danh mục hoạt động."""
    asset_id = asset_id.strip()
    with get_db() as conn:
        conn.execute("""
            UPDATE assets 
            SET is_deleted = 0, 
                Status = 'Đang hoạt động',
                deleted_at = NULL, 
                deleted_by = NULL
            WHERE ID_assets = ?
        """, (asset_id,))
        conn.commit()
    return redirect(url_for("assets"))


# ==========================================
# CHI TIẾT TÀI SẢN + GHI LỊCH SỬ QUÉT
# ==========================================
@app.route("/asset/<asset_id>", strict_slashes=False)
@require_role(["admin", "manager", "user"])
def asset_detail(asset_id):
    assets = load_assets(include_deleted=True)
    asset = assets.get(asset_id.strip())

    if not asset:
        return "Không tìm thấy tài sản", 404

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Lưu lịch sử quét vào SQLite
    with get_db() as conn:
        conn.execute("""
            INSERT INTO scan_history (user, asset_id, room, type, time)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session["username"],
            asset_id,
            asset.get("Room"),
            asset.get("Type_asset"),
            now_str
        ))
        conn.commit()

    # Kiểm tra sai phòng khi quét QR
    scanned_room = request.args.get("scan_room")
    real_room = (asset.get("Room") or "").strip()

    if scanned_room and scanned_room != real_room:
        save_alert(session["username"], asset_id, real_room, scanned_room, "wrong_room")

    return render_template("asset.html", asset=asset)


# ==========================================
# BÁO HỎNG TÀI SẢN
# ==========================================
@app.route("/report/<asset_id>", methods=["GET", "POST"])
@require_role(["admin", "manager", "user"])
def report(asset_id):
    assets = load_assets(include_deleted=True)
    asset = assets.get(asset_id.strip())

    if not asset:
        return redirect("/scan")

    if request.method == "POST":
        description = request.form.get("description", "").strip()
        save_alert(
            session["username"],
            asset_id,
            asset.get("Room"),
            asset.get("Room"),
            "damage",
            description
        )
        return render_template("report_success.html", asset=asset)

    return render_template("report_form.html", asset=asset)


# ==========================================
# LỊCH SỬ KIỂM KÊ (ADMIN, MANAGER)
# ==========================================
@app.route("/history")
@require_role(["admin", "manager"])
def history():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM scan_history ORDER BY id DESC").fetchall()
        history_list = [dict(r) for r in rows]
    return render_template("history.html", history=history_list)


# ==========================================
# TÀI SẢN BẤT THƯỜNG (ADMIN)
# ==========================================
@app.route("/abnormal")
@require_role(["admin"])
def abnormal():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM alerts 
            WHERE LOWER(TRIM(status)) NOT IN ('resolved', 'đã xử lý')
            ORDER BY id DESC
        """).fetchall()
        abnormal_list = [dict(r) for r in rows]
    return render_template("abnormal.html", abnormal_assets=abnormal_list)


@app.route("/delete_abnormal", methods=["POST"])
@require_role(["admin"])
def delete_abnormal():
    asset_id = request.form.get("asset_id")
    alert_time = request.form.get("time")

    with get_db() as conn:
        if alert_time:
            conn.execute("UPDATE alerts SET status = 'resolved' WHERE asset_id = ? AND time = ?", (asset_id, alert_time))
        else:
            conn.execute("UPDATE alerts SET status = 'resolved' WHERE asset_id = ?", (asset_id,))
        conn.commit()

    return redirect("/abnormal")


# ==========================================
# RUN SERVER
# ==========================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
