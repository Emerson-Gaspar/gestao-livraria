import csv
import hmac
import io
import os
import secrets
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("BOOKSTORE_DB", os.path.join(BASE, "bookstore.db"))
SENHA_INICIAL = "livraria123"
MOEDA = "Kz"

app = Flask(__name__)


def _segredo():
    caminho = os.path.join(BASE, "secret.key")
    if not os.path.exists(caminho):
        with open(caminho, "w") as f:
            f.write(secrets.token_hex(32))
    with open(caminho) as f:
        return f.read().strip()


app.secret_key = _segredo()
app.permanent_session_lifetime = timedelta(hours=8)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

PT = {
    "Active": "Ativo", "Inactive": "Inativo", "Discontinued": "Descontinuado",
    "Draft": "Rascunho", "Completed": "Concluída", "Received": "Recebida",
    "Cancelled": "Cancelada", "Refunded": "Reembolsada",
    "In-store": "Na loja", "Online": "Online", "Phone": "Telefone",
    "Admin": "Administrador", "Manager": "Gestor", "Attendant": "Atendente",
    "Fiction": "Ficção", "Non-fiction": "Não ficção", "Children": "Infantil",
    "Education": "Educação", "Comics": "Banda desenhada", "Business": "Negócios", "Other": "Outro",
}
CATEGORIAS = ["Fiction", "Non-fiction", "Children", "Education", "Comics", "Business", "Other"]
ESTADOS_VENDA = ["Draft", "Completed", "Cancelled", "Refunded"]
ESTADOS_COMPRA = ["Draft", "Received", "Cancelled"]
CANAIS = ["In-store", "Online", "Phone"]
PERFIS = ["Admin", "Manager", "Attendant"]

# Quem pode fazer o quê. Todos os perfis veem painel, livros, clientes e vendas,
# criam vendas e criam/editam clientes.
PERMS = {
    "compras": {"Admin", "Manager"},
    "editar_livros": {"Admin", "Manager"},
    "apagar": {"Admin", "Manager"},
    "estado": {"Admin", "Manager"},
    "ver_custos": {"Admin", "Manager"},
    "utilizadores": {"Admin"},
}


# ------------------------------------------------------------------ base de dados
def migrar():
    con = sqlite3.connect(DB_PATH)
    cols = {r[1] for r in con.execute("PRAGMA table_info(users)")}
    if "password_hash" not in cols:
        con.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    if "must_change" not in cols:
        con.execute("ALTER TABLE users ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0")
    for (uid,) in con.execute("SELECT id FROM users WHERE password_hash IS NULL OR password_hash=''").fetchall():
        con.execute("UPDATE users SET password_hash=?, must_change=1 WHERE id=?",
                    (generate_password_hash(SENHA_INICIAL), uid))
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users(lower(email))")
    con.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, quando TEXT, user_id INTEGER, user_name TEXT,
        acao TEXT, detalhe TEXT)""")
    # Stock = compras RECEBIDAS - vendas CONCLUÍDAS (rascunhos, canceladas e reembolsadas não contam)
    con.executescript("""
    DROP VIEW IF EXISTS books_v;
    CREATE VIEW books_v AS
      SELECT b.*,
        COALESCE((SELECT SUM(pi.quantity) FROM purchase_items pi
                  JOIN purchases p ON p.purchase_number = pi.purchase_number
                  WHERE pi.book_id = b.id AND p.status = 'Received'), 0) AS total_purchased,
        COALESCE((SELECT SUM(si.quantity) FROM sales_items si
                  JOIN sales s ON s.sale_number = si.sale_number
                  WHERE si.book_id = b.id AND s.status = 'Completed'), 0) AS total_sold,
        COALESCE((SELECT SUM(pi.quantity) FROM purchase_items pi
                  JOIN purchases p ON p.purchase_number = pi.purchase_number
                  WHERE pi.book_id = b.id AND p.status = 'Received'), 0)
        - COALESCE((SELECT SUM(si.quantity) FROM sales_items si
                  JOIN sales s ON s.sale_number = si.sale_number
                  WHERE si.book_id = b.id AND s.status = 'Completed'), 0) AS stock_on_hand
      FROM books b;
    DROP VIEW IF EXISTS customers_v;
    CREATE VIEW customers_v AS
      SELECT c.*,
        (SELECT COUNT(*) FROM sales WHERE customer_id = c.id AND status = 'Completed') AS total_orders,
        ROUND(COALESCE((SELECT SUM(si.quantity * si.unit_price - si.discount)
                        FROM sales s JOIN sales_items si ON si.sale_number = s.sale_number
                        WHERE s.customer_id = c.id AND s.status = 'Completed'), 0), 2) AS lifetime_value
      FROM customers c;
    """)
    con.commit()
    con.close()


migrar()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def rows(sql, args=()):
    return db().execute(sql, args).fetchall()


def row(sql, args=()):
    return db().execute(sql, args).fetchone()


# ------------------------------------------------------------------ filtros e helpers
@app.template_filter("pt")
def pt(v):
    return PT.get(v, v if v is not None else "")


@app.template_filter("money")
def money(v):
    s = f"{float(v or 0):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"{s} {MOEDA}"


@app.template_filter("data")
def data(v):
    if not v:
        return "—"
    try:
        if "T" in v:
            return datetime.strptime(v[:16], "%Y-%m-%dT%H:%M").strftime("%d/%m/%Y %H:%M")
        return datetime.strptime(v[:10], "%Y-%m-%d").strftime("%d/%m/%Y")
    except ValueError:
        return v


def num(v, cast=float, default=0):
    try:
        return cast(str(v).replace(",", "."))
    except (TypeError, ValueError):
        return default


def pode(acao):
    u = g.get("user")
    return bool(u and u["role"] in PERMS.get(acao, set()))


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals.update(
    pode=pode, MOEDA=MOEDA,
    csrf_field=lambda: Markup(f'<input type="hidden" name="_csrf" value="{csrf_token()}">'),
)


@app.context_processor
def ctx():
    return {"user": g.get("user")}


def registar(acao, detalhe="", u=None):
    """Regista uma linha no histórico de atividade (o commit fica a cargo de quem chama)."""
    u = u or g.get("user")
    db().execute("""INSERT INTO audit_log (quando,user_id,user_name,acao,detalhe)
        VALUES (strftime('%Y-%m-%dT%H:%M:%S','now','localtime'),?,?,?,?)""",
                 (u["id"] if u else None, u["name"] if u else "—", acao, detalhe))


def faltas_de_stock(necessario):
    """necessario: {book_id: quantidade a retirar do stock}. Devolve lista de problemas."""
    erros = []
    for bid, qtd in necessario.items():
        r = row("SELECT title, stock_on_hand s FROM books_v WHERE id=?", (bid,))
        if r and qtd > r["s"]:
            erros.append(f"«{r['title']}»: disponível {r['s']}, pedido {qtd}")
    return erros


def por_livro(linhas):
    """Soma quantidades por livro. Aceita dicts (qtd) ou linhas SQL (quantity)."""
    tot = {}
    for l in linhas:
        bid = l["book_id"]
        if bid:
            tot[bid] = tot.get(bid, 0) + (l["qtd"] if "qtd" in l.keys() else l["quantity"])
    return tot


FALHAS = {}
MAX_FALHAS, JANELA = 5, 300  # 5 tentativas falhadas => bloqueio de 5 minutos


def bloqueado(email):
    k, agora = (request.remote_addr, email), time.time()
    FALHAS[k] = [t for t in FALHAS.get(k, []) if agora - t < JANELA]
    return len(FALHAS[k]) >= MAX_FALHAS


def csv_resposta(nome, cabecalho, linhas):
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(cabecalho)
    w.writerows(linhas)
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{nome}_{datetime.now():%Y-%m-%d}.csv"'})


def permissao(acao):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if not pode(acao):
                abort(403)
            return f(*a, **k)
        return w
    return deco


@app.before_request
def antes():
    g.user = None
    if session.get("uid"):
        g.user = row("SELECT * FROM users WHERE id=?", (session["uid"],))
        if g.user is None:
            session.clear()
    if request.method == "POST":
        esperado = session.get("csrf", "")
        recebido = request.form.get("_csrf", "")
        if not esperado or not hmac.compare_digest(esperado.encode(), recebido.encode()):
            abort(400)
    ep = request.endpoint
    if ep in (None, "static", "login"):
        return
    if not g.user:
        return redirect(url_for("login", next=request.path))
    if g.user["must_change"] and ep not in ("conta_senha", "logout"):
        return redirect(url_for("conta_senha"))


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def erro(e):
    msgs = {400: "Pedido inválido ou sessão expirada. Volte atrás e tente de novo.",
            403: "Não tem permissão para esta ação.", 404: "Página não encontrada."}
    return render_template("erro.html", codigo=e.code, msg=msgs.get(e.code, "Erro.")), e.code


# ------------------------------------------------------------------ autenticação
@app.route("/entrar", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("painel"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if bloqueado(email):
            flash("Demasiadas tentativas falhadas. Aguarde 5 minutos e tente de novo.", "erro")
            return render_template("login.html")
        u = row("SELECT * FROM users WHERE lower(email)=?", (email,))
        if u and u["password_hash"] and check_password_hash(u["password_hash"], request.form.get("password", "")):
            FALHAS.pop((request.remote_addr, email), None)
            session.clear()
            session.permanent = True
            session["uid"] = u["id"]
            session["csrf"] = secrets.token_hex(16)
            registar("Início de sessão", u=u)
            db().commit()
            nxt = request.args.get("next", "")
            if not nxt.startswith("/") or nxt.startswith("//"):
                nxt = url_for("painel")
            return redirect(nxt)
        FALHAS.setdefault((request.remote_addr, email), []).append(time.time())
        registar("Tentativa de login falhada", email, u={"id": None, "name": "—"})
        db().commit()
        flash("E-mail ou palavra-passe incorretos.", "erro")
    return render_template("login.html")


@app.post("/sair")
def logout():
    registar("Fim de sessão")
    db().commit()
    session.clear()
    return redirect(url_for("login"))


@app.route("/conta/senha", methods=["GET", "POST"])
def conta_senha():
    if request.method == "POST":
        atual, nova, conf = (request.form.get(k, "") for k in ("atual", "nova", "conf"))
        if not check_password_hash(g.user["password_hash"], atual):
            flash("A palavra-passe atual está incorreta.", "erro")
        elif len(nova) < 6:
            flash("A nova palavra-passe deve ter pelo menos 6 caracteres.", "erro")
        elif nova == SENHA_INICIAL:
            flash("Escolha uma palavra-passe diferente da inicial.", "erro")
        elif nova != conf:
            flash("A confirmação não coincide com a nova palavra-passe.", "erro")
        else:
            db().execute("UPDATE users SET password_hash=?, must_change=0 WHERE id=?",
                         (generate_password_hash(nova), g.user["id"]))
            registar("Palavra-passe alterada")
            db().commit()
            flash("Palavra-passe alterada.", "ok")
            return redirect(url_for("painel"))
    return render_template("conta_senha.html")


# ------------------------------------------------------------------ painel
@app.route("/")
def painel():
    stats = {
        "livros": row("SELECT COUNT(*) c FROM books WHERE status='Active'")["c"],
        "clientes": row("SELECT COUNT(*) c FROM customers WHERE status='Active'")["c"],
        "receita": row("SELECT COALESCE(SUM(sale_total),0) c FROM sales_v WHERE status='Completed'")["c"],
        "custo": row("SELECT COALESCE(SUM(total_cost),0) c FROM purchases_v WHERE status='Received'")["c"],
    }
    baixo = rows("SELECT * FROM books_v WHERE status='Active' AND stock_on_hand<=reorder_level ORDER BY stock_on_hand")
    recentes = rows("""SELECT s.*, c.full_name FROM sales_v s
                       LEFT JOIN customers c ON c.id=s.customer_id ORDER BY s.sale_date DESC LIMIT 5""")
    canais = rows("""SELECT channel, COUNT(*) n, SUM(sale_total) total FROM sales_v
                     WHERE status='Completed' GROUP BY channel ORDER BY total DESC""")
    stats["valor_stock"] = row("SELECT COALESCE(SUM(stock_on_hand*cost_price),0) v FROM books_v WHERE stock_on_hand>0")["v"]
    top = rows("""SELECT b.id, b.title, SUM(si.quantity) q FROM sales_items si
                   JOIN sales s ON s.sale_number=si.sale_number JOIN books b ON b.id=si.book_id
                   WHERE s.status='Completed' GROUP BY b.id ORDER BY q DESC, b.title LIMIT 5""")
    return render_template("painel.html", stats=stats, baixo=baixo, recentes=recentes, canais=canais, top=top)


# ------------------------------------------------------------------ livros
def ler_livro(f):
    return {
        "title": f.get("title", "").strip(), "isbn": f.get("isbn", "").strip(),
        "author": f.get("author", "").strip(), "publisher": f.get("publisher", "").strip(),
        "category": f.get("category") if f.get("category") in CATEGORIAS else "Other",
        "unit_price": num(f.get("unit_price")), "cost_price": num(f.get("cost_price")),
        "reorder_level": num(f.get("reorder_level"), int),
        "status": "Discontinued" if f.get("status") == "Discontinued" else "Active",
    }


@app.route("/livros")
def livros():
    q = request.args.get("q", "").strip()
    like = f"%{q}%"
    lista = rows("""SELECT * FROM books_v WHERE title LIKE ? OR author LIKE ? OR isbn LIKE ?
                    ORDER BY title""", (like, like, like))
    return render_template("livros.html", lista=lista, q=q)


@app.route("/livros/novo", methods=["GET", "POST"])
@app.route("/livros/<int:id>/editar", methods=["GET", "POST"])
@permissao("editar_livros")
def livro_form(id=None):
    livro_ = row("SELECT * FROM books WHERE id=?", (id,)) if id else None
    if id and not livro_:
        abort(404)
    if request.method == "POST":
        d = ler_livro(request.form)
        if not d["title"]:
            flash("O título é obrigatório.", "erro")
            return render_template("livro_form.html", f=d, id=id, categorias=CATEGORIAS)
        if d["isbn"] and row("SELECT 1 FROM books WHERE isbn=? AND id IS NOT ?", (d["isbn"], id)):
            flash("Já existe um livro com esse ISBN.", "erro")
            return render_template("livro_form.html", f=d, id=id, categorias=CATEGORIAS)
        if id:
            db().execute("""UPDATE books SET title=:title,isbn=:isbn,author=:author,publisher=:publisher,
                category=:category,unit_price=:unit_price,cost_price=:cost_price,
                reorder_level=:reorder_level,status=:status WHERE id=:id""", {**d, "id": id})
            registar("Livro editado", d["title"])
            flash("Livro atualizado.", "ok")
        else:
            cur = db().execute("""INSERT INTO books (title,isbn,author,publisher,category,unit_price,
                cost_price,reorder_level,status,created_at) VALUES
                (:title,:isbn,:author,:publisher,:category,:unit_price,:cost_price,:reorder_level,:status,
                 strftime('%Y-%m-%dT%H:%M:%S','now'))""", d)
            id = cur.lastrowid
            registar("Livro criado", d["title"])
            flash("Livro criado.", "ok")
        db().commit()
        return redirect(url_for("livro", id=id))
    f = dict(livro_) if livro_ else {"status": "Active", "category": "Fiction", "reorder_level": 5}
    return render_template("livro_form.html", f=f, id=id, categorias=CATEGORIAS)


@app.route("/livros/<int:id>")
def livro(id):
    l = row("SELECT * FROM books_v WHERE id=?", (id,))
    if not l:
        abort(404)
    compras_ = []
    if pode("ver_custos"):
        compras_ = rows("""SELECT pi.*, p.purchase_date, p.status, p.supplier_name FROM purchase_items_v pi
                           JOIN purchases p ON p.purchase_number=pi.purchase_number WHERE pi.book_id=?""", (id,))
    vendas_ = rows("""SELECT si.*, s.sale_date, s.status FROM sales_items_v si
                      JOIN sales s ON s.sale_number=si.sale_number WHERE si.book_id=?""", (id,))
    return render_template("livro.html", l=l, compras=compras_, vendas=vendas_)


@app.post("/livros/<int:id>/apagar")
@permissao("apagar")
def livro_apagar(id):
    if not row("SELECT 1 FROM books WHERE id=?", (id,)):
        abort(404)
    mov = row("""SELECT (SELECT COUNT(*) FROM sales_items WHERE book_id=?)
                      + (SELECT COUNT(*) FROM purchase_items WHERE book_id=?) n""", (id, id))["n"]
    if mov:
        flash("Este livro tem compras ou vendas associadas e não pode ser apagado. "
              "Marque-o como Descontinuado.", "erro")
        return redirect(url_for("livro", id=id))
    titulo = row("SELECT title FROM books WHERE id=?", (id,))["title"]
    db().execute("DELETE FROM books WHERE id=?", (id,))
    registar("Livro apagado", titulo)
    db().commit()
    flash("Livro apagado.", "ok")
    return redirect(url_for("livros"))


# ------------------------------------------------------------------ clientes
def ler_cliente(f):
    return {
        "full_name": f.get("full_name", "").strip(), "email": f.get("email", "").strip(),
        "phone": f.get("phone", "").strip(), "document_id": f.get("document_id", "").strip(),
        "notes": f.get("notes", "").strip(),
        "status": "Inactive" if f.get("status") == "Inactive" else "Active",
    }


@app.route("/clientes")
def clientes():
    q = request.args.get("q", "").strip()
    like = f"%{q}%"
    lista = rows("""SELECT * FROM customers_v WHERE full_name LIKE ? OR email LIKE ? OR document_id LIKE ?
                    ORDER BY full_name""", (like, like, like))
    return render_template("clientes.html", lista=lista, q=q)


@app.route("/clientes/novo", methods=["GET", "POST"])
@app.route("/clientes/<int:id>/editar", methods=["GET", "POST"])
def cliente_form(id=None):
    c = row("SELECT * FROM customers WHERE id=?", (id,)) if id else None
    if id and not c:
        abort(404)
    if request.method == "POST":
        d = ler_cliente(request.form)
        if not d["full_name"]:
            flash("O nome é obrigatório.", "erro")
            return render_template("cliente_form.html", f=d, id=id)
        if id:
            db().execute("""UPDATE customers SET full_name=:full_name,email=:email,phone=:phone,
                document_id=:document_id,notes=:notes,status=:status WHERE id=:id""", {**d, "id": id})
            registar("Cliente editado", d["full_name"])
            flash("Cliente atualizado.", "ok")
        else:
            cur = db().execute("""INSERT INTO customers (full_name,email,phone,document_id,notes,status,created_at)
                VALUES (:full_name,:email,:phone,:document_id,:notes,:status,
                        strftime('%Y-%m-%dT%H:%M:%S','now'))""", d)
            id = cur.lastrowid
            registar("Cliente criado", d["full_name"])
            flash("Cliente criado.", "ok")
        db().commit()
        return redirect(url_for("cliente", id=id))
    return render_template("cliente_form.html", f=dict(c) if c else {"status": "Active"}, id=id)


@app.route("/clientes/<int:id>")
def cliente(id):
    c = row("SELECT * FROM customers_v WHERE id=?", (id,))
    if not c:
        abort(404)
    vendas_ = rows("SELECT * FROM sales_v WHERE customer_id=? ORDER BY sale_date DESC", (id,))
    return render_template("cliente.html", c=c, vendas=vendas_)


@app.post("/clientes/<int:id>/apagar")
@permissao("apagar")
def cliente_apagar(id):
    if not row("SELECT 1 FROM customers WHERE id=?", (id,)):
        abort(404)
    if row("SELECT COUNT(*) n FROM sales WHERE customer_id=?", (id,))["n"]:
        flash("Este cliente tem vendas associadas e não pode ser apagado. Marque-o como Inativo.", "erro")
        return redirect(url_for("cliente", id=id))
    nome = row("SELECT full_name FROM customers WHERE id=?", (id,))["full_name"]
    db().execute("DELETE FROM customers WHERE id=?", (id,))
    registar("Cliente apagado", nome)
    db().commit()
    flash("Cliente apagado.", "ok")
    return redirect(url_for("clientes"))


# ------------------------------------------------------------------ linhas (vendas e compras)
def ler_linhas(f, campo_preco, preco_livro):
    """Lê até 5 linhas do formulário. preco_livro: coluna do livro usada como preço por omissão."""
    linhas = []
    for i in range(1, 6):
        book_id = num(f.get(f"book_{i}"), int, None) or None
        nome = f.get(f"nome_{i}", "").strip()
        qtd = num(f.get(f"qtd_{i}"), int, 0)
        if qtd < 1 or not (book_id or nome):
            continue
        l = row(f"SELECT title, {preco_livro} AS p FROM books WHERE id=?", (book_id,)) if book_id else None
        if book_id and not l:
            continue
        preco = num(f.get(f"{campo_preco}_{i}"), float, None)
        if preco is None:
            preco = l["p"] if l else 0
        linhas.append({"book_id": book_id, "nome": nome or l["title"], "qtd": qtd,
                       "preco": preco, "desc": num(f.get(f"desc_{i}"))})
    return linhas


# ------------------------------------------------------------------ vendas
@app.route("/vendas")
def vendas():
    estado = request.args.get("estado", "")
    q = request.args.get("q", "").strip()
    cond, args = [], []
    if estado in ESTADOS_VENDA:
        cond.append("s.status=?")
        args.append(estado)
    if q:
        like = f"%{q.upper().removeprefix('SO-')}%"
        cond.append("(CAST(s.sale_number AS TEXT) LIKE ? OR c.full_name LIKE ? OR s.notes LIKE ?)")
        args += [like, f"%{q}%", f"%{q}%"]
    sql = "SELECT s.*, c.full_name FROM sales_v s LEFT JOIN customers c ON c.id=s.customer_id"
    if cond:
        sql += " WHERE " + " AND ".join(cond)
    lista = rows(sql + " ORDER BY s.sale_number DESC", args)
    return render_template("vendas.html", lista=lista, estado=estado, estados=ESTADOS_VENDA, q=q)


@app.route("/vendas/nova", methods=["GET", "POST"])
def venda_form():
    livros_ = rows("SELECT id, title, unit_price, stock_on_hand FROM books_v WHERE status='Active' ORDER BY title")
    clientes_ = rows("SELECT id, full_name FROM customers WHERE status='Active' ORDER BY full_name")
    agora = datetime.now().strftime("%Y-%m-%dT%H:%M")
    if request.method == "POST":
        f = request.form
        linhas = ler_linhas(f, "preco", "unit_price")
        if not linhas:
            flash("Adicione pelo menos uma linha com quantidade.", "erro")
            return render_template("venda_form.html", livros=livros_, clientes=clientes_, agora=agora)
        for l in linhas:
            if l["desc"] > l["qtd"] * l["preco"]:
                flash(f"O desconto da linha «{l['nome']}» é maior do que o valor da linha.", "erro")
                return render_template("venda_form.html", livros=livros_, clientes=clientes_, agora=agora)
        if f.get("status") == "Completed":
            faltas = faltas_de_stock(por_livro(linhas))
            if faltas:
                flash("Stock insuficiente — " + "; ".join(faltas) + ". Reduza a quantidade ou guarde como rascunho.", "erro")
                return render_template("venda_form.html", livros=livros_, clientes=clientes_, agora=agora)
        n = row("SELECT COALESCE(MAX(sale_number),0)+1 n FROM sales")["n"]
        data_ = (f.get("sale_date") or agora) + ":00Z"
        estado = f.get("status") if f.get("status") in ("Draft", "Completed") else "Draft"
        canal = f.get("channel") if f.get("channel") in CANAIS else "In-store"
        db().execute("""INSERT INTO sales (sale_number,sale_date,status,channel,notes,customer_id,created_at)
            VALUES (?,?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%S','now'))""",
                     (n, data_, estado, canal, f.get("notes", "").strip(),
                      num(f.get("customer_id"), int, None) or None))
        db().executemany("""INSERT INTO sales_items (sale_number,book_id,line_name,quantity,unit_price,discount)
            VALUES (?,?,?,?,?,?)""", [(n, l["book_id"], l["nome"], l["qtd"], l["preco"], l["desc"]) for l in linhas])
        registar("Venda criada", f"SO-{n} ({estado})")
        db().commit()
        flash(f"Venda SO-{n} registada.", "ok")
        return redirect(url_for("venda", n=n))
    return render_template("venda_form.html", livros=livros_, clientes=clientes_, agora=agora)


@app.route("/vendas/<int:n>")
def venda(n):
    s = row("SELECT s.*, c.full_name FROM sales_v s LEFT JOIN customers c ON c.id=s.customer_id WHERE s.sale_number=?", (n,))
    if not s:
        abort(404)
    itens = rows("SELECT * FROM sales_items_v WHERE sale_number=?", (n,))
    return render_template("venda.html", s=s, itens=itens, estados=ESTADOS_VENDA)


@app.post("/vendas/<int:n>/estado")
@permissao("estado")
def venda_estado(n):
    novo = request.form.get("status")
    atual = row("SELECT status FROM sales WHERE sale_number=?", (n,))
    if novo not in ESTADOS_VENDA or not atual:
        abort(400)
    if novo == "Completed" and atual["status"] != "Completed":
        faltas = faltas_de_stock(por_livro(rows("SELECT book_id, quantity FROM sales_items WHERE sale_number=?", (n,))))
        if faltas:
            flash("Stock insuficiente para concluir a venda — " + "; ".join(faltas) + ".", "erro")
            return redirect(url_for("venda", n=n))
    db().execute("UPDATE sales SET status=? WHERE sale_number=?", (novo, n))
    registar("Estado de venda alterado", f"SO-{n}: {PT.get(atual['status'])} → {PT.get(novo)}")
    db().commit()
    flash("Estado da venda atualizado.", "ok")
    return redirect(url_for("venda", n=n))


@app.post("/vendas/<int:n>/apagar")
@permissao("apagar")
def venda_apagar(n):
    if not row("SELECT 1 FROM sales WHERE sale_number=?", (n,)):
        abort(404)
    db().execute("DELETE FROM sales WHERE sale_number=?", (n,))
    registar("Venda apagada", f"SO-{n}")
    db().commit()
    flash(f"Venda SO-{n} apagada.", "ok")
    return redirect(url_for("vendas"))


@app.route("/vendas/<int:n>/recibo")
def venda_recibo(n):
    s = row("SELECT s.*, c.full_name, c.document_id FROM sales_v s LEFT JOIN customers c ON c.id=s.customer_id WHERE s.sale_number=?", (n,))
    if not s:
        abort(404)
    itens = rows("SELECT * FROM sales_items_v WHERE sale_number=?", (n,))
    subtotal = sum(i["quantity"] * i["unit_price"] for i in itens)
    desconto = sum(i["discount"] for i in itens)
    return render_template("recibo.html", s=s, itens=itens, subtotal=subtotal, desconto=desconto,
                           agora=datetime.now().strftime("%d/%m/%Y %H:%M"))


# ------------------------------------------------------------------ compras
@app.route("/compras")
@permissao("compras")
def compras():
    return render_template("compras.html", lista=rows("SELECT * FROM purchases_v ORDER BY purchase_number DESC"))


@app.route("/compras/nova", methods=["GET", "POST"])
@permissao("compras")
def compra_form():
    livros_ = rows("SELECT id, title, cost_price FROM books ORDER BY title")
    hoje = datetime.now().strftime("%Y-%m-%d")
    if request.method == "POST":
        f = request.form
        fornecedor = f.get("supplier_name", "").strip()
        linhas = ler_linhas(f, "custo", "cost_price")
        if not fornecedor or not linhas:
            flash("Indique o fornecedor e pelo menos uma linha com quantidade.", "erro")
            return render_template("compra_form.html", livros=livros_, hoje=hoje, estados=ESTADOS_COMPRA)
        n = row("SELECT COALESCE(MAX(purchase_number),0)+1 n FROM purchases")["n"]
        estado = f.get("status") if f.get("status") in ESTADOS_COMPRA else "Draft"
        db().execute("""INSERT INTO purchases (purchase_number,supplier_name,purchase_date,status,notes,created_at)
            VALUES (?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%S','now'))""",
                     (n, fornecedor, f.get("purchase_date") or hoje, estado, f.get("notes", "").strip()))
        db().executemany("""INSERT INTO purchase_items (purchase_number,book_id,line_name,quantity,unit_cost)
            VALUES (?,?,?,?,?)""", [(n, l["book_id"], l["nome"], l["qtd"], l["preco"]) for l in linhas])
        registar("Compra criada", f"PO-{n} ({fornecedor}, {estado})")
        db().commit()
        flash(f"Compra PO-{n} registada.", "ok")
        return redirect(url_for("compra", n=n))
    return render_template("compra_form.html", livros=livros_, hoje=hoje, estados=ESTADOS_COMPRA)


@app.route("/compras/<int:n>")
@permissao("compras")
def compra(n):
    p = row("SELECT * FROM purchases_v WHERE purchase_number=?", (n,))
    if not p:
        abort(404)
    return render_template("compra.html", p=p, estados=ESTADOS_COMPRA,
                           itens=rows("SELECT * FROM purchase_items_v WHERE purchase_number=?", (n,)))


@app.post("/compras/<int:n>/estado")
@permissao("compras")
def compra_estado(n):
    novo = request.form.get("status")
    atual = row("SELECT status FROM purchases WHERE purchase_number=?", (n,))
    if novo not in ESTADOS_COMPRA or not atual:
        abort(400)
    if atual["status"] == "Received" and novo != "Received":
        faltas = faltas_de_stock(por_livro(rows("SELECT book_id, quantity FROM purchase_items WHERE purchase_number=?", (n,))))
        if faltas:
            flash("Não é possível retirar esta compra de «Recebida» porque o stock já foi vendido — " + "; ".join(faltas) + ".", "erro")
            return redirect(url_for("compra", n=n))
    db().execute("UPDATE purchases SET status=? WHERE purchase_number=?", (novo, n))
    registar("Estado de compra alterado", f"PO-{n}: {PT.get(atual['status'])} → {PT.get(novo)}")
    db().commit()
    flash("Estado da compra atualizado.", "ok")
    return redirect(url_for("compra", n=n))


@app.post("/compras/<int:n>/apagar")
@permissao("apagar")
@permissao("compras")
def compra_apagar(n):
    atual = row("SELECT status FROM purchases WHERE purchase_number=?", (n,))
    if not atual:
        abort(404)
    if atual["status"] == "Received":
        faltas = faltas_de_stock(por_livro(rows("SELECT book_id, quantity FROM purchase_items WHERE purchase_number=?", (n,))))
        if faltas:
            flash("Não é possível apagar esta compra recebida porque o stock já foi vendido — " + "; ".join(faltas) + ".", "erro")
            return redirect(url_for("compra", n=n))
    db().execute("DELETE FROM purchases WHERE purchase_number=?", (n,))
    registar("Compra apagada", f"PO-{n}")
    db().commit()
    flash(f"Compra PO-{n} apagada.", "ok")
    return redirect(url_for("compras"))


# ------------------------------------------------------------------ utilizadores (só administradores)
def n_admins():
    return row("SELECT COUNT(*) n FROM users WHERE role='Admin'")["n"]


@app.route("/utilizadores")
@permissao("utilizadores")
def utilizadores():
    return render_template("utilizadores.html", lista=rows("SELECT * FROM users ORDER BY id"))


@app.route("/utilizadores/novo", methods=["GET", "POST"])
@app.route("/utilizadores/<int:id>/editar", methods=["GET", "POST"])
@permissao("utilizadores")
def utilizador_form(id=None):
    u = row("SELECT * FROM users WHERE id=?", (id,)) if id else None
    if id and not u:
        abort(404)
    f = dict(u) if u else {"role": "Attendant"}
    if request.method == "POST":
        nome = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        perfil = request.form.get("role") if request.form.get("role") in PERFIS else "Attendant"
        senha = request.form.get("password", "")
        f.update(name=nome, email=email, role=perfil)
        dup = row("SELECT id FROM users WHERE lower(email)=? AND id IS NOT ?", (email.lower(), id))
        erro_ = None
        if not nome or not email:
            erro_ = "Nome e e-mail são obrigatórios."
        elif dup:
            erro_ = "Já existe um utilizador com esse e-mail."
        elif not id and len(senha) < 6:
            erro_ = "Defina uma palavra-passe temporária com pelo menos 6 caracteres."
        elif id and senha and len(senha) < 6:
            erro_ = "A palavra-passe deve ter pelo menos 6 caracteres."
        elif id and u["role"] == "Admin" and perfil != "Admin" and n_admins() <= 1:
            erro_ = "Tem de existir pelo menos um administrador."
        if erro_:
            flash(erro_, "erro")
            return render_template("utilizador_form.html", f=f, id=id, perfis=PERFIS)
        if id:
            db().execute("UPDATE users SET name=?, email=?, role=? WHERE id=?", (nome, email, perfil, id))
            if senha:
                db().execute("UPDATE users SET password_hash=?, must_change=1 WHERE id=?",
                             (generate_password_hash(senha), id))
            registar("Utilizador editado", nome)
            flash("Utilizador atualizado.", "ok")
        else:
            db().execute("INSERT INTO users (email,name,role,password_hash,must_change) VALUES (?,?,?,?,1)",
                         (email, nome, perfil, generate_password_hash(senha)))
            registar("Utilizador criado", f"{nome} ({PT.get(perfil)})")
            flash("Utilizador criado. Terá de mudar a palavra-passe no primeiro acesso.", "ok")
        db().commit()
        return redirect(url_for("utilizadores"))
    return render_template("utilizador_form.html", f=f, id=id, perfis=PERFIS)


@app.post("/utilizadores/<int:id>/apagar")
@permissao("utilizadores")
def utilizador_apagar(id):
    u = row("SELECT * FROM users WHERE id=?", (id,))
    if not u:
        abort(404)
    if id == g.user["id"]:
        flash("Não pode apagar a sua própria conta.", "erro")
    elif u["role"] == "Admin" and n_admins() <= 1:
        flash("Tem de existir pelo menos um administrador.", "erro")
    else:
        db().execute("DELETE FROM users WHERE id=?", (id,))
        registar("Utilizador apagado", u["name"])
        db().commit()
        flash("Utilizador apagado.", "ok")
    return redirect(url_for("utilizadores"))


# ------------------------------------------------------------------ exportar CSV
@app.route("/exportar/<tabela>")
def exportar(tabela):
    if tabela == "livros":
        custo = pode("ver_custos")
        cab = ["Título", "Autor", "ISBN", "Editora", "Categoria", "Preço de venda (Kz)"] + (["Preço de custo (Kz)"] if custo else []) + ["Em stock", "Nível de reposição", "Estado"]
        dados = [[b["title"], b["author"], b["isbn"], b["publisher"], pt(b["category"]), b["unit_price"]]
                 + ([b["cost_price"]] if custo else []) + [b["stock_on_hand"], b["reorder_level"], pt(b["status"])]
                 for b in rows("SELECT * FROM books_v ORDER BY title")]
    elif tabela == "clientes":
        cab = ["Nome", "E-mail", "Telefone", "Documento", "Estado", "Vendas concluídas", "Valor total (Kz)"]
        dados = [[c["full_name"], c["email"], c["phone"], c["document_id"], pt(c["status"]), c["total_orders"], c["lifetime_value"]]
                 for c in rows("SELECT * FROM customers_v ORDER BY full_name")]
    elif tabela == "vendas":
        cab = ["Venda", "Data", "Cliente", "Canal", "Estado", "Total (Kz)"]
        dados = [[s["display_name"], data(s["sale_date"]), s["full_name"] or "Balcão", pt(s["channel"]), pt(s["status"]), s["sale_total"]]
                 for s in rows("SELECT s.*, c.full_name FROM sales_v s LEFT JOIN customers c ON c.id=s.customer_id ORDER BY s.sale_number")]
    elif tabela == "compras":
        if not pode("compras"):
            abort(403)
        cab = ["Compra", "Fornecedor", "Data", "Estado", "Custo total (Kz)"]
        dados = [[p["display_name"], p["supplier_name"], data(p["purchase_date"]), pt(p["status"]), p["total_cost"]]
                 for p in rows("SELECT * FROM purchases_v ORDER BY purchase_number")]
    else:
        abort(404)
    registar("Exportação CSV", tabela)
    db().commit()
    return csv_resposta(tabela, cab, dados)


# ------------------------------------------------------------------ atividade e backup (administradores)
@app.route("/atividade")
@permissao("utilizadores")
def atividade():
    return render_template("atividade.html", lista=rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200"))


@app.post("/backup")
@permissao("utilizadores")
def backup():
    fd, caminho = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    destino = sqlite3.connect(caminho)
    db().backup(destino)
    destino.close()
    with open(caminho, "rb") as f:
        conteudo = f.read()
    os.unlink(caminho)
    registar("Backup descarregado")
    db().commit()
    return Response(conteudo, mimetype="application/x-sqlite3",
                    headers={"Content-Disposition": f'attachment; filename="livraria_backup_{datetime.now():%Y-%m-%d_%H%M}.db"'})


if __name__ == "__main__":
    app.run(debug=True)
