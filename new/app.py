from flask import Flask, request, jsonify
from psycopg2 import connect, extras
from cryptography.fernet import Fernet, InvalidToken
from flask_cors import CORS

app = Flask(__name__)

# Clave Fernet, debes mantenerla constante entre ejecuciones
key = Fernet.generate_key()

host = 'localhost'
port = 5432
dbname = 'usersdb'
user = 'postgres'
password = '12345679'


def encrypt_password(plain_password):
    f = Fernet(key)
    encrypted_password = f.encrypt(plain_password.encode('utf-8'))
    return encrypted_password


def verify_password(plain_password, encrypted_password):
    f = Fernet(key)
    try:
        decrypted_password = f.decrypt(encrypted_password).decode('utf-8')
        return plain_password == decrypted_password
    except (InvalidToken, UnicodeDecodeError):
        return False



def get_connection():
    conn = connect(host=host, port=port, dbname=dbname, user=user,
                   password=password, options="-c client_encoding=UTF8")

    return conn


CORS(app, resources={r"/api/*": {"origins": "*"}})


def get_connection():
    conn = connect(host=host, port=port, dbname=dbname,
                   user=user, password=password)

    return conn


cors = CORS(app, resources={r"/api/*": {"origins": "*"}})


@app.get('/api/users')
def get_users():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)

    cur.execute('SELECT * FROM users')
    users = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify(users)


@app.post('/api/users')
def create_user():
    new_user = request.get_json()
    names = new_user['names']
    username = new_user['username']
    email = new_user['email']
    password = Fernet(key).encrypt(bytes(new_user['password'], 'utf-8'))

    conn = get_connection()
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)

    cur.execute('INSERT INTO users (names, username, email, password) VALUES (%s, %s, %s, %s)RETURNING *',
                (names, username, email, password))
    new_user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(new_user)


@app.route('/api/login', methods=['POST'])
def login():
    if request.method == 'POST':
        login_data = request.get_json()
        email = login_data.get('email')
        plain_password = login_data.get('password')  # Contraseña en texto plano

        # Consultar si el correo electrónico existe en la base de datos
        conn = get_connection()
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)
        cur.execute('SELECT password FROM users WHERE email = %s', (email,))
        stored_password = cur.fetchone()
        cur.close()
        conn.close()

        if stored_password:
            # La contraseña almacenada está cifrada en la base de datos
            if verify_password(plain_password, stored_password['password']):
                return "Contraseña correcta"
            else:
                return "Error en usuario o contraseña", 401
        else:
            return "Correo electrónico no registrado", 401


@app.delete('/api/users/<id>')
def delete_user(id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)

    cur.execute("DELETE FROM users WHERE id = %s RETURNING *", (id,))
    user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if user is None:
        return jsonify({'message': 'User not found'}), 404
    return jsonify(user)

# PUT ACTUALIZA USUARIO


@app.put('/api/users/<id>')
def update_user(id):
    conn = get_connection
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)

    new_user = request.get_json()
    names = new_user['names']
    username = new_user['username']
    email = new_user['email']
    password = Fernet(key).encrypt(bytes(new_user['password'], 'utf-8'))
    cur.execute("UPDATE users SET names = %s, username = %s, email = %s, password = %s WHERE id = %s RETURNING *",
                (names, username, email, password, id))

    updated_user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if updated_user is None:
        return jsonify({'message': 'User not found'}), 404
    return jsonify(updated_user)


@app.get('/api/users/<id>')
def get_user(id):

    conn = get_connection()
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE id = %s", (id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user is None:
        return jsonify({'message': 'User not found'}), 404

    return jsonify(user)


print(__name__)
if __name__ == '__main__':
    app.run(debug=True, port=5000)
