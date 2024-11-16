from datetime import datetime,timedelta
from flask import Flask, jsonify, request,render_template
from flask_cors import CORS
import requests 
from flask_sqlalchemy import SQLAlchemy
import os 
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
CORS(app)
#CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:5500,https://app-7074c222-a2e7-4059-9de0-2bfc84624604.cleverapps.io"}})
#CORS(app, resources={r"/*": {"origins": "*"}})  # Permitir todos los orígenes (cuidado con la seguridad)

# Configuración de la base de datos MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'mysql+pymysql://uempnxi2jnk2b17e:zlASN5eHACBwaTDYMQik@bvjvuwry1r9jvvpmeayt-mysql.services.clever-cloud.com:3306/bvjvuwry1r9jvvpmeayt')
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://uempnxi2jnk2b17e:zlASN5eHACBwaTDYMQik@bvjvuwry1r9jvvpmeayt-mysql.services.clever-cloud.com:3306/bvjvuwry1r9jvvpmeayt'  # Cambia esto según tu configuración
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#JWT
app.config['JWT_SECRET_KEY'] = 'CONTROL'  # Cambia esto por una clave segura
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=4)  # Duración del token a 4 horas

jwt = JWTManager(app)

db = SQLAlchemy(app)


class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id_usuario = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(50), nullable=False)
    contraseña = db.Column(db.String(255), nullable=False)
    nombre = db.Column(db.String(50), nullable=True)
    
    def set_password(self, password):
        self.contraseña = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.contraseña, password)

class UsuarioLogueado(db.Model):
    __tablename__ = 'usuarios_logueados'
    
    id_log = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), nullable=False)
    nombre_usuario = db.Column(db.String(50), nullable=False)
    hora_login = db.Column(db.DateTime, default=datetime.now)
    estado = db.Column(db.Enum('en línea', 'desconectado'), nullable=False)


class Login(db.Model):
    __tablename__ = 'login'
    id_login = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'))
    usuario = db.Column(db.String(50), nullable=False)
    contraseña = db.Column(db.String(255), nullable=False)

class Sensor(db.Model):
    __tablename__ = 'sensores'
    id_sensor = db.Column(db.Integer, primary_key=True)
    nombre_sensor = db.Column(db.String(50), nullable=False)
    tipo_sensor = db.Column(db.String(50), nullable=False)
    unidad = db.Column(db.String(20), nullable=False)

class LecturaSensor(db.Model):
    __tablename__ = 'lecturas_sensores'
    id_lectura = db.Column(db.Integer, primary_key=True)
    id_sensor = db.Column(db.Integer, db.ForeignKey('sensores.id_sensor'))
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'))
    valor_salida = db.Column(db.Float, nullable=False)
    fecha_hora = db.Column(db.DateTime, default=db.func.current_timestamp())
    
# Variable para almacenar el estado del LED
led_state = "off"  # "on" o "off"    
motor_state= "off"

# Rutas de la API

@app.route('/api/usuarios', methods=['GET'])
@jwt_required()
def get_usuarios():
    current_user = get_jwt_identity()
    usuarios = Usuario.query.all()
    return jsonify([{"id_usuario": u.id_usuario,
                     "usuario": u.usuario,
                     "nombre": u.nombre} for u in usuarios])

@app.route('/api/usuarios', methods=['POST'])
def add_usuario():
    if not request.json or 'usuario' not in request.json or 'contraseña' not in request.json:
        return jsonify({'error': 'Datos inválidos'}), 400

    nuevo_usuario = Usuario(
        usuario=request.json['usuario'],
        contraseña=request.json['contraseña'],
        nombre=request.json.get('nombre', '')  
    )
    db.session.add(nuevo_usuario)
    db.session.commit()

    return jsonify({'id_usuario': nuevo_usuario.id_usuario}), 201

@app.route('/api/login', methods=['GET'])
@jwt_required()
def get_login():
    login = Login.query.all()
    return jsonify([{"id_login":l.id_login,
                    "id_usuario": l.id_usuario,
                     "usuario": l.usuario,
                     "contraseña":l.contraseña} for l in login])
      


# Ruta de Login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    usuario = data.get('usuario')
    contraseña = data.get('contraseña')

    if not usuario or not contraseña:
        return jsonify({"message": "Faltan datos"}), 400

    # Busca el usuario en la base de datos
    login = Login.query.filter_by(usuario=usuario).first()

    if login and login.contraseña == contraseña:
        # Consulta el usuario en la tabla 'usuarios' usando el id_usuario del objeto 'login'
        usuario_obj = Usuario.query.filter_by(id_usuario=login.id_usuario).first()

        # Crear el token de acceso
        access_token = create_access_token(identity=usuario)

        # Registrar en la tabla `usuarios_logueados`
        nuevo_log = UsuarioLogueado(
            id_usuario=usuario_obj.id_usuario,
            nombre_usuario=usuario_obj.nombre,  # Almacenar el nombre del usuario
            estado='en línea'
        )
        db.session.add(nuevo_log)
        db.session.commit()

        return jsonify(token=access_token), 200
    else:
        return jsonify({"message": "Credenciales incorrectas"}), 401



# Ruta de Logout
@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    # Obtener el nombre de usuario a partir del token de acceso
    usuario = get_jwt_identity()

    # Consultar el usuario en la tabla `Login` para obtener su ID
    login = Login.query.filter_by(usuario=usuario).first()
    if not login:
        return jsonify({"message": "Usuario no encontrado"}), 404

    # Crear un nuevo registro en `usuarios_logueados` con estado 'desconectado'
    nuevo_log = UsuarioLogueado(
        id_usuario=login.id_usuario,
        nombre_usuario=login.usuario,  # Asegúrate de que `usuario` contiene el nombre del usuario
        estado='desconectado'
    )
    db.session.add(nuevo_log)
    db.session.commit()

    return jsonify({"message": "Cierre de sesión exitoso"}), 200


@app.route('/api/sensores', methods=['GET'])
@jwt_required()
def get_sensores():
    sensores = Sensor.query.all()
    return jsonify([{"id_sensor": s.id_sensor,
                     "nombre_sensor": s.nombre_sensor} for s in sensores])

@app.route('/api/lecturas', methods=['GET'])
@jwt_required()
def get_lecturas():
    lecturas = LecturaSensor.query.all()
    return jsonify([{"id_lectura": l.id_lectura,
                     "valor_salida": l.valor_salida,
                     "fecha_hora": l.fecha_hora,
                     "id_sensor": l.id_sensor,
                     "id_usuario": l.id_usuario} for l in lecturas])


@app.route('/api/controlar_led', methods=['POST'])
@jwt_required()
def controlar_led():
    try:
        data = request.get_json()

        # Verificación de parámetros
        if 'state' not in data:
            return jsonify({"error": "Falta el parámetro 'state'"}), 400

        # Obtener el estado deseado del LED
        led_state = data['state']

        # Validación estricta del estado
        if led_state not in ["on", "off"]:
            return jsonify({"error": "El estado debe ser 'on' o 'off'"}), 400

        # Obtener el nombre del usuario desde el JWT
        nombre_usuario = get_jwt_identity()

        # Obtener el ID del usuario desde la base de datos
        usuario = Usuario.query.filter_by(usuario=nombre_usuario).first()
        if not usuario:
            return jsonify({"error": "Usuario no encontrado"}), 404

        id_usuario = usuario.id_usuario
        valor_salida = 1 if led_state == "on" else 0
        id_sensor = 2  # Asumido que el LED tiene el ID de sensor 2
        
        # Registrar el estado del LED en la base de datos
        nueva_lectura = LecturaSensor(
            id_sensor=id_sensor,
            id_usuario=id_usuario,
            valor_salida=valor_salida
        )
        db.session.add(nueva_lectura)
        db.session.commit()

        return jsonify({
            "message": f"LED {led_state} y lectura registrada",
            "estado_actual": valor_salida
        }), 200

    except Exception as e:
        return jsonify({"error": "Error al procesar la solicitud", "detalles": str(e)}), 500


@app.route('/api/controlar_motor', methods=['POST'])
@jwt_required()
def controlar_motor():
    try:
        data = request.get_json()

        # Verificación de parámetros
        if 'state' not in data:
            return jsonify({"error": "Falta el parámetro 'state'"}), 400

        # Obtener el estado deseado del LED
        motor_state = data['state']

        # Validación estricta del estado
        if motor_state not in ["on", "off"]:
            return jsonify({"error": "El estado debe ser 'on' o 'off'"}), 400

        # Obtener el nombre del usuario desde el JWT
        nombre_usuario = get_jwt_identity()

        # Obtener el ID del usuario desde la base de datos
        usuario = Usuario.query.filter_by(usuario=nombre_usuario).first()
        if not usuario:
            return jsonify({"error": "Usuario no encontrado"}), 404

        id_usuario = usuario.id_usuario
        valor_salida = 1 if motor_state == "on" else 0
        id_sensor = 1  # Asumido que el LED tiene el ID de sensor 2
        
        # Registrar el estado del LED en la base de datos
        nueva_lectura = LecturaSensor(
            id_sensor=id_sensor,
            id_usuario=id_usuario,
            valor_salida=valor_salida
        )
        db.session.add(nueva_lectura)
        db.session.commit()

        return jsonify({
            "message": f"MOTOR {motor_state} y lectura registrada",
            "estado_actual": valor_salida
        }), 200

    except Exception as e:
        return jsonify({"error": "Error al procesar la solicitud", "detalles": str(e)}), 500



##########      ESTADOS   ###################
#################################################################################

@app.route('/api/estado_salida/<int:id_sensor>', methods=['GET'])
def get_estado_salida(id_sensor):
    # Validar que el id_sensor sea válido (1 para el motor, 2 para el LED)
    if id_sensor not in [1, 2]:
        return jsonify({"error": "ID de sensor no válido. Debe ser 1 para el motor o 2 para el LED."}), 400

    # Obtener la última lectura del sensor especificado
    ultima_lectura = (
        LecturaSensor.query
        .filter_by(id_sensor=id_sensor)
        .order_by(LecturaSensor.fecha_hora.desc())
        .first()
    )

    if ultima_lectura:
        # Devolver el estado de la salida
        estado = "on" if ultima_lectura.valor_salida == 1 else "off"
        return jsonify({
            "id_sensor": id_sensor,
            "estado_actual": estado,
            "valor_salida": ultima_lectura.valor_salida,
            "fecha_hora": ultima_lectura.fecha_hora
        }), 200
    else:
        # Si no se encuentra ninguna lectura para el sensor, devolver un mensaje de error
        return jsonify({"error": "No se encontraron lecturas para el sensor especificado."}), 404





@app.route('/api/estado_login', methods=['GET'])
def estado_login():
    # Consulta el último estado de login
    ultimo_estado = UsuarioLogueado.query.order_by(UsuarioLogueado.hora_login.desc()).first()
    
    if ultimo_estado:
        return jsonify({'estado': ultimo_estado.estado})
    else:
        return jsonify({'estado': 'desconocido'}), 404



if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0', port=5000)
    

    
