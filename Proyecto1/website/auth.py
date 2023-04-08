from flask import *
from flask_mysqldb import MySQL
from datetime import datetime
import hashlib
from PIL import Image
import base64
from io import *
from MySQLdb import IntegrityError
import cv2
from bson.objectid import ObjectId
from bson.binary import Binary


from . import dbmysql
from . import dataSetMongo
from . import r
from . import dbNeo4j
from . import dbMongo


auth = Blueprint('auth',__name__)

@auth.route('/login',methods =['GET','POST'])
def login():

    if request.method == 'POST':
        username  =request.form.get('username')
        password =request.form.get('password')

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        cursor = dbmysql.connection.cursor()
        queryLogin = "SELECT COUNT(*) FROM usuarios WHERE username=%s AND password=%s"
        cursor.execute(queryLogin, (username, hashed_password))
        result = cursor.fetchone()[0]
        if result == 1:
            query = "SELECT * FROM usuarios WHERE username=%s"
            cursor.execute(query, (username,))
            row = cursor.fetchone()
            id = row[0]
            nombreCompleto = row[3]
            fechaNacimietno = row[4]

            
            query = "SELECT picture_data FROM pictures WHERE id=%s"
            cursor.execute(query, (id,))
            image_data = cursor.fetchone()[0]
            image_buffer = BytesIO(image_data)
            base64_image = base64.b64encode(image_buffer.getvalue()).decode()
            cursor.close()
            return render_template("usuario.html",foto=base64_image,username=username,name=nombreCompleto,fecha=fechaNacimietno)
        else:
            cursor.close()
            flash('Error al ingresar Usuario o constraseña invalida ', 'error')
            return render_template("login.html")
   
    
    
    return render_template("login.html")

@auth.route('/logout')
def logout():
    return "<p>logout</p>"

@auth.route('/sign-up',methods =['GET','POST'])
def sign_up():
    if request.method == 'POST':
        
        username =request.form.get('username')
        password  =request.form.get('password')
        nombre =request.form.get('nombre')
        fecha =request.form.get('fecha')
        foto  = request.files['foto']
        if not username or not password or not nombre or not fecha or not foto.filename:
            flash('No ingreso los datos nesesarios ', 'error')
            return render_template("sign_up.html")
        else:
            try:
                # Se encrypta la contraseña
                hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

                cursor = dbmysql.connection.cursor()
                # query inserta el usuario en la base de datos
                cursor.execute(''' INSERT INTO usuarios (username, password, nombreCompleto, fechaNacimiento) VALUES(%s,%s,%s,%s)''',(username ,hashed_password,nombre,fecha))
                dbmysql.connection.commit()

                # Se le y parsea la foto para guardar en la base de datos mysql
                img_data = foto.read()
                img_base64 = base64.b64encode(img_data).decode('utf-8')
                img = Image.open(BytesIO(img_data))
                # query insertar la imagen en la base de datos
                query = "INSERT INTO pictures (username,picture_data) VALUES (%s, %s)"
                cursor.execute(query, (username,img_data))
                dbmysql.connection.commit()
                queryId = "SELECT id FROM usuarios WHERE username=%s"
                cursor.execute(queryId, (username,))
                row = cursor.fetchone()
                id = row[0]
                cursor.close()
                properties = {'id': id, 'username': username}
                label = "Usuarios"
                with dbNeo4j.session() as session:
                    session.run(f"CREATE (n:{label} $properties) RETURN n", properties=properties)
                flash("Creacion de usuario con exito", 'success')
                return redirect('/')
            
            except IntegrityError as e:
                flash('Error al registrarse '+str(e), 'error')
                return redirect('/')
            
    return render_template("sign_up.html")

@auth.route('/update',methods =['GET','POST'])
def update():

    if request.method == 'GET':
            username = request.args.get('username')
            cursor = dbmysql.connection.cursor()
            query = "SELECT * FROM usuarios WHERE username=%s"
            cursor.execute(query, (username,))
            row = cursor.fetchone()
            password = row[2]
            nombreCompleto = row[3]
            fechaNacimietno = row[4]
            cursor.close()
            return render_template('update.html', username=username,password=password,nombre=nombreCompleto,fecha=fechaNacimietno,foto=None)
    if request.method == 'POST':

        username = request.args.get('username')
        cursor = dbmysql.connection.cursor()
        query = "SELECT password FROM usuarios WHERE username=%s"
        cursor.execute(query, (username,))
        hashPassword = cursor.fetchone()[0]

        password  =request.form.get('password')
        nombre =request.form.get('nombre')
        fecha =request.form.get('fecha')
        foto  = request.files['foto']
        if  foto.filename:
            img_data = foto.read()
            img_base64 = base64.b64encode(img_data).decode('utf-8')
            img = Image.open(BytesIO(img_data))

            query = "UPDATE pictures SET picture_data=%s WHERE username=%s"
            cursor.execute(query, (img_data,username,))
            dbmysql.connection.commit()
          
        if hashPassword != password:
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            query = "UPDATE usuarios SET password=%s WHERE username=%s"
            cursor.execute(query, (hashed_password,username,))
            dbmysql.connection.commit()

        query = "UPDATE usuarios SET nombreCompleto=%s, fechaNacimiento=%s WHERE username=%s"
        cursor.execute(query, (nombre,fecha,username,))
        dbmysql.connection.commit()
        
    flash("Cambio en datos de usuario con exito", 'success')
    return render_template('home.html')
        

@auth.route('/usuario',methods =['GET','POST'])
def usuario():
    username = request.args.get('username')
    cursor = dbmysql.connection.cursor()
    queryLogin = "SELECT COUNT(*) FROM usuarios WHERE username=%s"
    cursor.execute(queryLogin, (username,))
    result = cursor.fetchone()[0]
    if result == 1:
        query = "SELECT * FROM usuarios WHERE username=%s"
        cursor.execute(query, (username,))
        row = cursor.fetchone()
        id = row[0]
        nombreCompleto = row[3]
        fechaNacimietno = row[4]

            
        query = "SELECT picture_data FROM pictures WHERE id=%s"
        cursor.execute(query, (id,))
        image_data = cursor.fetchone()[0]
        image_buffer = BytesIO(image_data)
        base64_image = base64.b64encode(image_buffer.getvalue()).decode()
        cursor.close()
        return render_template("usuario.html",foto=base64_image,username=username,name=nombreCompleto,fecha=fechaNacimietno)

@auth.route('/dataset',methods =['GET','POST'])
def dataset():
    username = request.args.get('username')
    if request.method == 'POST':
        if 'NomButton' in request.form:
            nombreDescripcion  =request.form.get('nombre')
            if nombreDescripcion == '':
                return render_template('dataset.html', username=username)
            else:
                documents = dataSetMongo.find({"nombre": {"$regex": nombreDescripcion}})
                return render_template('buscarDataset.html', documents=documents,username=username)
        
        if 'UsButton' in request.form:
            nombreDescripcion  =request.form.get('username')
            if nombreDescripcion == '':
                return render_template('dataset.html', username=username)
            else:
                documents = dataSetMongo.find({"username": {"$regex": nombreDescripcion}})
                return render_template('buscarDataset.html', documents=documents,username=username)
        
        if 'MiButton' in request.form:
            nombreDescripcion  =request.args.get('username')
            if nombreDescripcion == '':
                return render_template('dataset.html', username=username)
            else:
                
                documents = dataSetMongo.find({"username": nombreDescripcion})
                return render_template('buscarDataset.html', documents=documents,username=username)
        
        if 'DesButton' in request.form:
            nombreDescripcion  =request.form.get('Descripcion')
            if nombreDescripcion == '':
                return render_template('dataset.html', username=username)
            else:
                documents = dataSetMongo.find({"descripcion": {"$regex": nombreDescripcion}})
                return render_template('buscarDataset.html', documents=documents,username=username)
        
    return render_template('dataset.html', username=username)


@auth.route('/crearDataset',methods =['GET','POST'])
def crearDataset():
     username = request.args.get('username')
     if request.method == 'GET':
        return render_template('crearDataset.html', username=username)
     if request.method == 'POST':
        nombre  =request.form.get('nombre')
        descripcion =request.form.get('descripcion')
        foto  = request.files['foto']
        archivo  = request.files['archivo']
        video  = request.files['video']
        if not username or not nombre or not descripcion or not foto.filename or not archivo.filename or not video.filename:
            flash("Faltaron datos en el DataSet", 'error')
            return render_template("crearDataset.html", username=username)
        id = r.get('id')
        id = int(id)+1
        video_data = video.read()
        processed_video = {
        'name': video.filename,
        'data': video_data}
        img_data = foto.read()
        img_base64 = base64.b64encode(img_data).decode('utf-8')
        img = Image.open(BytesIO(img_data))
        # LEER archivo
        file_data = archivo.read()
        processed_archivo = {
        'name': archivo.filename,
        'data': file_data}
        try:
            dataset_doc = { 'id' : id,
                        'username' : username,
                        'nombre' :nombre,
                        'descripcion' : descripcion, 
                        'date' : datetime.utcnow(),
                        'foto' : img_data,
                        'archivo' : processed_archivo,
                        'video' : processed_video,
                        'descargas':0,
                        'usuariosDownload':[]}
            dataSetMongo.insert_one(dataset_doc)
            r.set('id',id)
            r.set("numDescargas"+str(id), 0)
            r.lpush("ListaUsuarios"+str(id), '')
            with dbNeo4j.session() as session:
                result = session.run("MATCH (user:Usuarios {username: $username})-[:AMIGOS]-(friend:Usuarios) "
                             "RETURN DISTINCT friend.username AS name", username=username)
                listAmigos = [record["name"] for record in result]
                for list in listAmigos:
                    r.lpush(str(list)+str(username), id)
        except:
            print("Tamaño demasido grande")
        flash("Creacion de dataset con exito", 'exito')
        return render_template('crearDataset.html', username=username)
     return render_template('crearDataset.html', username=username)

@auth.route('/verDataset',methods =['GET','POST'])
def verDataset():
    username = request.args.get('username')
    if request.method == 'POST':
        #descarga dataset
        if 'punButton' in request.form:
            idDocumento = request.args.get('idDocumento')
            puntaje  =request.form.get('puntuacion')
            try:
                puntaje  =int(request.form.get('puntuacion'))
                if puntaje <6 and puntaje > 0 :
                    r.set(str(username)+str(idDocumento),puntaje)
                else:
                    flash("La puntuacion debe ser 1 a 5", 'error')
            except:
                flash("Ingresaste una puntuacion que no es valida debe ser 1-5", 'error') 
            mydocs  = dataSetMongo.find({"id": int(idDocumento)})
            nombre = mydocs[0]['nombre']
            descripcion = mydocs[0]['descripcion']
            fecha = mydocs[0]['date']
            archivo = mydocs[0]['archivo']['data']
            image_base64 = base64.b64encode(mydocs[0]['foto']).decode('utf-8')
            video_base64 = base64.b64encode(mydocs[0]['video']['data']).decode('utf-8')
            archivo_decode = archivo.decode('utf-8')
            size  = str(len(archivo_decode) / 1024) + " kb"
            puntuacion = r.get(str(username)+str(idDocumento))
            if puntuacion == None:
                puntuacion = "Sin Puntuacion"
            else:
                puntuacion = int(r.get(str(username)+str(idDocumento)))
            return render_template('verDataset.html',puntuacion=puntuacion,size=size,username=username,archivo=archivo_decode, nombre=nombre,descripcion=descripcion,fecha=fecha,foto=image_base64,video_base64=video_base64)
        if 'DownlodButton' in request.form:
            idDocumento = request.args.get('idDocumento')
            username = request.args.get('username')
            mydoc  = dataSetMongo.find({"id": int(idDocumento)})
            archivo = mydoc[0]['archivo']['data']
            filename = mydoc[0]['archivo']['name']

            descargas = r.get("numDescargas"+str(idDocumento))
            #revisar si ya descargo el data set
            existing_items = set(r.lrange("ListaUsuarios"+str(id), 0, -1))
            if username.encode() not in existing_items:
            # If the item is not present in the list, append it
                r.rpush("ListaUsuarios"+str(id), username)
                dataSetMongo.update_one(
                {'id': int(idDocumento)}, # Filter to select the document to update
                {'$push': {'usuariosDownload': username}})

            descargas = int(descargas)+1
            dataSetMongo.update_one(
            {'id': int(idDocumento)}, # Filter to select the document to update
            {'$set': {'descargas': descargas}})
            

            r.set("numDescargas"+str(idDocumento), descargas)
            return send_file(BytesIO(archivo), as_attachment=True, mimetype='text/plain', download_name=filename)
        if 'ComenButton' in request.form:
            try:
                with dbNeo4j.session() as session:
                    result = session.run("MATCH (n) RETURN COUNT(n) AS count")
                    count = result.single()['count']
                message = f"Database connection successful! Found {count} nodes."
                status = "OK"
            except Exception as e:
                message = f"Database connection failed: {e}"
                status = "ERROR"
            return jsonify({"status": status, "message": message})

        if 'NotifButton' in request.form:
            idDocumento = request.args.get('idDocumento')
            mydocs  = dataSetMongo.find({"id": int(idDocumento)})
            nombre = mydocs[0]['nombre']
            descripcion = mydocs[0]['descripcion']
            fecha = mydocs[0]['date']
            archivo = mydocs[0]['archivo']['data']
            image_base64 = base64.b64encode(mydocs[0]['foto']).decode('utf-8')
            video_base64 = base64.b64encode(mydocs[0]['video']['data']).decode('utf-8')
            archivo_decode = archivo.decode('utf-8')
            size  = str(len(archivo_decode) / 1024) + " kb"
            puntuacion = r.get(str(username)+str(idDocumento))
            if puntuacion == None:
                puntuacion = "Sin Puntuacion"
            else:
                puntuacion = int(r.get(str(username)+str(idDocumento)))
            return render_template('verDataset.html',puntuacion=puntuacion,size=size,username=username,archivo=archivo_decode, nombre=nombre,descripcion=descripcion,fecha=fecha,foto=image_base64,video_base64=video_base64)
    
    if request.method == 'GET':
        idDocumento = request.args.get('idDocumento')
        mydoc  = dataSetMongo.find({"id": int(idDocumento)})
        nombre = mydoc[0]['nombre']
        descripcion = mydoc[0]['descripcion']
        fecha = mydoc[0]['date']
        archivo = mydoc[0]['archivo']['data']
        image_base64 = base64.b64encode(mydoc[0]['foto']).decode('utf-8')
        video_base64 = base64.b64encode(mydoc[0]['video']['data']).decode('utf-8')
        archivo_decode = archivo.decode('utf-8')
        size  = str(len(archivo_decode) / 1024) + " kb"
        puntuacion = r.get(str(username)+str(idDocumento))
        if puntuacion == None:
            puntuacion = "Sin Puntuacion"
        else:
            puntuacion = int(r.get(str(username)+str(idDocumento)))
        
        return render_template('verDataset.html',puntuacion=puntuacion,size=size,username=username,archivo=archivo_decode, nombre=nombre,descripcion=descripcion,fecha=fecha,foto=image_base64,video_base64=video_base64)
        
    
    return render_template('dataset.html',username=username)

@auth.route('/buscarDataset',methods =['GET','POST'])
def buscarDataset():
    username = request.args.get('username')
    if request.method == 'GET':
        return render_template('dataset.html', username=username)
    return render_template('dataset.html', username=username)

@auth.route('/amigos',methods =['GET','POST'])
def amigos():
    username = request.args.get('username')
    with dbNeo4j.session() as session:
        result = session.run("MATCH (user:Usuarios {username: $username})-[:AMIGOS]-(friend:Usuarios) "
                             "RETURN DISTINCT friend.username AS name", username=username)
        listAmigos = [record["name"] for record in result]
    if request.method == 'POST':
        if 'addButton' in request.form:
            usuario = request.args.get('username')
            amigo = request.form.get('addAmigo')
            with dbNeo4j.session() as session:
                session.run("MATCH (user1:Usuarios {username: $usuario}), (user2:Usuarios {username: $amigo})""MERGE  (user1)-[:AMIGOS]->(user2)",usuario=usuario, amigo=amigo)
                result = session.run("MATCH (user:Usuarios {username: $username})-[:AMIGOS]-(friend:Usuarios) "
                             "RETURN DISTINCT friend.username AS name", username=username)
                # Se sacan las relaciones AMIGO y se meten a una lista
                listAmigos = [record["name"] for record in result]
            return render_template('amigos.html', username=username,listAmigos=listAmigos,)
        if 'deleteButton' in request.form:
            usuario = request.args.get('username')
            amigo = request.form.get('deleteAmigo')
            with dbNeo4j.session() as session:
                session.run("MATCH (user1:Usuarios {username: $usuario})-[r:AMIGOS]-(user2:Usuarios {username: $amigo})""DELETE r",usuario=usuario, amigo=amigo)
                result = session.run("MATCH (user:Usuarios {username: $username})-[:AMIGOS]-(friend:Usuarios) "
                             "RETURN DISTINCT friend.username AS name", username=username)
                listAmigos = [record["name"] for record in result]
            return render_template('amigos.html', username=username,listAmigos=listAmigos,)
    return render_template('amigos.html', username=username,listAmigos=listAmigos,)


@auth.route('/notificaciones',methods =['GET','POST'])
def notificaciones():
    username = request.args.get('username')
    if request.method == 'POST':
        idDocumento = request.args.get('idDocumento')
        mydoc  = dataSetMongo.find({"id": int(idDocumento)})
        nombre = mydoc[0]['username']
        r.lrem(str(username)+str(nombre), 0, idDocumento)
        
    
    with dbNeo4j.session() as session:
        result = session.run("MATCH (user:Usuarios {username: $username})-[:AMIGOS]-(friend:Usuarios) "
                             "RETURN DISTINCT friend.username AS name", username=username)
        listAmigos = [record["name"] for record in result]
        idDataSet = []
        DataSet = []
        temDataSet = []
        for list in listAmigos:
            idDataSet.extend(r.lrange(str(username)+str(list), 0, -1))
        for i in idDataSet:
            mydoc  = dataSetMongo.find({"id": int(i)})
            temDataSet.append(mydoc[0]['username'])
            temDataSet.append(mydoc[0]['nombre'])
            temDataSet.append(int(i))
            DataSet.append(temDataSet)
            temDataSet = []
        print(DataSet)
    return render_template('notificaciones.html', username=username,DataSet=DataSet,)
    
@auth.route('/clonarDataset',methods =['GET','POST'])
def clonarDataset():
    username = request.args.get('username')
    idDocumento = request.args.get('idDocumento')
    mydoc  = dataSetMongo.find({"id": int(idDocumento)})
    nombre = mydoc[0]['nombre']
    if request.method == 'POST':
        if 'clonButton' in request.form:
            nombre  =request.form.get('nombre')
            id = r.get('id')
            id = int(id)+1
            processed_video = {
            'name': mydoc[0]['video']['name'],
            'data': mydoc[0]['video']['data']}
            processed_archivo = {
            'name': mydoc[0]['archivo']['name'],
            'data': mydoc[0]['archivo']['data']}
            try:
                dataset_doc = { 'id' : id,
                            'username' : username,
                            'nombre' :nombre,
                            'descripcion' : mydoc[0]['descripcion'], 
                            'date' : datetime.utcnow(),
                            'foto' : mydoc[0]['foto'],
                            'archivo' : processed_archivo,
                            'video' : processed_video,
                            'descargas':0,
                            'usuariosDownload':[]}
                dataSetMongo.insert_one(dataset_doc)
                r.set('id',id)
                r.set("numDescargas"+str(id), 0)
                r.lpush("ListaUsuarios"+str(id), '')
                with dbNeo4j.session() as session:
                    result = session.run("MATCH (user:Usuarios {username: $username})-[:AMIGOS]-(friend:Usuarios) "
                                "RETURN DISTINCT friend.username AS name", username=username)
                    listAmigos = [record["name"] for record in result]
                    for list in listAmigos:
                        r.lpush(str(list)+str(username), id)
            except:
                print("Tamaño demasido grande")
            flash("Clonacion de dataset con exito", 'exito')
            return render_template('clonarDataset.html', nombre=nombre,username=username,idDocumento=idDocumento,)
        return render_template('clonarDataset.html', nombre=nombre,username=username,idDocumento=idDocumento,)
    return render_template('clonarDataset.html', nombre=nombre,username=username,idDocumento=idDocumento,)