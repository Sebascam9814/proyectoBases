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
# Logica para cuando se ingresa a la aplicacion
@auth.route('/login',methods =['GET','POST'])
def login():
    
    if request.method == 'POST':
        #se trae el username y la contraseña
        username  =request.form.get('username')
        password =request.form.get('password')
        #Se hashea la contraseña para que se guardada con seguridad
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        #Se crea un cursor con la conexion abierta de MySql donde se trae el username y la contraseña
        cursor = dbmysql.connection.cursor()
        queryLogin = "SELECT COUNT(*) FROM usuarios WHERE username=%s AND password=%s"
        cursor.execute(queryLogin, (username, hashed_password))
        result = cursor.fetchone()[0]
        #Si encuentra un match devuelve un 1 significa que estan correctos
        if result == 1:
            # se trae todo la informacion del usuario a a mostar en la pagina Usuario
            query = "SELECT * FROM usuarios WHERE username=%s"
            cursor.execute(query, (username,))
            row = cursor.fetchone()
            id = row[0]
            nombreCompleto = row[3]
            fechaNacimietno = row[4]

            #se trae la foto de perfil y se codifica para mostrar en la pagina web.
            query = "SELECT picture_data FROM pictures WHERE id=%s"
            cursor.execute(query, (id,))
            image_data = cursor.fetchone()[0]
            image_buffer = BytesIO(image_data)
            base64_image = base64.b64encode(image_buffer.getvalue()).decode()
            #se cierra la conexion
            cursor.close()
            #se mustra la pagina usuario
            return render_template("usuario.html",foto=base64_image,username=username,name=nombreCompleto,fecha=fechaNacimietno)
        else:
            # no se encontro match entre el usuario y contraseña ingresado y devuelve error
            cursor.close()
            flash('Error al ingresar Usuario o constraseña invalida ', 'error')
            return render_template("login.html")
   
    
    
    return render_template("login.html")

#logica para registrarse en la aplicacion
@auth.route('/sign-up',methods =['GET','POST'])
def sign_up():
    # si se le da registrar trae los datos desde los inputs del HTML
    if request.method == 'POST':
        
        username =request.form.get('username')
        password  =request.form.get('password')
        nombre =request.form.get('nombre')
        fecha =request.form.get('fecha')
        foto  = request.files['foto']
        #si esta alguno vacio muestra que hubo un error que faltan datos

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
    # se traen los datos de la base de datos MySql
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
            # se muestra la pagina con los datos acutales del usuario
            return render_template('update.html', username=username,password=password,nombre=nombreCompleto,fecha=fechaNacimietno,foto=None)
    if request.method == 'POST':
        # si se cambio algo se registra el cambio y se guarda en  la base de datos.
        username = request.args.get('username')
        cursor = dbmysql.connection.cursor()
        query = "SELECT password FROM usuarios WHERE username=%s"
        cursor.execute(query, (username,))
        hashPassword = cursor.fetchone()[0]
        password  =request.form.get('password')
        nombre =request.form.get('nombre')
        fecha =request.form.get('fecha')
        foto  = request.files['foto']
        #si se subio una foto se cambia por la nueva
        if  foto.filename:
            img_data = foto.read()
            img_base64 = base64.b64encode(img_data).decode('utf-8')
            img = Image.open(BytesIO(img_data))

            query = "UPDATE pictures SET picture_data=%s WHERE username=%s"
            cursor.execute(query, (img_data,username,))
            dbmysql.connection.commit()
        #si es diferetne se cambia la constraseña
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
    #se traen los datos del usuario que huzo login y se myestrna en la pagina
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
    #se trae el usaurio actual
    username = request.args.get('username')
    if request.method == 'POST':
        #boton de busqueda por de los datasets por nombre  usando regex  

        if 'NomButton' in request.form:
            nombreDescripcion  =request.form.get('nombre')
            if nombreDescripcion == '':
                return render_template('dataset.html', username=username)
            else:
                documents = dataSetMongo.find({"nombre": {"$regex": nombreDescripcion}})
                return render_template('buscarDataset.html', documents=documents,username=username)

        #boton de busqueda por de los datasets por usuarios  usando regex  
        if 'UsButton' in request.form:
            nombreDescripcion  =request.form.get('username')
            if nombreDescripcion == '':
                return render_template('dataset.html', username=username)
            else:
                documents = dataSetMongo.find({"username": {"$regex": nombreDescripcion}})
                return render_template('buscarDataset.html', documents=documents,username=username)
       
        #boton de busqueda por de los datasets por del usaurio activo     
        if 'MiButton' in request.form:
            nombreDescripcion  =request.args.get('username')
            if nombreDescripcion == '':
                return render_template('dataset.html', username=username)
            else:
                
                documents = dataSetMongo.find({"username": nombreDescripcion})
                return render_template('buscarDataset.html', documents=documents,username=username)
        #boton de busqueda por de los datasets por descripcion  usando regex  
        
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
        #se traen los datos desde la pagina, se procesan y se almacinean en mongo
        nombre  =request.form.get('nombre')
        descripcion =request.form.get('descripcion')
        foto  = request.files['foto']
        archivo  = request.files['archivo']
        video  = request.files['video']
        #si falto alguno mustra error
        if not username or not nombre or not descripcion or not foto.filename or not archivo.filename or not video.filename:
            flash("Faltaron datos en el DataSet", 'error')
            return render_template("crearDataset.html", username=username)
        #Se trae el ultimo id almacenado en redis para la creacion del sigueinte dataset en mongo
        id = r.get('id')
        id = int(id)+1
        #Se procesa el video
        video_data = video.read()
        processed_video = {
        'name': video.filename,
        'data': video_data}
        #se procesa la imagen
        img_data = foto.read()
        img_base64 = base64.b64encode(img_data).decode('utf-8')
        img = Image.open(BytesIO(img_data))
        # LEER archivo
        file_data = archivo.read()
        processed_archivo = {
        'name': archivo.filename,
        'data': file_data}
        #se inserta la informacion en mongo
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
            #Se agrega 1 al contador
            r.set('id',id)
            #se Crea el contador de descargas de este dataset nuevo
            r.set("numDescargas"+str(id), 0)
            #Lista de los usuarios que lo han descargado
            r.lpush("ListaUsuarios"+str(id), '')
            #se revisa si tiene alguna relacion en neo para la cola de notidicaciones
            with dbNeo4j.session() as session:
                result = session.run("MATCH (user:Usuarios {username: $username})-[:AMIGOS]-(friend:Usuarios) "
                             "RETURN DISTINCT friend.username AS name", username=username)
                listAmigos = [record["name"] for record in result]
                for list in listAmigos:
                    #si tiene se agrega a la cola de notificaciones
                    r.lpush(str(list)+str(username), id)
        except:
            #si falla es porque los archivos son muy grandes y muestra el erroe
            print("Tamaño demasido grande")
        flash("Creacion de dataset con exito", 'exito')
        return render_template('crearDataset.html', username=username)
     return render_template('crearDataset.html', username=username)

@auth.route('/verDataset',methods =['GET','POST'])
def verDataset():
    username = request.args.get('username')
    if request.method == 'POST':
        #Puntuar dataset
        if 'punButton' in request.form:
            idDocumento = request.args.get('idDocumento')
            puntaje  =request.form.get('puntuacion')
            #se verifica que sea un numero entre 1 y 5
            try:
                puntaje  =int(request.form.get('puntuacion'))
                if puntaje <6 and puntaje > 0 :
                    r.set(str(username)+str(idDocumento),puntaje)
                else:
                    flash("La puntuacion debe ser 1 a 5", 'error')
            except:
                flash("Ingresaste una puntuacion que no es valida debe ser 1-5", 'error') 
            # se muestra el dataset con la informacion actualizada
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
            #Se traen los datos del arvhico
            idDocumento = request.args.get('idDocumento')
            username = request.args.get('username')
            mydoc  = dataSetMongo.find({"id": int(idDocumento)})
            archivo = mydoc[0]['archivo']['data']
            filename = mydoc[0]['archivo']['name']
            #se trae el numero de descargas
            descargas = r.get("numDescargas"+str(idDocumento))
            #revisar si ya descargo el data set
            existing_items = set(r.lrange("ListaUsuarios"+str(id), 0, -1))
            if username.encode() not in existing_items:
            # Si no existe el usuario se agrega a la lista de quien a descargado
                r.rpush("ListaUsuarios"+str(id), username)
                dataSetMongo.update_one(
                {'id': int(idDocumento)}, # Se agrega a mongo para llevar mas control
                {'$push': {'usuariosDownload': username}})

            descargas = int(descargas)+1
            dataSetMongo.update_one(
            {'id': int(idDocumento)}, # Se agrega a mongo para llevar mas control
            {'$set': {'descargas': descargas}})
            
            #se guarda en redis
            r.set("numDescargas"+str(idDocumento), descargas)
            #descarga el arvhico
            return send_file(BytesIO(archivo), as_attachment=True, mimetype='text/plain', download_name=filename)
        if 'ComenButton' in request.form:
            print('Funcionalidad en contruccion')
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
        #trae la informacion del dataset a buscar
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
        #none no tiene puntacuin asignada todavia sino se trae la asignada
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
    #se crea la secion de neo4j se traen los usuaruos a los que se siguen
    with dbNeo4j.session() as session:
        result = session.run("MATCH (user:Usuarios {username: $username})-[:AMIGOS]-(friend:Usuarios) "
                             "RETURN DISTINCT friend.username AS name", username=username)
        listAmigos = [record["name"] for record in result]
    if request.method == 'POST':
        #para agregar a un amigo
        if 'addButton' in request.form:
            usuario = request.args.get('username')
            amigo = request.form.get('addAmigo')
            #se trae el nombre ingresado si existe el nodo se crea la relacion 
            with dbNeo4j.session() as session:
                session.run("MATCH (user1:Usuarios {username: $usuario}), (user2:Usuarios {username: $amigo})""MERGE  (user1)-[:AMIGOS]->(user2)",usuario=usuario, amigo=amigo)
                result = session.run("MATCH (user:Usuarios {username: $username})-[:AMIGOS]-(friend:Usuarios) "
                             "RETURN DISTINCT friend.username AS name", username=username)
                # Se sacan las relaciones AMIGO y se meten a una lista
                listAmigos = [record["name"] for record in result]
            return render_template('amigos.html', username=username,listAmigos=listAmigos,)
            #se trae el nombre ingresado si ecites la relacion se elimina en caso de no no
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
   #Se elimina de la lista el dataset selecionado.
    username = request.args.get('username')
    if request.method == 'POST':
        idDocumento = request.args.get('idDocumento')
        mydoc  = dataSetMongo.find({"id": int(idDocumento)})
        nombre = mydoc[0]['username']
        r.lrem(str(username)+str(nombre), 0, idDocumento)
        
    #se crea una lista de los amigos que se relacionen
    with dbNeo4j.session() as session:
        result = session.run("MATCH (user:Usuarios {username: $username})-[:AMIGOS]-(friend:Usuarios) "
                             "RETURN DISTINCT friend.username AS name", username=username)
        listAmigos = [record["name"] for record in result]
        idDataSet = []
        DataSet = []
        temDataSet = []
        for list in listAmigos:
            #busca si en la lista de amigo se agregaron en el momento que ya fueorn amigos y trae el ida del documento a buscar en mongo
            idDataSet.extend(r.lrange(str(username)+str(list), 0, -1))
        for i in idDataSet:
            mydoc  = dataSetMongo.find({"id": int(i)})
            temDataSet.append(mydoc[0]['username'])
            temDataSet.append(mydoc[0]['nombre'])
            temDataSet.append(int(i))
            DataSet.append(temDataSet)
            temDataSet = []
    return render_template('notificaciones.html', username=username,DataSet=DataSet,)
    
@auth.route('/clonarDataset',methods =['GET','POST'])
def clonarDataset():
    #se traen todos los datos del dataset a clonar, y para asignar el nuevo nomvre se guarda en la base t se agrega.
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