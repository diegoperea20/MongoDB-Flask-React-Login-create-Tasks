from flask import Flask, request, jsonify
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import check_password_hash, generate_password_hash
import jwt
import datetime
from mongoengine import Document, StringField, connect


app = Flask(__name__)

# For using frontend
CORS(app)

# Configure MongoDB connection
# Replace 'flaskmongodb' with your database name, and 'localhost' with your MongoDB server address.
connect('flaskmongodb', host='mongodb://localhost:27017')

ma = Marshmallow(app)

# User collection
class User(Document):
    email = StringField(unique=True)
    user = StringField(unique=True)
    password = StringField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


# Task collection
class Task(Document):
    user = StringField()
    title = StringField()
    description = StringField()
    

class UserSchema(ma.Schema):
    class Meta:
        fields = ('email', 'user', 'password')


user_schema = UserSchema()
users_schema = UserSchema(many=True)


class TaskSchema(ma.Schema):
    class Meta:
        fields = ('user', 'title', 'description')


task_schema = TaskSchema()
tasks_schema = TaskSchema(many=True)


@app.route('/loginup', methods=['POST'])
def create_user():
    email = request.json['email']
    user = request.json['user']
    password = generate_password_hash(request.json['password'])
    existing_user = User.objects(user=user).first()
    if existing_user:
        return jsonify({'error': 'User already exists'}), 409
    new_user = User(email=email, user=user, password=password)
    new_user.save()
    return user_schema.jsonify(new_user)


@app.route('/loginup', methods=['GET'])
def get_users():
    all_users = User.objects.all()
    result = users_schema.dump(all_users)
    return jsonify(result)


@app.route('/loginup/<id>', methods=['GET'])
def get_user(id):
    user = User.objects(id=id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return user_schema.jsonify(user)


@app.route('/loginup/<id>', methods=['PUT'])
def update_user(id):
    user = User.objects(id=id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    email = request.json['email']
    user.user = request.json['user']
    password = request.json['password']

    user.email = email
    user.password = generate_password_hash(password).decode('utf-8')

    user.save()

    return user_schema.jsonify(user)


@app.route('/loginup/<id>', methods=['DELETE'])
def delete_user(id):
    user = User.objects(id=id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.delete()
    return jsonify({'message': 'User deleted successfully'}), 200


# Login IN (Iniciar sesion)
@app.route('/', methods=['POST'])
def login():
    data = request.get_json()
    username = data['user']
    password = data['password']

    user = User.objects(user=username).first()
    if user and check_password_hash(user.password, password):
        # Las credenciales son válidas, puedes generar un token de autenticación aquí
        token = generate_token(user)  # Ejemplo: función para generar el token

        return jsonify({'token': token, "user_id": str(user.id)}), 200

    # Las credenciales son incorrectas
    return jsonify({'error': 'Credenciales inválidas'}), 401


def generate_token(user):
    # Definir las opciones y configuraciones del token
    token_payload = {
        'user_id': str(user.id),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expira en 1 hora
    }
    secret_key = 'tuclavesecretadeltoken'  # Cambia esto a tu clave secreta real

    # Generar el token JWT utilizando PyJWT
    token = jwt.encode(token_payload, secret_key, algorithm='HS256')
    return token

#Task 

@app.route('/tasks', methods=['POST'])
def create_task():
    user = request.json['user']
    title = request.json['title']
    description = request.json['description']

    new_task = Task(user=user, title=title, description=description)
    new_task.save()  # Guardar la nueva tarea en la base de datos

    return task_schema.jsonify(new_task), 201


@app.route('/tasks', methods=['GET'])
def get_tasks():
    all_tasks = Task.objects.all()
    result = tasks_schema.dump(all_tasks)
    return jsonify(result)


@app.route('/tasks/<user>', methods=['GET'])
def get_task(user):
    tasks = Task.objects(user=user)
    serialized_tasks = []
    
    for task in tasks:
        task_data = task.to_mongo()
        task_data['id'] = str(task_data['_id'])
        del task_data['_id']
        serialized_tasks.append(task_data)

    return jsonify(serialized_tasks)






@app.route('/tasks/<id>', methods=['PUT'])
def update_task(id):
    try:
        task = Task.objects.get(id=id)
    except Task.DoesNotExist:
        return jsonify({'message': 'Task not found'}), 404

    user = request.json.get('user', task.user)
    title = request.json.get('title', task.title)
    description = request.json.get('description', task.description)

    task.user = user
    task.title = title
    task.description = description

    task.save()

    return task_schema.jsonify(task)



@app.route('/tasks/<id>', methods=['DELETE'])
def delete_task(id):
    try:
        task = Task.objects.get(id=id)
    except Task.DoesNotExist:
        return jsonify({'message': 'Task not found'}), 404

    task.delete()

    return jsonify({'message': 'Task deleted successfully'})


@app.route('/tasks/deleteall/<user>', methods=['DELETE'])
def delete_tasks_all(user):
    tasks = Task.objects(user=user)
    tasks.delete()

    return jsonify({'message': 'All tasks for the user have been deleted'})


@app.route('/tasks/<id>/<user>', methods=['GET'])
def get_task_with_id(id, user):
    task = Task.objects(id=id, user=user)
    return tasks_schema.jsonify(task)


@app.route('/tasks/countsames/<user>')
def get_same_count(user):
    # Get a list of task titles that belong to the specified user
    user_tasks = Task.objects(user=user).distinct('title')

    # Find tasks that have the same title as the user's tasks
    same_titles = Task.objects(title__in=user_tasks).distinct('title')

    # Use a list to store unique titles along with their counts
    unique_titles = []

    for title in same_titles:
        count = Task.objects(title=title, user__ne=user).count()

        if count > 0:  # Only consider titles that have duplicates
            unique_titles.append({"Number of titles": count, "title": title})

    if not unique_titles:
        return jsonify(message="Ningún título coincide con otros usuarios.")

    return jsonify(unique_titles)



@app.route('/tasks/countsame/<user>')
def get_same_title_email(user):
    # Get all tasks for the given user
    user_tasks = Task.objects(user=user)

    # Find titles that have more than one user associated
    duplicate_titles = Task.objects(user__ne=user, title__in=[task.title for task in user_tasks]) \
                        .distinct("title")

    # Create a list to store the results
    results = []

    # Loop through each duplicate title and find associated users' emails
    for title in duplicate_titles:
        tasks_with_same_title = Task.objects(title=title, user__ne=user)
        emails = []

        # Retrieve emails by querying the User collection based on usernames
        for task in tasks_with_same_title:
            user_object = User.objects(user=task.user).first()
            if user_object:
                emails.append(user_object.email)

        result = {
            "title": title,
            "emails": emails
        }

        results.append(result)

    if not results:
        return jsonify(message="Ningún título coincide con otros usuarios.")

    return jsonify(results)




if __name__ == '__main__':
    app.run(debug=True)


#docker run --name mymongo -p 27017:27017 -d mongo:latest
#docker exec -it mymongo bash
#mongosh
#use flaskmongodb;
#show collections;
#db.user.find().pretty();