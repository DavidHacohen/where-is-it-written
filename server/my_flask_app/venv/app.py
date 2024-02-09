from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pymongo
from bson import ObjectId
print("Flask app starting...")


app = Flask(__name__)
CORS(app)

# Configure JWT
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
jwt = JWTManager(app)

# Connect to MongoDB
client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client['the_database']
users_collection = db['users']
discussions_collection = db['discussions']

# Bcrypt for password hashing
bcrypt = Bcrypt(app)

@app.route('/userProfile', methods=['POST'])
@jwt_required()
def user_profile():
    # Fetch user profile information using the current user's identity
    current_user_email = get_jwt_identity()

    user_data = users_collection.find_one({'email': current_user_email}, {'_id': 0, 'password': 0})
    print(user_data)

    if user_data:
        return jsonify(user_data)
    else:
        return jsonify({'message': 'User not found'}), 404

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

     # Check if the email already exists in the database
    existing_user = users_collection.find_one({'email': data['email']})
    print(existing_user)
    if existing_user:
        return jsonify({'message': 'Email already exists'}), 400 

    # Hash the password before storing in MongoDB
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    # Store user information in MongoDB with hashed password
    users_collection.insert_one({
        'firstName': data['firstName'],
        'lastName': data['lastName'],
        'email': data['email'],
        'password': hashed_password,
        
    }   
)
    if users_collection.insert_one:
        return jsonify({'message': 'Registration successful'}), 201
        print("if")
    else:
        return("faild")
        print("els")

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = users_collection.find_one({'email': data['email']})
    print(user)
    a = request.cookies.get("access_token")
    print("gggggggggggggggggggggggggggggggggg")
    print(a)

    try:
        if user and bcrypt.check_password_hash(user['password'], data['password']):

            # Generate access token and return it
            access_token = create_access_token(identity=data['email'])
            print(access_token)
            return jsonify(access_token=access_token), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        print(f"Exception during login: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500


@app.route('/discussions', methods=['GET', 'POST'])
def discussions():
    print("get")
    if request.method == 'GET':
        # Fetch discussions from the database
        discussions = list(discussions_collection.find({}, {'_id': 1, 'text': 1, 'replies': 1}))
        for discussion in discussions:
            discussion['_id'] = str(discussion['_id'])
        return jsonify(discussions)
        print("if")

    elif request.method == 'POST':
        data = request.get_json()

        # Add the new discussion to the database
        a=  discussions_collection.insert_one({
            'text': data.get('text', ''),
            'replies': [],
        }).inserted_id


        return jsonify({'message': 'Discussion added successfully'}), 201

        print("elif")
    else:
        print("discussions else")


@app.route('/discussions/<discussion_id>/replies', methods=['POST'])
def add_reply(discussion_id):
    discussion_id = request.args.get("discussion_id",type=str)
    data = request.get_json()
    print("def replies")

    # Find the discussion by its ID
    discussion = discussions_collection.find_one({'_id': ObjectId(discussion_id)})
    if not discussion:
        print("replies if")
        return jsonify({'message': 'Discussion not found'}), 404

    # Add a new reply to the discussion
    discussion['replies'].append(data)
    discussions_collection.update_one(
        {'_id': ObjectId(discussion_id)},
        {'$set': {'replies': discussion['replies']}}
    )

    return jsonify({'message': 'Reply added successfully'}), 200

@app.route('/discussions/<discussion_id>/like', methods=['PUT'])
@jwt_required()
def like_discussion(discussion_id):
    print("like")
    current_user_email = get_jwt_identity()

    # Find the discussion by its ID
    discussion = discussions_collection.find_one({'_id': ObjectId(discussion_id)})
    if not discussion:
        return jsonify({'message': 'Discussion not found'}), 404
        print("find id")

    

    

def home():
    return 'Welcome to the backend of your website!'

if __name__ == '__main__':
    app.run(debug=True)
