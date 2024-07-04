from flask import Flask, request, jsonify
from SHA3_SemuaOutput import Sha3

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    return 'API is running successfully!'

@app.route('/hashpyhton', methods=['POST'])
def hash_message():
    data = request.get_json()
    message = data.get('message')
    hash_type = data.get('hashType')
    
    if not message or not hash_type:
        return jsonify({'error': 'Invalid input'}), 400
    
    hash_function = {
        '224': Sha3.hash224,
        '256': Sha3.hash256,
        '384': Sha3.hash384,
        '512': Sha3.hash512
    }.get(hash_type)
    
    if hash_function is None:
        return jsonify({'error': 'Invalid hash type'}), 400
    
    hash_value = hash_function(message)
    return jsonify({'hash': hash_value})

if __name__ == '__main__':
    app.run(port=3000)
