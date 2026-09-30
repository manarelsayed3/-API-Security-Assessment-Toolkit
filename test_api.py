from flask import Flask, jsonify, request

app = Flask(__name__)

users = {
    "1": {
        "name": "Manar",
        "email": "manar@example.com",
        "owner_id": "1"
    },
    "2": {
        "name": "Ahmed",
        "email": "ahmed@example.com",
        "owner_id": "2"
    }
}


@app.route("/api/users/<user_id>")
def get_user(user_id):

    current_user = request.headers.get("X-User-ID")

    if not current_user:
        return jsonify({
            "error": "Authentication required"
        }), 401

    user = users.get(user_id)

    if not user:
        return jsonify({
            "error": "User not found"
        }), 404

    # Object-level authorization

    if user["owner_id"] != current_user:
        return jsonify({
            "error": "Access denied"
        }), 403

    return jsonify(user)


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
