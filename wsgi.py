import os
from app import app as application  # Cambia 'app' por el nombre de tu archivo si es necesario

if __name__ == "__main__":
    application.run(debug=True,host='0.0.0.0', port=5000)
