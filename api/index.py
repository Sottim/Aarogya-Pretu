# api/index.py
import sys
import os

# Add the project root directory to the Python path
# This allows importing 'app' from the parent directory
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

try:
    from app import create_app
    app = create_app()
    # Vercel needs the application instance to be named 'app' or 'application'
except Exception as e:
    # Basic error logging in case app creation fails
    print(f"Error creating Flask app: {e}")
    raise

# Optional: Add a simple health check endpoint
@app.route('/api/health')
def health_check():
    return 'OK', 200

# The Flask app instance needs to be accessible at the module level for Vercel
# No need to run app.run() here; Vercel handles the server.
