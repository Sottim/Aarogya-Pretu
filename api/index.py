# api/index.py
import sys
import os

# Add the project root directory to the Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

try:
    from app import create_app
    # Use production config for Vercel
    app = create_app('production')
except Exception as e:
    print(f"Error creating Flask app: {e}")
    raise

# Health check endpoint
@app.route('/api/health')
def health_check():
    return 'OK', 200