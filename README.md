# Aarogya Pretu - Privacy Preserving Health Records System

A secure health records system that implements privacy-preserving data sharing between patients and healthcare providers.

## Features

- Secure user authentication and registration
- Encrypted health data storage
- Doctor verification system
- Consent-based data access
- Public key infrastructure for secure data sharing

## Setup

1. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Linux
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Initialize the database:

```bash
flask db init
flask db migrate
flask db upgrade
```

4. Run the application:

```bash
flask run
```

Alternatively, you can use `python app.py` to run the application directly.

## Security Features

- Public Key Encryption for data storage
- Secure key generation and management
- Consent-based access control
- Doctor verification system
