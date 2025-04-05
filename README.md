# Aarogya Pretu - Privacy Preserving Health Records System

A secure health records system that implements privacy-preserving data sharing between patients and healthcare providers.

## Features

- Secure user authentication and registration
- Encrypted health data storage
- Doctor verification system
- Consent-based data access
- Public key infrastructure for secure data sharing

## Setup

### 1. Create and activate a Conda environment

```bash
conda create -n pretu python=3.9
conda activate pretu
```

### 2. Install dependencies:

First, install core packages via Conda:

```bash
conda install flask sqlalchemy psycopg2 cryptography redis
```

Then, install remaining dependencies via pip:

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

Create a `.env` file in the root directory and add the following:

```bash
SECRET_KEY=your-super-secret-key
DATABASE_URL=postgresql://user:password@localhost/dbname
FLASK_ENV=development
```

Replace `user`, `password`, and `dbname` with your actual PostgreSQL credentials.

### 4. Initialize the database:

```bash
flask db init
flask db migrate
flask db upgrade
```

### 5. Run the application:

```bash
flask run
```

Alternatively, you can use `python run.py` to run the application directly.

## Security Features

- Public Key Encryption for data storage
- Secure key generation and management
- Consent-based access control
- Doctor verification system
