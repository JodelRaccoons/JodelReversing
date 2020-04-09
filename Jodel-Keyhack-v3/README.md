# Jodel Keyhack v3 (now with fancy angular gui)

# Install on Windows

(for Windows) Install package manager [Chocolatey](https://chocolatey.org/) for programs and
[scoop](https://scoop.sh/) for dev tools

1. Install requirements
   - `scoop install radare2`
   - `choco install nodejs`
   - `choco install python3`
2. Create virtual env
   - `py -3 -m venv venv`
3. Activate virtualenv
   - `venv\Scripts\activate`
4. Install python deps
   - `pip install -r requirements.txt`
5. Build frontend
   - `npm ci`
   - `npm run build:prod`
6. Start backend
   - `python3 backend/server.py`

# Install on macOS

1. Install requirements
   - `brew install radare2`
   - `brew install nodejs`
   - `brew install python3`
2. Create virtual env
   - `python3 -m venv venv`
3. Activate virtualenv
   - `. venv/bin/activate`
4. Install python deps
   - `pip install -r requirements.txt`
5. Build frontend
   - `npm ci`
   - `npm run build:prod`
6. Start backend
   - `python3 backend/server.py`
