import shutil, zipfile, jodel_api, tempfile, os, time

from flask import Flask, request, redirect, url_for
from werkzeug.utils import secure_filename
import decrypt as decrypt
from r2instance import R2Instance
from pyaxmlparser import APK

UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'apk'}

app = Flask(__name__, static_url_path="/static", static_folder="../frontend-dist")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('static', filename='index.html'))


@app.route('/api/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return jodel_api.json.dumps(process_file(filepath))
    else:
        return {'error':True, 'message': 'File type not allowed!'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def gather_apk_information(apk_file_path):
    try:
        apk = APK(apk_file_path)
        return {'error':False, 'package': apk.package, 'version_name': apk.version_name,
                'version_code': apk.version_code,
                'is_jodel_signature': True if apk.package == 'com.tellm.android.app' else False}
    except:
        return {'error':True, 'message': 'Failed verifying APK file!'}


def process_file(apk_file_path):
    apk_information = gather_apk_information(apk_file_path)
    if not apk_information['error']:
        r2instance, unzip_directory = extract_zip(apk_file_path)
        clean_up_mess(apk_file_path, unzip_directory)
        if r2instance is None:
            return {'error':True, 'message': 'Library file not found, exiting...'}
        apk_information['hmac_key'] = decrypt.decrypt(r2instance.key).decode("utf-8")
        apk_information['key_status'] = is_key_working(apk_information['hmac_key'], apk_information['version_name'])
        apk_information['error'] = False
        apk_information['message'] = 'Successfully extracted key!'

    return apk_information


def clean_up_mess(apk_file_path, extracted_file_path):
    try:
        if apk_file_path and os.path.isfile(apk_file_path):
            os.remove(apk_file_path)
            print('Removed APK file')

        if extracted_file_path and os.path.isdir(extracted_file_path):
            shutil.rmtree(extracted_file_path)
            print('Removed extracted files')
    except:
        print('failed to remove files')


def extract_zip(path):
    with zipfile.ZipFile(path) as archive:
        unzip_directory = os.path.join(UPLOAD_FOLDER, str(time.time()))
        for file in archive.namelist():
            if file.startswith('lib/') and file.find('x86') != -1:
                extracted_file = os.path.join(
                    unzip_directory, archive.extract(file, unzip_directory))
                _r2instance = R2Instance(extracted_file)
                if _r2instance.is_correct_binary:
                    return _r2instance, unzip_directory
                else:
                    del _r2instance

    return None, unzip_directory


def is_key_working(key, version):
    try:
        lat, lng, city = 48.148900, 11.567400, "Munich"
        j = jodel_api.JodelAccount(lat=lat, lng=lng, city=city)
        return {'working': True, 'account': j.get_account_data()}
    except Exception as e:
        print(e)
        return {'working': False}


if __name__ == '__main__':
    Flask.run(app, debug=False)

