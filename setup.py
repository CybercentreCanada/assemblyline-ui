
import os

from setuptools import setup, find_packages

# Try to load the version from a datafile in the package
package_version = "4.0.0.dev0"
package_version_path = os.path.join(os.path.dirname(__file__), 'assemblyline_ui', 'VERSION')
if os.path.exists(package_version_path):
    with open(package_version_path) as package_version_file:
        package_version = package_version_file.read().strip()

# read the contents of your README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="assemblyline-ui",
    version=package_version,
    description="Assemblyline 4 - User Interface",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/CybercentreCanada/assemblyline-ui/",
    author="CCCS Assemblyline development team",
    author_email="assemblyline@cyber.gc.ca",
    license="MIT",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords="assemblyline automated malware analysis gc canada cse-cst cse cst cyber cccs",
    packages=find_packages(),
    install_requires=[
        'assemblyline',
        'assemblyline-core',
        'werkzeug',
        'python-socketio<5.0.0',
        'flask',
        'flask-socketio<5.0.0',
        'greenlet',
        'gunicorn',
        'gevent',
        'gevent-websocket',
        'pyqrcode',
        'markdown',
        'python-ldap',
        'authlib',
        'fido2'
    ],
    extras_require={
        'test': [
            'pytest',
            'pytest-cov',
            'cart'
        ]
    },
    package_data={
        'assemblyline_ui': [
            "templates/*",
            "static_next/*",
            "static_next/images/*",
            "static_next/static/*",
            "static_next/static/css/*",
            "static_next/static/js/*",
            "static_next/static/media/*",
            "static/css/*",
            "static/fonts/*",
            "static/images/*",
            "static/js/*",
            "static/js/ace/*",
            "static/js/ace/snippets/*",
            "static/js/angular/*",
            "static/js/bootstrap/*",
            "static/js/cbor/*",
            "static/js/d3/*",
            "static/js/flow/*",
            "static/js/flow/directives/*",
            "static/js/infinite-scroll/*",
            "static/js/jquery/*",
            "static/js/jsoneditor/*",
            "static/js/socket.io/*",
            "static/js/swal/*",
            "static/js/ui-select/*",
            "static/ng-template/*",
            "static/pdf/*",
            "VERSION",
        ]
    }
)
