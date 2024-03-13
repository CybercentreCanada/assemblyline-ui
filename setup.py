
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
    description="Assemblyline 4 - API and Socket IO server",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/CybercentreCanada/assemblyline-ui/",
    author="CCCS Assemblyline development team",
    author_email="assemblyline@cyber.gc.ca",
    license="MIT",
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    keywords="assemblyline automated malware analysis gc canada cse-cst cse cst cyber cccs",
    packages=find_packages(),
    install_requires=[
        'assemblyline',
        'assemblyline-core',
        'werkzeug',
        'flask<3.0.0',
        'pyqrcode',
        'markdown',
        'python-ldap',
        'authlib<1.0.0',
        'fido2<1.0.0',
        'PyJWT',
        'gunicorn',
        'gevent',
        'hauntedhouse==0.1.7',
    ],
    extras_require={
        'test': [
            'pytest',
            'pytest-mock',
            'cart'
        ],
        'socketio': [
            'python-socketio',
            'flask-socketio',
            'gevent-websocket',
        ]
    },
    package_data={
        'assemblyline_ui': [
            "VERSION"
        ]
    }
)
