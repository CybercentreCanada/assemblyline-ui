
from setuptools import setup, find_packages


setup(
    name="assemblyline-ui",
    version="4.0.0.dev8",
    description="Assemblyline (v4) automated malware analysis framework - UI components.",
    long_description="This package provides the UI components of Assemblyline v4 malware analysis framework. "
                     "(UI, APIs and SocketIO Server)",
    url="https://bitbucket.org/cse-assemblyline/alv4_ui/",
    author="CCCS Assemblyline development team",
    author_email="assemblyline@cyber.gc.ca",
    license="MIT",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords="assemblyline malware gc canada cse-cst cse cst cyber cccs",
    packages=find_packages(),
    install_requires=[
        'assemblyline',
        'assemblyline-core',
        'python-baseconv',
        'werkzeug',
        'python-socketio<4',
        'flask',
        'flask-socketio',
        'greenlet',
        'gunicorn',
        'gevent',
        'gevent-websocket',
        'python_u2flib_server',
        'pyqrcode',
        'markdown',
        'elastic-apm[flask]'
    ],
    package_data={
        'al_ui': [
            "templates/*",
            "static/css/*",
            "static/fonts/*",
            "static/images/*",
            "static/js/*",
            "static/js/ace/*",
            "static/js/ace/snippets/*",
            "static/js/angular/*",
            "static/js/bootstrap/*",
            "static/js/d3/*",
            "static/js/flow/*",
            "static/js/flow/directives/*",
            "static/js/infinite-scroll/*",
            "static/js/jquery/*",
            "static/js/jsoneditor/*",
            "static/js/socket.io/*",
            "static/js/swal/*",
            "static/js/u2f/*",
            "static/js/ui-select/*",
            "static/ng-template/*",
            "static/pdf/*"
        ]
    }
)
