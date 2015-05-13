#! /bin/bash

THIS_DIR=`pwd`

# Create virtualenv
virtualenv venv
source venv/bin/activate

pip install -r requirements.txt

cd lib/gnupg
python setup.py install

cd $THIS_DIR
python setup.py "$@"

deactivate venv