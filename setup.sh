#!/bin/bash
# (c) J~Net 2026
#
# ./setup.sh
#
#
echo "Responder For Python 3 By J~Net 2026"
echo ""

mkdir -p ~/Documents/Scripts/HACKING/

cd ~/Documents/Scripts/HACKING/

git clone https://github.com/jamieduk/Responder.git

cd Responder

function venv() {
    #python3 -m venv venv
    python3.14 -m venv venv
    PYTHON_PATH=$(which python3.14)
    echo "alias python='$PYTHON_PATH'" >> venv/bin/activate
    source venv/bin/activate
    echo "Virtual Environment setup and ready!"
    echo ""
}

venv


echo "Setup Complete Now Read Notes.txt"


