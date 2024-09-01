#!/bin/bash

# Definindo variáveis
SERVICE_NAME="proxy"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
WORK_DIR="/home/ubuntu/PyProxy"
VENV_DIR="$WORK_DIR/venv"
PYTHON_EXEC="$VENV_DIR/bin/python"
SCRIPT="$WORK_DIR/main.py"
USER="ubuntu"

# Atualizar o sistema e instalar dependências
echo "Atualizando o sistema e instalando dependências..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv

# Criar o ambiente virtual se não existir
if [ ! -d "$VENV_DIR" ]; then
    echo "Criando ambiente virtual..."
    python3 -m venv "$VENV_DIR"
fi

# Ativar o ambiente virtual e instalar dependências do projeto
echo "Instalando dependências do projeto..."
source "$VENV_DIR/bin/activate"
pip install -r "$WORK_DIR/requirements.txt"
deactivate

# Criar o arquivo de serviço do systemd
echo "Criando o arquivo de serviço do systemd..."
sudo bash -c "cat > $SERVICE_FILE" <<EOF
[Unit]
Description=Proxy Python Service
After=network.target

[Service]
User=root
WorkingDirectory=$WORK_DIR
Environment="PATH=$VENV_DIR/bin"
ExecStart=$PYTHON_EXEC $SCRIPT

[Install]
WantedBy=multi-user.target
EOF

# Recarregar o systemd, habilitar e iniciar o serviço
echo "Recarregando o systemd e iniciando o serviço..."
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME.service
sudo systemctl start $SERVICE_NAME.service

echo "Deploy concluído com sucesso!"
